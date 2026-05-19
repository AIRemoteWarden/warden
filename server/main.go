package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed web web/assets
var webFS embed.FS

//go:embed policy.default.json
var embeddedDefaultPolicy []byte

type Config struct {
	ControlAddr string
	PublicHost  string
	PolicyPath  string
}

type Server struct {
	cfg          Config
	sessions     *SessionStore
	upgrader     websocket.Upgrader
	guestPage    *template.Template
	staticAssets http.Handler
}

func main() {
	cfg := Config{
		ControlAddr: envOrAny([]string{"WARDEN_CONTROL_ADDR", "DEBUGIT_CONTROL_ADDR"}, ":8080"),
		PublicHost:  envOrAny([]string{"WARDEN_PUBLIC_HOST", "DEBUGIT_PUBLIC_HOST"}, "localhost"),
		PolicyPath:  envOrAny([]string{"WARDEN_POLICY_PATH", "DEBUGIT_POLICY_PATH"}, ""),
	}

	assetFS, err := fs.Sub(webFS, "web/assets")
	if err != nil {
		log.Fatalf("asset fs error: %v", err)
	}

	guestPage, err := template.ParseFS(webFS, "web/guest.html")
	if err != nil {
		log.Fatalf("guest page template error: %v", err)
	}

	srv := &Server{
		cfg:       cfg,
		sessions:  NewSessionStore(),
		guestPage: guestPage,
		staticAssets: http.StripPrefix(
			"/assets/",
			http.FileServer(http.FS(assetFS)),
		),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	controlMux := http.NewServeMux()
	controlMux.Handle("/assets/", srv.staticAssets)
	controlMux.HandleFunc("/healthz", srv.handleHealthz)
	controlMux.HandleFunc("/v1/policy/default", srv.handleDefaultPolicy)
	controlMux.HandleFunc("/v1/sessions", srv.handleCreateSession)
	controlMux.HandleFunc("/api/session/", srv.handleSessionInfo)
	controlMux.HandleFunc("/session/", srv.handleSessionPage)
	controlMux.HandleFunc("/ws/host", srv.handleHostWS)
	controlMux.HandleFunc("/ws/guest", srv.handleGuestWS)

	controlServer := &http.Server{
		Addr:    cfg.ControlAddr,
		Handler: loggingMiddleware(controlMux),
	}

	go func() {
		log.Printf("server listening on %s", cfg.ControlAddr)
		if err := controlServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("control server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = controlServer.Shutdown(ctx)
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	session := s.sessions.Create(req.Readonly, s.cfg)
	writeJSON(w, http.StatusOK, CreateSessionResponse{
		SessionID: session.ID,
		HostToken: session.HostToken,
		GuestToken: session.GuestToken,
		GuestURL:  session.GuestURL,
		RelayURL:  session.HostRelayURL,
	})
}

func (s *Server) handleDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := s.loadDefaultPolicy()
	if err != nil {
		http.Error(w, "default policy unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", fmt.Sprintf(`W/"default-%d"`, len(raw)))
	_, _ = w.Write(raw)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/session/")
	session, ok := s.sessions.GetByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":      session.ID,
		"readonly":        session.Readonly,
		"host_connected":  session.HostConn != nil,
		"guest_connected": session.GuestConn != nil,
	})
}

func (s *Server) handleSessionPage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/session/")
	session, ok := s.sessions.GetByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	guestToken := r.URL.Query().Get("guest_token")
	if guestToken == "" || guestToken != session.GuestToken {
		http.Error(w, "invalid guest token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := guestPageView{
		Title:      "AI Warden Guest Terminal",
		SessionID:  session.ID,
		GuestToken: session.GuestToken,
		Readonly:   session.Readonly,
		ModeLabel: map[bool]string{
			true:  "read-only",
			false: "interactive",
		}[session.Readonly],
	}

	if err := s.guestPage.Execute(w, view); err != nil {
		http.Error(w, "failed to render guest page", http.StatusInternalServerError)
	}
}

func (s *Server) handleHostWS(w http.ResponseWriter, r *http.Request) {
	hostToken := r.URL.Query().Get("host_token")
	if hostToken == "" {
		hostToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if hostToken == "" {
		http.Error(w, "missing host token", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessions.GetByHostToken(hostToken)
	if !ok {
		http.Error(w, "invalid host token", http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	if err := s.sessions.AttachHost(session.ID, conn); err != nil {
		_ = conn.Close()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer s.sessions.DetachHost(session.ID, conn)

	if guest := s.sessions.CurrentGuest(session.ID); guest != nil {
		_ = writeWSJSON(conn, RelayJoined{})
	}

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			_ = s.sessions.BroadcastToGuest(session.ID, []byte(`{"type":"close"}`))
			return
		}

		var envelope MessageEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			_ = writeWSJSON(conn, RelayError{})
			continue
		}

		switch envelope.Type {
		case "host_output", "resize", "approval_state", "feedback", "close":
			_ = s.sessions.BroadcastToGuest(session.ID, data)
			if envelope.Type == "close" {
				return
			}
		default:
			_ = writeWSJSON(conn, RelayError{})
		}
	}
}

func (s *Server) handleGuestWS(w http.ResponseWriter, r *http.Request) {
	guestToken := r.URL.Query().Get("guest_token")
	if guestToken == "" {
		http.Error(w, "missing guest token", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessions.GetByGuestToken(guestToken)
	if !ok {
		http.Error(w, "invalid guest token", http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	if err := s.sessions.AttachGuest(session.ID, conn); err != nil {
		_ = conn.Close()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer s.sessions.DetachGuest(session.ID, conn)

	if host := s.sessions.CurrentHost(session.ID); host != nil {
		_ = writeWSJSON(host, RelayJoined{})
	}

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if host := s.sessions.CurrentHost(session.ID); host != nil {
				_ = writeWSJSON(host, RelayLeft{})
			}
			return
		}

		var msg GuestInbound
		if err := json.Unmarshal(data, &msg); err != nil {
			_ = writeWSJSON(conn, RelayError{})
			continue
		}

		switch msg.Type {
		case "guest_input":
			if _, err := base64.StdEncoding.DecodeString(msg.DataB64); err != nil {
				_ = writeWSJSON(conn, RelayError{})
				continue
			}
			if host := s.sessions.CurrentHost(session.ID); host != nil {
				_ = host.WriteMessage(websocket.TextMessage, data)
			}
		case "close":
			if host := s.sessions.CurrentHost(session.ID); host != nil {
				_ = writeWSJSON(host, RelayLeft{})
			}
			return
		default:
			_ = writeWSJSON(conn, RelayError{})
		}
	}
}

type SessionStore struct {
	mu           sync.RWMutex
	byID         map[string]*Session
	byHostToken  map[string]*Session
	byGuestToken map[string]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		byID:         make(map[string]*Session),
		byHostToken:  make(map[string]*Session),
		byGuestToken: make(map[string]*Session),
	}
}

func (s *SessionStore) Create(readonly bool, cfg Config) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := randomToken("sess")
	hostToken := randomToken("host")
	guestToken := randomToken("guest")
	session := &Session{
		ID:           id,
		HostToken:    hostToken,
		GuestToken:   guestToken,
		Readonly:     readonly,
		GuestURL:     fmt.Sprintf("%s/session/%s?guest_token=%s", publicHTTPBase(cfg), id, guestToken),
		HostRelayURL: fmt.Sprintf("%s/ws/host", publicWSBase(cfg)),
	}

	s.byID[id] = session
	s.byHostToken[hostToken] = session
	s.byGuestToken[guestToken] = session
	return session
}

func (s *SessionStore) GetByID(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.byID[id]
	return session, ok
}

func (s *SessionStore) GetByHostToken(token string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.byHostToken[token]
	return session, ok
}

func (s *SessionStore) GetByGuestToken(token string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.byGuestToken[token]
	return session, ok
}

func (s *SessionStore) AttachHost(id string, conn *websocket.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("unknown session")
	}
	if session.HostConn != nil {
		return fmt.Errorf("host already connected")
	}
	session.HostConn = conn
	return nil
}

func (s *SessionStore) AttachGuest(id string, conn *websocket.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("unknown session")
	}
	if session.GuestConn != nil {
		return fmt.Errorf("guest already connected")
	}
	session.GuestConn = conn
	return nil
}

func (s *SessionStore) DetachHost(id string, conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.byID[id]; ok && session.HostConn == conn {
		s.expireSessionLocked(session)
	}
}

func (s *SessionStore) DetachGuest(id string, conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.byID[id]; ok && session.GuestConn == conn {
		session.GuestConn = nil
		_ = conn.Close()
	}
}

func (s *SessionStore) CurrentHost(id string) *websocket.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, ok := s.byID[id]; ok {
		return session.HostConn
	}
	return nil
}

func (s *SessionStore) CurrentGuest(id string) *websocket.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, ok := s.byID[id]; ok {
		return session.GuestConn
	}
	return nil
}

func (s *SessionStore) BroadcastToGuest(id string, data []byte) error {
	s.mu.RLock()
	session, ok := s.byID[id]
	if !ok || session.GuestConn == nil {
		s.mu.RUnlock()
		return nil
	}
	guest := session.GuestConn
	s.mu.RUnlock()
	return guest.WriteMessage(websocket.TextMessage, data)
}

func (s *SessionStore) expireSessionLocked(session *Session) {
	delete(s.byID, session.ID)
	delete(s.byHostToken, session.HostToken)
	delete(s.byGuestToken, session.GuestToken)

	if session.GuestConn != nil {
		_ = session.GuestConn.WriteMessage(websocket.TextMessage, []byte(`{"type":"close"}`))
		_ = session.GuestConn.Close()
		session.GuestConn = nil
	}

	if session.HostConn != nil {
		_ = session.HostConn.Close()
		session.HostConn = nil
	}
}

type Session struct {
	ID           string
	HostToken    string
	GuestToken   string
	Readonly     bool
	GuestURL     string
	HostRelayURL string
	HostConn     *websocket.Conn
	GuestConn    *websocket.Conn
}

type CreateSessionRequest struct {
	Readonly bool `json:"readonly"`
}

type CreateSessionResponse struct {
	SessionID  string `json:"session_id"`
	HostToken  string `json:"host_token"`
	GuestToken string `json:"guest_token"`
	GuestURL   string `json:"guest_url"`
	RelayURL   string `json:"relay_url"`
}

type MessageEnvelope struct {
	Type string `json:"type"`
}

type GuestInbound struct {
	Type    string `json:"type"`
	DataB64 string `json:"data_b64,omitempty"`
}

type RelayJoined struct {
	Type string `json:"type"`
}

func (RelayJoined) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"type": "guest_joined"})
}

type RelayLeft struct {
	Type string `json:"type"`
}

func (RelayLeft) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"type": "guest_left"})
}

type RelayError struct {
	Type string `json:"type"`
}

func (RelayError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"type": "error"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeWSJSON(conn *websocket.Conn, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, redactRequestTarget(r.URL))
		next.ServeHTTP(w, r)
	})
}

func normalizeControlAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	return strings.TrimPrefix(addr, "http://")
}

func randomToken(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		log.Fatalf("token entropy error: %v", err)
	}

	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(raw[:]))
}

func redactRequestTarget(u *url.URL) string {
	if u == nil {
		return "/"
	}

	if u.RawQuery == "" {
		return u.Path
	}

	query := u.Query()
	for _, key := range []string{"guest_token", "host_token"} {
		if query.Has(key) {
			query.Set(key, "REDACTED")
		}
	}

	encoded := query.Encode()
	if encoded == "" {
		return u.Path
	}
	return u.Path + "?" + encoded
}

func publicHTTPBase(cfg Config) string {
	host := strings.TrimRight(cfg.PublicHost, "/")
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	if strings.Contains(host, ":") {
		return "http://" + host
	}
	return "http://" + host + normalizeControlAddr(cfg.ControlAddr)
}

func publicWSBase(cfg Config) string {
	host := strings.TrimRight(cfg.PublicHost, "/")
	if strings.HasPrefix(host, "ws://") || strings.HasPrefix(host, "wss://") {
		return host
	}
	if strings.HasPrefix(host, "http://") {
		return "ws://" + strings.TrimPrefix(host, "http://")
	}
	if strings.HasPrefix(host, "https://") {
		return "wss://" + strings.TrimPrefix(host, "https://")
	}
	if strings.Contains(host, ":") {
		return "ws://" + host
	}
	return "ws://" + host + normalizeControlAddr(cfg.ControlAddr)
}

func (s *Server) loadDefaultPolicy() ([]byte, error) {
	if s.cfg.PolicyPath != "" {
		return os.ReadFile(s.cfg.PolicyPath)
	}
	return embeddedDefaultPolicy, nil
}

func envOrAny(keys []string, fallback string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return fallback
}

type guestPageView struct {
	Title      string
	SessionID  string
	GuestToken string
	Readonly   bool
	ModeLabel  string
}
