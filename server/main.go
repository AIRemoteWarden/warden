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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
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
	ControlAddr           string
	PublicHost            string
	PolicyPath            string
	SessionIdleTimeout    time.Duration
	SessionMaxIdleTimeout time.Duration
	SessionIdleWarning    time.Duration
	DemoCommand           string
	DemoHostRelayURL      string
	DemoStartupTimeout    time.Duration
	DemoSessionTTL        time.Duration
}

type Server struct {
	cfg          Config
	sessions     *SessionStore
	demos        *DemoStore
	upgrader     websocket.Upgrader
	guestPage    *template.Template
	staticAssets http.Handler
}

func main() {
	cfg := Config{
		ControlAddr:           envOrAny([]string{"WARDEN_CONTROL_ADDR", "AIWARDEN_CONTROL_ADDR", "DEBUGIT_CONTROL_ADDR"}, ":8080"),
		PublicHost:            envOrAny([]string{"WARDEN_PUBLIC_HOST", "AIWARDEN_PUBLIC_HOST", "DEBUGIT_PUBLIC_HOST"}, "localhost"),
		PolicyPath:            envOrAny([]string{"WARDEN_POLICY_PATH", "AIWARDEN_POLICY_PATH", "DEBUGIT_POLICY_PATH"}, ""),
		SessionIdleTimeout:    envDurationSecondsAny([]string{"WARDEN_SESSION_IDLE_TIMEOUT_SECONDS", "AIWARDEN_SESSION_IDLE_TIMEOUT_SECONDS", "DEBUGIT_SESSION_IDLE_TIMEOUT_SECONDS"}, 10*time.Minute),
		SessionMaxIdleTimeout: envDurationSecondsAny([]string{"WARDEN_SESSION_MAX_IDLE_TIMEOUT_SECONDS", "AIWARDEN_SESSION_MAX_IDLE_TIMEOUT_SECONDS", "DEBUGIT_SESSION_MAX_IDLE_TIMEOUT_SECONDS"}, 2*time.Hour),
		SessionIdleWarning:    envDurationSecondsAny([]string{"WARDEN_SESSION_IDLE_WARNING_SECONDS", "AIWARDEN_SESSION_IDLE_WARNING_SECONDS", "DEBUGIT_SESSION_IDLE_WARNING_SECONDS"}, time.Minute),
		DemoCommand:           envOrAny([]string{"WARDEN_DEMO_COMMAND"}, ""),
		DemoHostRelayURL:      envOrAny([]string{"WARDEN_DEMO_HOST_RELAY_URL"}, ""),
		DemoStartupTimeout:    envDurationSecondsAny([]string{"WARDEN_DEMO_STARTUP_TIMEOUT_SECONDS"}, 20*time.Second),
		DemoSessionTTL:        envDurationSecondsAny([]string{"WARDEN_DEMO_SESSION_TTL_SECONDS"}, 15*time.Minute),
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
		demos:     NewDemoStore(),
		guestPage: guestPage,
		staticAssets: http.StripPrefix(
			"/assets/",
			http.FileServer(http.FS(assetFS)),
		),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go srv.runIdleExpiryLoop(cleanupCtx)

	controlMux := http.NewServeMux()
	controlMux.Handle("/assets/", srv.staticAssets)
	controlMux.HandleFunc("/healthz", srv.handleHealthz)
	controlMux.HandleFunc("/v1/policy/default", srv.handleDefaultPolicy)
	controlMux.HandleFunc("/v1/sessions", srv.handleCreateSession)
	controlMux.HandleFunc("/v1/demo-sessions", srv.handleCreateDemoSession)
	controlMux.HandleFunc("/api/session/", srv.handleSessionInfo)
	controlMux.HandleFunc("/s/", srv.handleShortSessionPage)
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
	cleanupCancel()

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

	idleTimeout, err := resolveIdleTimeout(req.IdleTimeoutSeconds, s.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	idleWarning, err := resolveIdleWarning(req.IdleWarningSeconds, idleTimeout, s.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.DemoSessionID != "" {
		if err := s.demos.ValidateForSessionCreate(req.DemoSessionID); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	session := s.sessions.Create(req.Readonly, idleTimeout, idleWarning, req.DemoSessionID, s.cfg)
	if req.DemoSessionID != "" {
		session.HostRelayURL = demoHostRelayURL(s.cfg)
	}
	if req.DemoSessionID != "" {
		if err := s.demos.MarkSessionCreated(req.DemoSessionID, session.ID, session.GuestURL); err != nil {
			s.sessions.CloseByID(session.ID, "demo_association_failed")
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}

	writeJSON(w, http.StatusOK, CreateSessionResponse{
		SessionID:          session.ID,
		HostToken:          session.HostToken,
		GuestURL:           session.GuestURL,
		RelayURL:           session.HostRelayURL,
		IdleTimeoutSeconds: int64(session.IdleTimeout / time.Second),
		IdleWarningSeconds: int64(session.IdleWarningBefore / time.Second),
	})
}

func (s *Server) handleCreateDemoSession(w http.ResponseWriter, r *http.Request) {
	setDemoCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.TrimSpace(s.cfg.DemoCommand) == "" {
		http.Error(w, "demo sandbox is not configured", http.StatusServiceUnavailable)
		return
	}

	demoID := randomToken("demo")
	log.Printf(
		"demo_session_requested demo_id=%s remote_ip=%s user_agent=%q",
		demoID,
		clientIP(r),
		r.UserAgent(),
	)
	pending := s.demos.Create(demoID, time.Now().UTC().Add(s.cfg.DemoSessionTTL))

	cmd, err := s.startDemoCommand(demoID)
	if err != nil {
		s.cleanupDemoSession(demoID, "demo_start_failed")
		http.Error(w, "failed to start demo sandbox", http.StatusInternalServerError)
		return
	}
	s.demos.SetCommand(demoID, cmd)

	startupTimeout := s.cfg.DemoStartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = 20 * time.Second
	}
	select {
	case <-pending.SessionCreated:
	case <-time.After(startupTimeout):
		s.cleanupDemoSession(demoID, "demo_session_create_timeout")
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{
			"error":   "session_startup_timeout",
			"message": "Session startup timed out",
		})
		return
	}

	select {
	case <-pending.HostConnected:
	case <-time.After(startupTimeout):
		s.cleanupDemoSession(demoID, "demo_host_connect_timeout")
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{
			"error":   "host_connect_timeout",
			"message": "Browser terminal failed to connect",
		})
		return
	}

	snapshot, ok := s.demos.Get(demoID)
	if !ok || snapshot.GuestURL == "" {
		s.cleanupDemoSession(demoID, "demo_missing_guest_url")
		http.Error(w, "demo session unavailable", http.StatusInternalServerError)
		return
	}
	log.Printf(
		"demo_session_ready demo_id=%s session_id=%s expires_at=%s",
		demoID,
		snapshot.SessionID,
		snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)

	go func() {
		ttl := time.Until(snapshot.ExpiresAt)
		if ttl > 0 {
			time.Sleep(ttl)
		}
		s.cleanupDemoSession(demoID, "demo_ttl_expired")
	}()

	writeJSON(w, http.StatusOK, DemoSessionResponse{
		SessionID:        snapshot.SessionID,
		GuestURL:         snapshot.GuestURL,
		ExpiresAt:        snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano),
		ExpiresInSeconds: int64(time.Until(snapshot.ExpiresAt).Round(time.Second) / time.Second),
	})
}

func (s *Server) startDemoCommand(demoSessionID string) (*exec.Cmd, error) {
	commandText := strings.ReplaceAll(s.cfg.DemoCommand, "{demo_session_id}", demoSessionID)
	cmd := exec.Command("/bin/sh", "-c", commandText)
	cmd.Env = append(os.Environ(), "WARDEN_DEMO_SESSION_ID="+demoSessionID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func (s *Server) cleanupDemoSession(demoSessionID string, reason string) {
	pending, ok := s.demos.Remove(demoSessionID)
	if !ok {
		return
	}
	if pending.SessionID != "" {
		s.sessions.CloseByID(pending.SessionID, reason)
	}
	if pending.Cmd != nil && pending.Cmd.Process != nil {
		_ = syscall.Kill(-pending.Cmd.Process.Pid, syscall.SIGKILL)
		_, _ = pending.Cmd.Process.Wait()
	}
}

func setDemoCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
		"session_id":           session.ID,
		"state":                "active",
		"readonly":             session.Readonly,
		"host_connected":       session.HostConn != nil,
		"guest_connected":      session.GuestConn != nil,
		"idle_timeout_seconds": int64(session.IdleTimeout / time.Second),
		"idle_warning_seconds": int64(session.IdleWarningBefore / time.Second),
		"last_activity_at":     session.LastActivityAt.UTC().Format(time.RFC3339Nano),
		"expires_at":           session.LastActivityAt.Add(session.IdleTimeout).UTC().Format(time.RFC3339Nano),
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

	s.renderGuestPage(w, session)
}

func (s *Server) handleShortSessionPage(w http.ResponseWriter, r *http.Request) {
	inviteID := strings.TrimPrefix(r.URL.Path, "/s/")
	session, ok := s.sessions.GetByInviteID(inviteID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	s.renderGuestPage(w, session)
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
	if session.DemoSessionID != "" {
		s.demos.MarkHostConnected(session.DemoSessionID)
	}
	demoSessionID := session.DemoSessionID
	defer func() {
		s.sessions.DetachHost(session.ID, conn)
		if demoSessionID != "" {
			s.cleanupDemoSession(demoSessionID, "host_disconnected")
		}
	}()

	if guest := s.sessions.CurrentGuest(session.ID); guest != nil {
		_ = writeWSJSON(conn, RelayJoined{})
	}

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			_ = s.sessions.BroadcastToGuest(session.ID, []byte(`{"type":"close"}`))
			return
		}
		s.sessions.Touch(session.ID)

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
	if session.DemoSessionID != "" {
		log.Printf(
			"demo_guest_connected demo_id=%s session_id=%s remote_ip=%s user_agent=%q",
			session.DemoSessionID,
			session.ID,
			clientIP(r),
			r.UserAgent(),
		)
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
		s.sessions.Touch(session.ID)

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
	byInviteID   map[string]*Session
}

type DemoStore struct {
	mu   sync.RWMutex
	byID map[string]*PendingDemoSession
}

type PendingDemoSession struct {
	DemoSessionID   string
	SessionID       string
	GuestURL        string
	ExpiresAt       time.Time
	Cmd             *exec.Cmd
	SessionCreated  chan struct{}
	HostConnected   chan struct{}
	sessionSignaled bool
	hostSignaled    bool
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		byID:         make(map[string]*Session),
		byHostToken:  make(map[string]*Session),
		byGuestToken: make(map[string]*Session),
		byInviteID:   make(map[string]*Session),
	}
}

func NewDemoStore() *DemoStore {
	return &DemoStore{byID: make(map[string]*PendingDemoSession)}
}

func (s *DemoStore) Create(id string, expiresAt time.Time) *PendingDemoSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := &PendingDemoSession{
		DemoSessionID:  id,
		ExpiresAt:      expiresAt,
		SessionCreated: make(chan struct{}),
		HostConnected:  make(chan struct{}),
	}
	s.byID[id] = pending
	return pending
}

func (s *DemoStore) Get(id string) (*PendingDemoSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pending, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	copy := *pending
	return &copy, true
}

func (s *DemoStore) SetCommand(id string, cmd *exec.Cmd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pending, ok := s.byID[id]; ok {
		pending.Cmd = cmd
	}
}

func (s *DemoStore) Remove(id string) (*PendingDemoSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.byID[id]
	if ok {
		delete(s.byID, id)
	}
	return pending, ok
}

func (s *DemoStore) ValidateForSessionCreate(id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pending, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("invalid demo_session_id")
	}
	if pending.SessionID != "" {
		return fmt.Errorf("demo_session_id already used")
	}
	if time.Now().UTC().After(pending.ExpiresAt) {
		return fmt.Errorf("demo_session_id expired")
	}
	return nil
}

func (s *DemoStore) MarkSessionCreated(id string, sessionID string, guestURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("unknown demo_session_id")
	}
	if pending.SessionID != "" {
		return fmt.Errorf("demo_session_id already used")
	}
	pending.SessionID = sessionID
	pending.GuestURL = guestURL
	if !pending.sessionSignaled {
		close(pending.SessionCreated)
		pending.sessionSignaled = true
	}
	return nil
}

func (s *DemoStore) MarkHostConnected(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.byID[id]
	if !ok || pending.hostSignaled {
		return
	}
	close(pending.HostConnected)
	pending.hostSignaled = true
}

func (s *SessionStore) Create(readonly bool, idleTimeout time.Duration, idleWarning time.Duration, demoSessionID string, cfg Config) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	id := randomToken("sess")
	hostToken := randomToken("host")
	guestToken := randomToken("guest")
	inviteID := randomInviteID(10)
	session := &Session{
		ID:                id,
		HostToken:         hostToken,
		GuestToken:        guestToken,
		InviteID:          inviteID,
		DemoSessionID:     demoSessionID,
		Readonly:          readonly,
		GuestURL:          fmt.Sprintf("%s/s/%s", publicHTTPBase(cfg), inviteID),
		HostRelayURL:      fmt.Sprintf("%s/ws/host", publicWSBase(cfg)),
		CreatedAt:         now,
		LastActivityAt:    now,
		IdleTimeout:       idleTimeout,
		IdleWarningBefore: idleWarning,
	}

	s.byID[id] = session
	s.byHostToken[hostToken] = session
	s.byGuestToken[guestToken] = session
	s.byInviteID[inviteID] = session
	return session
}

func (s *SessionStore) CloseByID(id string, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.byID[id]; ok {
		s.closeSessionLocked(session, reason)
	}
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

func (s *SessionStore) GetByInviteID(inviteID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.byInviteID[inviteID]
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
	session.LastActivityAt = time.Now().UTC()
	session.IdleWarningSent = false
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
	session.LastActivityAt = time.Now().UTC()
	session.IdleWarningSent = false
	return nil
}

func (s *SessionStore) DetachHost(id string, conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.byID[id]; ok && session.HostConn == conn {
		s.closeSessionLocked(session, "host_disconnected")
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

func (s *SessionStore) Touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.byID[id]; ok {
		if session.IdleWarningSent {
			s.sendIdleWarningClearedLocked(session)
		}
		session.LastActivityAt = time.Now().UTC()
		session.IdleWarningSent = false
	}
}

func (s *SessionStore) ProcessIdleTimeouts(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	for _, session := range s.byID {
		elapsed := now.Sub(session.LastActivityAt)
		if elapsed >= session.IdleTimeout {
			s.closeSessionLocked(session, "idle_timeout")
			continue
		}

		if session.IdleWarningBefore <= 0 || session.IdleWarningSent {
			continue
		}

		remaining := session.IdleTimeout - elapsed
		if remaining <= session.IdleWarningBefore {
			session.IdleWarningSent = true
			s.sendIdleWarningLocked(session, remaining)
		}
	}
}

func (s *SessionStore) sendIdleWarningLocked(session *Session, remaining time.Duration) {
	if remaining < 0 {
		remaining = 0
	}
	remainingSeconds := int64(remaining.Round(time.Second) / time.Second)
	if remainingSeconds < 0 {
		remainingSeconds = 0
	}
	payload := IdleTimeoutWarning{
		Type:             "idle_timeout_warning",
		RemainingSeconds: remainingSeconds,
		ExpiresAt:        session.LastActivityAt.Add(session.IdleTimeout).UTC().Format(time.RFC3339Nano),
	}

	if session.HostConn != nil {
		_ = writeWSJSON(session.HostConn, payload)
	}
	if session.GuestConn != nil {
		_ = writeWSJSON(session.GuestConn, payload)
	}
}

func (s *SessionStore) sendIdleWarningClearedLocked(session *Session) {
	payload := IdleTimeoutWarningCleared{Type: "idle_timeout_warning_cleared"}
	if session.HostConn != nil {
		_ = writeWSJSON(session.HostConn, payload)
	}
	if session.GuestConn != nil {
		_ = writeWSJSON(session.GuestConn, payload)
	}
}

func (s *SessionStore) closeSessionLocked(session *Session, reason string) {
	delete(s.byID, session.ID)
	delete(s.byHostToken, session.HostToken)
	delete(s.byGuestToken, session.GuestToken)
	delete(s.byInviteID, session.InviteID)
	durationSeconds := int64(time.Since(session.CreatedAt).Round(time.Second) / time.Second)
	if session.DemoSessionID != "" {
		log.Printf(
			"demo_session_closed demo_id=%s session_id=%s reason=%s duration_seconds=%d",
			session.DemoSessionID,
			session.ID,
			reason,
			durationSeconds,
		)
	} else {
		log.Printf(
			"session_closed session_id=%s reason=%s duration_seconds=%d",
			session.ID,
			reason,
			durationSeconds,
		)
	}

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
	ID                string
	HostToken         string
	GuestToken        string
	InviteID          string
	DemoSessionID     string
	Readonly          bool
	GuestURL          string
	HostRelayURL      string
	CreatedAt         time.Time
	LastActivityAt    time.Time
	IdleTimeout       time.Duration
	IdleWarningBefore time.Duration
	IdleWarningSent   bool
	HostConn          *websocket.Conn
	GuestConn         *websocket.Conn
}

type CreateSessionRequest struct {
	Readonly           bool   `json:"readonly"`
	IdleTimeoutSeconds *int64 `json:"idle_timeout_seconds,omitempty"`
	IdleWarningSeconds *int64 `json:"idle_warning_seconds,omitempty"`
	DemoSessionID      string `json:"demo_session_id,omitempty"`
}

type CreateSessionResponse struct {
	SessionID          string `json:"session_id"`
	HostToken          string `json:"host_token"`
	GuestURL           string `json:"guest_url"`
	RelayURL           string `json:"relay_url"`
	IdleTimeoutSeconds int64  `json:"idle_timeout_seconds"`
	IdleWarningSeconds int64  `json:"idle_warning_seconds"`
}

type DemoSessionResponse struct {
	SessionID        string `json:"session_id"`
	GuestURL         string `json:"guest_url"`
	ExpiresAt        string `json:"expires_at"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
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

type IdleTimeoutWarning struct {
	Type             string `json:"type"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	ExpiresAt        string `json:"expires_at"`
}

type IdleTimeoutWarningCleared struct {
	Type string `json:"type"`
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

func randomInviteID(length int) string {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if length <= 0 {
		length = 10
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("invite entropy error: %v", err)
	}

	var out strings.Builder
	out.Grow(length)
	for _, b := range bytes {
		out.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	return out.String()
}

func redactRequestTarget(u *url.URL) string {
	if u == nil {
		return "/"
	}

	if strings.HasPrefix(u.Path, "/s/") {
		return "/s/REDACTED"
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

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		return strings.TrimSpace(first)
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
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

func demoHostRelayURL(cfg Config) string {
	if cfg.DemoHostRelayURL != "" {
		return cfg.DemoHostRelayURL
	}

	addr := normalizeControlAddr(cfg.ControlAddr)
	if strings.HasPrefix(addr, ":") {
		return "ws://127.0.0.1" + addr + "/ws/host"
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "ws://127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:") + "/ws/host"
	}
	if strings.HasPrefix(addr, "[::]:") {
		return "ws://127.0.0.1:" + strings.TrimPrefix(addr, "[::]:") + "/ws/host"
	}
	return "ws://" + addr + "/ws/host"
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

func envDurationSecondsAny(keys []string, fallback time.Duration) time.Duration {
	for _, key := range keys {
		if raw := os.Getenv(key); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value <= 0 {
				log.Fatalf("invalid %s: expected positive integer seconds", key)
			}
			return time.Duration(value) * time.Second
		}
	}
	return fallback
}

func resolveIdleTimeout(requestedSeconds *int64, cfg Config) (time.Duration, error) {
	timeout := cfg.SessionIdleTimeout
	if requestedSeconds != nil {
		if *requestedSeconds <= 0 {
			return 0, fmt.Errorf("idle_timeout_seconds must be positive")
		}
		timeout = time.Duration(*requestedSeconds) * time.Second
	}

	if cfg.SessionMaxIdleTimeout > 0 && timeout > cfg.SessionMaxIdleTimeout {
		timeout = cfg.SessionMaxIdleTimeout
	}
	return timeout, nil
}

func resolveIdleWarning(requestedSeconds *int64, idleTimeout time.Duration, cfg Config) (time.Duration, error) {
	if requestedSeconds != nil {
		if *requestedSeconds < 0 {
			return 0, fmt.Errorf("idle_warning_seconds must be zero or positive")
		}
		if *requestedSeconds == 0 {
			return 0, nil
		}
		warning := time.Duration(*requestedSeconds) * time.Second
		if warning >= idleTimeout {
			return 0, fmt.Errorf("idle_warning_seconds must be less than idle_timeout_seconds")
		}
		return warning, nil
	}

	if cfg.SessionIdleWarning <= 0 || idleTimeout <= time.Second {
		return 0, nil
	}
	if cfg.SessionIdleWarning >= idleTimeout {
		return idleTimeout - time.Second, nil
	}
	return cfg.SessionIdleWarning, nil
}

func (s *Server) runIdleExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.sessions.ProcessIdleTimeouts(now)
		}
	}
}

type guestPageView struct {
	Title      string
	SessionID  string
	GuestToken string
	Readonly   bool
	ModeLabel  string
}

func (s *Server) renderGuestPage(w http.ResponseWriter, session *Session) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := guestPageView{
		Title:      "AI Warden Guest Terminal",
		SessionID:  session.InviteID,
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
