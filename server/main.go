package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	ControlAddr string
	RelayAddr   string
	PublicHost  string
}

type Server struct {
	cfg      Config
	sessions *SessionStore
	upgrader websocket.Upgrader
}

func main() {
	cfg := Config{
		ControlAddr: envOr("DEBUGIT_CONTROL_ADDR", ":8080"),
		RelayAddr:   envOr("DEBUGIT_RELAY_ADDR", ":8081"),
		PublicHost:  envOr("DEBUGIT_PUBLIC_HOST", "localhost"),
	}

	srv := &Server{
		cfg:      cfg,
		sessions: NewSessionStore(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	controlMux := http.NewServeMux()
	controlMux.HandleFunc("/v1/policy/default", srv.handleDefaultPolicy)
	controlMux.HandleFunc("/v1/sessions", srv.handleCreateSession)
	controlMux.HandleFunc("/api/session/", srv.handleSessionInfo)
	controlMux.HandleFunc("/session/", srv.handleSessionPage)
	controlMux.HandleFunc("/ws/host", srv.handleHostWS)
	controlMux.HandleFunc("/ws/guest", srv.handleGuestWS)

	relayMux := http.NewServeMux()
	relayMux.HandleFunc("/ws/host", srv.handleHostWS)
	relayMux.HandleFunc("/ws/guest", srv.handleGuestWS)

	controlServer := &http.Server{
		Addr:    cfg.ControlAddr,
		Handler: loggingMiddleware(controlMux),
	}
	relayServer := &http.Server{
		Addr:    cfg.RelayAddr,
		Handler: loggingMiddleware(relayMux),
	}

	go func() {
		log.Printf("control listening on %s", cfg.ControlAddr)
		if err := controlServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("control server error: %v", err)
		}
	}()

	go func() {
		log.Printf("relay listening on %s", cfg.RelayAddr)
		if err := relayServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("relay server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = controlServer.Shutdown(ctx)
	_ = relayServer.Shutdown(ctx)
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
		GuestURL:  session.GuestURL,
		RelayURL:  session.HostRelayURL,
	})
}

func (s *Server) handleDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := os.ReadFile("policy.default.json")
	if err != nil {
		http.Error(w, "default policy unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", fmt.Sprintf(`W/"default-%d"`, len(raw)))
	_, _ = w.Write(raw)
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
	_, _ = w.Write([]byte(renderGuestPage(session, s.cfg)))
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
		GuestURL:     fmt.Sprintf("http://%s%s/session/%s?guest_token=%s", cfg.PublicHost, normalizeControlAddr(cfg.ControlAddr), id, guestToken),
		HostRelayURL: fmt.Sprintf("ws://%s%s/ws/host?host_token=%s", cfg.PublicHost, normalizeControlAddr(cfg.ControlAddr), hostToken),
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
	SessionID string `json:"session_id"`
	HostToken string `json:"host_token"`
	GuestURL  string `json:"guest_url"`
	RelayURL  string `json:"relay_url"`
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
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	})
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func normalizeControlAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	return strings.TrimPrefix(addr, "http://")
}

func normalizeRelayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	addr = strings.TrimPrefix(addr, "ws://")
	addr = strings.TrimPrefix(addr, "wss://")
	return addr
}

func randomToken(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func renderGuestPage(session *Session, cfg Config) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DebugIt Session %s</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css">
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f1115;
      --panel: #171a21;
      --muted: #8e97a7;
      --fg: #e8ecf3;
      --accent: #7dd3fc;
      --border: #283042;
      --ok: #86efac;
      --warn: #fca5a5;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at top, #1a2030 0%%, var(--bg) 42%%);
      color: var(--fg);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
    }
    header, footer {
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      background: rgba(15, 17, 21, 0.75);
      backdrop-filter: blur(8px);
    }
    footer {
      border-bottom: none;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
    }
    .title {
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .meta {
      margin-top: 6px;
      color: var(--muted);
      font-size: 12px;
    }
    .status {
      color: var(--accent);
    }
    main {
      padding: 18px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 280px;
      gap: 18px;
    }
    .terminal-wrap, .side {
      background: rgba(23, 26, 33, 0.88);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.25);
      overflow: hidden;
    }
    .terminal-header, .side-header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    #terminal {
      min-height: 60vh;
      height: 100%%;
      padding: 8px;
      outline: none;
    }
    .side {
      display: grid;
      grid-template-rows: auto auto 1fr;
    }
    .side-section {
      padding: 14px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .side-section:last-child {
      border-bottom: none;
    }
    .label {
      color: var(--muted);
      display: block;
      margin-bottom: 8px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    #approval, #feedback {
      color: var(--fg);
      min-height: 20px;
    }
    #approval.warn {
      color: var(--warn);
    }
    #feedback.ok {
      color: var(--ok);
    }
  </style>
</head>
<body>
  <header>
    <div class="title">DebugIt Guest Terminal</div>
    <div class="meta">session <span id="session-id">%s</span> · status <span class="status" id="status">connecting</span></div>
  </header>
  <main>
    <section class="terminal-wrap">
      <div class="terminal-header">Terminal</div>
      <div id="terminal" tabindex="0"></div>
    </section>
    <aside class="side">
      <div class="side-header">Session</div>
      <div class="side-section">
        <span class="label">Mode</span>
        %s
      </div>
      <div class="side-section">
        <span class="label">Approval</span>
        <div id="approval">no pending approvals</div>
      </div>
      <div class="side-section">
        <span class="label">Feedback</span>
        <div id="feedback">waiting for host output</div>
      </div>
    </aside>
  </main>
  <footer>Type directly in the terminal. This page uses xterm.js for ANSI and cursor handling.</footer>
  <script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
  <script>
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsURL = wsProtocol + "//" + window.location.host + "/ws/guest?guest_token=%s";
    const terminalEl = document.getElementById("terminal");
    const statusEl = document.getElementById("status");
    const approvalEl = document.getElementById("approval");
    const feedbackEl = document.getElementById("feedback");
    const ws = new WebSocket(wsURL);

    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontSize: 14,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      theme: {
        background: '#171a21',
        foreground: '#e8ecf3',
        cursor: '#7dd3fc',
        black: '#0f1115',
        brightBlack: '#5f6b7a'
      }
    });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalEl);
    fitAddon.fit();

    function bytesToBase64(bytes) {
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }

    function base64ToBytes(b64) {
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }

    ws.addEventListener("open", () => {
      statusEl.textContent = "connected";
      feedbackEl.textContent = "connected to host";
      feedbackEl.className = "ok";
      term.focus();
    });

    ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      switch (msg.type) {
        case "host_output":
          term.write(base64ToBytes(msg.data_b64));
          break;
        case "approval_state":
          approvalEl.textContent = [msg.decision, msg.reason, msg.risk].filter(Boolean).join(" · ");
          approvalEl.className = msg.decision === "require_approval" ? "warn" : "";
          break;
        case "feedback":
          feedbackEl.textContent = msg.message || "";
          feedbackEl.className = "ok";
          break;
        case "close":
          statusEl.textContent = "closed";
          feedbackEl.textContent = "session closed";
          break;
      }
    });

    ws.addEventListener("close", () => {
      statusEl.textContent = "closed";
    });

    ws.addEventListener("error", () => {
      statusEl.textContent = "error";
      feedbackEl.textContent = "websocket error";
    });

    term.onData((data) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const bytes = new TextEncoder().encode(data);
      ws.send(JSON.stringify({ type: "guest_input", data_b64: bytesToBase64(bytes) }));
    });

    window.addEventListener("resize", () => fitAddon.fit());
    terminalEl.addEventListener("click", () => term.focus());
    term.focus();
  </script>
</body>
</html>`,
		session.ID,
		session.ID,
		map[bool]string{
			true:  "read-only",
			false: "interactive",
		}[session.Readonly],
		session.GuestToken,
	)
}
