package main

import (
	"testing"
	"time"
)

func TestResolveIdleTimeoutUsesServerDefault(t *testing.T) {
	cfg := Config{
		SessionIdleTimeout:    10 * time.Minute,
		SessionMaxIdleTimeout: 2 * time.Hour,
	}

	timeout, err := resolveIdleTimeout(nil, cfg)
	if err != nil {
		t.Fatalf("resolveIdleTimeout returned error: %v", err)
	}
	if timeout != 10*time.Minute {
		t.Fatalf("expected default timeout, got %s", timeout)
	}
}

func TestResolveIdleTimeoutClampsToServerMax(t *testing.T) {
	cfg := Config{
		SessionIdleTimeout:    10 * time.Minute,
		SessionMaxIdleTimeout: 30 * time.Minute,
	}
	requested := int64(7200)

	timeout, err := resolveIdleTimeout(&requested, cfg)
	if err != nil {
		t.Fatalf("resolveIdleTimeout returned error: %v", err)
	}
	if timeout != 30*time.Minute {
		t.Fatalf("expected timeout to clamp to max, got %s", timeout)
	}
}

func TestResolveIdleTimeoutRejectsNonPositiveValues(t *testing.T) {
	cfg := Config{
		SessionIdleTimeout:    10 * time.Minute,
		SessionMaxIdleTimeout: 2 * time.Hour,
	}
	requested := int64(0)

	if _, err := resolveIdleTimeout(&requested, cfg); err == nil {
		t.Fatal("expected error for non-positive timeout")
	}
}

func TestExpireIdleSessionsRemovesExpiredSession(t *testing.T) {
	cfg := Config{
		ControlAddr: "localhost:8080",
		PublicHost:  "localhost",
	}
	store := NewSessionStore()
	session := store.Create(false, 10*time.Second, cfg)
	session.LastActivityAt = time.Now().UTC().Add(-11 * time.Second)

	store.ExpireIdleSessions(time.Now().UTC())

	if _, ok := store.GetByID(session.ID); ok {
		t.Fatal("expected expired session to be removed")
	}
}

func TestExpireIdleSessionsKeepsActiveSession(t *testing.T) {
	cfg := Config{
		ControlAddr: "localhost:8080",
		PublicHost:  "localhost",
	}
	store := NewSessionStore()
	session := store.Create(false, 10*time.Second, cfg)
	session.LastActivityAt = time.Now().UTC().Add(-5 * time.Second)

	store.ExpireIdleSessions(time.Now().UTC())

	if _, ok := store.GetByID(session.ID); !ok {
		t.Fatal("expected active session to remain")
	}
}
