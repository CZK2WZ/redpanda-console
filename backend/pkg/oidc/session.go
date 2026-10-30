// Copyright 2026 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// ErrNoSession is returned when a request carries no valid login session.
var ErrNoSession = errors.New("no valid login session")

// Session is an authenticated OIDC login.
type Session struct {
	ID          string
	Subject     string
	DisplayName string
	ExpiresAt   time.Time

	tokens oauth2.TokenSource
}

// AccessToken returns a valid OAuth access token for the session, refreshing it
// with the identity provider if it has expired.
func (s *Session) AccessToken() (string, error) {
	tok, err := s.tokens.Token()
	if err != nil {
		return "", fmt.Errorf("failed to obtain access token: %w", err)
	}
	return tok.AccessToken, nil
}

type sessionCtxKey struct{}

// ContextWithSession returns a copy of ctx that carries the given session.
func ContextWithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, s)
}

// SessionFromContext returns the session bound to ctx by the authentication middleware.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(*Session)
	return s, ok
}

// SessionStore keeps login sessions in memory. Sessions do not survive a
// restart and are not shared between replicas.
type SessionStore struct {
	mu        sync.RWMutex
	sessions  map[string]*Session
	lastSweep time.Time
	now       func() time.Time
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		now:      time.Now,
	}
}

// Put stores a session.
func (st *SessionStore) Put(s *Session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()
	st.sessions[s.ID] = s
}

// Get returns the session with the given ID if it exists and has not expired.
func (st *SessionStore) Get(id string) (*Session, bool) {
	st.mu.RLock()
	s, ok := st.sessions[id]
	st.mu.RUnlock()
	if !ok || !st.now().Before(s.ExpiresAt) {
		return nil, false
	}
	return s, true
}

// Delete removes the session with the given ID.
func (st *SessionStore) Delete(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, id)
}

// SessionID returns the ID of the session bound to ctx.
func (*SessionStore) SessionID(ctx context.Context) (string, error) {
	s, ok := SessionFromContext(ctx)
	if !ok {
		return "", ErrNoSession
	}
	return s.ID, nil
}

// AccessToken returns a valid access token for the session with the given ID.
func (st *SessionStore) AccessToken(id string) (string, error) {
	s, ok := st.Get(id)
	if !ok {
		return "", ErrNoSession
	}
	return s.AccessToken()
}

// SessionActive reports whether the session with the given ID still exists.
func (st *SessionStore) SessionActive(id string) bool {
	_, ok := st.Get(id)
	return ok
}

func (st *SessionStore) sweepLocked() {
	now := st.now()
	if now.Sub(st.lastSweep) < time.Minute {
		return
	}
	st.lastSweep = now
	for id, s := range st.sessions {
		if !now.Before(s.ExpiresAt) {
			delete(st.sessions, id)
		}
	}
}
