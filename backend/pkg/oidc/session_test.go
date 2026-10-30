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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestSessionStore(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewSessionStore()
	st.now = func() time.Time { return now }

	st.Put(&Session{
		ID:        "s1",
		ExpiresAt: now.Add(time.Hour),
		tokens:    oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t1"}),
	})

	token, err := st.AccessToken("s1")
	require.NoError(t, err)
	assert.Equal(t, "t1", token)
	assert.True(t, st.SessionActive("s1"))

	_, err = st.AccessToken("missing")
	require.ErrorIs(t, err, ErrNoSession)

	now = now.Add(time.Hour)
	assert.False(t, st.SessionActive("s1"), "session must expire at ExpiresAt")

	// A later Put sweeps expired sessions out of memory.
	st.Put(&Session{ID: "s2", ExpiresAt: now.Add(time.Hour)})
	st.mu.RLock()
	_, stillStored := st.sessions["s1"]
	st.mu.RUnlock()
	assert.False(t, stillStored)

	st.Delete("s2")
	assert.False(t, st.SessionActive("s2"))
}

func TestSessionStoreSessionID(t *testing.T) {
	st := NewSessionStore()

	_, err := st.SessionID(context.Background())
	require.ErrorIs(t, err, ErrNoSession)

	id, err := st.SessionID(ContextWithSession(context.Background(), &Session{ID: "s1"}))
	require.NoError(t, err)
	assert.Equal(t, "s1", id)
}
