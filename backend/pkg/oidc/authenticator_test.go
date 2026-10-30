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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redpanda-data/console/backend/pkg/config"
)

const testClientID = "console"

type fakeProvider struct {
	*httptest.Server
	signer jose.Signer
	key    *rsa.PrivateKey
	// codes maps issued authorization codes to the nonce of the login.
	codes map[string]string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
	require.NoError(t, err)

	p := &fakeProvider{signer: signer, key: key, codes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/authorize",
			"token_endpoint":                        p.URL + "/token",
			"jwks_uri":                              p.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		nonce, ok := p.codes[r.PostForm.Get("code")]
		if !ok || r.PostForm.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		idToken, err := jwt.Signed(p.signer).Claims(jwt.Claims{
			Issuer:   p.URL,
			Subject:  "user-1",
			Audience: jwt.Audience{testClientID},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		}).Claims(map[string]any{"nonce": nonce, "name": "Jane Doe"}).Serialize()
		require.NoError(t, err)
		writeJSON(w, map[string]any{
			"access_token": "user-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newTestAuthenticator(t *testing.T, p *fakeProvider) *Authenticator {
	t.Helper()
	cfg := config.Authentication{}
	cfg.SetDefaults()
	cfg.OIDC.Enabled = true
	cfg.OIDC.IssuerURL = p.URL
	cfg.OIDC.ClientID = testClientID
	cfg.OIDC.RedirectURL = "http://console.local/login/callbacks/oidc"
	a, err := NewAuthenticator(context.Background(), cfg, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return a
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login starts a login and returns the state cookie and the authorize URL.
func login(t *testing.T, a *Authenticator) (*http.Cookie, *url.URL) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.HandleLogin()(rec, httptest.NewRequest(http.MethodGet, "/auth/login/oidc", http.NoBody))
	require.Equal(t, http.StatusFound, rec.Code)

	authURL, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	stateCookie := cookieByName(rec.Result().Cookies(), loginCookieName)
	require.NotNil(t, stateCookie)
	return stateCookie, authURL
}

func TestLoginFlow(t *testing.T) {
	p := newFakeProvider(t)
	a := newTestAuthenticator(t, p)

	stateCookie, authURL := login(t, a)
	q := authURL.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, stateCookie.Value, q.Get("state"))
	p.codes["code-1"] = q.Get("nonce")

	req := httptest.NewRequest(http.MethodGet, "/auth/callbacks/oidc?code=code-1&state="+url.QueryEscape(q.Get("state")), http.NoBody)
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	a.HandleCallback()(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "Jane Doe", body["displayName"])

	sessionCookie := cookieByName(rec.Result().Cookies(), SessionCookieName)
	require.NotNil(t, sessionCookie)
	assert.True(t, sessionCookie.HttpOnly)
	token, err := a.Sessions().AccessToken(sessionCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "user-access-token", token)

	var gotSession *Session
	protected := a.RequireSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotSession, _ = SessionFromContext(r.Context())
	}))
	req = httptest.NewRequest(http.MethodGet, "/api/topics", http.NoBody)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, gotSession)
	assert.Equal(t, "user-1", gotSession.Subject)

	req = httptest.NewRequest(http.MethodGet, "/auth/logout", http.NoBody)
	req.AddCookie(sessionCookie)
	a.HandleLogout()(httptest.NewRecorder(), req)
	assert.False(t, a.Sessions().SessionActive(sessionCookie.Value))

	// The pending login is consumed, so replaying the callback must fail.
	req = httptest.NewRequest(http.MethodGet, "/auth/callbacks/oidc?code=code-1&state="+url.QueryEscape(q.Get("state")), http.NoBody)
	req.AddCookie(stateCookie)
	rec = httptest.NewRecorder()
	a.HandleCallback()(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCallbackRejectsInvalidRequests(t *testing.T) {
	p := newFakeProvider(t)
	a := newTestAuthenticator(t, p)

	tests := []struct {
		name      string
		query     func(state string) string
		useCookie bool
		wantInMsg string
	}{
		{
			name:      "missing state cookie",
			query:     func(state string) string { return "code=c&state=" + state },
			wantInMsg: "state mismatch",
		},
		{
			name:      "state mismatch",
			query:     func(string) string { return "code=c&state=other" },
			useCookie: true,
			wantInMsg: "state mismatch",
		},
		{
			name:      "identity provider error",
			query:     func(string) string { return "error=access_denied" },
			useCookie: true,
			wantInMsg: "access_denied",
		},
		{
			name:      "unknown code",
			query:     func(state string) string { return "code=unknown&state=" + state },
			useCookie: true,
			wantInMsg: "exchange",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateCookie, _ := login(t, a)
			req := httptest.NewRequest(http.MethodGet, "/auth/callbacks/oidc?"+tt.query(url.QueryEscape(stateCookie.Value)), http.NoBody)
			if tt.useCookie {
				req.AddCookie(stateCookie)
			}
			rec := httptest.NewRecorder()
			a.HandleCallback()(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantInMsg)
			assert.Nil(t, cookieByName(rec.Result().Cookies(), SessionCookieName))
		})
	}
}

func TestRequireSessionRejectsUnauthenticated(t *testing.T) {
	a := newTestAuthenticator(t, newFakeProvider(t))
	const publicPath = "/redpanda.api.console.v1alpha1.AuthenticationService/ListAuthenticationMethods"
	handler := a.RequireSession(publicPath)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name        string
		path        string
		contentType string
		cookie      string
		wantStatus  int
		wantBody    string
	}{
		{name: "public path", path: "/base" + publicPath, contentType: "application/json", wantStatus: http.StatusNoContent},
		{name: "rest without cookie", path: "/api/topics", wantStatus: http.StatusUnauthorized},
		{name: "rest with unknown session", path: "/api/topics", cookie: "unknown", wantStatus: http.StatusUnauthorized},
		{
			name:        "connect without cookie",
			path:        "/redpanda.api.console.v1alpha1.AuthenticationService/GetIdentity",
			contentType: "application/json",
			wantStatus:  http.StatusUnauthorized,
			wantBody:    `"code":"unauthenticated"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader("{}"))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tt.cookie})
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.Contains(t, rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{name: "preferred claim", claims: map[string]any{"name": "Jane", "email": "jane@example.com"}, want: "Jane"},
		{name: "falls back to email", claims: map[string]any{"name": "", "email": "jane@example.com"}, want: "jane@example.com"},
		{name: "falls back to preferred_username", claims: map[string]any{"preferred_username": "jane"}, want: "jane"},
		{name: "ignores non-string claims", claims: map[string]any{"name": 42}, want: "sub-1"},
		{name: "falls back to subject", claims: map[string]any{}, want: "sub-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, displayName(tt.claims, "name", "sub-1"))
		})
	}
}
