// Copyright 2026 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

// Package oidc implements Console login through an OpenID Connect identity
// provider using the authorization code flow with PKCE.
package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	commonv1alpha1 "buf.build/gen/go/redpandadata/common/protocolbuffers/go/redpanda/api/common/v1alpha1"
	"connectrpc.com/connect"
	"github.com/cloudhut/common/rest"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	apierrors "github.com/redpanda-data/console/backend/pkg/api/connect/errors"
	"github.com/redpanda-data/console/backend/pkg/config"
)

const (
	// SessionCookieName is the cookie that carries the session ID.
	SessionCookieName = "console_session"
	loginCookieName   = "console_oidc_login"

	loginTimeout     = 10 * time.Minute
	maxPendingLogins = 10_000

	// authenticationMethodOIDC mirrors AUTHENTICATION_METHOD_OIDC in the
	// console.v1alpha1 proto, which the frontend reads from the callback response.
	authenticationMethodOIDC = 2
)

type pendingLogin struct {
	nonce     string
	verifier  string
	expiresAt time.Time
}

// Authenticator handles the OIDC login flow and authenticates requests by
// their session cookie.
type Authenticator struct {
	cfg      config.Authentication
	logger   *slog.Logger
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
	sessions *SessionStore
	errw     *connect.ErrorWriter

	pendingMu sync.Mutex
	pending   map[string]pendingLogin
}

// NewAuthenticator discovers the identity provider's endpoints and returns an
// Authenticator for it.
func NewAuthenticator(ctx context.Context, cfg config.Authentication, logger *slog.Logger) (*Authenticator, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover oidc provider %q: %w", cfg.OIDC.IssuerURL, err)
	}

	return &Authenticator{
		cfg:      cfg,
		logger:   logger,
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.OIDC.ClientID}),
		oauth2: oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDC.RedirectURL,
			Scopes:       cfg.OIDC.Scopes,
		},
		sessions: NewSessionStore(),
		errw:     connect.NewErrorWriter(),
		pending:  make(map[string]pendingLogin),
	}, nil
}

// Sessions returns the store holding all active login sessions.
func (a *Authenticator) Sessions() *SessionStore {
	return a.sessions
}

// HandleLogin redirects the browser to the identity provider. If HC functions
// are configured, the hcFunction query parameter must name one of them, and it
// is requested as an additional scope.
func (a *Authenticator) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scopes, err := a.loginScopes(r.URL.Query().Get("hcFunction"))
		if err != nil {
			rest.SendRESTError(w, r, a.logger, &rest.Error{Err: err, Status: http.StatusBadRequest, Message: err.Error()})
			return
		}

		state, nonce, verifier := rand.Text(), rand.Text(), oauth2.GenerateVerifier()
		if err := a.addPendingLogin(state, pendingLogin{nonce: nonce, verifier: verifier, expiresAt: time.Now().Add(loginTimeout)}); err != nil {
			rest.SendRESTError(w, r, a.logger, &rest.Error{Err: err, Status: http.StatusServiceUnavailable, Message: err.Error()})
			return
		}

		oauth2Cfg := a.oauth2
		oauth2Cfg.Scopes = scopes
		a.setCookie(w, loginCookieName, state, loginTimeout)
		http.Redirect(w, r, oauth2Cfg.AuthCodeURL(state, gooidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
	}
}

// HandleLoginOptions returns the choices the login page must offer.
func (a *Authenticator) HandleLoginOptions() http.HandlerFunc {
	hcFunctions := a.cfg.HCFunctions
	if hcFunctions == nil {
		hcFunctions = []string{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rest.SendResponse(w, r, a.logger, http.StatusOK, map[string]any{"hcFunctions": hcFunctions})
	}
}

func (a *Authenticator) loginScopes(hcFunction string) ([]string, error) {
	if len(a.cfg.HCFunctions) == 0 {
		return a.oauth2.Scopes, nil
	}
	if !slices.Contains(a.cfg.HCFunctions, hcFunction) {
		return nil, errors.New("hcFunction must be one of the configured HC functions")
	}
	if slices.Contains(a.oauth2.Scopes, hcFunction) {
		return a.oauth2.Scopes, nil
	}
	return append(slices.Clone(a.oauth2.Scopes), hcFunction), nil
}

// HandleCallback completes the login after the identity provider redirected
// back to the frontend, which forwards the query parameters here.
func (a *Authenticator) HandleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := a.completeLogin(r)
		if err != nil {
			rest.SendRESTError(w, r, a.logger, &rest.Error{Err: err, Status: http.StatusUnauthorized, Message: err.Error()})
			return
		}

		if c, err := r.Cookie(SessionCookieName); err == nil {
			a.sessions.Delete(c.Value)
		}
		a.sessions.Put(session)
		a.deleteCookie(w, loginCookieName)
		a.setCookie(w, SessionCookieName, session.ID, a.cfg.SessionDuration)

		a.logger.InfoContext(r.Context(), "user logged in", slog.String("subject", session.Subject))
		rest.SendResponse(w, r, a.logger, http.StatusOK, map[string]any{
			"displayName":          session.DisplayName,
			"avatarUrl":            "",
			"authenticationMethod": authenticationMethodOIDC,
		})
	}
}

// HandleLogout ends the current session.
func (a *Authenticator) HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SessionCookieName); err == nil {
			a.sessions.Delete(c.Value)
		}
		a.deleteCookie(w, SessionCookieName)
		rest.SendResponse(w, r, a.logger, http.StatusOK, map[string]any{})
	}
}

// RequireSession rejects requests without a valid session and binds the
// session to the request context. Requests whose path ends with one of
// publicPathSuffixes pass through unauthenticated.
func (a *Authenticator) RequireSession(publicPathSuffixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slices.ContainsFunc(publicPathSuffixes, func(s string) bool { return strings.HasSuffix(r.URL.Path, s) }) {
				next.ServeHTTP(w, r)
				return
			}

			session, err := a.sessionFromRequest(r)
			if err != nil {
				a.writeUnauthenticated(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), session)))
		})
	}
}

func (a *Authenticator) sessionFromRequest(r *http.Request) (*Session, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, ErrNoSession
	}
	session, ok := a.sessions.Get(c.Value)
	if !ok {
		return nil, ErrNoSession
	}
	// Fails once the access token expired and cannot be refreshed, which ends
	// the session early because upstream calls would be rejected anyway.
	if _, err := session.AccessToken(); err != nil {
		a.sessions.Delete(session.ID)
		a.logger.InfoContext(r.Context(), "ending session", slog.String("subject", session.Subject), slog.Any("error", err))
		return nil, ErrNoSession
	}
	return session, nil
}

func (a *Authenticator) completeLogin(r *http.Request) (*Session, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("identity provider returned error %q: %s", e, q.Get("error_description"))
	}

	state := q.Get("state")
	c, err := r.Cookie(loginCookieName)
	if err != nil || state == "" || c.Value != state {
		return nil, errors.New("login state mismatch, please try logging in again")
	}
	login, ok := a.takePendingLogin(state)
	if !ok {
		return nil, errors.New("login attempt expired, please try logging in again")
	}

	token, err := a.oauth2.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(login.verifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("identity provider did not return an id_token")
	}
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}
	if idToken.Nonce != login.nonce {
		return nil, errors.New("id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode id_token claims: %w", err)
	}

	return &Session{
		ID:          rand.Text(),
		Subject:     idToken.Subject,
		DisplayName: displayName(claims, a.cfg.OIDC.DisplayNameClaim, idToken.Subject),
		ExpiresAt:   time.Now().Add(a.cfg.SessionDuration),
		// Detached from the request context, as the token source outlives the
		// request and uses its context for refresh calls.
		tokens: a.oauth2.TokenSource(context.WithoutCancel(r.Context()), token),
	}, nil
}

func displayName(claims map[string]any, preferredClaim, subject string) string {
	for _, claim := range []string{preferredClaim, "email", "preferred_username"} {
		if v, ok := claims[claim].(string); ok && v != "" {
			return v
		}
	}
	return subject
}

func (a *Authenticator) addPendingLogin(state string, login pendingLogin) error {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()

	now := time.Now()
	for s, l := range a.pending {
		if now.After(l.expiresAt) {
			delete(a.pending, s)
		}
	}
	if len(a.pending) >= maxPendingLogins {
		return errors.New("too many concurrent login attempts, please retry later")
	}
	a.pending[state] = login
	return nil
}

func (a *Authenticator) takePendingLogin(state string) (pendingLogin, bool) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()

	login, ok := a.pending[state]
	delete(a.pending, state)
	if !ok || time.Now().After(login.expiresAt) {
		return pendingLogin{}, false
	}
	return login, true
}

func (a *Authenticator) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	a.writeCookie(w, name, value, int(maxAge.Seconds()))
}

func (a *Authenticator) deleteCookie(w http.ResponseWriter, name string) {
	a.writeCookie(w, name, "", -1)
}

func (a *Authenticator) writeCookie(w http.ResponseWriter, name, value string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   a.cfg.UseSecureCookies,
		// Lax rather than Strict so the cookie survives the top-level redirect
		// back from the identity provider.
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) writeUnauthenticated(w http.ResponseWriter, r *http.Request, err error) {
	if a.errw.IsSupported(r) {
		connectErr := apierrors.NewConnectError(
			connect.CodeUnauthenticated,
			err,
			apierrors.NewErrorInfo(commonv1alpha1.Reason_REASON_NO_AUTHENTICATION_TOKEN.String()),
		)
		if writeErr := a.errw.Write(w, r, connectErr); writeErr != nil {
			a.logger.DebugContext(r.Context(), "failed to write unauthenticated error", slog.Any("error", writeErr))
		}
		return
	}
	rest.SendRESTError(w, r, a.logger, &rest.Error{Err: err, Status: http.StatusUnauthorized, Message: err.Error(), IsSilent: true})
}
