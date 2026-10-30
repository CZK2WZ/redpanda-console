// Copyright 2026 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"slices"
	"time"
)

// Authentication configures how users log in to Console.
type Authentication struct {
	// UseSecureCookies sets the Secure attribute on session cookies. Disable
	// only when Console is served over plain HTTP, e.g. for local development.
	UseSecureCookies bool `yaml:"useSecureCookies"`
	// SessionDuration is the maximum lifetime of a login session, regardless
	// of whether the identity provider could still refresh its tokens.
	SessionDuration time.Duration      `yaml:"sessionDuration"`
	OIDC            AuthenticationOIDC `yaml:"oidc"`
}

// AuthenticationOIDC configures login through an OpenID Connect provider.
type AuthenticationOIDC struct {
	Enabled bool `yaml:"enabled"`
	// IssuerURL is used for OIDC discovery via /.well-known/openid-configuration.
	IssuerURL    string `yaml:"issuerUrl"`
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	// RedirectURL must point to the frontend callback page, i.e.
	// https://<console-host>[/<base-path>]/login/callbacks/oidc, and must be
	// registered with the identity provider.
	RedirectURL string   `yaml:"redirectUrl"`
	Scopes      []string `yaml:"scopes"`
	// DisplayNameClaim is the ID token claim shown as the user's name. If it is
	// absent, email, preferred_username and sub are tried in that order.
	DisplayNameClaim string `yaml:"displayNameClaim"`
}

// RegisterFlags registers flags for sensitive authentication inputs.
func (c *Authentication) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&c.OIDC.ClientSecret, "authentication.oidc.client-secret", "", "OIDC client secret")
}

// SetDefaults for the authentication config.
func (c *Authentication) SetDefaults() {
	c.UseSecureCookies = true
	c.SessionDuration = 12 * time.Hour
	c.OIDC.Scopes = []string{"openid", "profile", "email", "offline_access"}
	c.OIDC.DisplayNameClaim = "name"
}

// Validate the authentication config.
func (c *Authentication) Validate() error {
	if !c.OIDC.Enabled {
		return nil
	}
	if c.SessionDuration <= 0 {
		return errors.New("sessionDuration must be positive")
	}
	if err := c.OIDC.Validate(); err != nil {
		return fmt.Errorf("failed to validate oidc config: %w", err)
	}
	return nil
}

// Validate the OIDC config.
func (c *AuthenticationOIDC) Validate() error {
	if c.IssuerURL == "" {
		return errors.New("issuerUrl must be set")
	}
	if c.ClientID == "" {
		return errors.New("clientId must be set")
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("redirectUrl must be an absolute URL")
	}
	if !slices.Contains(c.Scopes, "openid") {
		return errors.New("scopes must include openid")
	}
	return nil
}
