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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAuthentication() Authentication {
	var a Authentication
	a.SetDefaults()
	a.OIDC.Enabled = true
	a.OIDC.IssuerURL = "https://idp.example.com"
	a.OIDC.ClientID = "console"
	a.OIDC.RedirectURL = "https://console.example.com/login/callbacks/oidc"
	return a
}

func TestAuthenticationValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(a *Authentication)
		wantErr string
	}{
		{name: "valid", mutate: func(*Authentication) {}},
		{name: "disabled skips oidc validation", mutate: func(a *Authentication) { a.OIDC = AuthenticationOIDC{} }},
		{name: "missing issuer", mutate: func(a *Authentication) { a.OIDC.IssuerURL = "" }, wantErr: "issuerUrl"},
		{name: "missing client id", mutate: func(a *Authentication) { a.OIDC.ClientID = "" }, wantErr: "clientId"},
		{name: "relative redirect url", mutate: func(a *Authentication) { a.OIDC.RedirectURL = "/login/callbacks/oidc" }, wantErr: "redirectUrl"},
		{name: "missing openid scope", mutate: func(a *Authentication) { a.OIDC.Scopes = []string{"email"} }, wantErr: "openid"},
		{name: "non-positive session duration", mutate: func(a *Authentication) { a.SessionDuration = 0 }, wantErr: "sessionDuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAuthentication()
			tt.mutate(&a)
			err := a.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestOIDCImpersonationValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "wrong mechanism", mutate: func(c *Config) { c.Kafka.SASL.Mechanism = SASLMechanismPlain }, wantErr: SASLMechanismOAuthBearer},
		{name: "static username", mutate: func(c *Config) { c.Kafka.SASL.Username = "admin" }, wantErr: "static sasl credentials"},
		{name: "static token", mutate: func(c *Config) { c.Kafka.SASL.OAUth.Token = "t" }, wantErr: "static sasl credentials"},
		{
			name: "other login methods keep their own rules",
			mutate: func(c *Config) {
				c.Authentication.OIDC = AuthenticationOIDC{}
				c.Kafka.SASL.Mechanism = SASLMechanismScramSHA256
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Config
			c.SetDefaults()
			c.Kafka.Brokers = []string{"localhost:9092"}
			c.Authentication = validAuthentication()
			c.Kafka.SASL.Enabled = true
			c.Kafka.SASL.ImpersonateUser = true
			c.Kafka.SASL.Mechanism = SASLMechanismOAuthBearer
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
