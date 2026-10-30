// Copyright 2026 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package kafka

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	commonv1alpha1 "buf.build/gen/go/redpandadata/common/protocolbuffers/go/redpanda/api/common/v1alpha1"
	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/oauth"

	apierrors "github.com/redpanda-data/console/backend/pkg/api/connect/errors"
	"github.com/redpanda-data/console/backend/pkg/config"
)

// Clients are evicted only once their session ends rather than after idling,
// because a client may back a long-running live-tail stream. Idle broker
// connections are already closed by franz-go itself.
const impersonatedClientSweepEvery = time.Minute

// UserTokenResolver resolves the logged-in user of a request and provides
// OAuth access tokens on their behalf.
type UserTokenResolver interface {
	// SessionID returns a stable identifier of the user session bound to ctx.
	SessionID(ctx context.Context) (string, error)
	// AccessToken returns a currently valid access token for the session.
	AccessToken(sessionID string) (string, error)
	// SessionActive reports whether the session still exists.
	SessionActive(sessionID string) bool
}

var _ ClientFactory = (*ImpersonatingClientProvider)(nil)

// ImpersonatingClientProvider creates one Kafka client per user session that
// authenticates via SASL OAUTHBEARER with the user's own access token, so
// that Kafka authorizes every request as that user.
type ImpersonatingClientProvider struct {
	cfg            *config.Config
	logger         *slog.Logger
	registry       prometheus.Registerer
	factoryMetrics *FactoryMetrics
	resolver       UserTokenResolver

	mu        sync.Mutex
	clients   map[string]*kgo.Client
	lastSweep time.Time
}

// NewImpersonatingClientProvider creates a new ImpersonatingClientProvider.
func NewImpersonatingClientProvider(cfg *config.Config, logger *slog.Logger, registry prometheus.Registerer, resolver UserTokenResolver) *ImpersonatingClientProvider {
	return &ImpersonatingClientProvider{
		cfg:            cfg,
		logger:         logger,
		registry:       registry,
		factoryMetrics: NewFactoryMetrics(cfg.MetricsNamespace, "impersonating_client_provider", registry),
		resolver:       resolver,
		clients:        make(map[string]*kgo.Client),
	}
}

// GetKafkaClient returns the Kafka client of the user bound to ctx.
func (f *ImpersonatingClientProvider) GetKafkaClient(ctx context.Context) (*kgo.Client, *kadm.Client, error) {
	sessionID, err := f.resolver.SessionID(ctx)
	if err != nil {
		return nil, nil, apierrors.NewConnectError(
			connect.CodeUnauthenticated,
			fmt.Errorf("cannot impersonate user for Kafka: %w", err),
			apierrors.NewErrorInfo(commonv1alpha1.Reason_REASON_NO_AUTHENTICATION_TOKEN.String()),
		)
	}

	f.mu.Lock()
	stale := f.sweepLocked(time.Now())
	cl, ok := f.clients[sessionID]
	if !ok {
		cl, err = f.createClient(sessionID)
		if err == nil {
			f.clients[sessionID] = cl
			f.factoryMetrics.IncrementActiveClients()
		}
	}
	f.mu.Unlock()

	f.closeClients(stale)
	if err != nil {
		return nil, nil, err
	}
	return cl, kadm.NewClient(cl), nil
}

func (f *ImpersonatingClientProvider) createClient(sessionID string) (*kgo.Client, error) {
	// Static SASL is disabled because the per-user mechanism is added below.
	kafkaCfg := f.cfg.Kafka
	kafkaCfg.SASL.Enabled = false
	opts, err := NewKgoConfig(kafkaCfg, f.logger, f.cfg.MetricsNamespace, f.registry)
	if err != nil {
		return nil, apierrors.NewConnectError(
			connect.CodeInternal,
			fmt.Errorf("failed to build Kafka config: %w", err),
			apierrors.NewErrorInfo(commonv1alpha1.Reason_REASON_SERVER_ERROR.String()),
		)
	}

	// The token is resolved on every (re)authentication rather than captured
	// once, so refreshed tokens are picked up when brokers enforce KIP-368
	// session lifetimes.
	mechanism := oauth.Oauth(func(context.Context) (oauth.Auth, error) {
		token, err := f.resolver.AccessToken(sessionID)
		return oauth.Auth{Token: token}, err
	})
	opts = append(opts, kgo.SASL(mechanism))

	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka client: %w", err)
	}
	return cl, nil
}

func (f *ImpersonatingClientProvider) sweepLocked(now time.Time) []*kgo.Client {
	if now.Sub(f.lastSweep) < impersonatedClientSweepEvery {
		return nil
	}
	f.lastSweep = now

	var stale []*kgo.Client
	for id, cl := range f.clients {
		if !f.resolver.SessionActive(id) {
			stale = append(stale, cl)
			delete(f.clients, id)
			f.factoryMetrics.DecrementActiveClients()
		}
	}
	return stale
}

func (*ImpersonatingClientProvider) closeClients(clients []*kgo.Client) {
	if len(clients) == 0 {
		return
	}
	// Closing waits for in-flight requests, which must not block the caller.
	go func() {
		for _, cl := range clients {
			cl.Close()
		}
	}()
}
