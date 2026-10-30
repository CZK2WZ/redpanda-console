// Copyright 2026 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package api

import (
	"context"
	"errors"

	commonv1alpha1 "buf.build/gen/go/redpandadata/common/protocolbuffers/go/redpanda/api/common/v1alpha1"
	"connectrpc.com/connect"

	apierrors "github.com/redpanda-data/console/backend/pkg/api/connect/errors"
	"github.com/redpanda-data/console/backend/pkg/oidc"
	v1alpha1 "github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/console/v1alpha1"
	"github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/console/v1alpha1/consolev1alpha1connect"
)

var _ consolev1alpha1connect.AuthenticationServiceHandler = (*OIDCAuthenticationHandler)(nil)

// OIDCAuthenticationHandler serves the authentication API when users log in
// through the built-in OIDC authenticator. It grants every UI capability,
// since authorization is left to the upstream services.
type OIDCAuthenticationHandler struct{}

// ListAuthenticationMethods tells the frontend to offer OIDC login.
func (*OIDCAuthenticationHandler) ListAuthenticationMethods(context.Context, *connect.Request[v1alpha1.ListAuthenticationMethodsRequest]) (*connect.Response[v1alpha1.ListAuthenticationMethodsResponse], error) {
	return connect.NewResponse(&v1alpha1.ListAuthenticationMethodsResponse{
		Methods: []v1alpha1.AuthenticationMethod{v1alpha1.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC},
	}), nil
}

// LoginSaslScram is not supported when OIDC login is configured.
func (*OIDCAuthenticationHandler) LoginSaslScram(context.Context, *connect.Request[v1alpha1.LoginSaslScramRequest]) (*connect.Response[v1alpha1.LoginSaslScramResponse], error) {
	return nil, errUnsupportedWithOIDC()
}

// GetIdentity returns the logged-in OIDC user.
func (*OIDCAuthenticationHandler) GetIdentity(ctx context.Context, _ *connect.Request[v1alpha1.GetIdentityRequest]) (*connect.Response[v1alpha1.GetIdentityResponse], error) {
	session, ok := oidc.SessionFromContext(ctx)
	if !ok {
		return nil, apierrors.NewConnectError(
			connect.CodeUnauthenticated,
			oidc.ErrNoSession,
			apierrors.NewErrorInfo(commonv1alpha1.Reason_REASON_NO_AUTHENTICATION_TOKEN.String()),
		)
	}
	return connect.NewResponse(&v1alpha1.GetIdentityResponse{
		DisplayName:          session.DisplayName,
		AuthenticationMethod: v1alpha1.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC,
		Permissions: &v1alpha1.GetIdentityResponse_Permissions{
			KafkaClusterOperations: GetAllKafkaACLOperations(),
			SchemaRegistry:         GetAllSchemaRegistryCapabilities(),
			Redpanda:               GetAllRedpandaCapabilities(),
		},
	}), nil
}

// ListConsoleUsers is not supported when OIDC login is configured.
func (*OIDCAuthenticationHandler) ListConsoleUsers(context.Context, *connect.Request[v1alpha1.ListConsoleUsersRequest]) (*connect.Response[v1alpha1.ListConsoleUsersResponse], error) {
	return nil, errUnsupportedWithOIDC()
}

func (api *API) authenticationHandler() consolev1alpha1connect.AuthenticationServiceHandler {
	if api.oidc != nil {
		return &OIDCAuthenticationHandler{}
	}
	return &AuthenticationDefaultHandler{}
}

func errUnsupportedWithOIDC() error {
	return apierrors.NewConnectError(
		connect.CodeUnimplemented,
		errors.New("not supported with oidc authentication"),
		apierrors.NewErrorInfo(commonv1alpha1.Reason_REASON_FEATURE_NOT_SUPPORTED.String()),
	)
}
