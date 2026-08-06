package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) RevokeAccessTokenRequest(ctx context.Context, req *authpb.RevokeAccessTokenRequest) (*authpb.RevokeAccessTokenResponse, error) {
	accessToken := req.GetAccessToken()

	if accessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	err := s.tokenManager.RevokeAccessToken(ctx, accessToken)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.RevokeAccessTokenResponse{}, nil
}
