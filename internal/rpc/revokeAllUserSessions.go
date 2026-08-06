package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) RevokeAllUserSessions(ctx context.Context, req *authpb.RevokeAllUserSessionsRequest) (*authpb.RevokeAllUserSessionsResponse, error) {
	userID := req.GetUserId()

	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	err := s.tokenManager.RevokeAllUserSessions(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.RevokeAllUserSessionsResponse{}, nil
}
