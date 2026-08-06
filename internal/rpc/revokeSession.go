package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) RevokeSession(ctx context.Context, req *authpb.RevokeSessionRequest) (*authpb.RevokeSessionResponse, error) {
	userID := req.GetUserId()
	sessionID := req.GetSessionId()

	if userID == "" || sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, session_id are required")
	}

	err := s.tokenManager.RevokeSession(ctx, sessionID)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.RevokeSessionResponse{}, nil
}
