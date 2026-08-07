package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) GetSessionTokensValidAfter(ctx context.Context, req *authpb.GetSessionTokensValidAfterRequest) (*authpb.GetSessionTokensValidAfterResponse, error) {
	sessionID := req.GetSessionId()

	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	time, err := s.tokenManager.TokenStore.GetSessionTokensValidAfter(ctx, sessionID)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.GetSessionTokensValidAfterResponse{
		ValidAfter: timestamppb.New(time),
	}, nil
}
