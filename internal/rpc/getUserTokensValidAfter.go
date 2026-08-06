package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) GetUserTokensValidAfter(ctx context.Context, req *authpb.GetUserTokensValidAfterRequest) (*authpb.GetUserTokensValidAfterResponse, error) {
	userID := req.GetUserId()

	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	time, err := s.tokenManager.TokenStore.GetUserTokensValidAfter(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.GetUserTokensValidAfterResponse{
		ValidAfter: timestamppb.New(time),
	}, nil
}
