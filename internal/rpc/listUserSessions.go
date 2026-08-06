package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) ListUserSessions(ctx context.Context, req *authpb.ListUserSessionsRequest) (*authpb.ListUserSessionsResponse, error) {
	userID := req.GetUserId()

	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	sessions, err := s.tokenManager.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	parsedSessions := make([]*authpb.Session, len(sessions))
	for i, session := range sessions {
		parsedSessions[i] = &authpb.Session{
			SessionId:  session.SessionID,
			DeviceName: session.DeviceName,
			IpAddress:  session.IPAddress,
			CreatedAt:  timestamppb.New(session.CreatedAt),
			LastUsedAt: timestamppb.New(session.LastUsedAt),
		}
	}

	return &authpb.ListUserSessionsResponse{
		Sessions: parsedSessions,
	}, nil
}
