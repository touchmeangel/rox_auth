package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
)

func (s *Server) GetPublicKeys(ctx context.Context, req *authpb.GetPublicKeysRequest) (*authpb.GetPublicKeysResponse, error) {
	err := s.tokenManager.RevokeAllUserSessions(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.GetPublicKeysResponse{}, nil
}
