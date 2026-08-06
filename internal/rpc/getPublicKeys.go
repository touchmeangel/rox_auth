package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
)

func (s *Server) GetPublicKeys(ctx context.Context, req *authpb.GetPublicKeysRequest) (*authpb.GetPublicKeysResponse, error) {
	pubkeys := s.tokenManager.PublicKeys()
	return &authpb.GetPublicKeysResponse{}, nil
}
