package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
)

func (s *Server) GetPublicKeys(ctx context.Context, req *authpb.GetPublicKeysRequest) (*authpb.GetPublicKeysResponse, error) {
	keys := s.tokenManager.PublicKeys()

	resp := &authpb.GetPublicKeysResponse{
		Keys: make([]*authpb.PublicKey, 0, len(keys)),
	}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, &authpb.PublicKey{
			KeyId:     k.KeyID,
			PublicKey: k.PublicKey,
		})
	}
	return resp, nil
}
