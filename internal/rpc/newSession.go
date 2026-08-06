package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) NewSession(ctx context.Context, req *authpb.NewSessionRequest) (*authpb.NewSessionResponse, error) {
	userID := req.GetUserId()
	deviceName := req.GetDeviceName()
	ipAddress := req.GetIpAddress()

	if userID == "" || deviceName == "" || ipAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, device_name, and ip_address are required")
	}

	user, err := s.userStore.GetProfile(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	username := user.Username
	email := user.Email
	roles := user.Roles
	tokenPair, err := s.tokenManager.NewSession(ctx, userID, username, email, roles, deviceName, ipAddress)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.NewSessionResponse{
		TokenPair: &authpb.TokenPair{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}
