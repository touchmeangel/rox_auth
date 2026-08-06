package rpc

import (
	"context"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Refresh(ctx context.Context, req *authpb.RefreshRequest) (*authpb.RefreshResponse, error) {
	refreshToken := req.GetRefreshToken()
	deviceName := req.GetDeviceName()
	ipAddress := req.GetIpAddress()
	if refreshToken == "" || deviceName == "" || ipAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token, device_name, and ip_address are required")
	}

	claims, err := s.tokenManager.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, toStatus(err)
	}

	userID := claims.UserID

	user, err := s.userStore.GetUserProfile(ctx, userID)
	if err != nil {
		return nil, toStatus(err)
	}

	username := user.Username
	email := user.Email
	roles := user.Roles
	tokenPair, err := s.tokenManager.Refresh(ctx, claims, refreshToken, username, email, roles, deviceName, ipAddress)
	if err != nil {
		return nil, toStatus(err)
	}

	return &authpb.RefreshResponse{
		TokenPair: &authpb.TokenPair{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}
