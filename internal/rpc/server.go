package rpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"time"

	"github.com/touchmeangel/rox_auth/internal/store"
	"github.com/touchmeangel/rox_auth/internal/token"
	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	authpb.UnimplementedAuthServiceServer

	tokenManager *token.Manager
	userStore    store.UserStore
}

func NewServer(userStore store.UserStore, tokenStore token.Store, accessTokenSecret, refreshTokenSecret ed25519.PrivateKey, accessTokenTTL, refreshTokenTTL time.Duration, issuer string, audience []string) *Server {
	tokenManager := token.NewManager(tokenStore, accessTokenSecret, refreshTokenSecret, accessTokenTTL, refreshTokenTTL, issuer, audience)

	return &Server{
		tokenManager: tokenManager,
		userStore:    userStore,
	}
}

func ConcurrencyLimiter(sem chan struct{}) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return handler(ctx, req)
	}
}

func LoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		dur := time.Since(start)

		code := status.Code(err)
		attrs := []any{
			"method", info.FullMethod,
			"duration_ms", dur.Milliseconds(),
			"code", code.String(),
		}
		if err != nil {
			logger.ErrorContext(ctx, "rpc failed", append(attrs, "error", err)...)
		} else {
			logger.InfoContext(ctx, "rpc completed", attrs...)
		}
		return resp, err
	}
}

var sentinelCodes = map[error]codes.Code{
	token.ErrInvalidToken:     codes.Unauthenticated,
	token.ErrExpiredToken:     codes.Unauthenticated,
	token.ErrInvalidClaims:    codes.Unauthenticated,
	token.ErrTokenRevoked:     codes.Unauthenticated,
	token.ErrTokenReused:      codes.Unauthenticated,
	token.ErrInvalidTokenType: codes.InvalidArgument,
	token.ErrSessionNotFound:  codes.Unauthenticated,
}

func toStatus(err error) error {
	for sentinel, code := range sentinelCodes {
		if errors.Is(err, sentinel) {
			return status.Error(code, err.Error())
		}
	}

	return status.Errorf(codes.Internal, "%v", err)
}
