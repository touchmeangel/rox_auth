package token

import (
	"context"
	"time"
)

type Store interface {
	StoreRefreshToken(ctx context.Context, tokenID, userID string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenData, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error)
	BlacklistToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	GetUserTokenVersion(ctx context.Context, userID string) (int, error)
	IncrementUserTokenVersion(ctx context.Context, userID string) (int64, error)
}
