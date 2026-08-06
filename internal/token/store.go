package token

import (
	"context"
	"time"
)

type SessionData struct {
	SessionID  string
	UserID     string
	DeviceName string
	IPAddress  string
	CreatedAt  time.Time
	LastUsedAt time.Time
	Revoked    bool
}

type Store interface {
	CreateSession(ctx context.Context, sessionID, userID, deviceName, ipAddress, tokenHash string, expiresAt time.Time) error
	ConsumeRefreshToken(ctx context.Context, sessionID, presentedHash, newHash, deviceName, ipAddress string, newExpiresAt time.Time) (userID string, err error)
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	ListUserSessions(ctx context.Context, userID string) ([]*SessionData, error)
	GetUserTokensValidAfter(ctx context.Context, userID string) (time.Time, error)
	SetUserTokensValidAfter(ctx context.Context, userID string, cutoff time.Time) error
}
