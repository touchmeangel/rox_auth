package token

import "time"

type RefreshTokenData struct {
	SessionID string
	UserID    string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}
