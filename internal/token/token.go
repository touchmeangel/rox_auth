package token

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrTokenRevoked     = errors.New("token has been revoked")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrSessionNotFound  = errors.New("session not found")
	ErrTokenReused      = errors.New("refresh token has already been rotated")
)

type Claims struct {
	jwt.RegisteredClaims
	UserID       string   `json:"user_id"`
	SessionID    string   `json:"session_id"`
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
	TokenVersion int      `json:"token_version"`
	TokenType    string   `json:"token_type"`
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Manager struct {
	TokenStore         Store
	AccessTokenSecret  ed25519.PrivateKey
	RefreshTokenSecret ed25519.PrivateKey
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	Issuer             string
	Audience           []string
}

func NewManager(store Store, accessTokenSecret, refreshTokenSecret ed25519.PrivateKey, accessTokenTTL, refreshTokenTTL time.Duration, issuer string, audience []string) *Manager {
	return &Manager{
		TokenStore:         store,
		AccessTokenSecret:  accessTokenSecret,
		RefreshTokenSecret: refreshTokenSecret,
		AccessTokenTTL:     accessTokenTTL,
		RefreshTokenTTL:    refreshTokenTTL,
		Issuer:             issuer,
		Audience:           audience,
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) GenerateAccessToken(ctx context.Context, userID, sessionID, email string, roles []string) (string, error) {
	version, err := m.TokenStore.GetUserTokenVersion(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get token version: %w", err)
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID,
			Issuer:    m.Issuer,
			Audience:  m.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.AccessTokenTTL)),
		},
		UserID:       userID,
		SessionID:    sessionID,
		Email:        email,
		Roles:        roles,
		TokenVersion: version,
		TokenType:    "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(m.AccessTokenSecret)
}

func (m *Manager) generateRefreshToken(sessionID, userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID,
			Subject:   userID,
			Issuer:    m.Issuer,
			Audience:  m.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.RefreshTokenTTL)),
		},
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(m.RefreshTokenSecret)
}

func (m *Manager) NewSession(ctx context.Context, userID, email string, roles []string, deviceName, ipAddress string) (*TokenPair, error) {
	sessionID := uuid.New().String()

	refreshToken, err := m.generateRefreshToken(sessionID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresAt := time.Now().Add(m.RefreshTokenTTL)
	if err := m.TokenStore.CreateSession(ctx, sessionID, userID, deviceName, ipAddress, hashToken(refreshToken), expiresAt); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	accessToken, err := m.GenerateAccessToken(ctx, userID, sessionID, email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(m.AccessTokenTTL),
	}, nil
}

func (m *Manager) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.AccessTokenSecret.Public().(ed25519.PublicKey), nil
		},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(m.Issuer),
		jwt.WithAudience(m.Audience[0]),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}
	if claims.TokenType != "access" {
		return nil, ErrInvalidTokenType
	}

	blacklisted, err := m.TokenStore.IsAccessTokenBlacklisted(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	if blacklisted {
		return nil, ErrTokenRevoked
	}

	currentVersion, err := m.TokenStore.GetUserTokenVersion(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user token version: %w", err)
	}
	if claims.TokenVersion < currentVersion {
		return nil, ErrTokenRevoked
	}

	return claims, nil
}

func (m *Manager) Refresh(ctx context.Context, refreshTokenString, email string, roles []string, deviceName, ipAddress string) (*TokenPair, error) {
	token, err := jwt.ParseWithClaims(
		refreshTokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.RefreshTokenSecret.Public().(ed25519.PublicKey), nil
		},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(m.Issuer),
		jwt.WithAudience(m.Audience[0]),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}
	if claims.TokenType != "refresh" {
		return nil, ErrInvalidTokenType
	}

	sessionID := claims.ID
	newExpiresAt := time.Now().Add(m.RefreshTokenTTL)

	newRefreshToken, err := m.generateRefreshToken(sessionID, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	userID, err := m.TokenStore.ConsumeRefreshToken(
		ctx, sessionID,
		hashToken(refreshTokenString), hashToken(newRefreshToken),
		deviceName, ipAddress, newExpiresAt,
	)
	if err != nil {
		if errors.Is(err, ErrTokenReused) {
			_ = m.RevokeAllUserSessions(ctx, claims.UserID)
		}
		return nil, err
	}

	accessToken, err := m.GenerateAccessToken(ctx, userID, sessionID, email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(m.AccessTokenTTL),
	}, nil
}

func (m *Manager) RevokeAccessToken(ctx context.Context, tokenString string) error {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return ErrInvalidClaims
	}
	return m.TokenStore.BlacklistAccessToken(ctx, claims.ID, claims.ExpiresAt.Time)
}

func (m *Manager) RevokeSession(ctx context.Context, sessionID string) error {
	return m.TokenStore.RevokeSession(ctx, sessionID)
}

func (m *Manager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	if _, err := m.TokenStore.IncrementUserTokenVersion(ctx, userID); err != nil {
		return fmt.Errorf("failed to increment token version: %w", err)
	}
	return m.TokenStore.RevokeAllUserSessions(ctx, userID)
}

func (m *Manager) ListUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	return m.TokenStore.ListUserSessions(ctx, userID)
}
