package token

import (
	"context"
	"crypto/ed25519"
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
)

type Claims struct {
	jwt.RegisteredClaims
	UserID       string   `json:"user_id"`
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

func NewManager(store Store, accessTokenSecret, refreshTokenSecret []byte, accessTokenTTL, refreshTokenTTL time.Duration, issuer string, audience []string) *Manager {
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

func (m *Manager) GenerateAccessToken(ctx context.Context, userID, email string, roles []string) (string, error) {
	version, err := m.TokenStore.GetUserTokenVersion(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get token version: %w", err)
	}

	now := time.Now()
	tokenID := uuid.New().String()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID,
			Issuer:    m.Issuer,
			Audience:  m.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.AccessTokenTTL)),
		},
		UserID:       userID,
		Email:        email,
		Roles:        roles,
		TokenVersion: version,
		TokenType:    "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signedToken, err := token.SignedString(m.AccessTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (m *Manager) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	now := time.Now()
	tokenID := uuid.New().String()
	expiresAt := now.Add(m.RefreshTokenTTL)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID,
			Issuer:    m.Issuer,
			Audience:  m.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		UserID:    userID,
		TokenType: "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signedToken, err := token.SignedString(m.RefreshTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	if err := m.TokenStore.StoreRefreshToken(ctx, tokenID, userID, expiresAt); err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return signedToken, nil
}

func (m *Manager) GenerateTokenPair(ctx context.Context, userID, email string, roles []string) (*TokenPair, error) {
	accessToken, err := m.GenerateAccessToken(ctx, userID, email, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := m.GenerateRefreshToken(ctx, userID)
	if err != nil {
		return nil, err
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

	blacklisted, err := m.TokenStore.IsTokenBlacklisted(ctx, claims.ID)
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

func (m *Manager) RefreshTokens(ctx context.Context, refreshTokenString string, email string, roles []string) (*TokenPair, error) {
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

	storedToken, err := m.TokenStore.GetRefreshToken(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get stored refresh token: %w", err)
	}
	if storedToken == nil {
		return nil, ErrInvalidToken
	}
	if storedToken.Revoked {
		_ = m.TokenStore.RevokeAllUserTokens(ctx, claims.UserID)
		return nil, ErrTokenRevoked
	}

	if err := m.TokenStore.RevokeRefreshToken(ctx, claims.ID); err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	return m.GenerateTokenPair(ctx, claims.UserID, email, roles)
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

	return m.TokenStore.BlacklistToken(ctx, claims.ID, claims.ExpiresAt.Time)
}

func (m *Manager) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := m.TokenStore.IncrementUserTokenVersion(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to increment token version: %w", err)
	}

	return m.TokenStore.RevokeAllUserTokens(ctx, userID)
}
