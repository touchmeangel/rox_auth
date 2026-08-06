package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/touchmeangel/rox_sdk_go/models/user"
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
	UserID       string      `json:"user_id"`
	Username     string      `json:"username"`
	SessionID    string      `json:"session_id"`
	Email        string      `json:"email"`
	Roles        []user.Role `json:"roles"`
	TokenVersion int         `json:"token_version"`
	TokenType    string      `json:"token_type"`
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SigningKey struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
	RetiredAt  time.Time
}

type Manager struct {
	TokenStore Store

	accessKeysMu    sync.RWMutex
	AccessTokenKeys []SigningKey

	refreshKeysMu    sync.RWMutex
	RefreshTokenKeys []SigningKey

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
	Audience        []string
}

func NewManager(store Store, accessTokenTTL, refreshTokenTTL time.Duration, issuer string, audience []string) *Manager {
	return &Manager{
		TokenStore:       store,
		AccessTokenKeys:  []SigningKey{newSigningKey()},
		RefreshTokenKeys: []SigningKey{newSigningKey()},
		AccessTokenTTL:   accessTokenTTL,
		RefreshTokenTTL:  refreshTokenTTL,
		Issuer:           issuer,
		Audience:         audience,
	}
}

func newSigningKey() SigningKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("token: failed to generate signing key: %v", err))
	}
	return SigningKey{KeyID: uuid.New().String(), PrivateKey: priv}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) RotateAccessTokenKey() {
	next := newSigningKey()

	m.accessKeysMu.Lock()
	defer m.accessKeysMu.Unlock()

	if len(m.AccessTokenKeys) > 0 {
		m.AccessTokenKeys[0].RetiredAt = time.Now()
	}
	keys := append([]SigningKey{next}, m.AccessTokenKeys...)

	retained := make([]SigningKey, 0, len(keys))
	for _, k := range keys {
		if k.RetiredAt.IsZero() || time.Since(k.RetiredAt) < m.AccessTokenTTL {
			retained = append(retained, k)
		}
	}
	m.AccessTokenKeys = retained
}

func (m *Manager) StartAccessKeyRotation(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.RotateAccessTokenKey()
			}
		}
	}()
}

func (m *Manager) RotateRefreshTokenKey() {
	next := newSigningKey()

	m.refreshKeysMu.Lock()
	defer m.refreshKeysMu.Unlock()

	if len(m.RefreshTokenKeys) > 0 {
		m.RefreshTokenKeys[0].RetiredAt = time.Now()
	}
	keys := append([]SigningKey{next}, m.RefreshTokenKeys...)

	retained := make([]SigningKey, 0, len(keys))
	for _, k := range keys {
		if k.RetiredAt.IsZero() || time.Since(k.RetiredAt) < m.RefreshTokenTTL {
			retained = append(retained, k)
		}
	}
	m.RefreshTokenKeys = retained
}

func (m *Manager) StartRefreshKeyRotation(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.RotateRefreshTokenKey()
			}
		}
	}()
}

func (m *Manager) GenerateAccessToken(ctx context.Context, userID, sessionID, username, email string, roles []user.Role) (string, error) {
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
		Username:     username,
		Email:        email,
		Roles:        roles,
		TokenVersion: version,
		TokenType:    "access",
	}

	m.accessKeysMu.RLock()
	signingKey := m.AccessTokenKeys[0]
	m.accessKeysMu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = signingKey.KeyID
	return token.SignedString(signingKey.PrivateKey)
}

func (m *Manager) generateRefreshToken(sessionID, userID string) (signed string, err error) {
	m.refreshKeysMu.RLock()
	signingKey := m.RefreshTokenKeys[0]
	m.refreshKeysMu.RUnlock()

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
	token.Header["kid"] = signingKey.KeyID

	signed, err = token.SignedString(signingKey.PrivateKey)
	return signed, err
}

func (m *Manager) NewSession(ctx context.Context, userID, username, email string, roles []user.Role, deviceName, ipAddress string) (*TokenPair, error) {
	sessionID := uuid.New().String()

	refreshToken, err := m.generateRefreshToken(sessionID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresAt := time.Now().Add(m.RefreshTokenTTL)
	if err := m.TokenStore.CreateSession(ctx, sessionID, userID, deviceName, ipAddress, hashToken(refreshToken), expiresAt); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	accessToken, err := m.GenerateAccessToken(ctx, userID, sessionID, username, email, roles)
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
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("token missing kid header")
			}

			m.accessKeysMu.RLock()
			defer m.accessKeysMu.RUnlock()
			for _, k := range m.AccessTokenKeys {
				if k.KeyID == kid {
					return k.PrivateKey.Public().(ed25519.PublicKey), nil
				}
			}
			return nil, fmt.Errorf("unknown key id: %s", kid)
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

func (m *Manager) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("token missing kid header")
			}

			m.refreshKeysMu.RLock()
			defer m.refreshKeysMu.RUnlock()
			for _, k := range m.RefreshTokenKeys {
				if k.KeyID == kid {
					return k.PrivateKey.Public().(ed25519.PublicKey), nil
				}
			}
			return nil, fmt.Errorf("unknown key id: %s", kid)
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

	return claims, nil
}

func (m *Manager) Refresh(ctx context.Context, claims *Claims, refreshTokenString, username, email string, roles []user.Role, deviceName, ipAddress string) (*TokenPair, error) {
	sessionID := claims.ID

	newRefreshToken, err := m.generateRefreshToken(sessionID, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	newExpiresAt := time.Now().Add(m.RefreshTokenTTL)

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

	accessToken, err := m.GenerateAccessToken(ctx, userID, sessionID, username, email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(m.AccessTokenTTL),
	}, nil
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

type PublicKeyInfo struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

func (m *Manager) PublicKeys() []PublicKeyInfo {
	m.accessKeysMu.RLock()
	defer m.accessKeysMu.RUnlock()

	keys := make([]PublicKeyInfo, 0, len(m.AccessTokenKeys))
	for _, k := range m.AccessTokenKeys {
		keys = append(keys, PublicKeyInfo{
			KeyID:     k.KeyID,
			PublicKey: k.PrivateKey.Public().(ed25519.PublicKey),
		})
	}
	return keys
}
