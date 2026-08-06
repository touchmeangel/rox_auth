package token

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisTokenStore struct {
	client *redis.Client
}

const (
	refreshTokenPrefix = "refresh_token:"
	blacklistPrefix    = "blacklist:"
	tokenVersionPrefix = "token_version:"
	userTokensPrefix   = "user_tokens:"
)

func NewRedisTokenStore(addr, password string, db int) *RedisTokenStore {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisTokenStore{client: client}
}

func (s *RedisTokenStore) StoreRefreshToken(ctx context.Context, tokenID, userID string, expiresAt time.Time) error {
	data := &RefreshTokenData{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Revoked:   false,
		CreatedAt: time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	ttl := time.Until(expiresAt)
	if err := s.client.Set(ctx, refreshTokenPrefix+tokenID, jsonData, ttl).Err(); err != nil {
		return err
	}

	if err := s.client.SAdd(ctx, userTokensPrefix+userID, tokenID).Err(); err != nil {
		return err
	}

	return s.client.Expire(ctx, userTokensPrefix+userID, ttl).Err()
}

func (s *RedisTokenStore) GetRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenData, error) {
	jsonData, err := s.client.Get(ctx, refreshTokenPrefix+tokenID).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var data RefreshTokenData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *RedisTokenStore) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	data, err := s.GetRefreshToken(ctx, tokenID)
	if err != nil || data == nil {
		return err
	}

	data.Revoked = true
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	ttl := time.Until(data.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return s.client.Set(ctx, refreshTokenPrefix+tokenID, jsonData, ttl).Err()
}

func (s *RedisTokenStore) RevokeAllUserTokens(ctx context.Context, userID string) error {
	tokenIDs, err := s.client.SMembers(ctx, userTokensPrefix+userID).Result()
	if err != nil {
		return err
	}

	for _, tokenID := range tokenIDs {
		if err := s.RevokeRefreshToken(ctx, tokenID); err != nil {
			continue
		}
	}

	return nil
}

func (s *RedisTokenStore) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	exists, err := s.client.Exists(ctx, blacklistPrefix+tokenID).Result()
	return exists > 0, err
}

func (s *RedisTokenStore) BlacklistToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	return s.client.Set(ctx, blacklistPrefix+tokenID, "1", ttl).Err()
}

func (s *RedisTokenStore) GetUserTokenVersion(ctx context.Context, userID string) (int, error) {
	version, err := s.client.Get(ctx, tokenVersionPrefix+userID).Int()
	if err == redis.Nil {
		return 0, nil // Default version is 0
	}
	return version, err
}

func (s *RedisTokenStore) IncrementUserTokenVersion(ctx context.Context, userID string) (int64, error) {
	return s.client.Incr(ctx, tokenVersionPrefix+userID).Result()
}
