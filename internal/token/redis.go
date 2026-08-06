package token

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	sessionKeyPrefix      = "session:"
	userSessionsKeyPrefix = "user_sessions:"
	validAfterKeyPrefix   = "tokens_valid_after:"
)

func sessionKey(sessionID string) string   { return sessionKeyPrefix + sessionID }
func userSessionsKey(userID string) string { return userSessionsKeyPrefix + userID }
func validAfterKey(userID string) string   { return validAfterKeyPrefix + userID }

type RedisTokenStore struct {
	client *redis.Client
}

func NewRedisTokenStore(addr, password string, db int) *RedisTokenStore {
	return &RedisTokenStore{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		}),
	}
}

var _ Store = (*RedisTokenStore)(nil)

func (s *RedisTokenStore) CreateSession(ctx context.Context, sessionID, userID, deviceName, ipAddress, tokenHash string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("create session: expiresAt %s is already in the past", expiresAt)
	}

	key := sessionKey(sessionID)
	now := time.Now().Unix()

	_, err := s.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, key, map[string]interface{}{
			"user_id":      userID,
			"device_name":  deviceName,
			"ip_address":   ipAddress,
			"token_hash":   tokenHash,
			"created_at":   now,
			"last_used_at": now,
			"expires_at":   expiresAt.Unix(),
			"revoked":      "0",
		})
		pipe.Expire(ctx, key, ttl)
		pipe.SAdd(ctx, userSessionsKey(userID), sessionID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// KEYS[1] = session key
// ARGV[1] = presentedHash, ARGV[2] = newHash, ARGV[3] = deviceName,
// ARGV[4] = ipAddress, ARGV[5] = new expires_at (unix), ARGV[6] = now (unix),
// ARGV[7] = new TTL seconds
var consumeRefreshTokenScript = redis.NewScript(`
local key = KEYS[1]

if redis.call('EXISTS', key) == 0 then
	return 'ERR_NOT_FOUND'
end

if redis.call('HGET', key, 'revoked') == '1' then
	return 'ERR_REVOKED'
end

if redis.call('HGET', key, 'token_hash') ~= ARGV[1] then
	return 'ERR_REUSED'
end

local userID = redis.call('HGET', key, 'user_id')

redis.call('HSET', key,
	'token_hash', ARGV[2],
	'device_name', ARGV[3],
	'ip_address', ARGV[4],
	'expires_at', ARGV[5],
	'last_used_at', ARGV[6]
)
redis.call('EXPIRE', key, ARGV[7])

return userID
`)

func (s *RedisTokenStore) ConsumeRefreshToken(ctx context.Context, sessionID, presentedHash, newHash, deviceName, ipAddress string, newExpiresAt time.Time) (string, error) {
	ttl := time.Until(newExpiresAt)
	if ttl <= 0 {
		return "", ErrExpiredToken
	}

	res, err := consumeRefreshTokenScript.Run(ctx, s.client,
		[]string{sessionKey(sessionID)},
		presentedHash, newHash, deviceName, ipAddress,
		newExpiresAt.Unix(), time.Now().Unix(), int64(ttl.Seconds()),
	).Result()
	if err != nil {
		return "", fmt.Errorf("consume refresh token: %w", err)
	}

	result, ok := res.(string)
	if !ok {
		return "", fmt.Errorf("consume refresh token: unexpected script result type %T", res)
	}

	switch result {
	case "ERR_NOT_FOUND":
		return "", ErrSessionNotFound
	case "ERR_REVOKED":
		return "", ErrTokenRevoked
	case "ERR_REUSED":
		return "", ErrTokenReused
	default:
		return result, nil
	}
}

// KEYS[1] = session key
var revokeSessionScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
	return 0
end
redis.call('HSET', KEYS[1], 'revoked', '1')
return 1
`)

func (s *RedisTokenStore) RevokeSession(ctx context.Context, sessionID string) error {
	n, err := revokeSessionScript.Run(ctx, s.client, []string{sessionKey(sessionID)}).Int()
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// KEYS[1] = user_sessions set key, ARGV[1] = session key prefix
var revokeAllUserSessionsScript = redis.NewScript(`
local ids = redis.call('SMEMBERS', KEYS[1])
local revoked = {}
for _, id in ipairs(ids) do
	local key = ARGV[1] .. id
	if redis.call('EXISTS', key) == 1 then
		redis.call('HSET', key, 'revoked', '1')
		table.insert(revoked, id)
	end
end
if #revoked < #ids then
	local isRevoked = {}
	for _, id in ipairs(revoked) do isRevoked[id] = true end
	local stale = {}
	for _, id in ipairs(ids) do
		if not isRevoked[id] then table.insert(stale, id) end
	end
	if #stale > 0 then
		redis.call('SREM', KEYS[1], unpack(stale))
	end
end
return #revoked
`)

func (s *RedisTokenStore) RevokeAllUserSessions(ctx context.Context, userID string) error {
	if _, err := revokeAllUserSessionsScript.Run(ctx, s.client,
		[]string{userSessionsKey(userID)}, sessionKeyPrefix,
	).Result(); err != nil {
		return fmt.Errorf("revoke all user sessions: %w", err)
	}
	return nil
}

func (s *RedisTokenStore) ListUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	setKey := userSessionsKey(userID)
	ids, err := s.client.SMembers(ctx, setKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	pipe := s.client.Pipeline()
	cmds := make(map[string]*redis.MapStringStringCmd, len(ids))
	for _, id := range ids {
		cmds[id] = pipe.HGetAll(ctx, sessionKey(id))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}

	sessions := make([]*SessionData, 0, len(ids))
	var stale []interface{}
	for id, cmd := range cmds {
		fields, err := cmd.Result()
		if err != nil || len(fields) == 0 {
			stale = append(stale, id)
			continue
		}
		sd, err := parseSessionData(id, fields)
		if err != nil {
			stale = append(stale, id)
			continue
		}
		sessions = append(sessions, sd)
	}

	if len(stale) > 0 {
		_ = s.client.SRem(ctx, setKey, stale...).Err()
	}

	return sessions, nil
}

func parseSessionData(sessionID string, fields map[string]string) (*SessionData, error) {
	createdAt, err := strconv.ParseInt(fields["created_at"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	lastUsedAt, err := strconv.ParseInt(fields["last_used_at"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse last_used_at: %w", err)
	}

	return &SessionData{
		SessionID:  sessionID,
		UserID:     fields["user_id"],
		DeviceName: fields["device_name"],
		IPAddress:  fields["ip_address"],
		CreatedAt:  time.Unix(createdAt, 0),
		LastUsedAt: time.Unix(lastUsedAt, 0),
		Revoked:    fields["revoked"] == "1",
	}, nil
}

var setTokensValidAfterScript = redis.NewScript(`
local current = redis.call('GET', KEYS[1])
if current == false or tonumber(ARGV[1]) > tonumber(current) then
	redis.call('SET', KEYS[1], ARGV[1])
	return 1
end
return 0
`)

func (s *RedisTokenStore) GetUserTokensValidAfter(ctx context.Context, userID string) (time.Time, error) {
	v, err := s.client.Get(ctx, validAfterKey(userID)).Int64()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get user tokens valid-after: %w", err)
	}
	return time.UnixMilli(v), nil
}

func (s *RedisTokenStore) SetUserTokensValidAfter(ctx context.Context, userID string, cutoff time.Time) error {
	if _, err := setTokensValidAfterScript.Run(ctx, s.client,
		[]string{validAfterKey(userID)}, cutoff.UnixMilli(),
	).Result(); err != nil {
		return fmt.Errorf("set user tokens valid-after: %w", err)
	}
	return nil
}
