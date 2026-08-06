package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr         string
	RedisAddr          string
	RedisPassword      string
	DatabaseURL        string
	MaxConcurrentTasks int
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	JwtIssuer          string
	JwtAudiences       []string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:    os.Getenv("LISTEN_ADDRESS"),
		RedisAddr:     os.Getenv("REDIS_ADDRESS"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		JwtIssuer:     os.Getenv("JWT_ISSUER"),
	}

	var missing []string
	if cfg.ListenAddr == "" {
		missing = append(missing, "LISTEN_ADDRESS")
	}
	if cfg.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if cfg.RedisAddr == "" {
		missing = append(missing, "REDIS_ADDRESS")
	}
	if cfg.RedisPassword == "" {
		missing = append(missing, "REDIS_PASSWORD")
	}
	if cfg.JwtIssuer == "" {
		missing = append(missing, "JWT_ISSUER")
	}

	raw := os.Getenv("MAX_CONCURRENT_TASKS")
	if raw == "" {
		missing = append(missing, "MAX_CONCURRENT_TASKS")
	} else if n, err := strconv.Atoi(raw); err != nil || n <= 0 {
		return cfg, fmt.Errorf("MAX_CONCURRENT_TASKS must be a positive integer, got %q", raw)
	} else {
		cfg.MaxConcurrentTasks = n
	}

	accessTTLRaw := os.Getenv("ACCESS_TOKEN_TTL")
	if accessTTLRaw == "" {
		missing = append(missing, "ACCESS_TOKEN_TTL")
	} else if d, err := time.ParseDuration(accessTTLRaw); err != nil || d <= 0 {
		return cfg, fmt.Errorf("ACCESS_TOKEN_TTL must be a positive duration (e.g. \"15m\"), got %q", accessTTLRaw)
	} else {
		cfg.AccessTokenTTL = d
	}

	refreshTTLRaw := os.Getenv("REFRESH_TOKEN_TTL")
	if refreshTTLRaw == "" {
		missing = append(missing, "REFRESH_TOKEN_TTL")
	} else if d, err := time.ParseDuration(refreshTTLRaw); err != nil || d <= 0 {
		return cfg, fmt.Errorf("REFRESH_TOKEN_TTL must be a positive duration (e.g. \"168h\"), got %q", refreshTTLRaw)
	} else {
		cfg.RefreshTokenTTL = d
	}

	audRaw := os.Getenv("JWT_AUDIENCES")
	if audRaw == "" {
		missing = append(missing, "JWT_AUDIENCES")
	} else {
		parts := strings.Split(audRaw, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cfg.JwtAudiences = append(cfg.JwtAudiences, trimmed)
			}
		}
		if len(cfg.JwtAudiences) == 0 {
			return cfg, fmt.Errorf("JWT_AUDIENCES must contain at least one valid audience")
		}
	}

	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}
