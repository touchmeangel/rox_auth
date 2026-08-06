import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr         string
	MaxConcurrentTasks int
	JWTAccessPrivKey   ed25519.PrivateKey
	JWTRefreshPrivKey  ed25519.PrivateKey
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr: os.Getenv("LISTEN_ADDRESS"),
	}

	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")

	var missing []string
	if cfg.ListenAddr == "" {
		missing = append(missing, "LISTEN_ADDRESS")
	}
	if accessSecret == "" {
		missing = append(missing, "JWT_ACCESS_SECRET")
	}
	if refreshSecret == "" {
		missing = append(missing, "JWT_REFRESH_SECRET")
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

	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}

	accessKey, err := parseEd25519PrivateKey(accessSecret)
	if err != nil {
		return cfg, fmt.Errorf("JWT_ACCESS_SECRET: %w", err)
	}
	refreshKey, err := parseEd25519PrivateKey(refreshSecret)
	if err != nil {
		return cfg, fmt.Errorf("JWT_REFRESH_SECRET: %w", err)
	}

	cfg.JWTAccessPrivKey = accessKey
	cfg.JWTRefreshPrivKey = refreshKey

	return cfg, nil
}