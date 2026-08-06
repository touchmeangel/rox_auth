package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr        string
	JWTAccessPrivKey  ed25519.PrivateKey
	JWTRefreshPrivKey ed25519.PrivateKey
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

func parseEd25519PrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)

	return parseBase64Ed25519Key(raw)
}

func parseBase64Ed25519Key(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}

	switch len(raw) {
	case ed25519.SeedSize: // 32 bytes
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize: // 64 bytes
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("expected a %d-byte seed or %d-byte key, got %d bytes", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}
