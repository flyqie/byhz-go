// Package config loads the runtime configuration from environment variables.
package config

import (
	"net"
	"os"
	"strings"
)

// Config is the process-wide configuration.
type Config struct {
	Host       string
	Port       string
	APIBase    string
	PID        string
	Device     string
	Token      string
	AESIV      string
	UserAgent  string
	RelayUA    string
	Proxy      string // upstream proxy for the app API and playback APIs (PROXY)
	RelayProxy string // optional proxy for /api/proxy (RELAY_PROXY); empty = direct
	KiwiDebug  bool
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Load reads configuration from the environment, applying the same defaults
// as the original Python viewer.
func Load() *Config {
	return &Config{
		Host:       env("HOST", "127.0.0.1"),
		Port:       env("PORT", "8000"),
		APIBase:    strings.TrimRight(env("API_BASE", ""), "/"),
		PID:        env("APP_PID", "0"),
		Device:     env("APP_DEVICE", ""),
		Token:      env("APP_TOKEN", ""),
		AESIV:      env("APP_AES_IV", ""),
		UserAgent:  env("APP_UA", "Dart/3.5 (dart:io)"),
		RelayUA:    env("RELAY_UA", "okhttp/4.8.0"),
		Proxy:      env("PROXY", ""),
		RelayProxy: env("RELAY_PROXY", ""),
		KiwiDebug:  strings.TrimSpace(os.Getenv("KIWI_DEBUG")) != "",
	}
}

// Addr returns the listen address.
func (c *Config) Addr() string {
	return net.JoinHostPort(c.Host, c.Port)
}
