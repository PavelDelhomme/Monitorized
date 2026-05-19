package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr            string
	DataDir         string
	AdminUser       string
	AdminPassword   string
	JWTSecret       string
	AllowedOrigins  []string
	DockerHost      string
	NPMLogGlob      string
	HostInterval    time.Duration
	DockerInterval  time.Duration
	NPMInterval     time.Duration
	RetentionDays   int
	AlertWebhookURL string

	// Veille compromission (fuites, threat intel — pas de scraping dark web)
	CompromiseEnabled        bool
	CompromiseInterval       time.Duration
	CompromiseServerIP       string
	CompromiseDetectPublicIP bool
	CompromiseAutoNPMDomains bool
}

func Load() Config {
	return Config{
		Addr:            env("MONITORIZED_ADDR", ":8080"),
		DataDir:         env("MONITORIZED_DATA_DIR", "./data"),
		AdminUser:       env("MONITORIZED_ADMIN_USER", "admin"),
		AdminPassword:   env("MONITORIZED_ADMIN_PASSWORD", ""),
		JWTSecret:       env("MONITORIZED_JWT_SECRET", ""),
		AllowedOrigins:  split(env("MONITORIZED_ALLOWED_ORIGINS", "http://localhost:8080")),
		DockerHost:      env("DOCKER_HOST", "unix:///var/run/docker.sock"),
		NPMLogGlob:      env("NPM_LOG_GLOB", "/data/logs/proxy-host-*_access.log"),
		HostInterval:    durationSec("COLLECT_HOST_INTERVAL", 10),
		DockerInterval:  durationSec("COLLECT_DOCKER_INTERVAL", 15),
		NPMInterval:     durationSec("COLLECT_NPM_INTERVAL", 30),
		RetentionDays:   intEnv("RETENTION_DAYS", 14),
		AlertWebhookURL: env("ALERT_WEBHOOK_URL", ""),

		CompromiseEnabled:        env("COMPROMISE_ENABLED", "true") == "true",
		CompromiseInterval:       durationSec("COMPROMISE_INTERVAL", 3600),
		CompromiseServerIP:       env("COMPROMISE_SERVER_IP", ""),
		CompromiseDetectPublicIP: env("COMPROMISE_DETECT_PUBLIC_IP", "true") == "true",
		CompromiseAutoNPMDomains: env("COMPROMISE_AUTO_NPM_DOMAINS", "true") == "true",
	}
}

func (c Config) Valid() error {
	if c.AdminPassword == "" {
		return errConfig("MONITORIZED_ADMIN_PASSWORD requis")
	}
	if len(c.JWTSecret) < 32 {
		return errConfig("MONITORIZED_JWT_SECRET doit faire au moins 32 caractères")
	}
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func intEnv(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func durationSec(k string, def int) time.Duration {
	return time.Duration(intEnv(k, def)) * time.Second
}

func splitList(s string) []string {
	if trim(s) == "" {
		return nil
	}
	return split(s)
}

func split(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trim(s[start:i])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	if len(out) == 0 {
		return []string{"http://localhost:8080"}
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

type configError string

func (e configError) Error() string { return string(e) }

func errConfig(msg string) error { return configError(msg) }
