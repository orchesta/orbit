package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// minJWTSecretLen is the shortest accepted HS256 signing secret (256 bits as hex).
const minJWTSecretLen = 32

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Crypto   CryptoConfig   `mapstructure:"crypto"`
	Log      LogConfig      `mapstructure:"log"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	JWTSecret  string `mapstructure:"jwt_secret"`
	SetupToken string `mapstructure:"setup_token"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host               string   `mapstructure:"host"`
	Port               int      `mapstructure:"port"`
	TrustProxyHeaders  bool     `mapstructure:"trust_proxy_headers"`
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
	ShutdownTimeout    int      `mapstructure:"shutdown_timeout"` // seconds to finish requests and requeue scans
}

// Address returns the server address string.
func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// DSN returns the PostgreSQL connection string with credentials URL-escaped.
func (d DatabaseConfig) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(d.User, d.Password),
		Host:     net.JoinHostPort(d.Host, strconv.Itoa(d.Port)),
		Path:     "/" + d.Name,
		RawQuery: url.Values{"sslmode": {d.SSLMode}}.Encode(),
	}
	return u.String()
}

// CryptoConfig holds encryption configuration.
type CryptoConfig struct {
	EncryptionKey string `mapstructure:"encryption_key"`
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"` // "json" or "text"
}

// ScannerConfig holds scanner configuration.
type ScannerConfig struct {
	WorkDir         string `mapstructure:"work_dir"`         // Temp directory for cloning repos
	CloneTimeout    int    `mapstructure:"clone_timeout"`    // Timeout in seconds for git clone
	DefaultSchedule string `mapstructure:"default_schedule"` // Default cron schedule

	MaxConcurrentScans int `mapstructure:"max_concurrent_scans"` // scans that may run at once
	ScanTimeout        int `mapstructure:"scan_timeout"`         // seconds a whole scan may take
	RetainScans        int `mapstructure:"retain_scans"`         // finished scans kept per repository
}

// Load reads configuration from file and environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.trust_proxy_headers", false)
	v.SetDefault("server.cors_allowed_origins", []string{})
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "orbit")
	v.SetDefault("database.password", "orbit")
	v.SetDefault("database.name", "orbit")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("scanner.work_dir", "/tmp/orbit-repos")
	v.SetDefault("scanner.clone_timeout", 120)
	v.SetDefault("scanner.default_schedule", "0 */6 * * *")
	v.SetDefault("scanner.max_concurrent_scans", 3)
	v.SetDefault("scanner.scan_timeout", 900)
	v.SetDefault("scanner.retain_scans", 10)
	v.SetDefault("server.shutdown_timeout", 25)

	// Config file
	// No SetConfigType: with it, viper also accepts an extensionless file
	// named "orbit", which is the binary itself when run from its own
	// directory. Without it only orbit.<ext> (orbit.yaml, orbit.yml, ...) matches.
	v.SetConfigName("orbit")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/orbit")
	v.AddConfigPath("$HOME/.orbit")

	// Environment variables
	v.SetEnvPrefix("ORBIT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Env names that don't follow ORBIT_<SECTION>_<KEY>, plus legacy spellings
	// still used by older deploy manifests. The first name listed wins.
	envAliases := map[string][]string{
		"auth.jwt_secret":       {"ORBIT_JWT_SECRET", "ORBIT_AUTH_JWT_SECRET"},
		"auth.setup_token":      {"ORBIT_SETUP_TOKEN", "ORBIT_AUTH_SETUP_TOKEN"},
		"crypto.encryption_key": {"ORBIT_CRYPTO_ENCRYPTION_KEY"},
		"database.ssl_mode":     {"ORBIT_DATABASE_SSL_MODE", "ORBIT_DATABASE_SSLMODE"},
		"scanner.work_dir":      {"ORBIT_SCANNER_WORK_DIR", "ORBIT_SCANNER_WORKDIR"},
	}
	for key, names := range envAliases {
		if err := v.BindEnv(append([]string{key}, names...)...); err != nil {
			return nil, fmt.Errorf("error binding env for %s: %w", key, err)
		}
	}

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate rejects configurations that are unsafe to run with.
func (c *Config) Validate() error {
	if len(c.Auth.JWTSecret) < minJWTSecretLen {
		return fmt.Errorf("ORBIT_JWT_SECRET must be set to at least %d characters (generate one with: openssl rand -hex 32)", minJWTSecretLen)
	}
	if key, err := hex.DecodeString(c.Crypto.EncryptionKey); err != nil || len(key) != 32 {
		return fmt.Errorf("ORBIT_CRYPTO_ENCRYPTION_KEY must be 64 hex characters (generate one with: openssl rand -hex 32)")
	}
	if c.Scanner.MaxConcurrentScans < 1 {
		return fmt.Errorf("ORBIT_SCANNER_MAX_CONCURRENT_SCANS must be at least 1")
	}
	if c.Scanner.ScanTimeout < 1 {
		return fmt.Errorf("ORBIT_SCANNER_SCAN_TIMEOUT must be at least 1")
	}
	if c.Server.ShutdownTimeout < 1 {
		return fmt.Errorf("ORBIT_SERVER_SHUTDOWN_TIMEOUT must be at least 1")
	}
	if c.Scanner.RetainScans < 0 {
		return fmt.Errorf("ORBIT_SCANNER_RETAIN_SCANS must not be negative")
	}
	if c.Scanner.CloneTimeout < 0 {
		return fmt.Errorf("ORBIT_SCANNER_CLONE_TIMEOUT must not be negative")
	}
	return nil
}
