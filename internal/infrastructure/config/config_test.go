package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

const testSecret = "0123456789abcdef0123456789abcdef"

const testEncryptionKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// setRequiredEnv sets every secret Load insists on, so a test can focus on one setting.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ORBIT_JWT_SECRET", testSecret)
	t.Setenv("ORBIT_CRYPTO_ENCRYPTION_KEY", testEncryptionKey)
}

func TestLoadRequiresJWTSecret(t *testing.T) {
	t.Setenv("ORBIT_CRYPTO_ENCRYPTION_KEY", testEncryptionKey)
	for _, secret := range []string{"", "too-short"} {
		t.Setenv("ORBIT_JWT_SECRET", secret)
		_, err := Load()
		if err == nil {
			t.Fatalf("secret %q: expected error, got nil", secret)
		}
		if !strings.Contains(err.Error(), "ORBIT_JWT_SECRET") {
			t.Fatalf("secret %q: error should name the env var, got %q", secret, err)
		}
	}
}

func TestLoadReadsJWTSecret(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.JWTSecret != testSecret {
		t.Fatalf("JWTSecret = %q", cfg.Auth.JWTSecret)
	}
}

func TestLoadAcceptsLegacyEnvNames(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_DATABASE_SSLMODE", "require")
	t.Setenv("ORBIT_SCANNER_WORKDIR", "/var/orbit")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.SSLMode != "require" {
		t.Fatalf("SSLMode = %q, want require", cfg.Database.SSLMode)
	}
	if cfg.Scanner.WorkDir != "/var/orbit" {
		t.Fatalf("WorkDir = %q, want /var/orbit", cfg.Scanner.WorkDir)
	}
}

func TestLoadPrefersCanonicalEnvNames(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_DATABASE_SSL_MODE", "verify-full")
	t.Setenv("ORBIT_DATABASE_SSLMODE", "disable")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.SSLMode != "verify-full" {
		t.Fatalf("SSLMode = %q, want verify-full", cfg.Database.SSLMode)
	}
}

func TestLoadRequiresEncryptionKey(t *testing.T) {
	t.Setenv("ORBIT_JWT_SECRET", testSecret)
	for _, key := range []string{"", "not-hex", testEncryptionKey[:62]} {
		t.Setenv("ORBIT_CRYPTO_ENCRYPTION_KEY", key)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "ORBIT_CRYPTO_ENCRYPTION_KEY") {
			t.Fatalf("key %q: want error naming ORBIT_CRYPTO_ENCRYPTION_KEY, got %v", key, err)
		}
	}
}

func TestDSNEscapesCredentials(t *testing.T) {
	d := DatabaseConfig{Host: "db", Port: 5432, User: "orbit", Password: "p@ss/w#rd", Name: "orbit_db", SSLMode: "disable"}
	pc, err := pgconn.ParseConfig(d.DSN())
	if err != nil {
		t.Fatal(err)
	}
	if pc.Host != "db" || pc.Port != 5432 || pc.User != "orbit" || pc.Password != "p@ss/w#rd" || pc.Database != "orbit_db" {
		t.Fatalf("parsed DSN = host=%q port=%d user=%q password=%q db=%q", pc.Host, pc.Port, pc.User, pc.Password, pc.Database)
	}
}

func TestLoadParsesCORSOrigins(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_SERVER_CORS_ALLOWED_ORIGINS", "https://a.example,https://b.example")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.CORSAllowedOrigins) != 2 || cfg.Server.CORSAllowedOrigins[1] != "https://b.example" {
		t.Fatalf("CORSAllowedOrigins = %q", cfg.Server.CORSAllowedOrigins)
	}
}

func TestLoadScannerDefaults(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner.MaxConcurrentScans != 3 || cfg.Scanner.ScanTimeout != 900 || cfg.Scanner.RetainScans != 10 || cfg.Server.ShutdownTimeout != 25 {
		t.Fatalf("defaults = %+v / %+v", cfg.Scanner, cfg.Server)
	}
}

func TestLoadRejectsInvalidScannerSettings(t *testing.T) {
	cases := []struct{ env, value string }{
		{"ORBIT_SCANNER_MAX_CONCURRENT_SCANS", "0"},
		{"ORBIT_SCANNER_MAX_CONCURRENT_SCANS", "-1"},
		{"ORBIT_SCANNER_SCAN_TIMEOUT", "0"},
		{"ORBIT_SERVER_SHUTDOWN_TIMEOUT", "0"},
		{"ORBIT_SCANNER_RETAIN_SCANS", "-1"},
		{"ORBIT_SCANNER_CLONE_TIMEOUT", "-1"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(tc.env, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("error should name %s, got %q", tc.env, err)
			}
		})
	}
}

// A binary named "orbit" in the working directory (the usual layout for a
// downloaded release) must not be mistaken for the config file.
func TestLoadIgnoresExtensionlessOrbitFile(t *testing.T) {
	setRequiredEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "orbit"), []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x01\x02\x03"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with a binary named orbit in cwd: %v", err)
	}
	if cfg.Scanner.RetainScans != 10 {
		t.Fatalf("RetainScans = %d, want the default 10", cfg.Scanner.RetainScans)
	}
}

func TestLoadStillReadsOrbitYAML(t *testing.T) {
	setRequiredEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "orbit"), []byte("\x7fELF\x02\x01\x01\x00"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "orbit.yaml"), []byte("scanner:\n  retain_scans: 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner.RetainScans != 4 {
		t.Fatalf("RetainScans = %d, want 4 from orbit.yaml", cfg.Scanner.RetainScans)
	}
}

func TestLoadExploitDefaults(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Exploit.Enabled || cfg.Exploit.KEVURL != "" || cfg.Exploit.EPSSURL != "" {
		t.Fatalf("exploit defaults = %+v; want enabled with the public services", cfg.Exploit)
	}
}

func TestLoadExploitSettings(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_EXPLOIT_ENABLED", "false")
	t.Setenv("ORBIT_EXPLOIT_KEV_URL", "https://mirror.example/kev.json")
	t.Setenv("ORBIT_EXPLOIT_EPSS_URL", "https://mirror.example/epss")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exploit.Enabled || cfg.Exploit.KEVURL != "https://mirror.example/kev.json" || cfg.Exploit.EPSSURL != "https://mirror.example/epss" {
		t.Fatalf("exploit = %+v", cfg.Exploit)
	}
}

// Compose passes ORBIT_EXPLOIT_KEV_URL and ORBIT_EXPLOIT_EPSS_URL as
// empty strings when deploy/docker/.env does not set them; that means the
// public services.
func TestLoadTreatsEmptyExploitURLsAsTheDefaults(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_EXPLOIT_ENABLED", "true")
	t.Setenv("ORBIT_EXPLOIT_KEV_URL", "")
	t.Setenv("ORBIT_EXPLOIT_EPSS_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Exploit.Enabled || cfg.Exploit.KEVURL != "" || cfg.Exploit.EPSSURL != "" {
		t.Fatalf("exploit = %+v; want enabled with the public services", cfg.Exploit)
	}
}

func TestLoadRejectsInvalidExploitURLs(t *testing.T) {
	for _, env := range []string{"ORBIT_EXPLOIT_KEV_URL", "ORBIT_EXPLOIT_EPSS_URL"} {
		for _, value := range []string{"ftp://mirror.example/kev.json", "mirror.example/kev.json", "https://"} {
			t.Run(env+"="+value, func(t *testing.T) {
				setRequiredEnv(t)
				t.Setenv(env, value)
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), env) {
					t.Fatalf("err = %v, want one naming %s", err, env)
				}
			})
		}
	}
}
