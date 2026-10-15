package config

import "testing"

func TestLoadScannerLicensesIsOffByDefault(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ORBIT_SCANNER_LICENSES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner.Licenses {
		t.Fatal("scanner.licenses defaults to true, want false")
	}
	t.Setenv("ORBIT_SCANNER_LICENSES", "true")
	if cfg, err = Load(); err != nil || !cfg.Scanner.Licenses {
		t.Fatalf("ORBIT_SCANNER_LICENSES=true: Licenses = %v, %v", cfg != nil && cfg.Scanner.Licenses, err)
	}
}
