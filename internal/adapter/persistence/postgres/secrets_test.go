package postgres

import "testing"

func TestMaskToken(t *testing.T) {
	tests := map[string]string{
		"ghp_abcdefghijklmnop1234": "****1234",
		"12345678":                 "****",
		"":                         "****",
	}
	for in, want := range tests {
		if got := MaskToken(in); got != want {
			t.Errorf("MaskToken(%q) = %q, want %q", in, got, want)
		}
	}
}
