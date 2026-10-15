package spdx

import (
	"strings"
	"testing"
)

func TestNormalizeListed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"MIT", "MIT"},
		{"mit or apache-2.0", "MIT OR Apache-2.0"},
		{"(MIT AND BSD-3-Clause) OR GPL-2.0+", "MIT AND BSD-3-Clause OR GPL-2.0-or-later"},
		{"GPL-2.0-only WITH classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"Apache-2.0+", "Apache-2.0+"},
		{"bsd-3-clause", "BSD-3-Clause"},
		// A LicenseRef would need a definition in the document.
		{"LicenseRef-Toml", ""},
		{"MIT OR LicenseRef-Acme", ""},
		{"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", ""},
		// Not SPDX at all.
		{"SEE LICENSE IN LICENSE.md", ""},
		{"NOASSERTION", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeListed(c.in); got != c.want {
			t.Errorf("NormalizeListed(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeListedIsCappedAndIdempotent(t *testing.T) {
	// Over-long input is refused outright.
	long := strings.Repeat("MIT OR ", MaxExpressionLen) + "MIT"
	if got := NormalizeListed(long); got != "" {
		t.Errorf("NormalizeListed(over-long input) = %d bytes, want empty", len(got))
	}
	// Short input whose current form exceeds the cap is refused too: each
	// deprecated identifier grows when it is rewritten.
	grows := strings.TrimSuffix(strings.Repeat("GPL-2.0-with-classpath-exception OR ", 14), " OR ")
	if len(grows) > MaxExpressionLen {
		t.Fatalf("fixture is %d bytes, want at most %d", len(grows), MaxExpressionLen)
	}
	if got := NormalizeListed(grows); got != "" {
		t.Errorf("NormalizeListed(growing input) = %d bytes, want empty", len(got))
	}
	// Whatever comes back is within the cap, stable, and parseable.
	for _, in := range []string{"MIT", "mit or apache-2.0", "GPL-2.0+ AND (MIT OR BSD-3-Clause)", "GPL-3.0-with-gcc-exception", grows, long} {
		got := NormalizeListed(in)
		if len(got) > MaxExpressionLen {
			t.Errorf("NormalizeListed(%.30q) is %d bytes, over the cap", in, len(got))
		}
		if got == "" {
			continue
		}
		if again := NormalizeListed(got); again != got {
			t.Errorf("NormalizeListed not idempotent: %q then %q", got, again)
		}
		if _, err := parse(got); err != nil {
			t.Errorf("result %q does not parse: %v", got, err)
		}
		if _, denied := Evaluate(got, func(string) bool { return true }); !denied {
			t.Errorf("Evaluate cannot parse result %q", got)
		}
	}
}
