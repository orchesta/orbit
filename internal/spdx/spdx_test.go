package spdx

import (
	"slices"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"MIT", "MIT"},
		{"mit", "MIT"},
		{"  Apache-2.0 ", "Apache-2.0"},
		{"(MIT OR Apache-2.0)", "MIT OR Apache-2.0"},
		{"MIT or apache-2.0", "MIT OR Apache-2.0"},
		{"(MIT AND BSD-3-Clause) OR Apache-2.0", "MIT AND BSD-3-Clause OR Apache-2.0"},
		{"MIT AND (BSD-3-Clause OR Apache-2.0)", "MIT AND (BSD-3-Clause OR Apache-2.0)"},
		{"((MIT))", "MIT"},
		{"MIT AND (ISC AND 0BSD)", "MIT AND ISC AND 0BSD"},
		{"GPL-2.0", "GPL-2.0-only"},
		{"GPL-2.0+", "GPL-2.0-or-later"},
		{"gpl-3.0-only+", "GPL-3.0-or-later"},
		{"LGPL-2.1-or-later", "LGPL-2.1-or-later"},
		{"Apache-2.0+", "Apache-2.0+"},
		{"GPL-2.0-only WITH classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"LicenseRef-acme-1.0", "LicenseRef-acme-1.0"},
		{"licenseref-Acme", "LicenseRef-Acme"},
		{"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"},
		{"Unlicense", "Unlicense"},
		// Not SPDX: unknown.
		{"", ""},
		{"UNLICENSED", ""},
		{"non-standard", ""},
		{"SEE LICENSE IN LICENSE.md", ""},
		{"BSD", ""},
		{"Apache 2.0", ""},
		{"MIT/X11", ""},
		{"NOASSERTION", ""},
		{"NONE", ""},
		{"MIT OR", ""},
		{"OR MIT", ""},
		{"(MIT", ""},
		{"MIT)", ""},
		{"MIT Apache-2.0", ""},
		{"MIT WITH", ""},
		{"MIT WITH MIT", ""},
		{"LicenseRef-", ""},
		{"LicenseRef-a_b", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{"MIT AND (ISC OR GPL-2.0+)", "(a OR b", "LGPL-2.1 OR MIT AND Zlib"} {
		once := Normalize(in)
		if twice := Normalize(once); twice != once {
			t.Errorf("Normalize(Normalize(%q)) = %q, want %q", in, twice, once)
		}
	}
}

func TestNormalizeRejectsOversizedAndDeepInput(t *testing.T) {
	long := strings.Repeat("MIT AND ", MaxExpressionLen/8) + "MIT"
	if got := Normalize(long); got != "" {
		t.Errorf("oversized expression = %q, want \"\"", got)
	}
	deep := strings.Repeat("(", maxDepth+1) + "MIT" + strings.Repeat(")", maxDepth+1)
	if got := Normalize(deep); got != "" {
		t.Errorf("deep expression = %q, want \"\"", got)
	}
	ok := strings.Repeat("(", maxDepth) + "MIT" + strings.Repeat(")", maxDepth)
	if got := Normalize(ok); got != "MIT" {
		t.Errorf("depth %d = %q, want MIT", maxDepth, got)
	}
}

func TestJoin(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"MIT"}, "MIT"},
		{[]string{"MIT", "Apache-2.0"}, "MIT AND Apache-2.0"},
		{[]string{"GPL-3.0-or-later OR MIT", "Apache-2.0"}, "(GPL-3.0-or-later OR MIT) AND Apache-2.0"},
		{[]string{"MIT", "mit", "non-standard"}, "MIT"},
		{[]string{"non-standard"}, ""},
	}
	for _, c := range cases {
		if got := Join(c.in); got != c.want {
			t.Errorf("Join(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseIDs(t *testing.T) {
	got, err := ParseIDs(" gpl-3.0 , AGPL-3.0-only,,GPL-3.0-only, LicenseRef-Acme, LGPL-2.1+")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AGPL-3.0-only", "GPL-3.0-only", "LGPL-2.1-or-later", "LicenseRef-Acme"}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseIDs = %q, want %q", got, want)
	}
	for _, bad := range []string{"GPLv3", "MIT OR Apache-2.0", "Apache-2.0+", "UNLICENSED", "GPL 3.0"} {
		if _, err := ParseIDs(bad); err == nil {
			t.Errorf("ParseIDs(%q) succeeded, want an error", bad)
		}
	}
	if ids, err := ParseIDs(""); err != nil || len(ids) != 0 {
		t.Errorf("ParseIDs(\"\") = %q, %v", ids, err)
	}
}

func TestEvaluate(t *testing.T) {
	deny := func(ids ...string) func(string) bool {
		return func(id string) bool { return slices.Contains(ids, id) }
	}
	cases := []struct {
		expr       string
		deny       []string
		wantDenied bool
		wantHits   []string
	}{
		{"MIT", []string{"GPL-3.0-only"}, false, nil},
		{"GPL-3.0-only", []string{"GPL-3.0-only"}, true, []string{"GPL-3.0-only"}},
		{"GPL-3.0", []string{"GPL-3.0-only"}, true, []string{"GPL-3.0-only"}},
		{"GPL-3.0-or-later", []string{"GPL-3.0-only"}, false, nil},
		// OR: one allowed branch is enough.
		{"GPL-3.0-only OR MIT", []string{"GPL-3.0-only"}, false, nil},
		{"GPL-3.0-only OR AGPL-3.0-only", []string{"GPL-3.0-only", "AGPL-3.0-only"}, true, []string{"AGPL-3.0-only", "GPL-3.0-only"}},
		// AND: one denied operand is enough.
		{"MIT AND GPL-3.0-only", []string{"GPL-3.0-only"}, true, []string{"GPL-3.0-only"}},
		{"MIT AND (GPL-3.0-only OR Apache-2.0)", []string{"GPL-3.0-only"}, false, nil},
		{"(MIT AND GPL-3.0-only) OR (Apache-2.0 AND AGPL-3.0-only)", []string{"GPL-3.0-only", "AGPL-3.0-only"}, true, []string{"AGPL-3.0-only", "GPL-3.0-only"}},
		{"(MIT AND GPL-3.0-only) OR Apache-2.0", []string{"GPL-3.0-only"}, false, nil},
		// The exception and "+" are not part of the identifier.
		{"GPL-2.0-only WITH Classpath-exception-2.0", []string{"GPL-2.0-only"}, true, []string{"GPL-2.0-only"}},
		{"Apache-2.0+", []string{"Apache-2.0"}, true, []string{"Apache-2.0"}},
		// Unknown values are never denied.
		{"", []string{"MIT"}, false, nil},
		{"SEE LICENSE IN x", []string{"MIT"}, false, nil},
	}
	for _, c := range cases {
		hits, denied := Evaluate(c.expr, deny(c.deny...))
		if denied != c.wantDenied || !slices.Equal(hits, c.wantHits) {
			t.Errorf("Evaluate(%q, %q) = %q, %v; want %q, %v", c.expr, c.deny, hits, denied, c.wantHits, c.wantDenied)
		}
	}
}

func TestListsAreLoaded(t *testing.T) {
	for _, id := range []string{"MIT", "Apache-2.0", "GPL-3.0-only", "0BSD", "CC-BY-4.0"} {
		if got, ok := CanonicalID(id); !ok || got != id {
			t.Errorf("CanonicalID(%q) = %q, %v", id, got, ok)
		}
	}
	if len(licenseIDs) < 500 || len(exceptionIDs) < 50 {
		t.Fatalf("lists look truncated: %d licenses, %d exceptions", len(licenseIDs), len(exceptionIDs))
	}
}
