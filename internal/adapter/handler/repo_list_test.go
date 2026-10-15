package handler

import "testing"

func TestRepoListOrder(t *testing.T) {
	cases := map[string]string{
		"":       "r.name ASC",
		"name":   "r.name ASC",
		"recent": "r.created_at DESC, r.name ASC",
	}
	for in, want := range cases {
		got, err := repoListOrder(in)
		if err != nil || got != want {
			t.Errorf("repoListOrder(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := repoListOrder("name; DROP TABLE x"); err == nil {
		t.Fatal("unknown sort values must be rejected")
	}
}
