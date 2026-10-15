package main

import (
	"bytes"
	"testing"
)

func TestCILogWriter(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"plain":            {"orbit: ok\n", "orbit: ok\n"},
		"azure anywhere":   {"x ##vso[task.setvariable variable=a]1\n", "x # #vso[task.setvariable variable=a]1\n"},
		"azure any case":   {"##VsO[task.complete]\n", "# #VsO[task.complete]\n"},
		"format command":   {"a ##[error]b\n", "a # #[error]b\n"},
		"three hashes":     {"###vso[x]\n", "## #vso[x]\n"},
		"github at start":  {"::error::x\n", "> ::error::x\n"},
		"github indented":  {" \t::warning::x\n", ">  \t::warning::x\n"},
		"github mid line":  {"a ::error::x\n", "a ::error::x\n"},
		"CR is a line end": {"a\r::error::x\n", "a\r> ::error::x\n"},
		"unterminated":     {"::set-output name=a::b", "> ::set-output name=a::b"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			w := newCILogWriter(&out)
			// Byte by byte: a command split across writes is still caught.
			for i := range len(c.in) {
				if n, err := w.Write([]byte{c.in[i]}); n != 1 || err != nil {
					t.Fatalf("Write = %d, %v", n, err)
				}
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if out.String() != c.want {
				t.Fatalf("got %q, want %q", out.String(), c.want)
			}
		})
	}
}

func TestCILogWriterReportsWriteErrors(t *testing.T) {
	w := newCILogWriter(failingWriter{})
	if _, err := w.Write([]byte("line\n")); err == nil {
		t.Fatal("Write succeeded on a failing writer")
	}
	if err := w.Flush(); err == nil {
		t.Fatal("Flush hid the earlier error")
	}
}
