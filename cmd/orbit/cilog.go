package main

import (
	"bytes"
	"io"
	"regexp"
	"unicode"
)

// ciLogWriter keeps text from the scanned repository and from osv.dev
// (manifest paths, package names, .orbitignore IDs, advisory summaries) from
// acting as a CI log command when it reaches the job log:
//
//   - Azure Pipelines acts on "##vso[" and "##[" anywhere in a line, GitHub
//     Actions on the legacy "##[". Each is written as "# #vso[" or "# #[" (a
//     space between the two "#"), case-insensitively.
//   - GitHub Actions acts on "::" at the start of a line, after leading
//     whitespace. Such a line gets the prefix "> ".
//
// Lines end at LF or CR, as the agents read them. Output is written line by
// line; Flush writes a final line without a terminator.
type ciLogWriter struct {
	w   io.Writer
	buf []byte
	err error
}

func newCILogWriter(w io.Writer) *ciLogWriter { return &ciLogWriter{w: w} }

var ciCommandRE = regexp.MustCompile(`(?i)##(vso)?\[`)

func (c *ciLogWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexAny(c.buf, "\r\n")
		if i < 0 {
			break
		}
		if err := c.writeLine(c.buf[:i+1]); err != nil {
			return 0, err
		}
		c.buf = c.buf[i+1:]
	}
	return len(p), nil
}

// Flush writes what is left of an unterminated last line.
func (c *ciLogWriter) Flush() error {
	if c.err == nil && len(c.buf) > 0 {
		_ = c.writeLine(c.buf)
		c.buf = nil
	}
	return c.err
}

func (c *ciLogWriter) writeLine(line []byte) error {
	out := ciCommandRE.ReplaceAllFunc(line, func(m []byte) []byte {
		return append([]byte("# #"), m[2:]...)
	})
	if bytes.HasPrefix(bytes.TrimLeftFunc(out, unicode.IsSpace), []byte("::")) {
		out = append([]byte("> "), out...)
	}
	if _, err := c.w.Write(out); err != nil {
		c.err = err
	}
	return c.err
}
