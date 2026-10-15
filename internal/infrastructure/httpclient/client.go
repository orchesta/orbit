// Package httpclient builds HTTP clients for talking to registries and APIs
// Orbit does not control.
package httpclient

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// MaxResponseBytes caps how much of any upstream response body Orbit reads.
// npm packuments of very popular packages run to tens of megabytes.
const MaxResponseBytes = 32 << 20

// ErrResponseTooLarge is returned when a response body exceeds the limit.
var ErrResponseTooLarge = errors.New("upstream response exceeds size limit")

// New returns a client with the given timeout whose response bodies fail with
// ErrResponseTooLarge after MaxResponseBytes, so an oversized or malicious
// response cannot exhaust memory.
func New(timeout time.Duration) *http.Client {
	return newWithLimit(timeout, MaxResponseBytes)
}

func newWithLimit(timeout time.Duration, max int64) *http.Client {
	return &http.Client{Timeout: timeout, Transport: limitTransport{base: http.DefaultTransport, max: max}}
}

type limitTransport struct {
	base http.RoundTripper
	max  int64
}

func (t limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{rc: resp.Body, remaining: t.max}
	return resp, nil
}

type limitedBody struct {
	rc        io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// A body of exactly the limit is fine; one more byte is not.
		var probe [1]byte
		n, err := b.rc.Read(probe[:])
		if n > 0 {
			return 0, ErrResponseTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.rc.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }
