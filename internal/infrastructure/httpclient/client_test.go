package httpclient

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
}

func TestBodyOverLimitFails(t *testing.T) {
	srv := serve(strings.Repeat("x", 101))
	defer srv.Close()
	resp, err := newWithLimit(5*time.Second, 100).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestBodyAtLimitIsAllowed(t *testing.T) {
	srv := serve(strings.Repeat("x", 100))
	defer srv.Close()
	resp, err := newWithLimit(5*time.Second, 100).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) != 100 {
		t.Fatalf("read %d bytes, err %v", len(b), err)
	}
}

func TestNewUsesProductionLimit(t *testing.T) {
	c := New(time.Second)
	if c.Timeout != time.Second {
		t.Fatalf("timeout = %v", c.Timeout)
	}
	if lt, ok := c.Transport.(limitTransport); !ok || lt.max != MaxResponseBytes {
		t.Fatalf("transport = %#v", c.Transport)
	}
}
