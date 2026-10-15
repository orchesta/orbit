package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetLatestVersionEscapesScopedName(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"20.1.0"}}`))
	}))
	defer srv.Close()

	a := NewAnalyzer()
	a.registryURL = srv.URL
	v, err := a.GetLatestVersion(context.Background(), "@types/node")
	if err != nil || v != "20.1.0" {
		t.Fatalf("GetLatestVersion = %q, %v", v, err)
	}
	if gotPath != "/@types%2Fnode" {
		t.Fatalf("path = %q, want /@types%%2Fnode", gotPath)
	}
}
