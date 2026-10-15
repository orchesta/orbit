package server

import "net/http"

// maxRequestBodyBytes caps API request bodies; the largest legitimate body
// is a bulk import of a few hundred repositories.
const maxRequestBodyBytes = 1 << 20

// contentSecurityPolicy allows only same-origin scripts. Inline styles stay
// allowed because React style props and Tailwind rely on them; the favicon
// is an inline data: SVG.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// limitRequestBody makes reads beyond maxRequestBodyBytes fail.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets browser hardening headers on every response. HSTS is
// left to the TLS-terminating proxy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}
