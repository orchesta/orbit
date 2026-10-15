package report

import (
	"strings"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// purlType maps an ecosystem to its Package URL type.
var purlType = map[entity.Ecosystem]string{
	entity.EcosystemNpm:   "npm",
	entity.EcosystemPyPI:  "pypi",
	entity.EcosystemNuGet: "nuget",
	entity.EcosystemGo:    "golang",
}

// purlEscape percent-encodes s as the Package URL standard (ECMA-427, 5.4)
// requires: ASCII letters, digits, ".-_~" and ":" stay, every other byte of
// the UTF-8 encoding becomes %XX with upper-case hex digits.
func purlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			c == '.', c == '-', c == '_', c == '~', c == ':':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// nativeVersion is the version as the ecosystem writes it. Orbit stores Go
// module versions without their "v" ("1.2.3"); Go, the module proxy and
// osv.dev write "v1.2.3".
func nativeVersion(eco entity.Ecosystem, v string) string {
	if eco == entity.EcosystemGo && v != "" && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// exactVersion reports whether v looks like one concrete version: it starts
// with a digit and uses only [0-9A-Za-z.+_-]. Ranges, wildcards, dist-tags
// (latest, 1.x), URLs, paths and anything with whitespace or control
// characters are not versions and stay out of a purl.
func exactVersion(v string) bool {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			c == '.', c == '+', c == '_', c == '-':
		default:
			return false
		}
	}
	// "1.x" and "1.X.0" are x-ranges, not versions.
	for _, seg := range strings.Split(v, ".") {
		if seg == "x" || seg == "X" {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only, so non-ASCII bytes (which are
// percent-encoded) keep distinct names apart.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// badSegment reports whether s cannot be a purl namespace or name segment.
func badSegment(s string) bool { return s == "" || s == "." || s == ".." }

// purlName splits name into the purl namespace segments and name for eco and
// applies the type's normalisation. ok is false when the name has an empty,
// "." or ".." segment, so no purl can name it. A "/" left inside a name is
// percent-encoded by the caller.
//   - npm: "@scope/name" has the namespace "@scope" (encoded %40scope);
//   - pypi: ASCII lower case, "_" becomes "-";
//   - golang: the module path up to the last "/" is the namespace. Case is
//     kept: Go module paths are case-sensitive, although the purl type
//     definition says to lowercase them;
//   - nuget: no namespace, case kept.
func purlName(eco entity.Ecosystem, name string) (namespace []string, base string, ok bool) {
	switch eco {
	case entity.EcosystemNpm:
		if i := strings.IndexByte(name, '/'); i > 1 && name[0] == '@' {
			if badSegment(name[i+1:]) {
				return nil, "", false
			}
			return []string{name[:i]}, name[i+1:], true
		}
	case entity.EcosystemPyPI:
		name = strings.ReplaceAll(asciiLower(name), "_", "-")
	case entity.EcosystemGo:
		segs := strings.Split(name, "/")
		for _, s := range segs {
			if badSegment(s) {
				return nil, "", false
			}
		}
		return segs[:len(segs)-1], segs[len(segs)-1], true
	}
	return nil, name, !badSegment(name)
}

// PackageURL returns the purl of a dependency, for example
// pkg:npm/%40scope/name@1.2.3 or pkg:golang/github.com/x/y@v1.2.3. The
// version is left out when it is empty or not exact (see exactVersion). It
// returns "" for an ecosystem without a purl type.
func PackageURL(eco entity.Ecosystem, name, version string) string {
	return buildPURL(eco, name, version, false)
}

// buildPURL builds the purl; with anyVersion a non-exact version is kept
// (percent-encoded), which bomRef uses to keep references unique.
func buildPURL(eco entity.Ecosystem, name, version string, anyVersion bool) string {
	typ, ok := purlType[eco]
	if !ok || name == "" {
		return ""
	}
	ns, base, ok := purlName(eco, name)
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	for _, seg := range ns {
		b.WriteString(purlEscape(seg))
		b.WriteByte('/')
	}
	b.WriteString(purlEscape(base))
	v := nativeVersion(eco, version)
	exact := exactVersion(v)
	if eco == entity.EcosystemGo && strings.HasPrefix(v, "v") {
		exact = exactVersion(v[1:])
	}
	if v != "" && (anyVersion || exact) {
		b.WriteByte('@')
		b.WriteString(purlEscape(v))
	}
	return b.String()
}
