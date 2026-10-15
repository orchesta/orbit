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

// exactVersion reports whether v looks like one version rather than a range,
// a wildcard, a URL or a path. Only such versions go into a purl.
func exactVersion(v string) bool {
	return v != "" && !strings.ContainsAny(v, " \t*^~<>=!,|[]()/:@")
}

// purlName splits name into the purl namespace and name for eco and applies
// the type's normalisation:
//   - npm: "@scope/name" has the namespace "@scope" (encoded %40scope);
//   - pypi: lower case, "_" becomes "-";
//   - golang: the module path up to the last "/" is the namespace. Case is
//     kept: Go module paths are case-sensitive, although the purl type
//     definition says to lowercase them;
//   - nuget: no namespace, case kept.
func purlName(eco entity.Ecosystem, name string) (namespace, base string) {
	switch eco {
	case entity.EcosystemNpm:
		if strings.HasPrefix(name, "@") {
			if i := strings.IndexByte(name, '/'); i > 0 {
				return name[:i], name[i+1:]
			}
		}
		return "", name
	case entity.EcosystemPyPI:
		return "", strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case entity.EcosystemGo:
		if i := strings.LastIndexByte(name, '/'); i > 0 {
			return name[:i], name[i+1:]
		}
	}
	return "", name
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
	ns, base := purlName(eco, strings.Trim(name, "/"))
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	if ns != "" {
		for _, seg := range strings.Split(strings.Trim(ns, "/"), "/") {
			if seg == "" {
				continue
			}
			b.WriteString(purlEscape(seg))
			b.WriteByte('/')
		}
	}
	b.WriteString(purlEscape(base))
	v := nativeVersion(eco, version)
	if v != "" && (anyVersion || exactVersion(v)) {
		b.WriteByte('@')
		b.WriteString(purlEscape(v))
	}
	return b.String()
}
