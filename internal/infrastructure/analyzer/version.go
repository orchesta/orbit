package analyzer

import (
	"regexp"
	"strconv"
	"strings"
)

// parsedVersion is a parsed version: epoch, numeric core, and an optional
// pre-release or post-release marker.
type parsedVersion struct {
	epoch int
	core  []int
	pre   []string // pre-release identifiers; empty for a final release
	post  int      // PEP 440 post-release number + 1; 0 when absent
}

var (
	epochRe   = regexp.MustCompile(`^(\d+)!`)
	coreRe    = regexp.MustCompile(`^\d+(?:\.\d+)*`)
	pepPreRe  = regexp.MustCompile(`^[.\-_]?(dev|alpha|a|beta|b|preview|pre|rc|c)[.\-_]?(\d*)$`)
	pepPostRe = regexp.MustCompile(`^[.\-_]?(?:post|rev|r)[.\-_]?(\d*)$`)
)

// pepPhase maps PEP 440 pre-release spellings to identifiers that sort
// dev < a < b < rc.
var pepPhase = map[string]string{
	"dev": "0dev", "a": "a", "alpha": "a", "b": "b", "beta": "b",
	"c": "rc", "rc": "rc", "pre": "rc", "preview": "rc",
}

// CompareVersions determines the update type between two versions.
// Returns "major", "minor", "patch", or "none".
//
// Accepted formats: semver ("1.2.3", "v1.2.3", "1.2.3-beta.1", "+build"
// metadata ignored), range-prefixed ("^1.2"), any number of numeric core
// segments ("1.2.3.4", missing segments count as 0), and PEP 440 forms
// ("1!2.0" epoch, "2.0rc1", "1.0.post1", "1.0.dev1"). The type comes from the
// first three segments (or the epoch); a difference only in segment 4+, a
// pre-release or a post-release is "patch". "none" is returned when latest is
// not newer than current, or when either side cannot be parsed.
func CompareVersions(current, latest string) string {
	cur, ok := parseVersion(current)
	if !ok {
		return "none"
	}
	lat, ok := parseVersion(latest)
	if !ok {
		return "none"
	}
	if compareVersion(cur, lat) >= 0 {
		return "none"
	}
	if cur.epoch != lat.epoch {
		return "major"
	}
	for i := 0; i < 3; i++ {
		if segment(cur.core, i) != segment(lat.core, i) {
			return [3]string{"major", "minor", "patch"}[i]
		}
	}
	return "patch"
}

func segment(core []int, i int) int {
	if i < len(core) {
		return core[i]
	}
	return 0
}

// parseVersion parses the formats listed on CompareVersions.
func parseVersion(version string) (parsedVersion, bool) {
	var v parsedVersion
	version = CleanVersion(version)
	if idx := strings.IndexByte(version, '+'); idx != -1 {
		version = version[:idx]
	}
	if m := epochRe.FindStringSubmatch(version); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return v, false
		}
		v.epoch = n
		version = version[len(m[0]):]
	}
	core := coreRe.FindString(version)
	if core == "" {
		return v, false
	}
	for _, p := range strings.Split(core, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, false
		}
		v.core = append(v.core, n)
	}
	rest := version[len(core):]
	switch {
	case rest == "":
	case pepPreRe.MatchString(rest):
		m := pepPreRe.FindStringSubmatch(rest)
		v.pre = []string{pepPhase[m[1]]}
		if m[2] != "" {
			v.pre = append(v.pre, m[2])
		}
	case pepPostRe.MatchString(rest):
		m := pepPostRe.FindStringSubmatch(rest)
		n := 0
		if m[1] != "" {
			var err error
			if n, err = strconv.Atoi(m[1]); err != nil {
				return v, false
			}
		}
		v.post = n + 1
	case rest[0] == '-' && len(rest) > 1:
		v.pre = strings.Split(rest[1:], ".")
	default:
		return v, false
	}
	return v, true
}

// compareVersion returns -1, 0 or 1: epoch, then core, then pre-release
// (lowest), final release, post-release (highest).
func compareVersion(a, b parsedVersion) int {
	if a.epoch != b.epoch {
		if a.epoch < b.epoch {
			return -1
		}
		return 1
	}
	for i := 0; i < len(a.core) || i < len(b.core); i++ {
		x, y := segment(a.core, i), segment(b.core, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		switch {
		case a.post < b.post:
			return -1
		case a.post > b.post:
			return 1
		}
		return 0
	case len(a.pre) == 0:
		return 1 // a release outranks its pre-releases
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := comparePreIdent(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

func comparePreIdent(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	switch {
	case aErr == nil && bErr == nil:
		if an < bn {
			return -1
		}
		if an > bn {
			return 1
		}
		return 0
	case aErr == nil:
		return -1 // numeric identifiers rank below alphanumeric ones
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// CleanVersion strips semver range operators from a version string.
func CleanVersion(version string) string {
	return strings.TrimLeft(version, "^~>=<! v")
}
