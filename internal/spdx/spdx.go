// Package spdx normalises SPDX license expressions and checks them against a
// list of denied licenses. It knows the identifiers of one release of the
// SPDX License List (licenses.txt, exceptions.txt; see gen.go) and nothing
// else: a value that is not a valid expression over those identifiers, such
// as "SEE LICENSE IN LICENSE.md", "UNLICENSED", "BSD" or deps.dev's
// "non-standard", normalises to "".
package spdx

import (
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
)

//go:generate go run gen.go v3.29.0

//go:embed licenses.txt
var licenseList string

//go:embed exceptions.txt
var exceptionList string

// MaxExpressionLen caps the length of an expression, in bytes. Longer input
// normalises to "", so a lockfile cannot make one value arbitrarily large.
const MaxExpressionLen = 512

// maxDepth caps the nesting of parentheses.
const maxDepth = 16

var (
	licenseIDs   = indexList(licenseList)   // lower case -> canonical
	exceptionIDs = indexList(exceptionList) // lower case -> canonical
)

func indexList(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		if id := strings.TrimSpace(line); id != "" && !strings.HasPrefix(id, "#") {
			m[strings.ToLower(id)] = id
		}
	}
	return m
}

// gnuFamilies are the GNU licenses whose bare and "+" identifiers are
// deprecated in favour of "-only" and "-or-later".
var gnuFamilies = []string{
	"AGPL-1.0", "AGPL-3.0", "GFDL-1.1", "GFDL-1.2", "GFDL-1.3",
	"GPL-1.0", "GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
}

// gnuForm maps a canonical GNU identifier, with or without a trailing "+",
// to its current "-only" or "-or-later" form.
func gnuForm(id string, plus bool) (string, bool) {
	for _, f := range gnuFamilies {
		switch id {
		case f, f + "-only":
			if plus {
				return f + "-or-later", true
			}
			return f + "-only", true
		case f + "-or-later":
			return id, true
		}
	}
	return "", false
}

// CanonicalID returns the canonical spelling of one license identifier:
// the SPDX list's case, the current form of a deprecated GNU identifier
// ("GPL-2.0" is "GPL-2.0-only", "GPL-2.0+" is "GPL-2.0-or-later"), a
// LicenseRef- or DocumentRef- as written, and a trailing "+" kept on other
// licenses. ok is false for anything else.
func CanonicalID(tok string) (id string, ok bool) {
	plus := strings.HasSuffix(tok, "+")
	base := strings.TrimSuffix(tok, "+")
	if ref, ok := licenseRef(base); ok {
		if plus {
			ref += "+"
		}
		return ref, true
	}
	canon, ok := licenseIDs[strings.ToLower(base)]
	if !ok {
		// "GPL-2.0+" is itself on the list as a deprecated identifier.
		if canon, ok = licenseIDs[strings.ToLower(tok)]; !ok {
			return "", false
		}
		plus = false
	}
	if g, ok := gnuForm(strings.TrimSuffix(canon, "+"), plus || strings.HasSuffix(canon, "+")); ok {
		return g, true
	}
	if plus {
		canon += "+"
	}
	return canon, true
}

// licenseRef accepts "LicenseRef-<idstring>" and
// "DocumentRef-<idstring>:LicenseRef-<idstring>", with the prefixes in
// canonical case.
func licenseRef(tok string) (string, bool) {
	doc := ""
	if len(tok) > len("DocumentRef-") && strings.EqualFold(tok[:len("DocumentRef-")], "DocumentRef-") {
		name, rest, found := strings.Cut(tok[len("DocumentRef-"):], ":")
		if !found || !isIDString(name) {
			return "", false
		}
		doc, tok = "DocumentRef-"+name+":", rest
	}
	if len(tok) <= len("LicenseRef-") || !strings.EqualFold(tok[:len("LicenseRef-")], "LicenseRef-") {
		return "", false
	}
	name := tok[len("LicenseRef-"):]
	if !isIDString(name) {
		return "", false
	}
	return doc + "LicenseRef-" + name, true
}

// isIDString reports whether s is an SPDX idstring: letters, digits, "-"
// and ".".
func isIDString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// expr is a parsed expression: a license (op "") or an AND/OR of at least
// two operands. Operands of an AND are never ANDs themselves, and the same
// for OR, so String needs parentheses only around an OR inside an AND.
type expr struct {
	op        string // "", "AND" or "OR"
	args      []*expr
	id        string // canonical license ID, for op ""
	exception string // canonical WITH exception, for op ""
}

func (e *expr) String() string {
	if e.op == "" {
		if e.exception != "" {
			return e.id + " WITH " + e.exception
		}
		return e.id
	}
	parts := make([]string, len(e.args))
	for i, a := range e.args {
		parts[i] = a.String()
		if a.op == "OR" && e.op == "AND" {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, " "+e.op+" ")
}

// group joins args with op, splicing in operands that already use op.
func group(op string, args []*expr) *expr {
	if len(args) == 1 {
		return args[0]
	}
	g := &expr{op: op}
	for _, a := range args {
		if a.op == op {
			g.args = append(g.args, a.args...)
		} else {
			g.args = append(g.args, a)
		}
	}
	return g
}

var errSyntax = errors.New("not an SPDX license expression")

// parse parses an expression. Operators are accepted in any case and
// identifiers are matched case-insensitively, as the SPDX specification
// recommends for consumers.
func parse(s string) (*expr, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxExpressionLen {
		return nil, errSyntax
	}
	p := &parser{toks: tokenize(s)}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("%w: unexpected %q", errSyntax, p.toks[p.pos])
	}
	return e, nil
}

func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			toks = append(toks, string(r))
		case unicode.IsSpace(r):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

type parser struct {
	toks  []string
	pos   int
	depth int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func isKeyword(tok string) bool {
	return strings.EqualFold(tok, "AND") || strings.EqualFold(tok, "OR") || strings.EqualFold(tok, "WITH")
}

// or = and { "OR" and }
func (p *parser) or() (*expr, error) {
	return p.list("OR", p.and)
}

// and = term { "AND" term }
func (p *parser) and() (*expr, error) {
	return p.list("AND", p.term)
}

func (p *parser) list(op string, operand func() (*expr, error)) (*expr, error) {
	first, err := operand()
	if err != nil {
		return nil, err
	}
	args := []*expr{first}
	for strings.EqualFold(p.peek(), op) {
		p.pos++
		next, err := operand()
		if err != nil {
			return nil, err
		}
		args = append(args, next)
	}
	return group(op, args), nil
}

// term = "(" or ")" | license [ "WITH" exception ]
func (p *parser) term() (*expr, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return nil, fmt.Errorf("%w: unexpected end", errSyntax)
	case tok == "(":
		p.pos++
		if p.depth++; p.depth > maxDepth {
			return nil, fmt.Errorf("%w: nested too deeply", errSyntax)
		}
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("%w: missing )", errSyntax)
		}
		p.pos++
		p.depth--
		return e, nil
	case tok == ")" || isKeyword(tok):
		return nil, fmt.Errorf("%w: unexpected %q", errSyntax, tok)
	}
	p.pos++
	id, ok := CanonicalID(tok)
	if !ok {
		return nil, fmt.Errorf("%w: unknown license %q", errSyntax, tok)
	}
	e := &expr{id: id}
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		exc, ok := exceptionIDs[strings.ToLower(p.peek())]
		if !ok {
			return nil, fmt.Errorf("%w: unknown exception %q", errSyntax, p.peek())
		}
		p.pos++
		e.exception = exc
	}
	return e, nil
}

// Normalize returns s as a canonical SPDX expression: identifiers in the
// SPDX list's case, deprecated GNU identifiers in their current form,
// operators in upper case, and parentheses only where AND and OR mix. It
// returns "" for an empty value, for anything that is not a valid
// expression over the known identifiers and for input longer than
// MaxExpressionLen.
func Normalize(s string) string {
	e, err := parse(s)
	if err != nil {
		return ""
	}
	return e.String()
}

// Join combines expressions that all apply to one package, such as the
// several licenses deps.dev lists for a version, with AND. Values that do
// not normalise and repeats are left out; "" is returned when nothing is
// left or the result would exceed MaxExpressionLen.
func Join(values []string) string {
	var parts []*expr
	seen := make(map[string]bool)
	for _, v := range values {
		e, err := parse(v)
		if err != nil {
			continue
		}
		if k := e.String(); !seen[k] {
			seen[k] = true
			parts = append(parts, e)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	s := group("AND", parts).String()
	if len(s) > MaxExpressionLen {
		return ""
	}
	return s
}

// ParseIDs parses a comma-separated list of license identifiers, such as
// the value of --deny-license, into canonical identifiers (see
// CanonicalID), sorted and without repeats. Blank items are skipped. An
// item that is not a known identifier is an error naming it. A trailing
// "+" is accepted only on GNU identifiers, where it selects "-or-later".
func ParseIDs(list string) ([]string, error) {
	var ids []string
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, ok := CanonicalID(item)
		if !ok || strings.ContainsFunc(item, unicode.IsSpace) {
			return nil, fmt.Errorf("unknown SPDX license identifier %q", item)
		}
		if strings.HasSuffix(id, "+") {
			return nil, fmt.Errorf("license identifier %q: name the license without \"+\"", item)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// Evaluate reports whether expression cannot be satisfied without a denied
// license, and which denied licenses it then names. deny is asked about
// canonical identifiers; a WITH exception and a trailing "+" are not part
// of the identifier it sees. An AND is denied when any operand is; an OR
// only when every operand is, since the licensee may pick any one branch.
// An expression that does not parse is never denied: the caller treats it
// as unknown.
func Evaluate(expression string, deny func(id string) bool) (hits []string, denied bool) {
	e, err := parse(expression)
	if err != nil {
		return nil, false
	}
	found := make(map[string]bool)
	if !e.denied(deny, found) {
		return nil, false
	}
	return slices.Sorted(maps.Keys(found)), true
}

func (e *expr) denied(deny func(string) bool, hits map[string]bool) bool {
	switch e.op {
	case "":
		id := strings.TrimSuffix(e.id, "+")
		if deny(id) {
			hits[id] = true
			return true
		}
		return false
	case "AND":
		hit := false
		for _, a := range e.args {
			if a.denied(deny, hits) {
				hit = true
			}
		}
		return hit
	default: // OR: hits count only if every branch is denied
		branch := make(map[string]bool)
		for _, a := range e.args {
			if !a.denied(deny, branch) {
				return false
			}
		}
		for id := range branch {
			hits[id] = true
		}
		return true
	}
}
