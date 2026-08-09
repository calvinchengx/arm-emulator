package abac

// Evaluation. The rules here are Azure's, and the two that matter most are
// the easy ones to get wrong:
//
//   - An attribute that is not supplied makes its comparison FALSE, including
//     a negative comparison. `StringNotEquals` against a missing attribute
//     does not pass. That is why real conditions are written as
//     `!(ActionMatches{…}) OR (…)`: the guard lets every unrelated operation
//     through, and only the named one has to satisfy the attribute test.
//   - A condition narrows a grant; it never widens one. Evaluate returns
//     whether the assignment still applies, and the caller has already
//     decided the role grants the action.

import (
	"strconv"
	"strings"
	"time"
)

// Context is what a request looks like to a condition: the action being
// attempted and the attributes known about it. Keys are written as they are
// in the condition — `Resource[Microsoft.KeyVault/vaults/secrets:name]` — and
// matched case-insensitively.
type Context struct {
	Action       string
	SubOperation string
	Attributes   map[string]any
}

// NewContext builds a context, canonicalizing attribute keys so a caller may
// write them with or without the leading `@`.
func NewContext(action string, attrs map[string]any) *Context {
	c := &Context{Action: action, Attributes: map[string]any{}}
	for k, v := range attrs {
		c.Attributes[attrKey(strings.TrimPrefix(k, "@"))] = v
	}
	return c
}

func attrKey(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

// Evaluate reports whether the condition allows the request.
func (c *Condition) Evaluate(ctx *Context) bool {
	if ctx == nil {
		ctx = &Context{}
	}
	return c.root.eval(ctx)
}

// Attributes lists the attribute references the condition reads, so a data
// plane can be told what it must supply. Order is stable.
func (c *Condition) Attributes() []string {
	seen := map[string]bool{}
	var out []string
	var walk func(node)
	add := func(a attrRef) {
		s := "@" + a.source + "[" + a.key + "]"
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	walk = func(n node) {
		switch v := n.(type) {
		case *andNode:
			walk(v.left)
			walk(v.right)
		case *orNode:
			walk(v.left)
			walk(v.right)
		case *notNode:
			walk(v.inner)
		case *existsNode:
			add(v.attr)
		case *compareNode:
			add(v.attr)
		}
	}
	walk(c.root)
	return out
}

func (n *andNode) eval(c *Context) bool { return n.left.eval(c) && n.right.eval(c) }
func (n *orNode) eval(c *Context) bool  { return n.left.eval(c) || n.right.eval(c) }
func (n *notNode) eval(c *Context) bool { return !n.inner.eval(c) }

func (n *actionNode) eval(c *Context) bool {
	subject := c.Action
	if n.sub {
		subject = c.SubOperation
	}
	return Glob(n.pattern, subject)
}

func (n *existsNode) eval(c *Context) bool {
	vals, ok := c.lookup(n.attr)
	return ok && len(vals) > 0
}

func (c *Context) lookup(a attrRef) ([]any, bool) {
	v, ok := c.Attributes[attrKey(a.source+"["+a.key+"]")]
	if !ok {
		return nil, false
	}
	switch list := v.(type) {
	case []any:
		return list, true
	case []string:
		out := make([]any, 0, len(list))
		for _, s := range list {
			out = append(out, s)
		}
		return out, true
	default:
		return []any{v}, true
	}
}

func (n *compareNode) eval(c *Context) bool {
	attrVals, ok := c.lookup(n.attr)
	if !ok || len(attrVals) == 0 {
		// A missing attribute fails the comparison, negative operators
		// included: the condition could not be satisfied, so it was not.
		return false
	}
	match := func(a any, lit literal) bool { return compare(n.operator, a, lit) }

	switch n.quant {
	case "":
		// Without a quantifier the attribute must be single-valued; a
		// multi-valued one needs a ForAnyOf…/ForAllOf… form to say what the
		// author meant, so guessing here would invent an answer.
		if len(attrVals) != 1 {
			return false
		}
		return match(attrVals[0], n.values[0])
	case "ForAnyOfAnyValues":
		return anyAttr(attrVals, func(a any) bool { return anyLit(n.values, func(l literal) bool { return match(a, l) }) })
	case "ForAllOfAnyValues":
		return allAttr(attrVals, func(a any) bool { return anyLit(n.values, func(l literal) bool { return match(a, l) }) })
	case "ForAnyOfAllValues":
		return anyAttr(attrVals, func(a any) bool { return allLit(n.values, func(l literal) bool { return match(a, l) }) })
	default: // ForAllOfAllValues
		return allAttr(attrVals, func(a any) bool { return allLit(n.values, func(l literal) bool { return match(a, l) }) })
	}
}

func anyAttr(vals []any, f func(any) bool) bool {
	for _, v := range vals {
		if f(v) {
			return true
		}
	}
	return false
}

func allAttr(vals []any, f func(any) bool) bool {
	for _, v := range vals {
		if !f(v) {
			return false
		}
	}
	return true
}

func anyLit(lits []literal, f func(literal) bool) bool {
	for _, l := range lits {
		if f(l) {
			return true
		}
	}
	return false
}

func allLit(lits []literal, f func(literal) bool) bool {
	for _, l := range lits {
		if !f(l) {
			return false
		}
	}
	return true
}

// compare applies one operator to one attribute value and one literal. A
// value of the wrong type is a false comparison rather than an error: the
// request simply does not satisfy the condition.
func compare(op string, attr any, lit literal) bool {
	switch {
	case strings.HasPrefix(op, "string"):
		a, ok := asString(attr)
		if !ok || lit.kind != 's' {
			return false
		}
		return compareString(op, a, lit.str)
	case strings.HasPrefix(op, "numeric"):
		a, ok := asNumber(attr)
		if !ok || lit.kind != 'n' {
			return false
		}
		return compareNumber(op, a, lit.num)
	case strings.HasPrefix(op, "datetime"):
		a, ok := asTime(attr)
		b, ok2 := parseTime(lit.str)
		if !ok || !ok2 || lit.kind != 's' {
			return false
		}
		return compareNumber(strings.Replace(op, "datetime", "numeric", 1),
			float64(a.UnixNano()), float64(b.UnixNano()))
	case strings.HasPrefix(op, "bool"):
		a, ok := asBool(attr)
		if !ok || lit.kind != 'b' {
			return false
		}
		if op == "boolequals" {
			return a == lit.flag
		}
		return a != lit.flag
	default: // guidequals / guidnotequals — GUIDs compare case-insensitively
		a, ok := asString(attr)
		if !ok || lit.kind != 's' {
			return false
		}
		eq := strings.EqualFold(a, lit.str)
		if op == "guidequals" {
			return eq
		}
		return !eq
	}
}

func compareString(op, a, b string) bool {
	switch op {
	case "stringequals":
		return a == b
	case "stringnotequals":
		return a != b
	case "stringequalsignorecase":
		return strings.EqualFold(a, b)
	case "stringnotequalsignorecase":
		return !strings.EqualFold(a, b)
	case "stringstartswith":
		return strings.HasPrefix(a, b)
	case "stringnotstartswith":
		return !strings.HasPrefix(a, b)
	case "stringlike":
		return Glob(b, a)
	default: // stringnotlike
		return !Glob(b, a)
	}
}

func compareNumber(op string, a, b float64) bool {
	switch op {
	case "numericequals":
		return a == b
	case "numericnotequals":
		return a != b
	case "numericgreaterthan":
		return a > b
	case "numericgreaterthanorequals":
		return a >= b
	case "numericlessthan":
		return a < b
	default: // numericlessthanorequals
		return a <= b
	}
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		p, err := strconv.ParseBool(b)
		return p, err == nil
	}
	return false, false
}

func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

func asTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		return parseTime(t)
	}
	return time.Time{}, false
}

// parseTime accepts the shapes Azure writes in a condition: RFC 3339, with or
// without fractional seconds, and the trailing-Z form its own examples use.
func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.9Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Glob matches Azure's wildcard patterns: `*` spans any run of characters
// (segment boundaries included) and `?` matches exactly one. Matching is
// case-insensitive, as action names and resource names are in ARM.
func Glob(pattern, s string) bool {
	return globMatch([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(s)))
}

// globMatch is the classic two-pointer wildcard walk: linear, no recursion,
// and no backtracking blowup on a pattern like `a*a*a*`.
func globMatch(p, s []rune) bool {
	var pi, si, star, mark int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
