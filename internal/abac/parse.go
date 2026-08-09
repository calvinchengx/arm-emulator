// Package abac implements Azure's attribute-based access control conditions:
// the `condition` string a role assignment carries, in the version 2.0
// language documented at
// learn.microsoft.com/azure/role-based-access-control/conditions-format.
//
// A condition NARROWS a role assignment. The role says what may be done; the
// condition says under which attributes it may be done — "this role, but only
// for secrets whose name starts with app-". Storing the string and handing it
// back unread, as this emulator did before, teaches a developer that their
// condition works when nothing has ever tested it. So the language is parsed
// here and evaluated in eval.go, and a condition ARM would reject is rejected
// at write time rather than persisted.
package abac

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is the only conditionVersion Azure accepts.
const Version = "2.0"

// Condition is a parsed condition, ready to evaluate.
type Condition struct {
	Source string
	root   node
}

// Error is a parse failure, carrying the offset so the message can point at
// the offending text the way a compiler would.
type Error struct {
	Pos int
	Msg string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (at position %d)", e.Msg, e.Pos)
}

// ---- tokens ----

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokNumber
	tokAttr
	tokPunct
)

type token struct {
	kind tokKind
	text string // ident/punct text, or the string/number literal's value
	src  string // attribute source: Resource, Request, Principal, Environment
	key  string // attribute key inside the brackets
	pos  int
}

var attrSources = map[string]string{
	"resource": "Resource", "request": "Request",
	"principal": "Principal", "environment": "Environment",
}

// lex turns the condition text into tokens. Attributes are lexed whole
// (`@Resource[Microsoft.KeyVault/vaults/secrets:name]`) because their keys
// carry `/`, `.` and `:`, which would otherwise each need punctuation rules
// that exist nowhere else in the language.
func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '@':
			start := i
			j := strings.IndexByte(s[i:], '[')
			if j < 0 {
				return nil, &Error{start, "attribute is missing its '[' key"}
			}
			source := strings.ToLower(strings.TrimSpace(s[i+1 : i+j]))
			canonical, ok := attrSources[source]
			if !ok {
				return nil, &Error{start, fmt.Sprintf(
					"unknown attribute source %q: expected @Resource, @Request, @Principal or @Environment", source)}
			}
			k := strings.IndexByte(s[i+j:], ']')
			if k < 0 {
				return nil, &Error{start, "attribute is missing its closing ']'"}
			}
			key := strings.TrimSpace(s[i+j+1 : i+j+k])
			if key == "" {
				return nil, &Error{start, "attribute key is empty"}
			}
			out = append(out, token{kind: tokAttr, src: canonical, key: key, pos: start})
			i += j + k + 1
		case c == '\'' || c == '"':
			start := i
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, &Error{start, "unterminated string literal"}
			}
			out = append(out, token{kind: tokString, text: s[i+1 : i+1+j], pos: start})
			i += j + 2
		case c >= '0' && c <= '9', c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			start := i
			i++
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
				i++
			}
			out = append(out, token{kind: tokNumber, text: s[start:i], pos: start})
		case isIdentChar(c):
			start := i
			for i < len(s) && isIdentChar(s[i]) {
				i++
			}
			out = append(out, token{kind: tokIdent, text: s[start:i], pos: start})
		case strings.IndexByte("()[]{},:!", c) >= 0:
			out = append(out, token{kind: tokPunct, text: string(c), pos: i})
			i++
		default:
			return nil, &Error{i, fmt.Sprintf("unexpected character %q", string(c))}
		}
	}
	return append(out, token{kind: tokEOF, pos: len(s)}), nil
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == '/' || c == '-'
}

// ---- AST ----

type node interface {
	eval(*Context) bool
}

type andNode struct{ left, right node }
type orNode struct{ left, right node }
type notNode struct{ inner node }

// actionNode is `ActionMatches{'…'}` — the guard that scopes a condition to
// the operations it is about, so every other operation passes untouched.
type actionNode struct {
	pattern string
	sub     bool // SubOperationMatches rather than ActionMatches
}

// existsNode is `Exists @Request[…]`.
type existsNode struct{ attr attrRef }

type attrRef struct{ source, key string }

// compareNode is `[ForAnyOfAnyValues:]@Resource[k] StringEquals 'v'`.
type compareNode struct {
	attr     attrRef
	quant    string // "", ForAnyOfAnyValues, ForAllOfAnyValues, ForAnyOfAllValues, ForAllOfAllValues
	operator string
	values   []literal
	set      bool
}

type literal struct {
	str   string
	num   float64
	flag  bool
	kind  byte // 's', 'n', 'b'
	rawOK bool
}

// ---- parser ----

type parser struct {
	toks []token
	i    int
}

// Parse reads a condition. An empty string is not a condition and is
// rejected: ARM stores no condition rather than an empty one.
func Parse(src string) (*Condition, error) {
	if strings.TrimSpace(src) == "" {
		return nil, &Error{0, "the condition is empty"}
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, &Error{p.peek().pos, fmt.Sprintf("unexpected %s after the end of the expression",
			describe(p.peek()))}
	}
	return &Condition{Source: src, root: root}, nil
}

func describe(t token) string {
	switch t.kind {
	case tokEOF:
		return "end of the condition"
	case tokAttr:
		return "attribute @" + t.src + "[" + t.key + "]"
	case tokString:
		return "string " + strconv.Quote(t.text)
	default:
		return strconv.Quote(t.text)
	}
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

// isKeyword reports whether the current token is the given keyword, matched
// case-insensitively as Azure's parser does.
func (p *parser) isKeyword(word string) bool {
	t := p.peek()
	return t.kind == tokIdent && strings.EqualFold(t.text, word)
}

func (p *parser) isPunct(ch string) bool {
	t := p.peek()
	return t.kind == tokPunct && t.text == ch
}

func (p *parser) expectPunct(ch string) error {
	if !p.isPunct(ch) {
		return &Error{p.peek().pos, fmt.Sprintf("expected %q, found %s", ch, describe(p.peek()))}
	}
	p.next()
	return nil
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("OR") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("AND") {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	switch {
	case p.isPunct("!"):
		p.next()
		if err := p.expectPunct("("); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return &notNode{inner}, nil
	case p.isPunct("("):
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return inner, nil
	}
	return p.parsePredicate()
}

var quantifiers = map[string]string{
	"foranyofanyvalues": "ForAnyOfAnyValues", "forallofanyvalues": "ForAllOfAnyValues",
	"foranyofallvalues": "ForAnyOfAllValues", "forallofallvalues": "ForAllOfAllValues",
}

func (p *parser) parsePredicate() (node, error) {
	t := p.peek()
	if t.kind == tokIdent {
		switch {
		case strings.EqualFold(t.text, "ActionMatches"), strings.EqualFold(t.text, "SubOperationMatches"):
			return p.parseMatches()
		case strings.EqualFold(t.text, "Exists"):
			p.next()
			a := p.peek()
			if a.kind != tokAttr {
				return nil, &Error{a.pos, fmt.Sprintf("Exists needs an attribute, found %s", describe(a))}
			}
			p.next()
			return &existsNode{attrRef{a.src, a.key}}, nil
		}
		if _, ok := quantifiers[strings.ToLower(t.text)]; ok {
			return nil, &Error{t.pos, fmt.Sprintf(
				"%s: belongs after the attribute, as in @Resource[key] %s:StringEquals {'a','b'}",
				t.text, t.text)}
		}
		return nil, &Error{t.pos, fmt.Sprintf("unknown keyword %q", t.text)}
	}
	return p.parseComparison()
}

func (p *parser) parseMatches() (node, error) {
	kw := p.next()
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	v := p.peek()
	if v.kind != tokString {
		return nil, &Error{v.pos, fmt.Sprintf("%s needs a quoted action, found %s", kw.text, describe(v))}
	}
	p.next()
	if err := p.expectPunct("}"); err != nil {
		return nil, err
	}
	return &actionNode{pattern: v.text, sub: strings.EqualFold(kw.text, "SubOperationMatches")}, nil
}

// operators is the full documented set. Membership is what makes an unknown
// operator a parse error rather than a silently false comparison.
var operators = map[string]bool{}

func init() {
	for _, op := range []string{
		"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
		"StringStartsWith", "StringNotStartsWith", "StringLike", "StringNotLike",
		"NumericEquals", "NumericNotEquals", "NumericGreaterThan", "NumericGreaterThanOrEquals",
		"NumericLessThan", "NumericLessThanOrEquals",
		"DateTimeEquals", "DateTimeNotEquals", "DateTimeGreaterThan", "DateTimeGreaterThanOrEquals",
		"DateTimeLessThan", "DateTimeLessThanOrEquals",
		"BoolEquals", "BoolNotEquals", "GuidEquals", "GuidNotEquals",
	} {
		operators[strings.ToLower(op)] = true
	}
}

// parseComparison reads `@Source[key] [Quantifier:]Operator value`. The
// quantifier fuses onto the operator, which is where Azure writes it:
// `@Resource[…] ForAnyOfAnyValues:StringEquals {'a','b'}`.
func (p *parser) parseComparison() (node, error) {
	a := p.peek()
	if a.kind != tokAttr {
		return nil, &Error{a.pos, fmt.Sprintf("expected an attribute, found %s", describe(a))}
	}
	p.next()
	quant := ""
	opTok := p.peek()
	if opTok.kind == tokIdent {
		if q, ok := quantifiers[strings.ToLower(opTok.text)]; ok {
			quant = q
			p.next()
			if err := p.expectPunct(":"); err != nil {
				return nil, err
			}
			opTok = p.peek()
		}
	}
	if opTok.kind != tokIdent || !operators[strings.ToLower(opTok.text)] {
		return nil, &Error{opTok.pos, fmt.Sprintf("expected a comparison operator, found %s", describe(opTok))}
	}
	p.next()
	cmp := &compareNode{attr: attrRef{a.src, a.key}, quant: quant, operator: strings.ToLower(opTok.text)}

	if p.isPunct("{") {
		p.next()
		cmp.set = true
		for {
			lit, err := p.parseLiteral()
			if err != nil {
				return nil, err
			}
			cmp.values = append(cmp.values, lit)
			if p.isPunct(",") {
				p.next()
				continue
			}
			break
		}
		if err := p.expectPunct("}"); err != nil {
			return nil, err
		}
	} else {
		lit, err := p.parseLiteral()
		if err != nil {
			return nil, err
		}
		cmp.values = []literal{lit}
	}
	// A quantifier is about comparing MANY values; without a set it says
	// nothing, and Azure's own examples always pair the two.
	if quant != "" && !cmp.set {
		return nil, &Error{opTok.pos, quant + " needs a value set in braces, for example {'a','b'}"}
	}
	return cmp, nil
}

func (p *parser) parseLiteral() (literal, error) {
	t := p.peek()
	switch {
	case t.kind == tokString:
		p.next()
		return literal{str: t.text, kind: 's', rawOK: true}, nil
	case t.kind == tokNumber:
		p.next()
		n, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return literal{}, &Error{t.pos, fmt.Sprintf("%q is not a number", t.text)}
		}
		return literal{num: n, kind: 'n', rawOK: true}, nil
	case t.kind == tokIdent && (strings.EqualFold(t.text, "true") || strings.EqualFold(t.text, "false")):
		p.next()
		return literal{flag: strings.EqualFold(t.text, "true"), kind: 'b', rawOK: true}, nil
	}
	return literal{}, &Error{t.pos, fmt.Sprintf("expected a value, found %s", describe(t))}
}
