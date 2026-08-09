package abac

// The condition language: what parses, what does not, and what each parsed
// condition decides. The cases are written against Azure's documented
// semantics, including the ones that surprise people — a missing attribute
// fails a NEGATIVE comparison too, which is why real conditions carry an
// ActionMatches guard.

import (
	"strings"
	"testing"
)

// The shape Azure's own documentation uses: unrelated actions pass through
// the guard untouched, and only the named action has to satisfy the test.
const guarded = `(
 (
  !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})
 )
 OR
 (
  @Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith 'app-'
 )
)`

const readAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
const writeAction = "Microsoft.KeyVault/vaults/secrets/setSecret/action"

func mustParse(t *testing.T, src string) *Condition {
	t.Helper()
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q) = %v", src, err)
	}
	return c
}

func TestGuardedConditionNarrowsOnlyTheNamedAction(t *testing.T) {
	c := mustParse(t, guarded)

	secret := func(name string) *Context {
		return NewContext(readAction, map[string]any{
			"@Resource[Microsoft.KeyVault/vaults/secrets:name]": name,
		})
	}
	if !c.Evaluate(secret("app-db-password")) {
		t.Fatal("a matching secret name should satisfy the condition")
	}
	if c.Evaluate(secret("prod-db-password")) {
		t.Fatal("a non-matching secret name should not")
	}
	// The guard: an action the condition is not about passes regardless,
	// even with no attributes at all.
	if !c.Evaluate(NewContext(writeAction, nil)) {
		t.Fatal("an unrelated action should pass the guard")
	}
	// And the named action with no attribute supplied is refused — the
	// condition could not be satisfied, so it was not.
	if c.Evaluate(NewContext(readAction, nil)) {
		t.Fatal("the named action with no attributes should fail closed")
	}
	// The condition says which attributes it needs.
	if got := c.Attributes(); len(got) != 1 ||
		got[0] != "@Resource[Microsoft.KeyVault/vaults/secrets:name]" {
		t.Fatalf("Attributes() = %v", got)
	}
}

func TestNegativeComparisonFailsOnMissingAttribute(t *testing.T) {
	// The rule people get wrong: StringNotEquals against an attribute that
	// was never supplied is FALSE, not true.
	c := mustParse(t, `@Resource[Microsoft.KeyVault/vaults/secrets:name] StringNotEquals 'nope'`)
	if c.Evaluate(NewContext(readAction, nil)) {
		t.Fatal("a negative comparison must fail when the attribute is absent")
	}
	if !c.Evaluate(NewContext(readAction, map[string]any{
		"Resource[Microsoft.KeyVault/vaults/secrets:name]": "yes",
	})) {
		t.Fatal("and pass when it is present and differs")
	}
}

func TestOperators(t *testing.T) {
	const key = "@Request[x]"
	cases := []struct {
		cond string
		attr any
		want bool
	}{
		{`@Request[x] StringEquals 'a'`, "a", true},
		{`@Request[x] StringEquals 'a'`, "A", false},
		{`@Request[x] StringEqualsIgnoreCase 'a'`, "A", true},
		{`@Request[x] StringNotEqualsIgnoreCase 'a'`, "A", false},
		{`@Request[x] StringNotEquals 'a'`, "b", true},
		{`@Request[x] StringStartsWith 'ap'`, "apple", true},
		{`@Request[x] StringNotStartsWith 'ap'`, "apple", false},
		{`@Request[x] StringLike 'a*e'`, "apple", true},
		{`@Request[x] StringLike 'a?ple'`, "apple", true},
		{`@Request[x] StringLike 'a?le'`, "apple", false},
		{`@Request[x] StringNotLike 'a*e'`, "apple", false},
		{`@Request[x] NumericEquals 3`, 3, true},
		{`@Request[x] NumericNotEquals 3`, 4, true},
		{`@Request[x] NumericGreaterThan 3`, 3.5, true},
		{`@Request[x] NumericGreaterThanOrEquals 3`, 3, true},
		{`@Request[x] NumericLessThan 3`, 2, true},
		{`@Request[x] NumericLessThanOrEquals 3`, 4, false},
		{`@Request[x] NumericGreaterThan -3`, -2, true},
		// A number written as a string is still a number to compare.
		{`@Request[x] NumericEquals 3`, "3", true},
		{`@Request[x] NumericEquals 3`, "three", false},
		{`@Request[x] BoolEquals true`, true, true},
		{`@Request[x] BoolNotEquals true`, true, false},
		{`@Request[x] BoolEquals false`, "false", true},
		{`@Request[x] GuidEquals 'A1B2C3D4-0000-4000-8000-000000000000'`,
			"a1b2c3d4-0000-4000-8000-000000000000", true},
		{`@Request[x] GuidNotEquals 'a1b2c3d4-0000-4000-8000-000000000000'`,
			"a1b2c3d4-0000-4000-8000-000000000000", false},
		{`@Request[x] DateTimeGreaterThan '2024-01-01T00:00:00Z'`, "2024-06-01T00:00:00Z", true},
		{`@Request[x] DateTimeLessThan '2024-01-01T00:00:00Z'`, "2024-06-01T00:00:00Z", false},
		{`@Request[x] DateTimeEquals '2024-01-01T00:00:00Z'`, "2024-01-01T00:00:00Z", true},
		{`@Request[x] DateTimeNotEquals '2024-01-01T00:00:00Z'`, "2024-01-01T00:00:00Z", false},
		{`@Request[x] DateTimeGreaterThanOrEquals '2024-01-01'`, "2024-01-01T00:00:00Z", true},
		{`@Request[x] DateTimeLessThanOrEquals '2024-01-01T00:00:00Z'`, "not-a-date", false},
		// A type mismatch is a failed comparison, not an error.
		{`@Request[x] StringEquals 'a'`, 3, false},
		{`@Request[x] NumericEquals 3`, true, false},
		{`@Request[x] BoolEquals true`, "maybe", false},
		{`@Request[x] GuidEquals 'a'`, 3, false},
		{`@Request[x] BoolEquals true`, 3, false},
		// The numeric shapes a Go caller may hand over, not only JSON's
		// float64: an emulator is driven from tests as well as over the wire.
		{`@Request[x] NumericEquals 3`, float32(3), true},
		{`@Request[x] NumericEquals 3`, int64(3), true},
		{`@Request[x] NumericEquals 3`, float64(3), true},
	}
	for _, tc := range cases {
		t.Run(tc.cond+"/"+strings.TrimSpace(sprint(tc.attr)), func(t *testing.T) {
			c := mustParse(t, tc.cond)
			got := c.Evaluate(NewContext(readAction, map[string]any{key: tc.attr}))
			if got != tc.want {
				t.Fatalf("= %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTimeValuedAttribute(t *testing.T) {
	// An attribute may arrive as a time.Time rather than a string when the
	// caller is Go code rather than JSON.
	when, ok := parseTime("2024-06-01T00:00:00Z")
	if !ok {
		t.Fatal("parseTime rejected its own format")
	}
	c := mustParse(t, `@Request[x] DateTimeGreaterThan '2024-01-01T00:00:00Z'`)
	if !c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": when})) {
		t.Fatal("a time.Time attribute should compare")
	}
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": 3})) {
		t.Fatal("a numeric attribute is not a datetime")
	}
}

func sprint(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return "value"
	}
}

func TestMismatchedLiteralTypeFailsComparison(t *testing.T) {
	// A string operator given a numeric literal cannot match anything; the
	// parser accepts it (the grammar allows any literal), so the evaluator
	// must not treat it as a wildcard pass.
	c := mustParse(t, `@Request[x] StringEquals 3`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": "3"})) {
		t.Fatal("a string comparison against a numeric literal should fail")
	}
	c = mustParse(t, `@Request[x] NumericEquals 'three'`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": 3})) {
		t.Fatal("a numeric comparison against a string literal should fail")
	}
	c = mustParse(t, `@Request[x] BoolEquals 'true'`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": true})) {
		t.Fatal("a bool comparison against a string literal should fail")
	}
	c = mustParse(t, `@Request[x] DateTimeEquals 3`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": "2024-01-01"})) {
		t.Fatal("a datetime comparison against a numeric literal should fail")
	}
	c = mustParse(t, `@Request[x] GuidEquals 3`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[x]": "3"})) {
		t.Fatal("a guid comparison against a numeric literal should fail")
	}
}

func TestQuantifiers(t *testing.T) {
	tags := func(v ...string) map[string]any {
		return map[string]any{"@Request[tags]": v}
	}
	cases := []struct {
		cond string
		attr map[string]any
		want bool
	}{
		{`@Request[tags] ForAnyOfAnyValues:StringEquals {'red','blue'}`, tags("green", "blue"), true},
		{`@Request[tags] ForAnyOfAnyValues:StringEquals {'red','blue'}`, tags("green"), false},
		{`@Request[tags] ForAllOfAnyValues:StringEquals {'red','blue'}`, tags("red", "blue"), true},
		{`@Request[tags] ForAllOfAnyValues:StringEquals {'red','blue'}`, tags("red", "green"), false},
		{`@Request[tags] ForAnyOfAllValues:StringNotEquals {'red','blue'}`, tags("green", "red"), true},
		{`@Request[tags] ForAnyOfAllValues:StringNotEquals {'red','blue'}`, tags("red", "blue"), false},
		{`@Request[tags] ForAllOfAllValues:StringNotEquals {'red','blue'}`, tags("green", "cyan"), true},
		{`@Request[tags] ForAllOfAllValues:StringNotEquals {'red','blue'}`, tags("green", "red"), false},
		// A missing attribute fails every quantified form too.
		{`@Request[tags] ForAllOfAllValues:StringNotEquals {'red'}`, nil, false},
		// An attribute given as []any, which is what JSON decoding produces.
		{`@Request[tags] ForAnyOfAnyValues:StringEquals {'red'}`,
			map[string]any{"@Request[tags]": []any{"red"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.cond, func(t *testing.T) {
			c := mustParse(t, tc.cond)
			if got := c.Evaluate(NewContext(readAction, tc.attr)); got != tc.want {
				t.Fatalf("= %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMultiValuedAttributeNeedsAQuantifier(t *testing.T) {
	// Without a quantifier the author has not said whether they meant "any"
	// or "all", so the emulator refuses to guess rather than picking one.
	c := mustParse(t, `@Request[tags] StringEquals 'red'`)
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[tags]": []string{"red", "blue"}})) {
		t.Fatal("a multi-valued attribute matched an unquantified comparison")
	}
	if !c.Evaluate(NewContext(readAction, map[string]any{"@Request[tags]": []string{"red"}})) {
		t.Fatal("a single-valued list should still compare")
	}
	if c.Evaluate(NewContext(readAction, map[string]any{"@Request[tags]": []any{}})) {
		t.Fatal("an empty attribute list is not a match")
	}
}

func TestBooleanCombinators(t *testing.T) {
	ctx := NewContext(readAction, map[string]any{"@Request[a]": "1", "@Request[b]": "2"})
	cases := []struct {
		cond string
		want bool
	}{
		{`@Request[a] StringEquals '1' AND @Request[b] StringEquals '2'`, true},
		{`@Request[a] StringEquals '1' AND @Request[b] StringEquals '9'`, false},
		{`@Request[a] StringEquals '9' OR @Request[b] StringEquals '2'`, true},
		{`@Request[a] StringEquals '9' OR @Request[b] StringEquals '9'`, false},
		{`!(@Request[a] StringEquals '9')`, true},
		{`(@Request[a] StringEquals '1' OR @Request[b] StringEquals '9') AND @Request[b] StringEquals '2'`, true},
		// Case-insensitive keywords, as Azure's parser accepts.
		{`@Request[a] StringEquals '1' and @Request[b] StringEquals '2'`, true},
		{`@Request[a] StringEquals '9' or @Request[b] StringEquals '2'`, true},
		// Attribute keys match case-insensitively, and spacing is irrelevant.
		{`@Request[ A ] StringEquals '1'`, true},
		{`@REQUEST[a] StringEquals '1'`, true},
		// Exists.
		{`Exists @Request[a]`, true},
		{`Exists @Request[zzz]`, false},
		{`!(Exists @Request[zzz])`, true},
		// SubOperationMatches has its own subject.
		{`SubOperationMatches{'Blob.List'}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.cond, func(t *testing.T) {
			if got := mustParse(t, tc.cond).Evaluate(ctx); got != tc.want {
				t.Fatalf("= %v, want %v", got, tc.want)
			}
		})
	}
	sub := NewContext(readAction, nil)
	sub.SubOperation = "Blob.List"
	if !mustParse(t, `SubOperationMatches{'Blob.List'}`).Evaluate(sub) {
		t.Fatal("SubOperationMatches should read the sub-operation")
	}
	// A nil context is a request with nothing known about it.
	if mustParse(t, `Exists @Request[a]`).Evaluate(nil) {
		t.Fatal("a nil context should know no attributes")
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		src, wants string
	}{
		{``, "empty"},
		{`   `, "empty"},
		{`@Resource StringEquals 'a'`, "missing its '['"},
		{`@Nonsense[x] StringEquals 'a'`, "unknown attribute source"},
		{`@Resource[x StringEquals 'a'`, "closing ']'"},
		{`@Resource[] StringEquals 'a'`, "key is empty"},
		{`@Request[x] StringEquals 'unterminated`, "unterminated string"},
		{`@Request[x] Frobnicates 'a'`, "expected a comparison operator"},
		{`@Request[x] StringEquals`, "expected a value"},
		{`StringEquals 'a'`, "unknown keyword"},
		{`'a' StringEquals 'b'`, "expected an attribute"},
		{`(@Request[x] StringEquals 'a'`, `expected ")"`},
		{`!@Request[x] StringEquals 'a'`, `expected "("`},
		{`@Request[x] StringEquals 'a' @Request[y] StringEquals 'b'`, "after the end"},
		{`ActionMatches 'a'`, `expected "{"`},
		{`ActionMatches{a}`, "needs a quoted action"},
		{`ActionMatches{'a'`, `expected "}"`},
		{`Exists 'a'`, "Exists needs an attribute"},
		{`@Request[x] ForAnyOfAnyValues:StringEquals 'a'`, "needs a value set"},
		{`@Request[x] ForAnyOfAnyValues 'a'`, `expected ":"`},
		{`@Request[x] ForAnyOfAnyValues:Frobnicates {'a'}`, "expected a comparison operator"},
		{`ForAnyOfAnyValues:StringEquals @Request[x] {'a'}`, "belongs after the attribute"},
		{`@Request[x] StringEquals {'a',}`, "expected a value"},
		{`@Request[x] StringEquals 'a' ~ 'b'`, "unexpected character"},
		{`@Request[x] NumericEquals 1.2.3`, "is not a number"},
		// An error in the RIGHT operand of AND/OR, and inside every bracket
		// form, has to travel out rather than being swallowed.
		{`@Request[x] StringEquals 'a' AND bogus`, "unknown keyword"},
		{`@Request[x] StringEquals 'a' OR bogus`, "unknown keyword"},
		{`(bogus)`, "unknown keyword"},
		{`!(bogus)`, "unknown keyword"},
		{`!(@Request[x] StringEquals 'a'`, `expected ")"`},
		{`@Request[x] ForAnyOfAnyValues:StringEquals {'a'`, `expected "}"`},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			_, err := Parse(tc.src)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded", tc.src)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("Parse(%q) = %q, want it to mention %q", tc.src, err, tc.wants)
			}
			// Every message points at where the trouble is.
			if !strings.Contains(err.Error(), "at position") {
				t.Fatalf("error without a position: %q", err)
			}
		})
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
		{"a*", "abc", true},
		{"*c", "abc", true},
		{"a*c", "abc", true},
		{"a*c", "abd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"A*C", "abc", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxcyyb", false},
		// The pathological backtracking shape, which must still terminate.
		{"a*a*a*a*b", strings.Repeat("a", 40), false},
		{"*/action", "Microsoft.KeyVault/vaults/secrets/getSecret/action", true},
	}
	for _, tc := range cases {
		if got := Glob(tc.pattern, tc.s); got != tc.want {
			t.Fatalf("Glob(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestAttributesWalksEveryBranch(t *testing.T) {
	c := mustParse(t, `(Exists @Request[a] AND @Resource[b] StringEquals 'x') OR
		!(@Principal[c] StringEquals 'y') OR ActionMatches{'*'} OR @Request[a] StringEquals 'z'`)
	got := c.Attributes()
	want := []string{"@Request[a]", "@Resource[b]", "@Principal[c]"}
	if len(got) != len(want) {
		t.Fatalf("Attributes() = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Attributes() = %v, want %v (stable order, no duplicates)", got, want)
		}
	}
}
