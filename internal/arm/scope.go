package arm

// ARM scope grammar and inheritance. A scope is a resource ID:
//
//	/                                                        (tenant root)
//	/subscriptions/{sub}
//	/subscriptions/{sub}/resourceGroups/{rg}
//	/subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}[/{childType}/{childName}]
//
// Assignments inherit downward: a grant at a subscription applies to every
// group and resource beneath it. Matching is case-insensitive, as ARM treats
// resource IDs.

import "strings"

// CanonicalScope lowercases and trims a scope for comparison. The caller's
// original spelling is preserved separately and echoed in responses.
func CanonicalScope(scope string) string {
	s := strings.ToLower(strings.TrimSuffix(scope, "/"))
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		return "/" + s
	}
	return s
}

// ScopeApplies reports whether an assignment made at assignment applies to
// target — the same scope, or any scope beneath it. Both are canonicalized
// here, so callers may pass raw scopes.
func ScopeApplies(assignment, target string) bool {
	a, t := CanonicalScope(assignment), CanonicalScope(target)
	if a == "/" || a == t {
		return true
	}
	// Prefix match on a segment boundary: /subscriptions/s must not match
	// /subscriptions/s2, but must match /subscriptions/s/resourcegroups/g.
	return strings.HasPrefix(t, a+"/")
}

// ScopeChain returns target and every ancestor scope up to the tenant root,
// nearest first — the order ARM evaluates and the order a feed consumer can
// reason about.
func ScopeChain(target string) []string {
	t := CanonicalScope(target)
	if t == "/" {
		return []string{"/"}
	}
	out := []string{t}
	for {
		i := strings.LastIndex(t, "/")
		if i <= 0 {
			break
		}
		t = t[:i]
		out = append(out, t)
	}
	return append(out, "/")
}

// SubscriptionOf returns the subscription id in a scope, or "".
func SubscriptionOf(scope string) string {
	parts := strings.Split(strings.Trim(scope, "/"), "/")
	for i, p := range parts {
		if strings.EqualFold(p, "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ResourceGroupOf returns the resource-group name in a scope, or "".
func ResourceGroupOf(scope string) string {
	parts := strings.Split(strings.Trim(scope, "/"), "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourcegroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
