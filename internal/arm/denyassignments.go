package arm

// Deny assignments — the one part of Azure's authorization model that can
// take access away.
//
// Two things make them different from role assignments, and both are
// implemented here rather than mimed:
//
//  1. They are READ-ONLY over ARM. No customer creates one: Blueprints,
//     managed applications and deployment stacks do, and the API exposes only
//     GET and list. So the ARM surface here refuses writes, and the seeding
//     path lives on the /_emulator control surface instead — the honest place
//     for something Azure has no public API for.
//  2. They WIN. A deny beats every role assignment that grants the same
//     action, which is the whole point of the feature, and is the behaviour
//     graded in the parity map. Denies() below is that evaluation: wildcard
//     matching, notActions carve-outs, excluded principals, the
//     all-principals GUID, and doNotApplyToChildScopes.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// AllPrincipals is the GUID Azure uses in a deny assignment's principal list
// to mean "everyone" — how a system-created deny locks a resource against
// the whole directory rather than a named identity.
const AllPrincipals = "00000000-0000-0000-0000-000000000000"

// DenyPrincipal is one entry of a deny assignment's principals or
// excludePrincipals list.
type DenyPrincipal struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
}

// DenyPermission is one denied permission set. dataActions are denied unless
// notDataActions carves them back out, mirroring how a role definition's
// permissions read — with the sign flipped.
type DenyPermission struct {
	Actions          []string `json:"actions,omitempty"`
	NotActions       []string `json:"notActions,omitempty"`
	DataActions      []string `json:"dataActions,omitempty"`
	NotDataActions   []string `json:"notDataActions,omitempty"`
	Condition        string   `json:"condition,omitempty"`
	ConditionVersion string   `json:"conditionVersion,omitempty"`
}

// DenyAssignment is a deny assignment with its JSON members decoded — the
// shape the evaluator and the family feed work with.
type DenyAssignment struct {
	Name                    string           `json:"name"`
	Scope                   string           `json:"scope"`
	DenyAssignmentName      string           `json:"denyAssignmentName"`
	Description             string           `json:"description,omitempty"`
	Permissions             []DenyPermission `json:"permissions"`
	Principals              []DenyPrincipal  `json:"principals"`
	ExcludePrincipals       []DenyPrincipal  `json:"excludePrincipals"`
	DoNotApplyToChildScopes bool             `json:"doNotApplyToChildScopes"`
	IsSystemProtected       bool             `json:"isSystemProtected"`
}

// decodeDeny turns a stored row into the decoded form.
func decodeDeny(d *store.DenyAssignment) (DenyAssignment, error) {
	out := DenyAssignment{
		Name: d.Name, Scope: d.ScopeDisplay, DenyAssignmentName: d.DisplayName,
		Description: d.Description, DoNotApplyToChildScopes: d.DoNotApplyToChildScopes,
		IsSystemProtected: d.IsSystemProtected,
		Permissions:       []DenyPermission{}, Principals: []DenyPrincipal{},
		ExcludePrincipals: []DenyPrincipal{},
	}
	if err := json.Unmarshal([]byte(d.PermissionsJSON), &out.Permissions); err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(d.PrincipalsJSON), &out.Principals); err != nil {
		return out, err
	}
	err := json.Unmarshal([]byte(d.ExcludePrincipalsJSON), &out.ExcludePrincipals)
	return out, err
}

// ---- evaluation ----

// actionMatches reports whether an action string matches an authorization
// pattern. Azure's `*` matches any run of characters, segment boundaries
// included: `Microsoft.KeyVault/*` covers a vault's data actions.
func actionMatches(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	if !strings.Contains(p, "*") {
		return p == a
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(a, parts[0]) {
		return false
	}
	a = a[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(a, mid)
		if i < 0 {
			return false
		}
		a = a[i+len(mid):]
	}
	return strings.HasSuffix(a, parts[len(parts)-1])
}

func anyMatch(patterns []string, action string) bool {
	for _, p := range patterns {
		if actionMatches(p, action) {
			return true
		}
	}
	return false
}

// DeniesAction reports whether this deny assignment denies action for a
// caller holding any of the given principal ids (their own object id plus
// the groups they are in — the same set the role-assignment path resolves).
// data selects the data-action lists over the control-plane ones.
func (d DenyAssignment) DeniesAction(principals []string, action string, data bool) bool {
	if !d.appliesToPrincipal(principals) {
		return false
	}
	for _, p := range d.Permissions {
		denied, except := p.Actions, p.NotActions
		if data {
			denied, except = p.DataActions, p.NotDataActions
		}
		// notActions carve out of what this permission denies: "deny
		// everything except reads" is a real and common shape.
		if anyMatch(denied, action) && !anyMatch(except, action) {
			return true
		}
	}
	return false
}

// appliesToPrincipal implements the principal side of the rule: listed (or
// covered by the all-principals GUID), and not excluded. An exclusion wins,
// which is what makes "deny everyone but the managed application's own
// identity" expressible.
func (d DenyAssignment) appliesToPrincipal(principals []string) bool {
	if containsPrincipal(d.ExcludePrincipals, principals) {
		return false
	}
	for _, p := range d.Principals {
		if p.ID == AllPrincipals {
			return true
		}
	}
	return containsPrincipal(d.Principals, principals)
}

func containsPrincipal(list []DenyPrincipal, principals []string) bool {
	for _, entry := range list {
		for _, id := range principals {
			if id != "" && strings.EqualFold(entry.ID, id) {
				return true
			}
		}
	}
	return false
}

// appliesAt reports whether the deny reaches a target scope. Deny
// assignments inherit downward like everything else in ARM, unless
// doNotApplyToChildScopes pins them to their own scope.
func (d DenyAssignment) appliesAt(target string) bool {
	if d.DoNotApplyToChildScopes {
		return CanonicalScope(d.Scope) == CanonicalScope(target)
	}
	return ScopeApplies(d.Scope, target)
}

// DenyAssignmentsAt returns every deny assignment reaching a scope, decoded.
func (s *Service) DenyAssignmentsAt(scope string) ([]DenyAssignment, error) {
	all, err := s.Store.ListDenyAssignments()
	if err != nil {
		return nil, err
	}
	out := []DenyAssignment{}
	for _, row := range all {
		d, err := decodeDeny(row)
		if err != nil {
			return nil, err
		}
		if d.appliesAt(scope) {
			out = append(out, d)
		}
	}
	return out, nil
}

// Denies answers the question a data plane actually asks: at this scope, for
// this caller, is this data action denied? Deny assignments take precedence
// over every role assignment, so a true here ends the decision.
func (s *Service) Denies(scope string, principals []string, action string) (bool, error) {
	ds, err := s.DenyAssignmentsAt(scope)
	if err != nil {
		return false, err
	}
	for _, d := range ds {
		if d.DeniesAction(principals, action, true) {
			return true, nil
		}
	}
	return false, nil
}

// ---- ARM surface (read-only) ----

func (s *Service) denyBody(d DenyAssignment, row *store.DenyAssignment) map[string]any {
	perms := make([]map[string]any, 0, len(d.Permissions))
	for _, p := range d.Permissions {
		perms = append(perms, map[string]any{
			"actions": orEmpty(p.Actions), "notActions": orEmpty(p.NotActions),
			"dataActions": orEmpty(p.DataActions), "notDataActions": orEmpty(p.NotDataActions),
		})
	}
	return map[string]any{
		"id": fmt.Sprintf("%s/providers/Microsoft.Authorization/denyAssignments/%s",
			strings.TrimSuffix(d.Scope, "/"), d.Name),
		"type": "Microsoft.Authorization/denyAssignments",
		"name": d.Name,
		"properties": map[string]any{
			"denyAssignmentName":      d.DenyAssignmentName,
			"description":             d.Description,
			"permissions":             perms,
			"scope":                   d.Scope,
			"doNotApplyToChildScopes": d.DoNotApplyToChildScopes,
			"principals":              principalBodies(d.Principals),
			"excludePrincipals":       principalBodies(d.ExcludePrincipals),
			"isSystemProtected":       d.IsSystemProtected,
			"createdOn":               rfc3339(row.CreatedAt),
			"updatedOn":               rfc3339(row.UpdatedAt),
		},
	}
}

func principalBodies(ps []DenyPrincipal) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		body := map[string]any{"id": p.ID, "type": p.Type}
		if p.DisplayName != "" {
			body["displayName"] = p.DisplayName
		}
		if p.Email != "" {
			body["email"] = p.Email
		}
		out = append(out, body)
	}
	return out
}

// denyAssignments serves GET on one deny assignment and GET on the
// collection at a scope. Every other method is refused: real ARM has no
// create or delete here, and pretending otherwise would teach a client
// something Azure will not honour.
func (s *Service) denyAssignments(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	if sub := SubscriptionOf(scope); sub != "" && !s.checkSubscription(w, sub) {
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed",
			fmt.Sprintf("The http method '%s' is not allowed on deny assignments: they are created by "+
				"Azure (Blueprints, managed applications, deployment stacks) and are read-only over ARM. "+
				"This emulator seeds them through POST /_emulator/denyassignments.", r.Method))
		return
	}
	if len(rest) >= 1 && rest[0] != "" {
		row, err := s.Store.GetDenyAssignment(rest[0])
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "DenyAssignmentNotFound",
				fmt.Sprintf("The deny assignment '%s' was not found.", rest[0]))
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		d, err := decodeDeny(row)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.denyBody(d, row))
		return
	}
	s.listDenyAssignments(w, r, scope)
}

// listDenyAssignments honours the filters ARM documents for this collection:
// the default is "at or above" (an inherited deny is visible on the child),
// `atScope()` narrows to exactly this scope, and `principalId eq` /
// `denyAssignmentName eq` narrow by principal and display name.
func (s *Service) listDenyAssignments(w http.ResponseWriter, r *http.Request, scope string) {
	rows, err := s.Store.ListDenyAssignments()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	filter := r.URL.Query().Get("$filter")
	atScope := strings.Contains(strings.ToLower(filter), "atscope()")
	principal := filterPrincipalID(filter)
	wantName := filterClause(filter, "denyassignmentname")

	items := []map[string]any{}
	for _, row := range rows {
		d, err := decodeDeny(row)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		if atScope {
			if CanonicalScope(d.Scope) != CanonicalScope(scope) {
				continue
			}
		} else if !d.appliesAt(scope) {
			continue
		}
		if principal != "" && !containsPrincipal(d.Principals, []string{principal}) {
			continue
		}
		if wantName != "" && !strings.EqualFold(d.DenyAssignmentName, wantName) {
			continue
		}
		items = append(items, s.denyBody(d, row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

// ---- /_emulator seeding ----

// ServeDenyControl is POST/DELETE /_emulator/denyassignments[/{name}]. It
// exists because Azure creates deny assignments through services this
// emulator does not model, so there is no real wire to copy — putting the
// seam on the control surface keeps the ARM surface honestly read-only.
func (s *Service) ServeDenyControl(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/_emulator/denyassignments")
	name = strings.Trim(name, "/")

	switch r.Method {
	case http.MethodDelete:
		if name == "" {
			writeErr(w, http.StatusBadRequest, "BadParameter", "the deny assignment name is required")
			return
		}
		err := s.Store.DeleteDenyAssignment(name)
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost:
		s.seedDenyAssignment(w, r, name)
	default:
		methodNotAllowed(w, r.Method)
	}
}

func (s *Service) seedDenyAssignment(w http.ResponseWriter, r *http.Request, name string) {
	var body DenyAssignment
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	if strings.TrimSpace(body.Scope) == "" {
		writeErr(w, http.StatusBadRequest, "BadParameter", "scope is required")
		return
	}
	if len(body.Principals) == 0 {
		writeErr(w, http.StatusBadRequest, "BadParameter",
			"principals is required; use the all-principals GUID "+AllPrincipals+" to deny everyone")
		return
	}
	if name == "" {
		name = body.Name
	}
	if name == "" {
		name = store.NewGUID()
	}
	perms, _ := json.Marshal(orEmptySlice(body.Permissions))
	principals, _ := json.Marshal(body.Principals)
	excludes, _ := json.Marshal(orEmptySlice(body.ExcludePrincipals))
	row := &store.DenyAssignment{
		Name: name, Scope: CanonicalScope(body.Scope),
		ScopeDisplay: strings.TrimSuffix(body.Scope, "/"),
		DisplayName:  body.DenyAssignmentName, Description: body.Description,
		PermissionsJSON: string(perms), PrincipalsJSON: string(principals),
		ExcludePrincipalsJSON:   string(excludes),
		DoNotApplyToChildScopes: body.DoNotApplyToChildScopes,
		// Azure's own deny assignments are system-protected; that is the
		// default here too, and it is what the read surface reports.
		IsSystemProtected: true,
	}
	if row.ScopeDisplay == "" {
		row.ScopeDisplay = "/"
	}
	if err := s.Store.PutDenyAssignment(row); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	// The response is built from the body just validated, not by re-reading
	// what we encoded a line ago: a decode that cannot fail should not carry
	// an error branch nothing can reach.
	body.Name, body.Scope = row.Name, row.ScopeDisplay
	body.IsSystemProtected = row.IsSystemProtected
	body.Permissions = orEmptySlice(body.Permissions)
	body.ExcludePrincipals = orEmptySlice(body.ExcludePrincipals)
	writeJSON(w, http.StatusCreated, s.denyBody(body, row))
}

// orEmptySlice keeps a nil slice out of the stored JSON, so a seeded deny
// assignment always reads back as [] rather than null.
func orEmptySlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
