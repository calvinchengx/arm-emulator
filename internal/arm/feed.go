package arm

// The family feed: how a sibling data plane learns which principals hold
// which data actions at its scope.
//
// Azure's own ARM→data-plane propagation is internal, not public wire, so
// this endpoint's shape is ours to choose — it is deliberately the ONLY
// non-ARM surface here, and it is deliberately thin: it reports the
// assignments and the roles' dataActions verbatim, leaving each data plane
// to map dataActions onto its own operation vocabulary. That mirrors the
// real division of authority (ARM owns roles and assignments; the data plane
// interprets its own actions) and keeps the emulator honest about which part
// of the wire is real.

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/abac"
)

// EffectiveAssignment is one assignment applying at the requested scope.
type EffectiveAssignment struct {
	PrincipalID      string   `json:"principalId"`
	PrincipalType    string   `json:"principalType"`
	RoleName         string   `json:"roleName"`
	RoleDefinitionID string   `json:"roleDefinitionId"`
	Scope            string   `json:"scope"`
	DataActions      []string `json:"dataActions"`
	NotDataActions   []string `json:"notDataActions"`
	Condition        string   `json:"condition,omitempty"`
	ConditionVersion string   `json:"conditionVersion,omitempty"`
	// ConditionAttributes names what the condition reads, so a data plane
	// knows which attributes it must supply to have the condition decide
	// anything. A condition asking about an attribute nobody supplies is
	// false, which is a silent denial unless the requirement is visible.
	ConditionAttributes []string `json:"conditionAttributes,omitempty"`
	// Denied carries the deny-assignment permissions that reach this
	// principal at this scope. A deny beats the grant above it, so a data
	// plane must check these first: an action matching a Denied entry's
	// dataActions (and none of its notDataActions) is refused even though
	// the role grants it. Carried per assignment, in the same shape as the
	// grant, so the matcher a data plane already has applies unchanged.
	Denied []DenyPermission `json:"denied,omitempty"`
}

// EffectiveAt returns every assignment that applies at scope — this scope and
// every ancestor, since ARM assignments inherit downward.
func (s *Service) EffectiveAt(scope string) ([]EffectiveAssignment, error) {
	all, err := s.Store.ListRoleAssignments()
	if err != nil {
		return nil, err
	}
	denies, err := s.DenyAssignmentsAt(scope)
	if err != nil {
		return nil, err
	}
	out := []EffectiveAssignment{}
	for _, a := range all {
		if !ScopeApplies(a.ScopeDisplay, scope) {
			continue
		}
		def, ok := s.resolveRoleFromID(a.RoleDefinitionID)
		if !ok {
			continue // a dangling definition grants nothing
		}
		e := EffectiveAssignment{
			PrincipalID: a.PrincipalID, PrincipalType: a.PrincipalType,
			RoleName: def.RoleName, RoleDefinitionID: a.RoleDefinitionID,
			Scope: a.ScopeDisplay, Condition: a.Condition,
			ConditionVersion: a.ConditionVersion,
			DataActions:      []string{}, NotDataActions: []string{},
		}
		// A condition that no longer parses grants nothing: it was validated
		// when it was written, so reaching here means the stored text was
		// tampered with, and honouring the assignment unconditionally would
		// widen the grant its author narrowed.
		if a.Condition != "" {
			cond, err := abac.Parse(a.Condition)
			if err != nil {
				continue
			}
			e.ConditionAttributes = cond.Attributes()
		}
		for _, p := range def.Permissions {
			e.DataActions = append(e.DataActions, p.DataActions...)
			e.NotDataActions = append(e.NotDataActions, p.NotDataActions...)
		}
		// A deny naming this principal (or naming everyone) overrides the
		// grant. Group membership is resolved by the data plane, as it is
		// for the assignment itself, so a deny on a group also rides along.
		for _, d := range denies {
			if !d.appliesToPrincipal([]string{a.PrincipalID}) {
				continue
			}
			e.Denied = append(e.Denied, d.Permissions...)
		}
		out = append(out, e)
	}
	return out, nil
}

// ServeFeed handles GET /_family/authorization?scope=... — unauthenticated,
// like the sibling emulators' /_emulator control surfaces, because it is a
// localhost coordination channel rather than a customer-facing API.
func (s *Service) ServeFeed(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	if strings.TrimSpace(scope) == "" {
		writeErr(w, http.StatusBadRequest, "BadParameter", "the scope query parameter is required")
		return
	}

	// Every deny reaching this scope, verbatim. `assignments[].denied`
	// above covers the case where the deny names the assignment's own
	// principal; this block is what a data plane consults when the caller
	// reaches a deny through a GROUP it belongs to, since membership is
	// resolved there and not here.
	denies, err := s.DenyAssignmentsAt(scope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	eff, err := s.EffectiveAt(scope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	// When the scope names a vault, its whole configuration rides along —
	// access policies, the RBAC/access-policy switch, purge protection and
	// the soft-delete window. In Azure those are properties of the ARM
	// resource, so the data plane should learn them here rather than from
	// its own flags.
	vault, err := s.VaultConfigAt(scope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":           scope,
		"generated":       s.Store.Now(),
		"assignments":     eff,
		"denyAssignments": denies,
		"vault":           vault,
		// Kept alongside `vault` for consumers pinned to the earlier shape.
		"accessPolicies":          vault.AccessPolicies,
		"enableRbacAuthorization": vault.EnableRbacAuthorization,
	})
}
