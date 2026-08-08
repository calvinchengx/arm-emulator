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
}

// EffectiveAt returns every assignment that applies at scope — this scope and
// every ancestor, since ARM assignments inherit downward.
func (s *Service) EffectiveAt(scope string) ([]EffectiveAssignment, error) {
	all, err := s.Store.ListRoleAssignments()
	if err != nil {
		return nil, err
	}
	out := []EffectiveAssignment{}
	for _, a := range all {
		if !ScopeApplies(a.ScopeDisplay, scope) {
			continue
		}
		def, ok := RoleFromDefinitionID(a.RoleDefinitionID)
		if !ok {
			continue // a dangling definition grants nothing
		}
		e := EffectiveAssignment{
			PrincipalID: a.PrincipalID, PrincipalType: a.PrincipalType,
			RoleName: def.RoleName, RoleDefinitionID: a.RoleDefinitionID,
			Scope: a.ScopeDisplay, Condition: a.Condition,
			DataActions: []string{}, NotDataActions: []string{},
		}
		for _, p := range def.Permissions {
			e.DataActions = append(e.DataActions, p.DataActions...)
			e.NotDataActions = append(e.NotDataActions, p.NotDataActions...)
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
	eff, err := s.EffectiveAt(scope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":       scope,
		"generated":   s.Store.Now(),
		"assignments": eff,
	})
}
