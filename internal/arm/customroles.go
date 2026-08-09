package arm

// Custom role definitions: the half of Microsoft.Authorization a caller
// writes. Built-ins are Microsoft's and fixed; these are yours, and they are
// what makes `assignableScopes` load-bearing — a custom role may only be
// assigned at or below the scopes it names, which the assignment path
// enforces rather than merely storing.
//
// Custom roles resolve everywhere built-ins do, so a role a caller invented
// flows through role lookup, the assignment path, and the family feed —
// meaning its dataActions reach the sibling data planes and genuinely grant
// access.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/arm-emulator/internal/store"
)

// resolveRole finds a definition by GUID: built-ins first, since they are
// immutable and must never be shadowed, then the caller's own.
func (s *Service) resolveRole(guid string) (RoleDefinition, bool) {
	if def, ok := RoleByGUID(guid); ok {
		return def, true
	}
	d, err := s.Store.GetRoleDefinition(guid)
	if err != nil {
		return RoleDefinition{}, false
	}
	def, err := customToDefinition(d)
	if err != nil {
		return RoleDefinition{}, false
	}
	return def, true
}

// resolveRoleFromID accepts a full roleDefinitionId or a bare GUID.
func (s *Service) resolveRoleFromID(id string) (RoleDefinition, bool) {
	trimmed := strings.TrimSuffix(id, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	return s.resolveRole(trimmed)
}

// customToDefinition decodes the stored JSON into the in-memory shape the
// rest of the package already speaks.
func customToDefinition(d *store.CustomRoleDefinition) (RoleDefinition, error) {
	var perms []Permission
	if err := json.Unmarshal([]byte(d.PermissionsJSON), &perms); err != nil {
		return RoleDefinition{}, err
	}
	var scopes []string
	if err := json.Unmarshal([]byte(d.ScopesJSON), &scopes); err != nil {
		return RoleDefinition{}, err
	}
	return RoleDefinition{
		GUID: d.GUID, RoleName: d.RoleName, Description: d.Description,
		Permissions: perms, AssignableScopes: scopes, Custom: true,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}, nil
}

// putRoleDefinition is PUT .../roleDefinitions/{guid} — create or update a
// custom role.
func (s *Service) putRoleDefinition(w http.ResponseWriter, r *http.Request, scope, guid string) {
	// A built-in is Microsoft's definition; ARM will not let you write over
	// one, and neither will this.
	if _, ok := RoleByGUID(guid); ok {
		writeErr(w, http.StatusBadRequest, "RoleDefinitionUpdateNotPermitted",
			fmt.Sprintf("The role definition '%s' is a built-in role and cannot be modified.", guid))
		return
	}
	var body struct {
		Properties struct {
			RoleName         string       `json:"roleName"`
			Description      string       `json:"description"`
			Type             string       `json:"type"`
			Permissions      []Permission `json:"permissions"`
			AssignableScopes []string     `json:"assignableScopes"`
		} `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	props := body.Properties
	if strings.TrimSpace(props.RoleName) == "" {
		writeErr(w, http.StatusBadRequest, "MissingRoleName",
			"The role definition must have properties.roleName.")
		return
	}
	if len(props.Permissions) == 0 {
		writeErr(w, http.StatusBadRequest, "MissingPermissions",
			"The role definition must have at least one entry in properties.permissions.")
		return
	}
	// assignableScopes is the whole point of a custom role: without it there
	// is nowhere the role may be used.
	if len(props.AssignableScopes) == 0 {
		writeErr(w, http.StatusBadRequest, "MissingAssignableScopes",
			"The role definition must have at least one entry in properties.assignableScopes.")
		return
	}
	for _, sc := range props.AssignableScopes {
		if strings.TrimSpace(sc) == "" || !strings.HasPrefix(sc, "/") {
			writeErr(w, http.StatusBadRequest, "InvalidAssignableScope",
				fmt.Sprintf("The assignable scope '%s' is not a valid scope.", sc))
			return
		}
	}

	perms, err := json.Marshal(props.Permissions)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	scopes, err := json.Marshal(props.AssignableScopes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_, existed := s.Store.GetRoleDefinition(guid)
	d := &store.CustomRoleDefinition{
		GUID: guid, RoleName: props.RoleName, Description: props.Description,
		PermissionsJSON: string(perms), ScopesJSON: string(scopes),
	}
	if err := s.Store.PutRoleDefinition(d); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "RoleDefinitionWithSameNameExists",
				fmt.Sprintf("A role definition named '%s' already exists.", props.RoleName))
			return
		}
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	// Built from what was just validated, rather than decoded back out of
	// storage: there is no round trip here that could fail.
	def := RoleDefinition{
		GUID: guid, RoleName: props.RoleName, Description: props.Description,
		Permissions: props.Permissions, AssignableScopes: props.AssignableScopes,
		Custom: true, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
	status := http.StatusCreated
	if existed == nil {
		status = http.StatusOK
	}
	writeJSON(w, status, s.roleDefBody(scope, def))
}

// deleteRoleDefinition is DELETE .../roleDefinitions/{guid}. Built-ins are
// undeletable, and a definition still carrying assignments is refused rather
// than left granting nothing.
func (s *Service) deleteRoleDefinition(w http.ResponseWriter, r *http.Request, scope, guid string) {
	if _, ok := RoleByGUID(guid); ok {
		writeErr(w, http.StatusBadRequest, "RoleDefinitionDeleteNotPermitted",
			fmt.Sprintf("The role definition '%s' is a built-in role and cannot be deleted.", guid))
		return
	}
	d, err := s.Store.GetRoleDefinition(guid)
	if errors.Is(err, store.ErrNotFound) {
		// ARM treats deleting an absent definition as a no-op.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	n, err := s.Store.AssignmentsForRole(guid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, "RoleDefinitionHasAssignments",
			fmt.Sprintf("The role definition '%s' has %d assignment(s) and cannot be deleted.", guid, n))
		return
	}
	def, err := customToDefinition(d)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.DeleteRoleDefinition(guid); err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.roleDefBody(scope, def))
}

// assignableAt reports whether a definition may be assigned at a scope. A
// built-in is assignable anywhere ("/"); a custom role only at or below one
// of its assignableScopes.
func assignableAt(def RoleDefinition, scope string) bool {
	if !def.Custom {
		return true
	}
	for _, sc := range def.AssignableScopes {
		if ScopeApplies(sc, scope) {
			return true
		}
	}
	return false
}
