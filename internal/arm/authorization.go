package arm

// Microsoft.Authorization: role definitions (seeded built-ins) and role
// assignments (real CRUD at any scope, with downward inheritance on read).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/calvinchengx/arm-emulator/internal/abac"
	"github.com/calvinchengx/arm-emulator/internal/auth"
	"github.com/calvinchengx/arm-emulator/internal/store"
)

// rfc3339 renders an emulator-clock timestamp the way ARM stamps resources.
func rfc3339(epoch int64) string {
	return time.Unix(epoch, 0).UTC().Format("2006-01-02T15:04:05.0000000Z")
}

func (s *Service) roleDefinitionID(scope, guid string) string {
	return fmt.Sprintf("%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		strings.TrimSuffix(scope, "/"), guid)
}

func (s *Service) roleDefBody(scope string, r RoleDefinition) map[string]any {
	perms := make([]map[string]any, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		perms = append(perms, map[string]any{
			"actions": orEmpty(p.Actions), "notActions": orEmpty(p.NotActions),
			"dataActions": orEmpty(p.DataActions), "notDataActions": orEmpty(p.NotDataActions),
		})
	}
	kind, scopes := "BuiltInRole", []string{"/"}
	if r.Custom {
		kind, scopes = "CustomRole", orEmpty(r.AssignableScopes)
	}
	props := map[string]any{
		"roleName":         r.RoleName,
		"description":      r.Description,
		"type":             kind,
		"permissions":      perms,
		"assignableScopes": scopes,
	}
	if r.Custom {
		props["createdOn"] = rfc3339(r.CreatedAt)
		props["updatedOn"] = rfc3339(r.UpdatedAt)
	}
	return map[string]any{
		"id":         s.roleDefinitionID(scope, r.GUID),
		"type":       "Microsoft.Authorization/roleDefinitions",
		"name":       r.GUID,
		"properties": props,
	}
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// roleDefinitions serves list and get. Real ARM supports an OData $filter on
// roleName; the CLI uses it, so it is honoured here.
func (s *Service) roleDefinitions(w http.ResponseWriter, r *http.Request, scope string, rest []string) {
	named := len(rest) >= 1 && rest[0] != ""
	switch {
	case r.Method == http.MethodPut && named:
		s.putRoleDefinition(w, r, scope, rest[0])
		return
	case r.Method == http.MethodDelete && named:
		s.deleteRoleDefinition(w, r, scope, rest[0])
		return
	case r.Method != http.MethodGet:
		methodNotAllowed(w, r.Method)
		return
	}
	if named {
		def, ok := s.resolveRole(rest[0])
		if !ok {
			writeErr(w, http.StatusNotFound, "RoleDefinitionDoesNotExist",
				fmt.Sprintf("The role definition '%s' does not exist.", rest[0]))
			return
		}
		writeJSON(w, http.StatusOK, s.roleDefBody(scope, def))
		return
	}
	wantName := filterRoleName(r.URL.Query().Get("$filter"))
	defs := BuiltInRoles()
	customs, err := s.Store.ListRoleDefinitions()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	for _, d := range customs {
		def, err := customToDefinition(d)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		defs = append(defs, def)
	}
	items := []map[string]any{}
	for _, def := range defs {
		if wantName != "" && !strings.EqualFold(def.RoleName, wantName) {
			continue
		}
		items = append(items, s.roleDefBody(scope, def))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

// filterRoleName extracts N from `roleName eq 'N'`.
func filterRoleName(filter string) string {
	const key = "rolename eq "
	i := strings.Index(strings.ToLower(filter), key)
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(filter[i+len(key):])
	return strings.Trim(v, "'\"")
}

func (s *Service) assignmentBody(a *store.RoleAssignment) map[string]any {
	props := map[string]any{
		"scope":            a.ScopeDisplay,
		"roleDefinitionId": a.RoleDefinitionID,
		"principalId":      a.PrincipalID,
		"principalType":    a.PrincipalType,
		"createdOn":        rfc3339(a.CreatedAt),
		"updatedOn":        rfc3339(a.UpdatedAt),
		"createdBy":        a.CreatedBy,
		"updatedBy":        a.CreatedBy,
	}
	if a.Description != "" {
		props["description"] = a.Description
	}
	if a.Condition != "" {
		props["condition"] = a.Condition
		props["conditionVersion"] = a.ConditionVersion
	}
	return map[string]any{
		"id": fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s",
			strings.TrimSuffix(a.ScopeDisplay, "/"), a.Name),
		"type":       "Microsoft.Authorization/roleAssignments",
		"name":       a.Name,
		"properties": props,
	}
}

// roleAssignments serves PUT/GET/DELETE on one assignment and GET on the
// collection at a scope.
func (s *Service) roleAssignments(w http.ResponseWriter, r *http.Request, scope string, rest []string, p *auth.Principal) {
	if sub := SubscriptionOf(scope); sub != "" && !s.checkSubscription(w, sub) {
		return
	}
	if len(rest) == 0 || rest[0] == "" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r.Method)
			return
		}
		s.listAssignments(w, r, scope)
		return
	}
	name := rest[0]
	switch r.Method {
	case http.MethodPut:
		s.createAssignment(w, r, scope, name, p)
	case http.MethodGet:
		a, err := s.Store.GetRoleAssignment(scope, name)
		if errors.Is(err, store.ErrNotFound) {
			assignmentNotFound(w, name)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.assignmentBody(a))
	case http.MethodDelete:
		a, err := s.Store.DeleteRoleAssignment(name)
		if errors.Is(err, store.ErrNotFound) {
			// ARM answers 204 for a delete of something already gone.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.assignmentBody(a))
	default:
		methodNotAllowed(w, r.Method)
	}
}

func assignmentNotFound(w http.ResponseWriter, name string) {
	writeErr(w, http.StatusNotFound, "RoleAssignmentNotFound",
		fmt.Sprintf("The role assignment '%s' was not found.", name))
}

func (s *Service) createAssignment(w http.ResponseWriter, r *http.Request, scope, name string, p *auth.Principal) {
	var body struct {
		Properties struct {
			RoleDefinitionID string `json:"roleDefinitionId"`
			PrincipalID      string `json:"principalId"`
			PrincipalType    string `json:"principalType"`
			Description      string `json:"description"`
			Condition        string `json:"condition"`
			ConditionVersion string `json:"conditionVersion"`
		} `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "InvalidRequestContent",
			"The request content was invalid and could not be deserialized.")
		return
	}
	props := body.Properties
	if props.RoleDefinitionID == "" || props.PrincipalID == "" {
		writeErr(w, http.StatusBadRequest, "MissingSubscription",
			"The request did not have properties.roleDefinitionId and properties.principalId.")
		return
	}
	// The role must exist: real ARM refuses an assignment to an unknown
	// definition rather than storing a dangling reference.
	def, ok := s.resolveRoleFromID(props.RoleDefinitionID)
	if !ok {
		writeErr(w, http.StatusBadRequest, "RoleDefinitionDoesNotExist",
			fmt.Sprintf("The role definition '%s' does not exist.", props.RoleDefinitionID))
		return
	}
	// A custom role is assignable only at or below the scopes it declares —
	// the constraint assignableScopes exists to express.
	if !assignableAt(def, scope) {
		writeErr(w, http.StatusBadRequest, "ScopeNotAssignable",
			fmt.Sprintf("The role definition '%s' is not assignable at scope '%s'.", def.RoleName, scope))
		return
	}
	// An ABAC condition is parsed before it is stored. Accepting one that
	// cannot be evaluated would be the worst outcome available: the caller
	// believes their assignment is constrained, and it is not.
	if props.Condition != "" {
		if props.ConditionVersion == "" {
			props.ConditionVersion = abac.Version
		}
		if props.ConditionVersion != abac.Version {
			writeErr(w, http.StatusBadRequest, "InvalidConditionVersion",
				fmt.Sprintf("The condition version '%s' is invalid. The only supported version is '%s'.",
					props.ConditionVersion, abac.Version))
			return
		}
		if _, err := abac.Parse(props.Condition); err != nil {
			writeErr(w, http.StatusBadRequest, "InvalidCondition",
				fmt.Sprintf("The condition could not be parsed: %s", err.Error()))
			return
		}
	} else if props.ConditionVersion != "" {
		writeErr(w, http.StatusBadRequest, "InvalidCondition",
			"A conditionVersion was supplied without a condition.")
		return
	}
	a := &store.RoleAssignment{
		Name: name, ScopeDisplay: strings.TrimSuffix(scope, "/"),
		RoleDefinitionID: props.RoleDefinitionID, PrincipalID: props.PrincipalID,
		PrincipalType: props.PrincipalType, Description: props.Description,
		Condition: props.Condition, ConditionVersion: props.ConditionVersion,
		CreatedBy: p.ID,
	}
	if a.ScopeDisplay == "" {
		a.ScopeDisplay = "/"
	}
	err := s.Store.CreateRoleAssignment(a)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "RoleAssignmentExists",
			"The role assignment already exists.")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.assignmentBody(a))
}

// listAssignments returns assignments visible at a scope. ARM's default is
// "at or above" (inherited assignments are visible on a child scope);
// `$filter=atScope()` narrows to exactly this scope, and
// `principalId eq '{id}'` narrows to one principal — both used by the CLI.
func (s *Service) listAssignments(w http.ResponseWriter, r *http.Request, scope string) {
	all, err := s.Store.ListRoleAssignments()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	filter := r.URL.Query().Get("$filter")
	atScope := strings.Contains(strings.ToLower(filter), "atscope()")
	principal := filterPrincipalID(filter)
	items := []map[string]any{}
	for _, a := range all {
		if atScope {
			if CanonicalScope(a.ScopeDisplay) != CanonicalScope(scope) {
				continue
			}
		} else if !ScopeApplies(a.ScopeDisplay, scope) {
			continue
		}
		if principal != "" && !strings.EqualFold(a.PrincipalID, principal) {
			continue
		}
		items = append(items, s.assignmentBody(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

// filterPrincipalID extracts P from `principalId eq '{P}'`.
func filterPrincipalID(filter string) string {
	const key = "principalid eq "
	i := strings.Index(strings.ToLower(filter), key)
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(filter[i+len(key):])
	if j := strings.IndexAny(v, " &"); j >= 0 {
		v = v[:j]
	}
	return strings.Trim(v, "'\"")
}
