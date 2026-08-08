package store

import (
	"database/sql"
	"errors"
	"strings"
)

// ResourceGroup is a Microsoft.Resources/resourceGroups row.
type ResourceGroup struct {
	Subscription string
	Name         string
	Location     string
	TagsJSON     string
	CreatedAt    int64
}

// PutResourceGroup creates or updates a group (ARM's PUT is an upsert).
func (s *Store) PutResourceGroup(g *ResourceGroup) error {
	if g.TagsJSON == "" {
		g.TagsJSON = "{}"
	}
	if g.Location == "" {
		g.Location = "westeurope"
	}
	g.CreatedAt = s.Now()
	_, err := s.db.Exec(`INSERT INTO resource_groups (subscription, name, location, tags_json, created_at)
VALUES (?,?,?,?,?)
ON CONFLICT(subscription, name) DO UPDATE SET location = excluded.location, tags_json = excluded.tags_json`,
		g.Subscription, g.Name, g.Location, g.TagsJSON, g.CreatedAt)
	return err
}

// GetResourceGroup returns one group (name match is case-insensitive, as ARM
// treats resource-group names).
func (s *Store) GetResourceGroup(subscription, name string) (*ResourceGroup, error) {
	g := &ResourceGroup{}
	err := s.db.QueryRow(`SELECT subscription, name, location, tags_json, created_at
FROM resource_groups WHERE subscription = ? AND name = ? COLLATE NOCASE`, subscription, name).
		Scan(&g.Subscription, &g.Name, &g.Location, &g.TagsJSON, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// ListResourceGroups returns every group in the subscription.
func (s *Store) ListResourceGroups(subscription string) ([]*ResourceGroup, error) {
	rows, err := s.db.Query(`SELECT subscription, name, location, tags_json, created_at
FROM resource_groups WHERE subscription = ? ORDER BY rowid`, subscription)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ResourceGroup
	for rows.Next() {
		g := &ResourceGroup{}
		if err := rows.Scan(&g.Subscription, &g.Name, &g.Location, &g.TagsJSON, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteResourceGroup removes a group; ErrNotFound when absent.
func (s *Store) DeleteResourceGroup(subscription, name string) error {
	res, err := s.db.Exec(`DELETE FROM resource_groups WHERE subscription = ? AND name = ? COLLATE NOCASE`,
		subscription, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RoleAssignment is a Microsoft.Authorization/roleAssignments row.
type RoleAssignment struct {
	Name             string
	Scope            string // canonical, lowercased — what matching uses
	ScopeDisplay     string // as written by the caller — what responses echo
	RoleDefinitionID string
	PrincipalID      string
	PrincipalType    string
	Description      string
	Condition        string
	ConditionVersion string
	CreatedAt        int64
	UpdatedAt        int64
	CreatedBy        string
}

const raCols = `name, scope, scope_display, role_definition_id, principal_id, principal_type,
	description, condition, condition_version, created_at, updated_at, created_by`

func scanRA(row interface{ Scan(...any) error }) (*RoleAssignment, error) {
	a := &RoleAssignment{}
	err := row.Scan(&a.Name, &a.Scope, &a.ScopeDisplay, &a.RoleDefinitionID, &a.PrincipalID,
		&a.PrincipalType, &a.Description, &a.Condition, &a.ConditionVersion,
		&a.CreatedAt, &a.UpdatedAt, &a.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// CreateRoleAssignment inserts an assignment. A second assignment of the same
// role to the same principal at the same scope is ErrConflict, as ARM's
// RoleAssignmentExists.
func (s *Store) CreateRoleAssignment(a *RoleAssignment) error {
	if a.PrincipalType == "" {
		a.PrincipalType = "User"
	}
	a.Scope = strings.ToLower(a.ScopeDisplay)
	now := s.Now()
	a.CreatedAt, a.UpdatedAt = now, now
	_, err := s.db.Exec(`INSERT INTO role_assignments (`+raCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.Name, a.Scope, a.ScopeDisplay, a.RoleDefinitionID, a.PrincipalID, a.PrincipalType,
		a.Description, a.Condition, a.ConditionVersion, a.CreatedAt, a.UpdatedAt, a.CreatedBy)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrConflict
	}
	return err
}

// GetRoleAssignment returns one assignment by scope + name.
func (s *Store) GetRoleAssignment(scope, name string) (*RoleAssignment, error) {
	return scanRA(s.db.QueryRow(`SELECT `+raCols+` FROM role_assignments
WHERE name = ? AND scope = ?`, name, strings.ToLower(scope)))
}

// GetRoleAssignmentByName returns an assignment regardless of scope — the
// by-ID route (GET /{roleAssignmentId}) resolves this way.
func (s *Store) GetRoleAssignmentByName(name string) (*RoleAssignment, error) {
	return scanRA(s.db.QueryRow(`SELECT `+raCols+` FROM role_assignments WHERE name = ?`, name))
}

// DeleteRoleAssignment removes an assignment by name, returning what was
// removed (ARM's DELETE echoes the deleted resource).
func (s *Store) DeleteRoleAssignment(name string) (*RoleAssignment, error) {
	a, err := s.GetRoleAssignmentByName(name)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`DELETE FROM role_assignments WHERE name = ?`, name); err != nil {
		return nil, err
	}
	return a, nil
}

// ListRoleAssignments returns every assignment, newest last.
func (s *Store) ListRoleAssignments() ([]*RoleAssignment, error) {
	rows, err := s.db.Query(`SELECT ` + raCols + ` FROM role_assignments ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RoleAssignment
	for rows.Next() {
		a, err := scanRA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
