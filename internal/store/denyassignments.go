package store

// Deny assignments. In Azure these are not written by customers: Blueprints,
// managed applications and deployment stacks create them, and the ARM API
// exposes them read-only. They are stored here like any other resource, and
// the ARM layer owns their JSON-shaped members (permissions and principal
// lists), as it does for custom role definitions.

import (
	"database/sql"
	"errors"
)

// DenyAssignment is one deny assignment as persisted. Permissions and the
// two principal lists are JSON, decoded by the ARM layer.
type DenyAssignment struct {
	Name                    string
	Scope                   string // canonical, lowercased — what matching uses
	ScopeDisplay            string // as written — what responses echo
	DisplayName             string
	Description             string
	PermissionsJSON         string
	PrincipalsJSON          string
	ExcludePrincipalsJSON   string
	DoNotApplyToChildScopes bool
	IsSystemProtected       bool
	CreatedAt               int64
	UpdatedAt               int64
}

func (s *Store) migrateDenyAssignments() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS deny_assignments (
	name TEXT PRIMARY KEY,
	scope TEXT NOT NULL,
	scope_display TEXT NOT NULL,
	display_name TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	permissions_json TEXT NOT NULL DEFAULT '[]',
	principals_json TEXT NOT NULL DEFAULT '[]',
	exclude_principals_json TEXT NOT NULL DEFAULT '[]',
	do_not_apply_to_child_scopes INTEGER NOT NULL DEFAULT 0,
	is_system_protected INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);`)
	return err
}

const denyCols = `name, scope, scope_display, display_name, description, permissions_json,
	principals_json, exclude_principals_json, do_not_apply_to_child_scopes,
	is_system_protected, created_at, updated_at`

func scanDeny(scan func(...any) error) (*DenyAssignment, error) {
	d := &DenyAssignment{}
	err := scan(&d.Name, &d.Scope, &d.ScopeDisplay, &d.DisplayName, &d.Description,
		&d.PermissionsJSON, &d.PrincipalsJSON, &d.ExcludePrincipalsJSON,
		&d.DoNotApplyToChildScopes, &d.IsSystemProtected, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

// PutDenyAssignment creates or replaces a deny assignment.
func (s *Store) PutDenyAssignment(d *DenyAssignment) error {
	now := s.Now()
	d.UpdatedAt = now
	existing, err := s.GetDenyAssignment(d.Name)
	switch {
	case err == nil:
		d.CreatedAt = existing.CreatedAt
	case errors.Is(err, ErrNotFound):
		d.CreatedAt = now
	default:
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO deny_assignments (`+denyCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
	scope = excluded.scope, scope_display = excluded.scope_display,
	display_name = excluded.display_name, description = excluded.description,
	permissions_json = excluded.permissions_json, principals_json = excluded.principals_json,
	exclude_principals_json = excluded.exclude_principals_json,
	do_not_apply_to_child_scopes = excluded.do_not_apply_to_child_scopes,
	is_system_protected = excluded.is_system_protected, updated_at = excluded.updated_at`,
		d.Name, d.Scope, d.ScopeDisplay, d.DisplayName, d.Description, d.PermissionsJSON,
		d.PrincipalsJSON, d.ExcludePrincipalsJSON, d.DoNotApplyToChildScopes,
		d.IsSystemProtected, d.CreatedAt, d.UpdatedAt)
	return err
}

// GetDenyAssignment fetches one by name (its GUID).
func (s *Store) GetDenyAssignment(name string) (*DenyAssignment, error) {
	row := s.db.QueryRow(`SELECT `+denyCols+` FROM deny_assignments WHERE name = ? COLLATE NOCASE`, name)
	d, err := scanDeny(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ListDenyAssignments returns every deny assignment, oldest first. Scope
// filtering is the ARM layer's job, since inheritance is its grammar.
func (s *Store) ListDenyAssignments() ([]*DenyAssignment, error) {
	rows, err := s.db.Query(`SELECT ` + denyCols + ` FROM deny_assignments ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DenyAssignment
	for rows.Next() {
		d, err := scanDeny(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDenyAssignment removes one.
func (s *Store) DeleteDenyAssignment(name string) error {
	res, err := s.db.Exec(`DELETE FROM deny_assignments WHERE name = ? COLLATE NOCASE`, name)
	if err != nil {
		return err
	}
	// RowsAffected cannot fail for this driver; the house convention is to
	// read it directly, as the sibling repositories do.
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
