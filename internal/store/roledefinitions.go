package store

// Custom role definitions. Built-in definitions live in code (they are
// Microsoft's, and fixed); these are the ones a caller writes, and they are
// the reason `assignableScopes` matters — a custom role is assignable only
// at or below the scopes it names.

import (
	"database/sql"
	"errors"
	"strings"
)

// CustomRoleDefinition is a caller-created Microsoft.Authorization role.
// Permissions and assignable scopes are stored as JSON so the ARM layer owns
// their shape.
type CustomRoleDefinition struct {
	GUID             string
	RoleName         string
	Description      string
	PermissionsJSON  string
	ScopesJSON       string
	AssignableScopes []string // decoded by the ARM layer; not persisted directly
	CreatedAt        int64
	UpdatedAt        int64
}

func (s *Store) migrateRoleDefinitions() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS role_definitions (
	guid TEXT PRIMARY KEY,
	role_name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	permissions_json TEXT NOT NULL DEFAULT '[]',
	scopes_json TEXT NOT NULL DEFAULT '[]',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
-- Real ARM refuses a second definition with the same display name, so the
-- uniqueness is a storage-level guarantee rather than a handler check.
CREATE UNIQUE INDEX IF NOT EXISTS role_definitions_name
	ON role_definitions (role_name COLLATE NOCASE);`)
	return err
}

// PutRoleDefinition creates or updates a custom definition. A different
// definition already holding the same roleName is ErrConflict.
func (s *Store) PutRoleDefinition(d *CustomRoleDefinition) error {
	now := s.Now()
	d.UpdatedAt = now
	existing, err := s.GetRoleDefinition(d.GUID)
	switch {
	case err == nil:
		d.CreatedAt = existing.CreatedAt
	case errors.Is(err, ErrNotFound):
		d.CreatedAt = now
	default:
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO role_definitions (guid, role_name, description, permissions_json, scopes_json, created_at, updated_at)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(guid) DO UPDATE SET
	role_name = excluded.role_name, description = excluded.description,
	permissions_json = excluded.permissions_json, scopes_json = excluded.scopes_json,
	updated_at = excluded.updated_at`,
		d.GUID, d.RoleName, d.Description, d.PermissionsJSON, d.ScopesJSON, d.CreatedAt, d.UpdatedAt)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrConflict
	}
	return err
}

func scanRoleDefinition(scan func(...any) error) (*CustomRoleDefinition, error) {
	d := &CustomRoleDefinition{}
	err := scan(&d.GUID, &d.RoleName, &d.Description, &d.PermissionsJSON, &d.ScopesJSON,
		&d.CreatedAt, &d.UpdatedAt)
	return d, err
}

const roleDefCols = `guid, role_name, description, permissions_json, scopes_json, created_at, updated_at`

// GetRoleDefinition fetches one custom definition by GUID.
func (s *Store) GetRoleDefinition(guid string) (*CustomRoleDefinition, error) {
	row := s.db.QueryRow(`SELECT `+roleDefCols+` FROM role_definitions WHERE guid = ? COLLATE NOCASE`, guid)
	d, err := scanRoleDefinition(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ListRoleDefinitions returns every custom definition, oldest first.
func (s *Store) ListRoleDefinitions() ([]*CustomRoleDefinition, error) {
	rows, err := s.db.Query(`SELECT ` + roleDefCols + ` FROM role_definitions ORDER BY created_at, guid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CustomRoleDefinition
	for rows.Next() {
		d, err := scanRoleDefinition(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteRoleDefinition removes a custom definition.
func (s *Store) DeleteRoleDefinition(guid string) error {
	res, err := s.db.Exec(`DELETE FROM role_definitions WHERE guid = ? COLLATE NOCASE`, guid)
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

// AssignmentsForRole counts assignments referencing a definition GUID —
// what a delete consults, since removing a definition out from under a live
// assignment would leave it granting nothing.
func (s *Store) AssignmentsForRole(guid string) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE role_definition_id LIKE '%' || ? COLLATE NOCASE`, guid).Scan(&n)
	return n, err
}
