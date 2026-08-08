package store

import (
	"database/sql"
	"errors"
)

// Vault is a Microsoft.KeyVault/vaults row. The properties document is stored
// whole so the provider owns its shape and this layer stays generic.
type Vault struct {
	Subscription   string
	ResourceGroup  string
	Name           string
	Location       string
	TagsJSON       string
	PropertiesJSON string
	CreatedAt      int64
}

const vaultCols = `subscription, resource_group, name, location, tags_json, properties_json, created_at`

func scanVault(row interface{ Scan(...any) error }) (*Vault, error) {
	v := &Vault{}
	err := row.Scan(&v.Subscription, &v.ResourceGroup, &v.Name, &v.Location,
		&v.TagsJSON, &v.PropertiesJSON, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// PutVault creates or updates a vault (ARM's PUT is an upsert).
func (s *Store) PutVault(v *Vault) error {
	if v.TagsJSON == "" {
		v.TagsJSON = "{}"
	}
	if v.PropertiesJSON == "" {
		v.PropertiesJSON = "{}"
	}
	if v.Location == "" {
		v.Location = "westeurope"
	}
	v.CreatedAt = s.Now()
	_, err := s.db.Exec(`INSERT INTO vaults (`+vaultCols+`) VALUES (?,?,?,?,?,?,?)
ON CONFLICT(subscription, name) DO UPDATE SET resource_group = excluded.resource_group,
	location = excluded.location, tags_json = excluded.tags_json,
	properties_json = excluded.properties_json`,
		v.Subscription, v.ResourceGroup, v.Name, v.Location, v.TagsJSON, v.PropertiesJSON, v.CreatedAt)
	return err
}

// GetVault returns one vault by name (case-insensitive, as ARM matches).
func (s *Store) GetVault(subscription, name string) (*Vault, error) {
	return scanVault(s.db.QueryRow(`SELECT `+vaultCols+`
FROM vaults WHERE subscription = ? AND name = ? COLLATE NOCASE`, subscription, name))
}

// ListVaults returns the subscription's vaults, optionally narrowed to one
// resource group.
func (s *Store) ListVaults(subscription, resourceGroup string) ([]*Vault, error) {
	q := `SELECT ` + vaultCols + ` FROM vaults WHERE subscription = ?`
	args := []any{subscription}
	if resourceGroup != "" {
		q += ` AND resource_group = ? COLLATE NOCASE`
		args = append(args, resourceGroup)
	}
	rows, err := s.db.Query(q+` ORDER BY rowid`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteVault removes a vault; ErrNotFound when absent.
func (s *Store) DeleteVault(subscription, name string) error {
	res, err := s.db.Exec(`DELETE FROM vaults WHERE subscription = ? AND name = ? COLLATE NOCASE`,
		subscription, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
