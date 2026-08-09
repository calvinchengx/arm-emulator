package store

// Soft-deleted vaults. Real Key Vault does not destroy a vault on DELETE: it
// moves to a recoverable state for a retention window, keeps holding its
// name, and is destroyed only by an explicit purge or when the window
// lapses. The window runs on the controllable clock, so a test can watch a
// vault become unpurgeable-then-purgeable without waiting ninety days.

import (
	"database/sql"
	"errors"
)

// DeletedVault is a vault in the recoverable state.
type DeletedVault struct {
	Subscription     string
	ResourceGroup    string
	Name             string
	Location         string
	TagsJSON         string
	PropertiesJSON   string
	DeletedAt        int64
	ScheduledPurgeAt int64
}

func (s *Store) migrateDeletedVaults() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS deleted_vaults (
	subscription TEXT NOT NULL,
	resource_group TEXT NOT NULL,
	name TEXT NOT NULL,
	location TEXT NOT NULL DEFAULT 'westeurope',
	tags_json TEXT NOT NULL DEFAULT '{}',
	properties_json TEXT NOT NULL DEFAULT '{}',
	deleted_at INTEGER NOT NULL,
	scheduled_purge_at INTEGER NOT NULL,
	PRIMARY KEY (subscription, name COLLATE NOCASE)
);`)
	return err
}

// SoftDeleteVault moves a live vault into the recoverable state, holding its
// name until it is recovered or purged. retentionDays sets the window.
func (s *Store) SoftDeleteVault(subscription, name string, retentionDays int) error {
	v, err := s.GetVault(subscription, name)
	if err != nil {
		return err
	}
	now := s.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT INTO deleted_vaults (subscription, resource_group, name, location, tags_json, properties_json, deleted_at, scheduled_purge_at)
VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(subscription, name) DO UPDATE SET
	resource_group = excluded.resource_group, location = excluded.location,
	tags_json = excluded.tags_json, properties_json = excluded.properties_json,
	deleted_at = excluded.deleted_at, scheduled_purge_at = excluded.scheduled_purge_at`,
		v.Subscription, v.ResourceGroup, v.Name, v.Location, v.TagsJSON, v.PropertiesJSON,
		now, now+int64(retentionDays)*86400); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM vaults WHERE subscription = ? AND name = ? COLLATE NOCASE`,
		subscription, name); err != nil {
		return err
	}
	return tx.Commit()
}

func scanDeletedVault(scan func(...any) error) (*DeletedVault, error) {
	d := &DeletedVault{}
	err := scan(&d.Subscription, &d.ResourceGroup, &d.Name, &d.Location, &d.TagsJSON,
		&d.PropertiesJSON, &d.DeletedAt, &d.ScheduledPurgeAt)
	return d, err
}

const deletedVaultCols = `subscription, resource_group, name, location, tags_json, properties_json, deleted_at, scheduled_purge_at`

// GetDeletedVault fetches one soft-deleted vault. A vault whose retention
// window has lapsed on the clock is already gone, as if purged.
func (s *Store) GetDeletedVault(subscription, name string) (*DeletedVault, error) {
	row := s.db.QueryRow(`SELECT `+deletedVaultCols+`
FROM deleted_vaults WHERE subscription = ? AND name = ? COLLATE NOCASE AND scheduled_purge_at > ?`,
		subscription, name, s.Now())
	d, err := scanDeletedVault(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ListDeletedVaults returns every vault still inside its retention window.
func (s *Store) ListDeletedVaults(subscription string) ([]*DeletedVault, error) {
	rows, err := s.db.Query(`SELECT `+deletedVaultCols+`
FROM deleted_vaults WHERE subscription = ? AND scheduled_purge_at > ? ORDER BY deleted_at, name`,
		subscription, s.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DeletedVault
	for rows.Next() {
		d, err := scanDeletedVault(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PurgeVault destroys a soft-deleted vault permanently.
func (s *Store) PurgeVault(subscription, name string) error {
	res, err := s.db.Exec(
		`DELETE FROM deleted_vaults WHERE subscription = ? AND name = ? COLLATE NOCASE`, subscription, name)
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

// RecoverVault restores a soft-deleted vault to the live table.
func (s *Store) RecoverVault(subscription, name string) (*Vault, error) {
	d, err := s.GetDeletedVault(subscription, name)
	if err != nil {
		return nil, err
	}
	v := &Vault{
		Subscription: d.Subscription, ResourceGroup: d.ResourceGroup, Name: d.Name,
		Location: d.Location, TagsJSON: d.TagsJSON, PropertiesJSON: d.PropertiesJSON,
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT INTO vaults (subscription, resource_group, name, location, tags_json, properties_json, created_at)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(subscription, name) DO UPDATE SET
	resource_group = excluded.resource_group, location = excluded.location,
	tags_json = excluded.tags_json, properties_json = excluded.properties_json`,
		v.Subscription, v.ResourceGroup, v.Name, v.Location, v.TagsJSON, v.PropertiesJSON,
		s.Now()); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM deleted_vaults WHERE subscription = ? AND name = ? COLLATE NOCASE`,
		subscription, name); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}
