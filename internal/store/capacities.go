package store

import (
	"database/sql"
	"errors"
)

// FabricCapacity is a Microsoft.Fabric/capacities row. The properties
// document is stored whole so the provider owns its shape (administration,
// state, overage) and this layer stays generic. FabricID is the GUID the
// Fabric REST plane lists the capacity under — generated here at create so
// fabric-emulator can consume it without inventing a second identity.
type FabricCapacity struct {
	Subscription   string
	ResourceGroup  string
	Name           string
	Location       string
	SKUName        string
	SKUTier        string
	TagsJSON       string
	PropertiesJSON string
	FabricID       string
	CreatedAt      int64
}

const fabricCapacityCols = `subscription, resource_group, name, location, sku_name, sku_tier,
	tags_json, properties_json, fabric_id, created_at`

func scanFabricCapacity(row interface{ Scan(...any) error }) (*FabricCapacity, error) {
	c := &FabricCapacity{}
	err := row.Scan(&c.Subscription, &c.ResourceGroup, &c.Name, &c.Location,
		&c.SKUName, &c.SKUTier, &c.TagsJSON, &c.PropertiesJSON, &c.FabricID, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) migrateFabricCapacities() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS fabric_capacities (
	subscription TEXT NOT NULL,
	resource_group TEXT NOT NULL,
	name TEXT NOT NULL,
	location TEXT NOT NULL DEFAULT 'westeurope',
	sku_name TEXT NOT NULL,
	sku_tier TEXT NOT NULL DEFAULT 'Fabric',
	tags_json TEXT NOT NULL DEFAULT '{}',
	properties_json TEXT NOT NULL DEFAULT '{}',
	fabric_id TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (subscription, name COLLATE NOCASE)
);
CREATE UNIQUE INDEX IF NOT EXISTS fabric_capacities_fabric_id
	ON fabric_capacities (fabric_id);`)
	return err
}

// PutFabricCapacity creates or updates a capacity (ARM's PUT is an upsert).
// A new row without FabricID is assigned a GUID; an update keeps the one it
// already has so fabric-emulator's REST id never moves under a client.
func (s *Store) PutFabricCapacity(c *FabricCapacity) error {
	if c.TagsJSON == "" {
		c.TagsJSON = "{}"
	}
	if c.PropertiesJSON == "" {
		c.PropertiesJSON = "{}"
	}
	if c.Location == "" {
		c.Location = "westeurope"
	}
	if c.SKUTier == "" {
		c.SKUTier = "Fabric"
	}
	if c.FabricID == "" {
		if existing, err := s.GetFabricCapacity(c.Subscription, c.Name); err == nil {
			c.FabricID = existing.FabricID
		} else if errors.Is(err, ErrNotFound) {
			c.FabricID = NewGUID()
		} else {
			return err
		}
	}
	c.CreatedAt = s.Now()
	_, err := s.db.Exec(`INSERT INTO fabric_capacities (`+fabricCapacityCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(subscription, name) DO UPDATE SET resource_group = excluded.resource_group,
	location = excluded.location, sku_name = excluded.sku_name, sku_tier = excluded.sku_tier,
	tags_json = excluded.tags_json, properties_json = excluded.properties_json`,
		c.Subscription, c.ResourceGroup, c.Name, c.Location, c.SKUName, c.SKUTier,
		c.TagsJSON, c.PropertiesJSON, c.FabricID, c.CreatedAt)
	return err
}

// GetFabricCapacity returns one capacity by name (case-insensitive, as ARM matches).
func (s *Store) GetFabricCapacity(subscription, name string) (*FabricCapacity, error) {
	return scanFabricCapacity(s.db.QueryRow(`SELECT `+fabricCapacityCols+`
FROM fabric_capacities WHERE subscription = ? AND name = ? COLLATE NOCASE`, subscription, name))
}

// ListFabricCapacities returns the subscription's capacities, optionally
// narrowed to one resource group.
func (s *Store) ListFabricCapacities(subscription, resourceGroup string) ([]*FabricCapacity, error) {
	q := `SELECT ` + fabricCapacityCols + ` FROM fabric_capacities WHERE subscription = ?`
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
	var out []*FabricCapacity
	for rows.Next() {
		c, err := scanFabricCapacity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteFabricCapacity removes a capacity; ErrNotFound when absent.
func (s *Store) DeleteFabricCapacity(subscription, name string) error {
	res, err := s.db.Exec(`DELETE FROM fabric_capacities WHERE subscription = ? AND name = ? COLLATE NOCASE`,
		subscription, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
