// Package store is the persistence layer: pure-Go SQLite holding resource
// groups, role assignments, and (from P1) tracked resources. All timestamps
// flow through Now (the controllable clock), as in the sibling emulators.
package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/calvinchengx/arm-emulator/internal/clock"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write collides with existing state.
var ErrConflict = errors.New("conflict")

// Store wraps the database plus the emulator clock.
type Store struct {
	db    *sql.DB
	Clock *clock.Clock
}

// Open opens (creating if needed) the database in dataDir; empty = in-memory.
func Open(dataDir string, ck *clock.Clock) (*Store, error) {
	dsn := ":memory:"
	if dataDir != "" {
		dsn = filepath.Join(dataDir, "arm-emulator.db")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Clock: ck}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Now returns the current emulator time (epoch seconds).
func (s *Store) Now() int64 { return s.Clock.Now() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS resource_groups (
	subscription TEXT NOT NULL,
	name TEXT NOT NULL,
	location TEXT NOT NULL DEFAULT 'westeurope',
	tags_json TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL,
	PRIMARY KEY (subscription, name COLLATE NOCASE)
);
CREATE TABLE IF NOT EXISTS role_assignments (
	name TEXT NOT NULL,              -- the assignment GUID
	scope TEXT NOT NULL,             -- canonical (lowercased) ARM scope
	scope_display TEXT NOT NULL,     -- as the caller wrote it
	role_definition_id TEXT NOT NULL,
	principal_id TEXT NOT NULL,
	principal_type TEXT NOT NULL DEFAULT 'User',
	description TEXT NOT NULL DEFAULT '',
	condition TEXT NOT NULL DEFAULT '',
	condition_version TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (name)
);
-- Real ARM rejects a duplicate (scope, role, principal) triple with
-- RoleAssignmentExists; the index makes that a storage-level guarantee.
CREATE UNIQUE INDEX IF NOT EXISTS role_assignments_triple
	ON role_assignments (scope, role_definition_id, principal_id);
`)
	return err
}

// NewGUID returns a random RFC 4122 v4 UUID — the identifier shape ARM uses
// for role assignments and definitions.
func NewGUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
