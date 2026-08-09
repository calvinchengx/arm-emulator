package store

// ARM asynchronous operations. Their status is DERIVED on read from the
// controllable clock rather than advanced by a background worker: a test
// freezes time to hold an operation InProgress and advances time to finish
// it, with no sleeps, no goroutines and no races.

import (
	"database/sql"
	"errors"
)

// The states an ARM client sees while polling.
const (
	OpInProgress = "InProgress"
	OpSucceeded  = "Succeeded"
	OpFailed     = "Failed"
)

// Operation is one long-running operation.
type Operation struct {
	ID           string
	Kind         string // DeleteResourceGroup | CreateVault
	Subscription string
	ResourceID   string // the resource the operation acts on
	CreatedAt    int64
	CompleteAt   int64  // when it turns terminal, on the emulator clock
	FailWith     string // non-empty → terminal Failed with this error code
}

// StatusAt derives the wire status at a clock time.
func (o Operation) StatusAt(now int64) string {
	if now < o.CompleteAt {
		return OpInProgress
	}
	if o.FailWith != "" {
		return OpFailed
	}
	return OpSucceeded
}

func (s *Store) migrateOperations() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS operations (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	subscription TEXT NOT NULL,
	resource_id TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	complete_at INTEGER NOT NULL,
	fail_with TEXT NOT NULL DEFAULT ''
);`)
	return err
}

// CreateOperation records an operation. CompleteAt of zero means it is
// already terminal on the next read.
func (s *Store) CreateOperation(o *Operation) error {
	if o.ID == "" {
		o.ID = NewGUID()
	}
	o.CreatedAt = s.Now()
	if o.CompleteAt == 0 {
		o.CompleteAt = o.CreatedAt
	}
	_, err := s.db.Exec(
		`INSERT INTO operations (id, kind, subscription, resource_id, created_at, complete_at, fail_with)
		 VALUES (?,?,?,?,?,?,?)`,
		o.ID, o.Kind, o.Subscription, o.ResourceID, o.CreatedAt, o.CompleteAt, o.FailWith)
	return err
}

// GetOperation fetches one operation.
func (s *Store) GetOperation(id string) (*Operation, error) {
	o := &Operation{}
	err := s.db.QueryRow(`
SELECT id, kind, subscription, resource_id, created_at, complete_at, fail_with
FROM operations WHERE id = ?`, id).
		Scan(&o.ID, &o.Kind, &o.Subscription, &o.ResourceID, &o.CreatedAt, &o.CompleteAt, &o.FailWith)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return o, err
}

// OperationInFlight reports whether a resource has an operation still
// running — what a resource body consults to report a non-terminal
// provisioningState while its create is polling.
func (s *Store) OperationInFlight(resourceID string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM operations WHERE resource_id = ? COLLATE NOCASE AND complete_at > ?`,
		resourceID, s.Now()).Scan(&n)
	return n > 0, err
}
