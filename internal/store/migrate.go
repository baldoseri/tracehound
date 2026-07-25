package store

import (
	"database/sql"
	"fmt"
)

// migrations are applied in order and never edited once released.
//
// Schema changes go on the end as new entries. Editing an existing one would
// leave databases created by an earlier build permanently inconsistent with
// databases created by a later one, with nothing to detect the difference.
var migrations = []string{
	// 1: alerts.
	`CREATE TABLE alerts (
		id          TEXT    PRIMARY KEY,
		ts          INTEGER NOT NULL,
		rule_id     TEXT    NOT NULL,
		detector    TEXT    NOT NULL,
		title       TEXT    NOT NULL,
		description TEXT    NOT NULL DEFAULT '',
		severity    INTEGER NOT NULL,
		score       REAL    NOT NULL DEFAULT 0,
		src         TEXT    NOT NULL DEFAULT '',
		dst         TEXT    NOT NULL DEFAULT '',
		dst_port    INTEGER NOT NULL DEFAULT 0,
		proto       TEXT    NOT NULL DEFAULT '',
		techniques  TEXT    NOT NULL DEFAULT '[]',
		evidence    TEXT    NOT NULL DEFAULT '{}'
	);
	-- Timestamp descending is how every query reads this table, because
	-- triage starts at the most recent finding and works backwards.
	CREATE INDEX alerts_ts        ON alerts(ts DESC);
	CREATE INDEX alerts_severity  ON alerts(severity, ts DESC);
	CREATE INDEX alerts_src       ON alerts(src, ts DESC);
	CREATE INDEX alerts_rule      ON alerts(rule_id, ts DESC);`,

	// 2: passive asset inventory.
	`CREATE TABLE devices (
		addr       TEXT    PRIMARY KEY,
		mac        TEXT    NOT NULL DEFAULT '',
		hostname   TEXT    NOT NULL DEFAULT '',
		first_seen INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL,
		ja4s       TEXT    NOT NULL DEFAULT '[]',
		bytes_sent INTEGER NOT NULL DEFAULT 0,
		bytes_recv INTEGER NOT NULL DEFAULT 0,
		flows      INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX devices_last_seen ON devices(last_seen DESC);`,
}

// migrate brings a database up to the current schema.
//
// The version lives in SQLite's own user_version pragma rather than a table of
// our own: it costs no rows, cannot be accidentally deleted by a query, and is
// already part of the file format.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("store: database is at schema version %d but this build only knows %d; "+
			"it was written by a newer tracehound", version, len(migrations))
	}

	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		// PRAGMA does not accept bound parameters. The value is a loop index,
		// not anything a user supplied.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("store: migration %d: set version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: migration %d: commit: %w", i+1, err)
		}
	}
	return nil
}
