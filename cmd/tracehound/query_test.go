package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baldoseri/tracehound/internal/store"
)

// TestQueryRefusesToInventADatabase is the regression test for a silent false
// negative.
//
// store.Open creates the file when it is missing, which is right for a sensor
// starting a new capture and exactly wrong for a read. A mistyped path used to
// produce an empty database and report "0 shown of 0 stored" with a zero exit
// code. During an incident that reads as "there were no findings", which is the
// one answer this tool must never give by accident.
func TestQueryRefusesToInventADatabase(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "typo.db")

	err := queryCmd([]string{"-db", missing})
	if err == nil {
		t.Fatal("querying a database that does not exist returned no error")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error does not name the path it could not find: %v", err)
	}

	// And it must not have created one on the way out, or the second attempt
	// would succeed against an empty file and report a clean result.
	if _, statErr := os.Stat(missing); statErr == nil {
		t.Error("the missing database was created by the failed query")
	}
}

// TestQueryReadsAnExistingDatabase is the other half: the guard must not break
// the normal path.
func TestQueryReadsAnExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.db")

	// An empty but real database. The point is that it opens and reports
	// nothing, rather than failing, which is a different outcome from a path
	// that does not exist at all.
	db, err := store.Open(path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := queryCmd([]string{"-db", path}); err != nil {
		t.Errorf("querying an existing database failed: %v", err)
	}
}
