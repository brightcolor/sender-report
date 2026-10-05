package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckStorageAcceptsWritableDirectories(t *testing.T) {
	root := t.TempDir()
	// Values other than the defaults /data and /data/sender-report.db: the
	// database lives outside DATA_DIR, and neither directory exists yet.
	dataDir := filepath.Join(root, "state")
	dbPath := filepath.Join(root, "db", "reports.sqlite")

	if err := checkStorage(dataDir, dbPath); err != nil {
		t.Fatalf("checkStorage: %v", err)
	}
	for _, dir := range []string{dataDir, filepath.Dir(dbPath)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("checkStorage left %s missing: %v", dir, err)
		}
		if len(entries) != 0 {
			t.Errorf("%s keeps %d entries after the check, want an empty directory", dir, len(entries))
		}
	}
}

func TestCheckStorageAcceptsAnExistingWritableDatabase(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "reports.sqlite")
	for _, suffix := range sqliteFileSuffixes {
		if err := os.WriteFile(dbPath+suffix, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", dbPath+suffix, err)
		}
	}
	if err := checkStorage(dataDir, dbPath); err != nil {
		t.Fatalf("checkStorage: %v", err)
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil || string(raw) != "x" {
		t.Fatalf("the check changed the database file: %q, %v", raw, err)
	}
}

func TestCheckStorageNamesTheFileItCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes read-only files")
	}
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "reports.sqlite")
	walPath := dbPath + "-wal"
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatalf("write database: %v", err)
	}
	if err := os.WriteFile(walPath, nil, 0o444); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(walPath, 0o644) })

	err := checkStorage(dataDir, dbPath)
	if err == nil {
		t.Fatal("checkStorage accepted a read-only journal file")
	}
	if !strings.Contains(err.Error(), walPath) {
		t.Errorf("message does not name the file: %v", err)
	}
	if uid := os.Getuid(); uid >= 0 {
		want := fmt.Sprintf("sudo chown -R %d:%d ./data", uid, os.Getgid())
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks the command %q: %v", want, err)
		}
	}
}

func TestCheckStorageReportsADataDirThatIsAFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(dataDir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := checkStorage(dataDir, filepath.Join(dataDir, "reports.sqlite"))
	if err == nil {
		t.Fatal("checkStorage accepted a regular file as DATA_DIR")
	}
	if !strings.Contains(err.Error(), dataDir) {
		t.Errorf("message does not name DATA_DIR: %v", err)
	}
}

func TestCheckStorageReportsAReadOnlyDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lets every user create files in a read-only directory")
	}
	if os.Getuid() == 0 {
		t.Skip("root writes into read-only directories")
	}
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o755) })

	err := checkStorage(dataDir, filepath.Join(dataDir, "reports.sqlite"))
	if err == nil {
		t.Fatal("checkStorage accepted a read-only DATA_DIR")
	}
	if !strings.Contains(err.Error(), dataDir) || !strings.Contains(err.Error(), "chown") {
		t.Errorf("message does not name DATA_DIR and the command: %v", err)
	}
}
