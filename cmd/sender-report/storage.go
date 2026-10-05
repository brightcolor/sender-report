package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// sqliteFileSuffixes are the files SQLite keeps for one database: the
// database itself plus its write-ahead log and shared-memory index.
var sqliteFileSuffixes = []string{"", "-wal", "-shm"}

// checkStorage confirms, before the database opens, that the server process
// can write what it keeps on disk: DATA_DIR, the directory of DB_PATH and,
// where they exist, the database file and its SQLite companion files.
//
// The container runs as the unprivileged user "app". A data directory that
// belongs to another user, such as a ./data that Docker created for the bind
// mount, is reported here with the user's IDs and the command that hands the
// directory over.
func checkStorage(dataDir, dbPath string) error {
	dirs := []string{dataDir}
	if dbDir := filepath.Dir(dbPath); filepath.Clean(dbDir) != filepath.Clean(dataDir) {
		dirs = append(dirs, dbDir)
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return storageError(dir, err)
		}
		probe, err := os.CreateTemp(dir, ".write-check-*")
		if err != nil {
			return storageError(dir, err)
		}
		name := probe.Name()
		_ = probe.Close()
		if err := os.Remove(name); err != nil {
			return storageError(dir, err)
		}
	}
	for _, suffix := range sqliteFileSuffixes {
		path := dbPath + suffix
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return storageError(path, err)
		}
		_ = f.Close()
	}
	return nil
}

// storageError explains which path the server process cannot write and how
// the operator hands it over.
func storageError(path string, err error) error {
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 {
		return fmt.Errorf("%s is not writable for the server process: %w. Give the user that runs sender-report write access to it", path, err)
	}
	return fmt.Errorf("%s is not writable for the server process (uid %d, gid %d): %w. "+
		"Give this user write access; with the default docker-compose.yml run on the Docker host: sudo chown -R %d:%d ./data",
		path, uid, gid, err, uid, gid)
}
