// Package statsfiles persists platform statistics as plain-text files
// in the data directory so operators can inspect and adjust the values.
//
// File layout inside DataDir:
//
//	stat_messages   – total e-mails analysed (int)
//	stat_mailboxes  – total mailboxes ever created (int)
//	stat_active     – currently active mailboxes (int)
//	stat_reports    – total reports generated (int)
//	stat_avg_score  – average deliverability score (float, 1 decimal)
//
// Each file contains a bare ASCII number with no trailing newline.
// Edit any file to override the displayed value; the next automatic
// refresh (every StatsRefreshInterval) will overwrite it with DB data.
package statsfiles

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/brightcolor/sender-report/internal/store"
)

// StatsRefreshInterval controls how often the background writer
// re-reads the database and updates the stat files.
const StatsRefreshInterval = 5 * time.Minute

// Write persists every field of stats to its own file in dataDir.
// Existing files are overwritten atomically (write-then-rename).
func Write(dataDir string, stats store.GlobalStats) error {
	entries := []struct {
		name string
		val  string
	}{
		{"stat_messages", fmt.Sprintf("%d", stats.TotalMessages)},
		{"stat_mailboxes", fmt.Sprintf("%d", stats.TotalMailboxes)},
		{"stat_active", fmt.Sprintf("%d", stats.ActiveMailboxes)},
		{"stat_reports", fmt.Sprintf("%d", stats.TotalReports)},
		{"stat_avg_score", fmt.Sprintf("%.1f", stats.AvgScore)},
	}
	for _, e := range entries {
		dst := filepath.Join(dataDir, e.name)
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, []byte(e.val), 0o644); err != nil {
			return fmt.Errorf("statsfiles: write %s: %w", e.name, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("statsfiles: rename %s: %w", e.name, err)
		}
	}
	return nil
}

// Read loads GlobalStats from the files in dataDir.
// Missing or unreadable files return 0 for that field (no error).
func Read(dataDir string) store.GlobalStats {
	readInt := func(name string) int64 {
		b, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return n
	}
	readFloat := func(name string) float64 {
		b, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil {
			return 0
		}
		f, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		return f
	}
	return store.GlobalStats{
		TotalMessages:   readInt("stat_messages"),
		TotalMailboxes:  readInt("stat_mailboxes"),
		ActiveMailboxes: readInt("stat_active"),
		TotalReports:    readInt("stat_reports"),
		AvgScore:        readFloat("stat_avg_score"),
	}
}

// StartWriter launches a background goroutine that queries st for current
// stats and writes them to dataDir immediately, then on every
// StatsRefreshInterval tick until ctx is cancelled.
func StartWriter(ctx context.Context, logger *log.Logger, st *store.Store, dataDir string) {
	go func() {
		refresh := func() {
			s, err := st.GetGlobalStats(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Printf("statsfiles: db query error: %v", err)
				}
				return
			}
			if err := Write(dataDir, s); err != nil {
				logger.Printf("%v", err)
			}
		}

		refresh() // write once immediately on startup

		ticker := time.NewTicker(StatsRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}
