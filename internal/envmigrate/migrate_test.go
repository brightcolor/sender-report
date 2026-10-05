package envmigrate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/config"
)

// configDefaults are the settings whose defaults live in package config.
var configDefaults = map[string]string{
	"PAYLOAD_RATE_LIMIT_PER_MIN": strconv.Itoa(config.DefaultPayloadRateLimitPerMin),
	"IPT_RATE_LIMIT_PER_HOUR":    strconv.Itoa(config.DefaultIPTRateLimitPerHour),
	"FORCE_HTTPS_EXEMPT_PATHS":   config.DefaultForceHTTPSExemptPaths,
}

func TestAllCarriesTheDefaultsFromConfig(t *testing.T) {
	for key, want := range configDefaults {
		found := false
		for _, v := range All {
			if v.Key == key {
				found = true
				if v.Default != want {
					t.Errorf("%s: default %q, want %q", key, v.Default, want)
				}
				if v.Comment == "" {
					t.Errorf("%s has no comment", key)
				}
			}
		}
		if !found {
			t.Errorf("%s is missing from All", key)
		}
	}
}

func TestEnvExampleCarriesTheDefaultsFromConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	for key, want := range configDefaults {
		line := key + "=" + want
		found := false
		for _, l := range lines {
			if strings.TrimSpace(l) == line {
				found = true
			}
		}
		if !found {
			t.Errorf(".env.example lacks the line %q", line)
		}
	}
}

func TestMigrateFileAppendsMissingSettingsAndKeepsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PAYLOAD_RATE_LIMIT_PER_MIN=12\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	added, err := MigrateFile(path)
	if err != nil {
		t.Fatalf("MigrateFile: %v", err)
	}
	for _, key := range added {
		if key == "PAYLOAD_RATE_LIMIT_PER_MIN" {
			t.Error("PAYLOAD_RATE_LIMIT_PER_MIN was added although the file sets it")
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	content := string(raw)
	if !strings.HasPrefix(content, "PAYLOAD_RATE_LIMIT_PER_MIN=12\n") || strings.Count(content, "PAYLOAD_RATE_LIMIT_PER_MIN=") != 1 {
		t.Errorf("the value set in the file changed:\n%s", content)
	}
	if !strings.Contains(content, "\nIPT_RATE_LIMIT_PER_HOUR="+configDefaults["IPT_RATE_LIMIT_PER_HOUR"]+"\n") {
		t.Errorf("IPT_RATE_LIMIT_PER_HOUR was not appended with its default:\n%s", content)
	}
}
