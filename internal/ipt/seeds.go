package ipt

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"
)

// Account holds IMAP credentials for a single seed account.
type Account struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Provider is a mail provider with one or more seed accounts.
type Provider struct {
	Name     string    `json:"name"`
	IMAP     string    `json:"imap"` // host:port, e.g. "imap.gmail.com:993"
	Accounts []Account `json:"accounts"`
}

// SeedConfig is the parsed seeds.json file.
type SeedConfig struct {
	Providers []Provider `json:"providers"`
}

// SeedInfo is the client-visible view of a selected seed — no credentials.
type SeedInfo struct {
	Provider string `json:"provider"`
	Address  string `json:"address"`
}

// ProviderResult is the outcome of one provider's placement check.
type ProviderResult struct {
	Provider  string    `json:"provider"`
	Address   string    `json:"address"`
	Status    string    `json:"status"` // "inbox" | "spam" | "pending" | "timeout"
	Folder    string    `json:"folder,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// PlacementTest is the DB model for an inbox placement test run.
type PlacementTest struct {
	ID             int64
	MailboxID      int64
	PlacementToken string
	Status         string // "waiting" | "running" | "done" | "timeout"
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Seeds          []SeedInfo
	Results        []ProviderResult
}

// LoadSeeds parses the JSON file at path.
// Returns nil, nil when path is empty (feature stays disabled without error).
func LoadSeeds(path string) (*SeedConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seeds file %q: %w", path, err)
	}
	var sc SeedConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("parse seeds file %q: %w", path, err)
	}
	return &sc, nil
}

// Validate returns an error if the config has obvious problems.
func (sc *SeedConfig) Validate() error {
	if len(sc.Providers) == 0 {
		return fmt.Errorf("seeds.json: no providers configured")
	}
	for i, p := range sc.Providers {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("seeds.json: provider[%d] has no name", i)
		}
		if !strings.Contains(p.IMAP, ":") {
			return fmt.Errorf("seeds.json: provider %q: imap must be host:port", p.Name)
		}
		if len(p.Accounts) == 0 {
			return fmt.Errorf("seeds.json: provider %q has no accounts", p.Name)
		}
		for j, a := range p.Accounts {
			if a.User == "" || a.Pass == "" {
				return fmt.Errorf("seeds.json: provider %q account[%d]: user and pass required", p.Name, j)
			}
		}
	}
	return nil
}

// ProviderNames returns the names of all configured providers.
func (sc *SeedConfig) ProviderNames() []string {
	names := make([]string, len(sc.Providers))
	for i, p := range sc.Providers {
		names[i] = p.Name
	}
	return names
}

// Filter returns only the providers whose names are in selected.
// If selected is empty, all providers are returned.
func (sc *SeedConfig) Filter(selected []string) []Provider {
	if len(selected) == 0 {
		return sc.Providers
	}
	want := make(map[string]bool, len(selected))
	for _, s := range selected {
		want[strings.ToLower(s)] = true
	}
	out := make([]Provider, 0, len(selected))
	for _, p := range sc.Providers {
		if want[strings.ToLower(p.Name)] {
			out = append(out, p)
		}
	}
	return out
}

// Pick randomly selects one account per provider.
// Returns two parallel slices: SeedInfo (client-safe) and Account (server-only).
func Pick(providers []Provider) ([]SeedInfo, []Account) {
	infos := make([]SeedInfo, 0, len(providers))
	accounts := make([]Account, 0, len(providers))
	for _, p := range providers {
		idx := rand.IntN(len(p.Accounts))
		acc := p.Accounts[idx]
		infos = append(infos, SeedInfo{Provider: p.Name, Address: acc.User})
		accounts = append(accounts, acc)
	}
	return infos, accounts
}
