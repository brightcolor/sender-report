package ipt

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	pollInterval = 30 * time.Second
	// Spam folder names to probe in order after INBOX.
	// The first one that can be SELECT-ed successfully will be used.
)

var spamFolders = []string{"Spam", "Junk", "[Gmail]/Spam", "Bulk Mail", "Bulk", "Junk E-Mail"}

// PollWithHosts starts one goroutine per seed account. Each goroutine polls
// IMAP every 30 seconds until it finds the message or ctx expires. Results are
// sent to the results channel as each provider resolves; the channel is closed
// when all goroutines have finished. imapHosts[i] is the host:port for infos[i].
func PollWithHosts(
	ctx context.Context,
	infos []SeedInfo,
	accounts []Account,
	imapHosts []string,
	subjectToken string,
	since time.Time,
	results chan<- ProviderResult,
) {
	var wg sync.WaitGroup
	for i := range infos {
		wg.Add(1)
		go func(info SeedInfo, acc Account, host string) {
			defer wg.Done()
			res := pollOne(ctx, info, acc, host, subjectToken, since)
			results <- res
		}(infos[i], accounts[i], imapHosts[i])
	}
	wg.Wait()
	close(results)
}

// pollOne repeatedly tries to find the test message in INBOX and spam folders
// for a single account, until found or ctx expires.
func pollOne(
	ctx context.Context,
	info SeedInfo,
	acc Account,
	imapHost string,
	subjectToken string,
	since time.Time,
) ProviderResult {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Try immediately on first call, then on each tick.
	if folder := tryFind(ctx, acc, imapHost, subjectToken, since); folder != "" {
		return ProviderResult{
			Provider:  info.Provider,
			Address:   info.Address,
			Status:    folderStatus(folder),
			Folder:    folder,
			CheckedAt: time.Now().UTC(),
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ProviderResult{
				Provider:  info.Provider,
				Address:   info.Address,
				Status:    "timeout",
				CheckedAt: time.Now().UTC(),
			}
		case <-ticker.C:
			if folder := tryFind(ctx, acc, imapHost, subjectToken, since); folder != "" {
				return ProviderResult{
					Provider:  info.Provider,
					Address:   info.Address,
					Status:    folderStatus(folder),
					Folder:    folder,
					CheckedAt: time.Now().UTC(),
				}
			}
		}
	}
}

// tryFind opens an IMAP connection, checks INBOX and spam folders for a message
// whose Subject header contains subjectToken and was received SINCE since.
// Returns the folder name where the message was found, or "" if not found.
func tryFind(ctx context.Context, acc Account, imapHost, subjectToken string, since time.Time) string {
	host, _, err := net.SplitHostPort(imapHost)
	if err != nil {
		host = imapHost
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	c, err := imapclient.DialTLS(imapHost, &imapclient.Options{TLSConfig: tlsCfg})
	if err != nil {
		return ""
	}
	defer c.Logout()

	if err := c.Login(acc.User, acc.Pass).Wait(); err != nil {
		return ""
	}

	criteria := &imap.SearchCriteria{
		Since: since,
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: subjectToken},
		},
	}

	// Check INBOX first.
	if found := searchFolder(ctx, c, "INBOX", criteria); found {
		return "INBOX"
	}

	// Try each known spam folder name.
	for _, folder := range spamFolders {
		if found := searchFolder(ctx, c, folder, criteria); found {
			return folder
		}
	}

	return ""
}

// searchFolder selects a mailbox and runs a SEARCH. Returns true if at least
// one message matches.
func searchFolder(_ context.Context, c *imapclient.Client, folder string, criteria *imap.SearchCriteria) bool {
	_, err := c.Select(folder, nil).Wait()
	if err != nil {
		return false
	}
	data, err := c.Search(criteria, nil).Wait()
	if err != nil {
		return false
	}
	return data.Count > 0 || len(data.AllSeqNums()) > 0
}

// folderStatus maps an IMAP folder name to a placement status string.
func folderStatus(folder string) string {
	if folder == "INBOX" {
		return "inbox"
	}
	return "spam"
}
