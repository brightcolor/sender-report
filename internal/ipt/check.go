package ipt

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

// AccountStatus holds the result of a connectivity/auth ping for one seed account.
type AccountStatus struct {
	Provider  string
	User      string // never the password
	IMAP      string
	OK        bool
	ErrRaw    string // raw IMAP/TLS error — included in alert emails
	CheckedAt time.Time
}

// PingAccount opens a TLS IMAP connection, authenticates, then logs out.
// It returns nil on success or the raw error on failure.
// A 10-second deadline is applied regardless of the parent context.
func PingAccount(ctx context.Context, acc Account, imapHost string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	host, _, err := net.SplitHostPort(imapHost)
	if err != nil {
		host = imapHost
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := imapclient.DialTLS(imapHost, &imapclient.Options{TLSConfig: tlsCfg})
		if err != nil {
			ch <- result{err}
			return
		}
		defer c.Logout()
		if err := c.Login(acc.User, acc.Pass).Wait(); err != nil {
			ch <- result{err}
			return
		}
		ch <- result{nil}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		return r.err
	}
}

// CheckAll pings every account of every provider and returns one AccountStatus
// per account. Checks run concurrently; results arrive in undefined order.
func CheckAll(ctx context.Context, providers []Provider) []AccountStatus {
	type item struct {
		provider string
		acc      Account
		imap     string
	}
	var items []item
	for _, p := range providers {
		for _, a := range p.Accounts {
			items = append(items, item{p.Name, a, p.IMAP})
		}
	}

	out := make([]AccountStatus, len(items))
	done := make(chan struct{}, len(items))
	for i, it := range items {
		go func(idx int, it item) {
			err := PingAccount(ctx, it.acc, it.imap)
			s := AccountStatus{
				Provider:  it.provider,
				User:      it.acc.User,
				IMAP:      it.imap,
				OK:        err == nil,
				CheckedAt: time.Now().UTC(),
			}
			if err != nil {
				s.ErrRaw = err.Error()
			}
			out[idx] = s
			done <- struct{}{}
		}(i, it)
	}
	for range items {
		<-done
	}
	return out
}
