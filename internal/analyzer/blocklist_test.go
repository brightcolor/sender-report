package analyzer

import "testing"

// TestRBLQueryRefusal covers both directions in which the refusal detection was
// wrong, and both cost the sender something.
//
// Only two of Spamhaus's error codes were recognised, so the others counted as
// listings — the report then told a sender to file a delisting request for a
// listing that never existed. And 127.0.0.1, which several lists use as a test
// entry or as "query blocked", was read the same way.
func TestRBLQueryRefusal(t *testing.T) {
	refusals := []string{
		"127.255.255.252", // typing error / no such zone
		"127.255.255.253", // query via open resolver
		"127.255.255.254", // query limit exceeded
		"127.255.255.255", // blocked
		"127.0.0.1",       // test entry / query blocked
	}
	for _, ip := range refusals {
		if !rblQueryRefusal([]string{ip}) {
			t.Errorf("rblQueryRefusal(%q) = false — a provider error would be reported as a listing", ip)
		}
	}

	listings := []string{
		"127.0.0.2",  // the standard "listed" answer
		"127.0.0.3",  // spam source
		"127.0.0.4",  // exploit
		"127.0.0.10", // policy block list
		"127.0.0.11",
	}
	for _, ip := range listings {
		if rblQueryRefusal([]string{ip}) {
			t.Errorf("rblQueryRefusal(%q) = true — a real listing would be swallowed", ip)
		}
	}

	t.Run("one refusal among answers still counts as a refusal", func(t *testing.T) {
		if !rblQueryRefusal([]string{"127.0.0.2", "127.255.255.254"}) {
			t.Error("mixed response with an error code must not be trusted as a listing")
		}
	})

	t.Run("empty response is not a refusal", func(t *testing.T) {
		if rblQueryRefusal(nil) {
			t.Error("no addresses is not a refusal")
		}
	})
}

// TestRBLAllProvidersSilentIsNotAPass documents the rule the code now follows:
// a check whose providers all failed to answer may not report "not listed", and
// certainly not award the bonus point that came with it. The counting logic
// lives in rblHeuristics, which needs DNS; this test pins the invariant that
// makes it correct — an unanswered provider must not be counted as answered.
func TestRBLAllProvidersSilentIsNotAPass(t *testing.T) {
	// A refusal response is exactly the case that used to slip through as
	// "answered, and nothing found".
	if !rblQueryRefusal([]string{"127.255.255.254"}) {
		t.Fatal("precondition: a rate-limit answer must count as a refusal")
	}
	// And the standard listing response must stay a listing, or the mirror
	// error would be introduced: a real listing reported as clean.
	if rblQueryRefusal([]string{"127.0.0.2"}) {
		t.Fatal("a listing must not be swallowed as a refusal")
	}
}

// TestHELOIPLiteralIsRecognised covers the branch that gave a bonus point to
// the very form RFC 5321 §4.1.3 prescribes. net.ParseIP rejects the bracketed
// notation, and it contains no dot outside the brackets either, so a correctly
// formatted IP literal fell through to "looks plausible" while the bare form
// was flagged — the standard-conforming spelling scored better than the
// non-conforming one.
func TestHELOIPLiteralIsRecognised(t *testing.T) {
	literals := []string{
		"203.0.113.5",
		"[203.0.113.5]",
		"[IPv6:2001:db8::1]",
		"[ipv6:2001:db8::1]",
		"2001:db8::1",
	}
	for _, h := range literals {
		if !isIPLiteralHELO(h) {
			t.Errorf("isIPLiteralHELO(%q) = false — this would be scored as a plausible hostname", h)
		}
	}

	hostnames := []string{
		"mail.example.org",
		"smtp.versand.example",
		"[not-an-ip]",
		"example.org",
	}
	for _, h := range hostnames {
		if isIPLiteralHELO(h) {
			t.Errorf("isIPLiteralHELO(%q) = true — a real hostname would be penalised", h)
		}
	}
}

// TestSpamAssassinNearMiss covers the gap between "not spam here" and "not spam
// anywhere": every receiver sets its own limit, and many are stricter than the
// default of 5.0.
func TestSpamAssassinNearMiss(t *testing.T) {
	cases := []struct {
		line       string
		wantScore  float64
		wantLimit  float64
		wantParsed bool
	}{
		{"Spam: False ; 4.9 / 5.0", 4.9, 5.0, true},
		{"Spam: False ; 0.1 / 5.0", 0.1, 5.0, true},
		{"Spam: True ; 12.4 / 5.0", 12.4, 5.0, true},
		{"Spam: False ; -1.2 / 5.0", -1.2, 5.0, true},
		{"Spam: False", 0, 0, false},
		{"kein Score hier", 0, 0, false},
	}
	for _, tc := range cases {
		score, limit, ok := parseSpamAssassinScore(tc.line)
		if ok != tc.wantParsed {
			t.Errorf("parseSpamAssassinScore(%q): parsed = %v, want %v", tc.line, ok, tc.wantParsed)
			continue
		}
		if ok && (score != tc.wantScore || limit != tc.wantLimit) {
			t.Errorf("parseSpamAssassinScore(%q) = %v/%v, want %v/%v", tc.line, score, limit, tc.wantScore, tc.wantLimit)
		}
	}
}

// TestTLSTransportUsesTheFinalHop covers where the verdict comes from. Scanning
// every Received line at once let a "TLS" written by some earlier system decide
// the result, even when the last leg — the delivery to this server, the only one
// this server can vouch for — was in the clear.
func TestTLSTransportUsesTheFinalHop(t *testing.T) {
	t.Run("encrypted delivery to us passes", func(t *testing.T) {
		got := tlsTransportCheck([]string{
			"from mail.example.org ([203.0.113.5]) by sender.report with ESMTPS; Mon, 1 Sep 2026 10:00:00 +0000",
			"from old.example.net by mail.example.org with SMTP; Mon, 1 Sep 2026 09:59:00 +0000",
		})
		if got.Status != "pass" {
			t.Errorf("status = %q, want pass (%q)", got.Status, got.Summary)
		}
	})

	t.Run("plain delivery to us warns even with TLS earlier in the chain", func(t *testing.T) {
		got := tlsTransportCheck([]string{
			"from relay.example.net ([203.0.113.9]) by sender.report with ESMTP; Mon, 1 Sep 2026 10:00:00 +0000",
			"from origin.example.org by relay.example.net with ESMTPS (TLS1.3); Mon, 1 Sep 2026 09:59:00 +0000",
		})
		if got.Status != "warn" {
			t.Errorf("status = %q, want warn — the last leg was unencrypted (%q)", got.Status, got.Summary)
		}
		if got.ScoreDelta >= 0 {
			t.Errorf("ScoreDelta = %v, want a penalty", got.ScoreDelta)
		}
	})

	t.Run("no Received headers at all", func(t *testing.T) {
		if got := tlsTransportCheck(nil); got.Status != "warn" {
			t.Errorf("status = %q, want warn", got.Status)
		}
	})
}
