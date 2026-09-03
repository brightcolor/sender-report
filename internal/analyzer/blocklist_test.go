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
