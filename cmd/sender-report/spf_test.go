package main

import "testing"

// TestPTRNameUnderDomain guards the SPF ptr mechanism against the two ways its
// suffix comparison used to be wrong.
//
// With an empty domain — which is what `ptr` without a value produced, since
// RFC 7208 §5.5 says it defaults to the current domain and that default was
// missing — strings.HasSuffix(host, "") is true for every name. A record
// ending in `ptr -all` therefore authorised every IP on the internet, the exact
// opposite of what it states. Without the label boundary, an attacker's
// "notexample.org" passed for "example.org".
func TestPTRNameUnderDomain(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"mail.example.org", "example.org", true},
		{"example.org", "example.org", true},
		{"MAIL.EXAMPLE.ORG", "example.org", true},
		{"mail.example.org.", "example.org", true},
		{"a.b.example.org", "example.org", true},

		{"notexample.org", "example.org", false},
		{"evil-example.org", "example.org", false},
		{"example.org.attacker.net", "example.org", false},
		{"mail.example.com", "example.org", false},

		// The empty-domain case: every one of these must be false.
		{"mail.example.org", "", false},
		{"anything.at.all", "", false},
		{"", "example.org", false},
		{"", "", false},
	}

	for _, tc := range cases {
		if got := ptrNameUnderDomain(tc.host, tc.domain); got != tc.want {
			t.Errorf("ptrNameUnderDomain(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

// TestSPFLookupBudgetIsAConstant documents why the limit is not the recursion
// depth: RFC 7208 §4.6.4 counts DNS-querying mechanisms across the whole
// evaluation, so twenty includes side by side must fail even though none of
// them nests.
func TestSPFLookupBudgetIsAConstant(t *testing.T) {
	if spfLookupBudget != 10 {
		t.Errorf("spfLookupBudget = %d, want 10 (RFC 7208 §4.6.4)", spfLookupBudget)
	}
}
