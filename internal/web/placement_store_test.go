//go:build cgo
// +build cgo

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/model"
)

func TestNewPlacementTestsGetTheConfiguredTokenLength(t *testing.T) {
	for _, n := range []int{config.MinIPTTokenLength, config.DefaultIPTTokenLength, 41} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			srv, st := newStoreTestServer(t, func(c *config.Config) { c.IPTTokenLength = n })
			ctx := context.Background()
			mb, err := st.CreateMailbox(ctx, "t0kenb0x"+strconv.Itoa(n), "t0kenb0x"+strconv.Itoa(n)+"@example.test", "", "127.0.0.1", time.Hour)
			if err != nil {
				t.Fatalf("create mailbox: %v", err)
			}

			rr := serve(srv, http.MethodPost, "/api/mailboxes/"+mb.Token+"/ipt/start", `{"selected_providers":["Testmail"]}`, "203.0.113.9", "en")
			if rr.Code != http.StatusOK {
				t.Fatalf("start: status %d body %s", rr.Code, rr.Body.String())
			}
			body := decodeJSON(t, rr)
			token, _ := body["placement_token"].(string)
			if len(token) != n || !hexToken.MatchString(token) {
				t.Fatalf("placement_token %q: want %d hexadecimal characters", token, n)
			}
			if body["subject_tag"] != "[SR-"+token+"]" {
				t.Errorf("subject_tag = %q, want [SR-%s]", body["subject_tag"], token)
			}
			pt, err := st.GetPlacementTest(ctx, token)
			if err != nil || pt.MailboxID != mb.ID {
				t.Fatalf("stored test: %+v, %v", pt, err)
			}
			if rr := serve(srv, http.MethodGet, "/api/mailboxes/"+mb.Token+"/ipt/"+token, "", "203.0.113.9", "en"); rr.Code != http.StatusOK {
				t.Errorf("result route: status %d, want 200", rr.Code)
			}
		})
	}
}

// TestReportPlacementDialogCarriesItsMailbox renders a report with placement
// tests switched on: the script of the placement dialog takes the mailbox
// token from the page data, for plain and for encrypted reports alike.
func TestReportPlacementDialogCarriesItsMailbox(t *testing.T) {
	srv, st := newStoreTestServer(t, nil)
	ctx := context.Background()
	for _, publicKey := range []string{"", "cHVibGljLWtleS1mb3ItdGhlLXRlc3Q"} {
		token := "rep0rtb0x" + strconv.Itoa(len(publicKey))
		mb, err := st.CreateMailbox(ctx, token, token+"@example.test", publicKey, "127.0.0.1", time.Hour)
		if err != nil {
			t.Fatalf("create mailbox: %v", err)
		}
		msg, err := st.SaveMessage(ctx, model.Message{
			MailboxID: mb.ID, SMTPFrom: "sender@example.org", RCPTTo: mb.Address, RemoteIP: "203.0.113.20",
			HELO: "mx.example.org", ReceivedAt: time.Now().UTC(), RawSource: "Subject: Demo\r\n\r\nHallo",
			HeaderBlock: "Subject: Demo", Subject: "Demo", SizeBytes: 24,
		})
		if err != nil {
			t.Fatalf("save message: %v", err)
		}
		if _, err := st.SaveReport(ctx, model.AnalysisReport{
			MessageID: msg.ID, CreatedAt: time.Now().UTC(), Score: 8, ScoreLabel: "Good",
			Checks: []model.CheckResult{{ID: "spf", Name: "SPF", Status: "pass", Summary: "ok"}},
		}); err != nil {
			t.Fatalf("save report: %v", err)
		}

		rr := serve(srv, http.MethodGet, "/report/"+mb.Token+"?msg="+messageReference(mb.Token, msg.ID), "", "203.0.113.11", "de")
		if rr.Code != http.StatusOK {
			t.Fatalf("report %q: status %d", token, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `var IPT_MB_TOKEN = "`+token+`";`) {
			t.Errorf("report %q: the placement dialog script lacks the mailbox token", token)
		}
		if !strings.Contains(body, "mp-ipt-r-start-btn") {
			t.Errorf("report %q: the placement dialog is missing", token)
		}
		if !strings.Contains(body, "Warte auf Zustellung (bis zu 10 Minuten)") {
			t.Errorf("report %q: the placement dialog lacks the test duration", token)
		}
	}
}

// TestPlacementTokenRoutesFollowTheTokenLength stores finished placement tests
// with tokens of several lengths, running and expired, and asks for result and
// events with two settings of IPT_TOKEN_LENGTH.
func TestPlacementTokenRoutesFollowTheTokenLength(t *testing.T) {
	type row struct {
		length  int
		expired bool
	}
	rows := []row{{6, false}, {6, true}, {19, true}, {20, true}, {31, true}, {32, true}, {48, true}}
	for _, setting := range []int{20, config.DefaultIPTTokenLength} {
		t.Run("IPT_TOKEN_LENGTH="+strconv.Itoa(setting), func(t *testing.T) {
			srv, st := newStoreTestServer(t, func(c *config.Config) { c.IPTTokenLength = setting })
			ctx := context.Background()
			mb, err := st.CreateMailbox(ctx, "r0utesb0x", "r0utesb0x@example.test", "", "127.0.0.1", time.Hour)
			if err != nil {
				t.Fatalf("create mailbox: %v", err)
			}
			for i, rw := range rows {
				token := strings.Repeat(strconv.FormatInt(int64(i), 16), rw.length)
				expires := time.Now().Add(5 * time.Minute)
				if rw.expired {
					expires = time.Now().Add(-time.Minute)
				}
				if err := st.CreatePlacementTest(ctx, mb.ID, token, nil, expires); err != nil {
					t.Fatalf("create placement test: %v", err)
				}
				// A finished test lets the events route answer at once.
				if err := st.UpdatePlacementTestResult(ctx, token, nil, "done"); err != nil {
					t.Fatalf("finish placement test: %v", err)
				}

				want := rw.length >= setting || !rw.expired
				name := strconv.Itoa(rw.length) + " characters"
				if rw.expired {
					name += ", expired"
				}
				wantStatus := http.StatusNotFound
				if want {
					wantStatus = http.StatusOK
				}

				result := serve(srv, http.MethodGet, "/api/mailboxes/"+mb.Token+"/ipt/"+token, "", "203.0.113.10", "en")
				if result.Code != wantStatus {
					t.Errorf("%s: result status %d, want %d", name, result.Code, wantStatus)
				}

				reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mb.Token+"/ipt/"+token+"/events", nil).WithContext(reqCtx)
				req.RemoteAddr = "203.0.113.10:40000"
				events := httptest.NewRecorder()
				srv.Handler().ServeHTTP(events, req)
				cancel()
				if events.Code != wantStatus {
					t.Errorf("%s: events status %d, want %d", name, events.Code, wantStatus)
				}
				if want && !strings.Contains(events.Body.String(), "event: done") {
					t.Errorf("%s: events stream %q lacks the done event", name, events.Body.String())
				}
			}
		})
	}
}

// TestPlacementTestsRunForTheConfiguredDuration starts a test with two
// settings of IPT_TEST_DURATION and reads its end from the answer and from the
// store.
func TestPlacementTestsRunForTheConfiguredDuration(t *testing.T) {
	for _, d := range []time.Duration{config.DefaultIPTTestDuration, 3 * time.Minute} {
		t.Run(d.String(), func(t *testing.T) {
			srv, st := newStoreTestServer(t, func(c *config.Config) {
				c.IPTTokenLength = config.DefaultIPTTokenLength
				c.IPTTestDuration = d
			})
			ctx := context.Background()
			name := "dauerb0x" + strconv.Itoa(int(d/time.Minute))
			mb, err := st.CreateMailbox(ctx, name, name+"@example.test", "", "127.0.0.1", time.Hour)
			if err != nil {
				t.Fatalf("create mailbox: %v", err)
			}

			before := time.Now().UTC()
			rr := serve(srv, http.MethodPost, "/api/mailboxes/"+mb.Token+"/ipt/start", `{"selected_providers":["Testmail"]}`, "203.0.113.12", "en")
			after := time.Now().UTC()
			if rr.Code != http.StatusOK {
				t.Fatalf("start: status %d body %s", rr.Code, rr.Body.String())
			}
			body := decodeJSON(t, rr)
			raw, _ := body["expires_at"].(string)
			expires, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				t.Fatalf("expires_at %q: %v", raw, err)
			}
			if expires.Before(before.Add(d)) || expires.After(after.Add(d)) {
				t.Fatalf("expires_at = %s, want %s after the start", expires, d)
			}
			token, _ := body["placement_token"].(string)
			pt, err := st.GetPlacementTest(ctx, token)
			if err != nil {
				t.Fatalf("stored test: %v", err)
			}
			if diff := pt.ExpiresAt.Sub(expires); diff < -time.Second || diff > time.Second {
				t.Fatalf("stored expires_at = %s, answer says %s", pt.ExpiresAt, expires)
			}
		})
	}
}

// TestPlacementDialogNamesTheConfiguredDuration renders the start page with
// placement tests switched on and looks for the duration in the waiting line
// of the dialog, in both languages and for one and several minutes.
func TestPlacementDialogNamesTheConfiguredDuration(t *testing.T) {
	cases := []struct {
		d          time.Duration
		lang, want string
	}{
		{config.DefaultIPTTestDuration, "de", "Warte auf Zustellung (bis zu 10 Minuten)"},
		{3 * time.Minute, "de", "Warte auf Zustellung (bis zu 3 Minuten)"},
		{time.Minute, "de", "Warte auf Zustellung (bis zu 1 Minute)"},
		{3 * time.Minute, "en", "Waiting for delivery (up to 3 minutes)"},
		{time.Minute, "en", "Waiting for delivery (up to 1 minute)"},
	}
	for _, tc := range cases {
		t.Run(tc.lang+"/"+tc.d.String(), func(t *testing.T) {
			srv, _ := newStoreTestServer(t, func(c *config.Config) { c.IPTTestDuration = tc.d })
			rr := serve(srv, http.MethodGet, "/", "", "203.0.113.13", tc.lang)
			if rr.Code != http.StatusOK {
				t.Fatalf("start page: status %d", rr.Code)
			}
			if !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("start page lacks %q", tc.want)
			}
		})
	}
}
