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
