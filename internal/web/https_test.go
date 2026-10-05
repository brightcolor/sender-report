package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/config"
)

// exemptTestHandler wraps a handler that answers 200 in the HTTPS redirect
// with the given exempt paths.
func exemptTestHandler(paths []string) http.Handler {
	srv := &Server{cfg: config.Config{ForceHTTPS: true, PublicBaseURL: "https://sender.example", ForceHTTPSExemptPaths: paths}}
	return srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestForceHTTPSLeavesTheExemptPathsOnHTTP(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		pass  []string
		moved []string
	}{
		{
			name:  "default list",
			paths: strings.Split(config.DefaultForceHTTPSExemptPaths, ","),
			pass:  []string{"/healthz", "/readyz"},
			moved: []string{"/", "/about", "/metrics", "/healthz/", "/healthzx", "/readyz/x", "/api/payload/a/b"},
		},
		{
			name:  "own list with a subtree",
			paths: []string{"/livez", "/probe/"},
			pass:  []string{"/livez", "/probe/", "/probe/deep/check"},
			moved: []string{"/healthz", "/readyz", "/probe", "/livez/", "/probe/../about", "/probe/./x", "/probe//x"},
		},
		{
			name:  "none",
			paths: []string{},
			moved: []string{"/healthz", "/readyz", "/about"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := exemptTestHandler(tc.paths)
			for _, p := range tc.pass {
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8080"+p, nil))
				if rr.Code != http.StatusOK {
					t.Errorf("%s: status %d, want 200 over plain HTTP", p, rr.Code)
				}
			}
			for _, p := range tc.moved {
				req := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8080/", nil)
				req.URL.Path = p
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusPermanentRedirect || !strings.HasPrefix(rr.Header().Get("Location"), "https://sender.example/") {
					t.Errorf("%s: status %d Location %q, want 308 to https://sender.example", p, rr.Code, rr.Header().Get("Location"))
				}
			}
		})
	}
}

func TestCleanRequestPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/healthz": true, "/probe/": true, "/a/b.c/d": true,
		"": false, "healthz": false, "*": false, "//x": false, "/a//b": false,
		"/a/./b": false, "/a/../b": false, "/..": false, "/a/..": false, "/a/.": false,
	} {
		if got := cleanRequestPath(p); got != want {
			t.Errorf("cleanRequestPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestHealthcheckReachesTheServerWhateverThePublicURL sends the request of the
// container healthcheck (wget http://127.0.0.1:8080/healthz) through the full
// handler with FORCE_HTTPS, once without PUBLIC_BASE_URL and once with it.
func TestHealthcheckReachesTheServerWhateverThePublicURL(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, publicURL := range []string{"", "https://sender.example"} {
		t.Run("PUBLIC_BASE_URL="+publicURL, func(t *testing.T) {
			srv, err := New(config.Config{
				UIDefaultTheme: "auto", WebRateLimitPerMin: 60, WebBurstPer10Sec: 20,
				ForceHTTPS: true, PublicBaseURL: publicURL,
				ForceHTTPSExemptPaths: strings.Split(config.DefaultForceHTTPSExemptPaths, ","),
			}, nil, nil, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			h := srv.Handler()
			for path, want := range map[string]string{"/healthz": "ok", "/readyz": "ready"} {
				req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+path, nil)
				req.RemoteAddr = "127.0.0.1:51000"
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Body.String(), want) {
					t.Errorf("%s: status %d body %q, want 200 %q", path, rr.Code, rr.Body.String(), want)
				}
			}
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/about", nil)
			req.RemoteAddr = "127.0.0.1:51000"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusPermanentRedirect || !strings.HasPrefix(rr.Header().Get("Location"), "https://") {
				t.Errorf("/about: status %d Location %q, want a redirect to HTTPS", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}
