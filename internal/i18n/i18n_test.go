package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectReadsTheNamedCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.8")
	req.AddCookie(&http.Cookie{Name: "ui_language", Value: "de"})

	if got := Detect(req, "ui_language"); got != DE {
		t.Errorf("Detect with the cookie name = %q, want de", got)
	}
	if got := Detect(req, "sr_lang"); got != EN {
		t.Errorf("Detect with another cookie name = %q, want en from Accept-Language", got)
	}
}

func TestDetectIgnoresUnknownCookieValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "de-DE")
	req.AddCookie(&http.Cookie{Name: "sr_lang", Value: "fr"})

	if got := Detect(req, "sr_lang"); got != DE {
		t.Errorf("Detect = %q, want de from Accept-Language", got)
	}
}
