package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func getWithToken(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSiteClientsRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)

	// Empty -> [] never null.
	rec := getWithToken(h, "/api/v1/clients")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"clients":[]`) {
		t.Fatalf("empty: %d %q", rec.Code, rec.Body.String())
	}

	be.siteClients = []SiteClientView{{MAC: "aa:bb:cc:dd:ee:ff", Hostname: "phone", Connected: true, AP: "f0:9f:c2:84:8f:2a", APName: "office-ceiling", SSID: "TNG", Since: 100}}
	rec = getWithToken(h, "/api/v1/clients")
	var env struct {
		Clients []SiteClientView `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || len(env.Clients) != 1 || env.Clients[0].APName != "office-ceiling" {
		t.Fatalf("clients: %v %+v", err, env)
	}

	// Token gate.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/api/v1/clients", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec2.Code)
	}
}

func TestEventsRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)

	// History off: enabled=false, events is [] not null.
	rec := getWithToken(h, "/api/v1/events")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Fatalf("disabled: %d %q", rec.Code, rec.Body.String())
	}
	if be.lastEventsQuery.Limit != defaultEventsLimit {
		t.Fatalf("default limit = %d", be.lastEventsQuery.Limit)
	}

	be.eventsView = EventsView{Enabled: true, Events: []EventView{{Key: "EVT_WU_Roam", Client: "aa:bb:cc:dd:ee:ff", Msg: "x roamed"}}}
	rec = getWithToken(h, "/api/v1/events?client=AA-BB-CC-DD-EE-FF&ap=f0:9f:c2:84:8f:2a&key=EVT_WU_Roam&since=2026-01-02T03:04:05Z&until=1800000000&limit=10")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "EVT_WU_Roam") {
		t.Fatalf("query: %d %q", rec.Code, rec.Body.String())
	}
	q := be.lastEventsQuery
	if q.Client != "aa:bb:cc:dd:ee:ff" || q.AP != "f0:9f:c2:84:8f:2a" || q.Key != "EVT_WU_Roam" || q.Limit != 10 ||
		!q.Since.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) || !q.Until.Equal(time.Unix(1800000000, 0)) {
		t.Fatalf("query = %+v", q)
	}

	for _, bad := range []string{"client=zz", "ap=zz", "since=yesterday", "until=-5", "limit=0", "limit=99999", "limit=abc"} {
		if rec := getWithToken(h, "/api/v1/events?"+bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rec.Code)
		}
	}
}

func TestClientHistoryRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)

	rec := getWithToken(h, "/api/v1/clients/AA-BB-CC-DD-EE-FF/history")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"intervals":[]`) {
		t.Fatalf("empty: %d %q", rec.Code, rec.Body.String())
	}
	if be.lastHistoryMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("backend got %q, want normalized colon-hex", be.lastHistoryMAC)
	}

	be.historyView = ClientHistoryView{Enabled: true, Client: "aa:bb:cc:dd:ee:ff", Intervals: []AssignmentView{{AP: "f0:9f:c2:84:8f:2a", From: 1000}}}
	rec = getWithToken(h, "/api/v1/clients/aa:bb:cc:dd:ee:ff/history")
	var v ClientHistoryView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || !v.Enabled || len(v.Intervals) != 1 {
		t.Fatalf("history: %v %+v", err, v)
	}

	if rec := getWithToken(h, "/api/v1/clients/zz/history"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad mac: %d, want 400", rec.Code)
	}
}
