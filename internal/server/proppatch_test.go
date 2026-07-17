package server

// Tests of the PROPPATCH interceptor: go-webdav answers 501, which breaks
// dataaccessd's sync, so we intercept and answer a 207 multistatus that
// accepts each requested property (propstat 200). These tests pin that shape —
// they guard a proven macOS "Error 2" fix against a refactor regression.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"encoding/xml"
)

// proppatchMultistatus maps the DAV:multistatus a PROPPATCH returns so the
// tests can assert its shape (href, per-prop names, propstat status).
type proppatchMultistatus struct {
	XMLName  xml.Name `xml:"DAV: multistatus"`
	Response []struct {
		Href     string `xml:"DAV: href"`
		Propstat []struct {
			Prop struct {
				Names []xml.Name `xml:",any"`
			} `xml:"DAV: prop"`
			Status string `xml:"DAV: status"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

// doProppatch runs a PROPPATCH through the interceptor and returns the parsed
// multistatus (fatal on any malformed XML).
func doProppatch(t *testing.T, path, body string) (*httptest.ResponseRecorder, proppatchMultistatus) {
	t.Helper()
	next := &nextRecorder{}
	h := interceptProppatch(next)

	req := httptest.NewRequest("PROPPATCH", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if next.called {
		t.Fatalf("downstream handler called; PROPPATCH must be fully intercepted")
	}
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	var ms proppatchMultistatus
	if err := xml.Unmarshal(rec.Body.Bytes(), &ms); err != nil {
		t.Fatalf("multistatus does not parse: %v\n%s", err, rec.Body.String())
	}
	return rec, ms
}

func TestProppatchAcceptsRequestedProps(t *testing.T) {
	const appleNS = "http://apple.com/ns/ical/"
	cases := []struct {
		name      string
		body      string
		wantHref  string
		wantNames []xml.Name
	}{
		{
			name: "set calendar-color and calendar-order",
			body: `<?xml version="1.0" encoding="utf-8"?>` +
				`<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">` +
				`<D:set><D:prop>` +
				`<A:calendar-color>#FF0000FF</A:calendar-color>` +
				`<A:calendar-order>3</A:calendar-order>` +
				`</D:prop></D:set></D:propertyupdate>`,
			wantHref: "/alice/calendars/cal1/",
			wantNames: []xml.Name{
				{Space: appleNS, Local: "calendar-color"},
				{Space: appleNS, Local: "calendar-order"},
			},
		},
		{
			name: "remove is echoed too",
			body: `<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">` +
				`<D:remove><D:prop><A:calendar-color/></D:prop></D:remove>` +
				`</D:propertyupdate>`,
			wantHref:  "/alice/calendars/cal2/",
			wantNames: []xml.Name{{Space: appleNS, Local: "calendar-color"}},
		},
		{
			name: "arbitrary namespace preserved",
			body: `<D:propertyupdate xmlns:D="DAV:" xmlns:X="urn:example:ns">` +
				`<D:set><D:prop><X:custom-flag>1</X:custom-flag></D:prop></D:set>` +
				`</D:propertyupdate>`,
			wantHref:  "/alice/calendars/cal3/",
			wantNames: []xml.Name{{Space: "urn:example:ns", Local: "custom-flag"}},
		},
		{
			name:      "empty body still yields one accepting propstat",
			body:      "",
			wantHref:  "/alice/calendars/cal4/",
			wantNames: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ms := doProppatch(t, tc.wantHref, tc.body)

			if len(ms.Response) != 1 {
				t.Fatalf("response count = %d, want 1", len(ms.Response))
			}
			resp := ms.Response[0]
			if resp.Href != tc.wantHref {
				t.Errorf("href = %q, want %q", resp.Href, tc.wantHref)
			}
			if len(resp.Propstat) != 1 {
				t.Fatalf("propstat count = %d, want 1", len(resp.Propstat))
			}
			ps := resp.Propstat[0]
			if !strings.Contains(ps.Status, "200 OK") {
				t.Errorf("status = %q, want it to accept (200 OK)", ps.Status)
			}
			if len(ps.Prop.Names) != len(tc.wantNames) {
				t.Fatalf("prop names = %v, want %v", ps.Prop.Names, tc.wantNames)
			}
			got := make(map[xml.Name]bool, len(ps.Prop.Names))
			for _, n := range ps.Prop.Names {
				got[n] = true
			}
			for _, want := range tc.wantNames {
				if !got[want] {
					t.Errorf("prop %v missing from propstat (got %v)", want, ps.Prop.Names)
				}
			}
		})
	}
}

// TestProppatchPassesOtherVerbs: any non-PROPPATCH verb falls through to the
// downstream handler untouched.
func TestProppatchPassesOtherVerbs(t *testing.T) {
	next := &nextRecorder{}
	h := interceptProppatch(next)
	req := httptest.NewRequest(http.MethodGet, "/alice/calendars/cal1/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !next.called {
		t.Fatalf("GET should have passed to the downstream handler")
	}
}
