package server

// Tests of the root PROPFIND interceptor: go-webdav only serves
// current-user-principal on "/", so a client rediscovering from "/" would not
// see calendar-home-set and would give up with "No calendar location
// specified". We answer the full discovery set ourselves; these tests pin the
// principal / home-set / resourcetype hrefs against a refactor regression.

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rootMultistatus maps the DAV:multistatus the root PROPFIND returns.
type rootMultistatus struct {
	XMLName  xml.Name `xml:"DAV: multistatus"`
	Response struct {
		Href     string `xml:"DAV: href"`
		Propstat struct {
			Prop struct {
				CurrentUserPrincipal struct {
					Href string `xml:"DAV: href"`
				} `xml:"DAV: current-user-principal"`
				PrincipalURL struct {
					Href string `xml:"DAV: href"`
				} `xml:"DAV: principal-URL"`
				CalendarHomeSet struct {
					Href string `xml:"DAV: href"`
				} `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set"`
				ResourceType struct {
					Collection *struct{} `xml:"DAV: collection"`
				} `xml:"DAV: resourcetype"`
			} `xml:"DAV: prop"`
			Status string `xml:"DAV: status"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

const (
	testPrincipalPath = "/alice/"
	testHomeSetPath   = "/alice/calendars/"
)

func doRootPropfind(t *testing.T, method, path string) (*httptest.ResponseRecorder, *nextRecorder) {
	t.Helper()
	next := &nextRecorder{}
	h := interceptRootPropfind(testPrincipalPath, testHomeSetPath, next)
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, next
}

// TestRootPropfindServesDiscoverySet: PROPFIND "/" returns 207 with
// current-user-principal, principal-URL, calendar-home-set and a collection
// resourcetype — all four discovery hrefs, whatever was requested.
func TestRootPropfindServesDiscoverySet(t *testing.T) {
	rec, next := doRootPropfind(t, "PROPFIND", "/")
	if next.called {
		t.Fatalf("downstream handler called; root PROPFIND must be intercepted")
	}
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Errorf("missing Content-Type")
	}

	var ms rootMultistatus
	if err := xml.Unmarshal(rec.Body.Bytes(), &ms); err != nil {
		t.Fatalf("multistatus does not parse: %v\n%s", err, rec.Body.String())
	}

	if ms.Response.Href != "/" {
		t.Errorf("response href = %q, want \"/\"", ms.Response.Href)
	}
	prop := ms.Response.Propstat.Prop
	if prop.CurrentUserPrincipal.Href != testPrincipalPath {
		t.Errorf("current-user-principal href = %q, want %q", prop.CurrentUserPrincipal.Href, testPrincipalPath)
	}
	if prop.PrincipalURL.Href != testPrincipalPath {
		t.Errorf("principal-URL href = %q, want %q", prop.PrincipalURL.Href, testPrincipalPath)
	}
	if prop.CalendarHomeSet.Href != testHomeSetPath {
		t.Errorf("calendar-home-set href = %q, want %q", prop.CalendarHomeSet.Href, testHomeSetPath)
	}
	if prop.ResourceType.Collection == nil {
		t.Errorf("resourcetype missing <collection>")
	}
	if ms.Response.Propstat.Status != "HTTP/1.1 200 OK" {
		t.Errorf("propstat status = %q, want \"HTTP/1.1 200 OK\"", ms.Response.Propstat.Status)
	}
}

// TestRootPropfindPassesNonRoot: a PROPFIND on a non-root path falls through
// to the go-webdav handler.
func TestRootPropfindPassesNonRoot(t *testing.T) {
	_, next := doRootPropfind(t, "PROPFIND", "/alice/")
	if !next.called {
		t.Fatalf("non-root PROPFIND should have passed to the downstream handler")
	}
}

// TestRootPropfindPassesOtherVerbs: a non-PROPFIND verb on "/" falls through.
func TestRootPropfindPassesOtherVerbs(t *testing.T) {
	_, next := doRootPropfind(t, http.MethodGet, "/")
	if !next.called {
		t.Fatalf("GET / should have passed to the downstream handler")
	}
}
