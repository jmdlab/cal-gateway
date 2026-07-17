// PROPFIND on the root "/": go-webdav (depth-based routing constraint, see
// internal/caldav/backend.go) serves ONLY current-user-principal there —
// principal-URL and calendar-home-set answer 404. But when macOS loses/resets
// the account's "server path", dataaccessd rediscovers from "/" by asking for
// EVERYTHING at once and, if it does not see calendar-home-set, gives up with
// "No calendar location specified" (observed in prod 2026-07-16) instead of
// following the principal. So we answer the root PROPFIND ourselves with the
// full set: principal, principal-URL, home set, resourcetype.
package server

import (
	"encoding/xml"
	"io"
	"net/http"
)

// interceptRootPropfind answers PROPFIND on "/" (any depth — the root has no
// WebDAV children here); everything else falls through to the go-webdav
// handler. principalPath/homeSetPath must reflect the caldav backend layout
// ("/{user}/" and "/{user}/calendars/").
func interceptRootPropfind(principalPath, homeSetPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PROPFIND" || r.URL.Path != "/" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writeRootPropfind(w, principalPath, homeSetPath)
	})
}

// writeRootPropfind emits the root multistatus. We always serve the four
// discovery properties, regardless of those requested: extra properties have
// never made a client fail, missing ones do.
func writeRootPropfind(w io.Writer, principalPath, homeSetPath string) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)

	dav := func(local string) xml.Name { return xml.Name{Space: "DAV:", Local: local} }
	caldavNS := "urn:ietf:params:xml:ns:caldav"

	start := xml.StartElement{Name: dav("multistatus")}
	enc.EncodeToken(start)
	resp := xml.StartElement{Name: dav("response")}
	enc.EncodeToken(resp)
	enc.EncodeElement("/", xml.StartElement{Name: dav("href")})

	ps := xml.StartElement{Name: dav("propstat")}
	enc.EncodeToken(ps)
	prop := xml.StartElement{Name: dav("prop")}
	enc.EncodeToken(prop)

	// <current-user-principal><href>…</href></current-user-principal>
	hrefIn := func(outer xml.Name, value string) {
		el := xml.StartElement{Name: outer}
		enc.EncodeToken(el)
		enc.EncodeElement(value, xml.StartElement{Name: dav("href")})
		enc.EncodeToken(el.End())
	}
	hrefIn(dav("current-user-principal"), principalPath)
	hrefIn(dav("principal-URL"), principalPath)
	hrefIn(xml.Name{Space: caldavNS, Local: "calendar-home-set"}, homeSetPath)

	rt := xml.StartElement{Name: dav("resourcetype")}
	enc.EncodeToken(rt)
	col := xml.StartElement{Name: dav("collection")}
	enc.EncodeToken(col)
	enc.EncodeToken(col.End())
	enc.EncodeToken(rt.End())

	enc.EncodeToken(prop.End())
	enc.EncodeElement("HTTP/1.1 200 OK", xml.StartElement{Name: dav("status")})
	enc.EncodeToken(ps.End())

	enc.EncodeToken(resp.End())
	enc.EncodeToken(start.End())
	enc.Flush()
}
