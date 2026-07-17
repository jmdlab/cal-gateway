// PROPFIND on the principal "/{user}/": go-webdav does not serve
// calendar-user-address-set (RFC 6638 §2.4.1, no occurrence in the module) —
// yet macOS Calendar HIDES the "Add invitees" field of an account whose
// principal does not announce which email address it represents (seen in prod
// 2026-07-16: no-invitees UI as long as the property is missing). So we answer
// the principal PROPFIND ourselves with the full set, same doctrine as
// rootpropfind.go: serve every useful discovery property, extras have never
// broken a client.
//
// Added on top are the RFC 6638 scheduling properties (schedule-inbox-URL,
// schedule-outbox-URL, calendar-user-type): the address alone is NOT enough,
// macOS only enables a network CalDAV account's invitees UI if the principal
// also announces scheduling — see scheduling.go for the collections.
package server

import (
	"encoding/xml"
	"io"
	"net/http"
)

// interceptPrincipalPropfind answers Depth:0 PROPFIND on the principal;
// everything else falls through to the go-webdav handler (the home set's
// Depth:1, etc.). addresses = the account's email addresses
// (calendar-user-address-set).
func interceptPrincipalPropfind(principalPath, homeSetPath, inboxPath, outboxPath, displayName string, addresses []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PROPFIND" || r.URL.Path != principalPath || r.Header.Get("Depth") == "1" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writePrincipalPropfind(w, principalPath, homeSetPath, inboxPath, outboxPath, displayName, addresses)
	})
}

// writePrincipalPropfind emits the principal's multistatus.
func writePrincipalPropfind(w io.Writer, principalPath, homeSetPath, inboxPath, outboxPath, displayName string, addresses []string) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)

	dav := func(local string) xml.Name { return xml.Name{Space: nsDAV, Local: local} }
	cal := func(local string) xml.Name { return xml.Name{Space: nsCalDAV, Local: local} }

	start := xml.StartElement{Name: dav("multistatus")}
	enc.EncodeToken(start)
	resp := xml.StartElement{Name: dav("response")}
	enc.EncodeToken(resp)
	enc.EncodeElement(principalPath, xml.StartElement{Name: dav("href")})

	ps := xml.StartElement{Name: dav("propstat")}
	enc.EncodeToken(ps)
	prop := xml.StartElement{Name: dav("prop")}
	enc.EncodeToken(prop)

	hrefIn := func(outer xml.Name, values ...string) {
		el := xml.StartElement{Name: outer}
		enc.EncodeToken(el)
		for _, v := range values {
			enc.EncodeElement(v, xml.StartElement{Name: dav("href")})
		}
		enc.EncodeToken(el.End())
	}
	hrefIn(dav("current-user-principal"), principalPath)
	hrefIn(dav("principal-URL"), principalPath)
	hrefIn(cal("calendar-home-set"), homeSetPath)

	// Scheduling RFC 6638: the inbox/outbox collections (served by
	// scheduling.go) and the principal type. calendar-user-type is emitted in
	// BOTH namespaces — CALDAV (RFC 6638 §2.4.2, the canonical one) and
	// calendarserver.org (the CalendarServer legacy some Apple clients probe) —
	// a harmless duplicate, a blocking absence.
	hrefIn(cal("schedule-inbox-URL"), inboxPath)
	hrefIn(cal("schedule-outbox-URL"), outboxPath)
	enc.EncodeElement("INDIVIDUAL", xml.StartElement{Name: cal("calendar-user-type")})
	enc.EncodeElement("INDIVIDUAL", xml.StartElement{Name: xml.Name{Space: nsCalServer, Local: "calendar-user-type"}})

	// calendar-user-address-set: the iCalendar addresses (mailto:) this
	// principal represents — THE trigger for Apple's invitees UI.
	mailtos := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, a := range addresses {
		if a != "" && !seen[a] {
			seen[a] = true
			mailtos = append(mailtos, "mailto:"+a)
		}
	}
	if len(mailtos) > 0 {
		hrefIn(cal("calendar-user-address-set"), mailtos...)
	}

	if displayName != "" {
		enc.EncodeElement(displayName, xml.StartElement{Name: dav("displayname")})
	}

	// resourcetype: collection + principal (RFC 3744).
	rt := xml.StartElement{Name: dav("resourcetype")}
	enc.EncodeToken(rt)
	for _, n := range []xml.Name{dav("collection"), dav("principal")} {
		el := xml.StartElement{Name: n}
		enc.EncodeToken(el)
		enc.EncodeToken(el.End())
	}
	enc.EncodeToken(rt.End())

	enc.EncodeToken(prop.End())
	enc.EncodeElement("HTTP/1.1 200 OK", xml.StartElement{Name: dav("status")})
	enc.EncodeToken(ps.End())

	enc.EncodeToken(resp.End())
	enc.EncodeToken(start.End())
	enc.Flush()
}
