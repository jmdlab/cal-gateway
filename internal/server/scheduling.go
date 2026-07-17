// CalDAV Scheduling announcement (RFC 6638) — the MISSING trigger for macOS
// Calendar's "Add invitees" UI: for a network CalDAV account, dataaccessd only
// enables the invitees field if the server announces scheduling
// (`calendar-auto-schedule` token in the OPTIONS DAV header +
// schedule-inbox-URL/schedule-outbox-URL on the principal). Our iMIP sending
// already exists (implicit scheduling: macOS PUTs the event with
// ORGANIZER+ATTENDEE, the backend sends — M5a/M5b); this file only adds the
// ANNOUNCEMENT and the minimal endpoints macOS probes:
//
//   - /{user}/inbox/  : schedule-inbox, a permanently EMPTY collection (we
//     store no incoming iTIP message — invitee replies arrive by email at
//     Proton, not here). PROPFIND/OPTIONS/GET/REPORT served, never 404.
//   - /{user}/outbox/ : schedule-outbox. macOS POSTs a VFREEBUSY iTIP
//     (METHOD:REQUEST) there to show an invitee's availability BEFORE sending.
//     We know no one's availability → for each ATTENDEE we reply `2.0;Success`
//     with a VFREEBUSY holding no busy range (= all free). A 5xx here would
//     make ADDING the invitee fail, hence the always-positive reply.
//
// Routing CONSTRAINT: inbox/outbox are at depth 2, the same as the home set —
// go-webdav v0.7.0 routes by DEPTH (see the layout comment in
// internal/caldav/backend.go) and would treat them as a home set. So we
// intercept them ENTIRELY here, before the go-webdav handler, for ALL verbs.
package server

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

// XML namespaces of the scheduling properties.
const (
	nsDAV       = "DAV:"
	nsCalDAV    = "urn:ietf:params:xml:ns:caldav"
	nsCalServer = "http://calendarserver.org/ns/"
)

// davAutoSchedule is the capability set announced on OPTIONS: go-webdav's
// ("1, 3, calendar-access") + the RFC 6638 §2.1 token. We announce ONLY
// calendar-auto-schedule (implicit scheduling) — NOT `calendar-schedule` (the
// old explicit scheduling), which would invite macOS to post the invitations
// itself to the outbox instead of PUTting the event.
const davAutoSchedule = "1, 3, calendar-access, calendar-auto-schedule"

// outboxMaxBody bounds an outbox POST body: a real VFREEBUSY iTIP is a few
// hundred bytes, 1 MiB is already very generous.
const outboxMaxBody = 1 << 20

// appendAutoScheduleDAV adds `calendar-auto-schedule` to the DAV header of
// EVERY OPTIONS response served by the downstream chain (principal, home set,
// calendar collections — where go-webdav sets "1, 3, calendar-access"). The
// extra token on a non-scheduling resource has never bothered a client; its
// ABSENCE on the principal disables the invitees UI. The other headers (Allow,
// etc.) are left intact: we only touch DAV, at WriteHeader time.
func appendAutoScheduleDAV(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&davHeaderAppender{ResponseWriter: w}, r)
	})
}

// davHeaderAppender intercepts WriteHeader to complete the DAV header (headers
// can no longer be modified afterwards).
type davHeaderAppender struct {
	http.ResponseWriter
	wrote bool
}

func (d *davHeaderAppender) WriteHeader(code int) {
	if !d.wrote {
		d.wrote = true
		h := d.Header()
		if dav := h.Get("DAV"); dav != "" && !strings.Contains(dav, "calendar-auto-schedule") {
			h.Set("DAV", dav+", calendar-auto-schedule")
		}
	}
	d.ResponseWriter.WriteHeader(code)
}

func (d *davHeaderAppender) Write(b []byte) (int, error) {
	if !d.wrote {
		d.WriteHeader(http.StatusOK)
	}
	return d.ResponseWriter.Write(b)
}

// interceptScheduling serves the inbox/outbox collections ENTIRELY (all
// verbs); any other path falls through to the next handler.
// defaultCalendarHref resolves the inbox's default calendar
// (schedule-default-calendar-URL) — nil or empty return = property omitted (it
// is optional, macOS copes without it).
func interceptScheduling(inboxPath, outboxPath string, defaultCalendarHref func(ctx context.Context) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case inboxPath:
			serveInbox(w, r, defaultCalendarHref)
		case outboxPath:
			serveOutbox(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// serveInbox: permanently empty schedule-inbox.
func serveInbox(w http.ResponseWriter, r *http.Request, defaultCalendarHref func(ctx context.Context) string) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", davAutoSchedule)
		w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, GET, HEAD")
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		var defaultCal string
		if defaultCalendarHref != nil {
			defaultCal = defaultCalendarHref(r.Context())
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writeScheduleCollectionPropfind(w, r.URL.Path, "schedule-inbox", "Inbox", defaultCal)
	case "REPORT":
		// Empty collection: a multistatus with no response, whatever the REPORT
		// type (calendar-query, multiget, sync-collection).
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writeEmptyMultistatus(w)
	case http.MethodGet, http.MethodHead:
		// GET of an empty collection: 200 with no content, never 404 (macOS
		// probes the path).
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, GET, HEAD")
		http.Error(w, "schedule-inbox: read-only (collection always empty)", http.StatusMethodNotAllowed)
	}
}

// serveOutbox: schedule-outbox, free-busy POST only.
func serveOutbox(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", davAutoSchedule)
		w.Header().Set("Allow", "OPTIONS, PROPFIND, POST")
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writeScheduleCollectionPropfind(w, r.URL.Path, "schedule-outbox", "Outbox", "")
	case http.MethodPost:
		serveOutboxPost(w, r)
	default:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, POST")
		http.Error(w, "schedule-outbox: iTIP POST only", http.StatusMethodNotAllowed)
	}
}

// serveOutboxPost answers macOS's free-busy probe (RFC 6638 §3.2.6): a POST of
// a VCALENDAR METHOD:REQUEST containing a VFREEBUSY with ORGANIZER+ATTENDEE. We
// know no external invitee's availability → for EACH attendee, `request-status
// 2.0;Success` + a VFREEBUSY REPLY with no FREEBUSY range (= no known busy
// time, the invitee appears free). Missing or non-iTIP body → a clean 400
// (never a 5xx: it would make adding the invitee fail on the client).
func serveOutboxPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, outboxMaxBody))
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "schedule-outbox: iTIP body required", http.StatusBadRequest)
		return
	}
	cal, err := ical.NewDecoder(bytes.NewReader(body)).Decode()
	if err != nil {
		http.Error(w, "schedule-outbox: invalid iCalendar", http.StatusBadRequest)
		return
	}

	method := ""
	if p := cal.Props.Get(ical.PropMethod); p != nil {
		method = strings.ToUpper(strings.TrimSpace(p.Value))
	}
	var fb *ical.Component
	for _, child := range cal.Children {
		if child.Name == ical.CompFreeBusy {
			fb = child
			break
		}
	}
	if method != "REQUEST" || fb == nil {
		http.Error(w, "schedule-outbox: only free-busy is supported (METHOD:REQUEST + VFREEBUSY)", http.StatusBadRequest)
		return
	}
	attendees := fb.Props.Values(ical.PropAttendee)
	if len(attendees) == 0 {
		http.Error(w, "schedule-outbox: VFREEBUSY without ATTENDEE", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	writeScheduleResponse(w, fb, attendees)
}

// writeScheduleResponse emits the <C:schedule-response> (RFC 6638 §3.2.9): one
// <C:response> per attendee — recipient, request-status 2.0, and the
// corresponding VFREEBUSY REPLY as calendar-data.
func writeScheduleResponse(w io.Writer, request *ical.Component, attendees []ical.Prop) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)

	caldav := func(local string) xml.Name { return xml.Name{Space: nsCalDAV, Local: local} }

	root := xml.StartElement{Name: caldav("schedule-response")}
	enc.EncodeToken(root)
	for _, att := range attendees {
		resp := xml.StartElement{Name: caldav("response")}
		enc.EncodeToken(resp)

		rcpt := xml.StartElement{Name: caldav("recipient")}
		enc.EncodeToken(rcpt)
		enc.EncodeElement(att.Value, xml.StartElement{Name: xml.Name{Space: nsDAV, Local: "href"}})
		enc.EncodeToken(rcpt.End())

		enc.EncodeElement("2.0;Success", xml.StartElement{Name: caldav("request-status")})
		enc.EncodeElement(freeBusyReply(request, att), xml.StartElement{Name: caldav("calendar-data")})

		enc.EncodeToken(resp.End())
	}
	enc.EncodeToken(root.End())
	enc.Flush()
}

// freeBusyReply builds ONE attendee's VCALENDAR METHOD:REPLY: UID,
// DTSTART/DTEND and ORGANIZER copied verbatim from the request, no FREEBUSY
// property (= no known busy range). Serialized to text to embed inside
// <C:calendar-data>.
func freeBusyReply(request *ical.Component, attendee ical.Prop) string {
	reply := ical.NewCalendar()
	reply.Props.SetText(ical.PropProductID, "-//cal-gateway//cal-gateway//EN")
	reply.Props.SetText(ical.PropVersion, "2.0")
	reply.Props.SetText(ical.PropMethod, "REPLY")

	fb := ical.NewComponent(ical.CompFreeBusy)
	fb.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	for _, name := range []string{ical.PropUID, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropOrganizer} {
		if p := request.Props.Get(name); p != nil {
			cp := *p
			fb.Props.Set(&cp)
		}
	}
	cp := attendee
	fb.Props.Set(&cp)
	reply.Children = append(reply.Children, fb)

	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(reply); err != nil {
		// Unreachable with verbatim-copied props; as a safety net we return a
		// minimal static VFREEBUSY rather than a corrupt body.
		return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//cal-gateway//cal-gateway//EN\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n"
	}
	return buf.String()
}

// writeScheduleCollectionPropfind emits a scheduling collection's multistatus
// (same doctrine as principalpropfind.go: all useful properties, regardless of
// those requested). kind = "schedule-inbox" or "schedule-outbox"; a non-empty
// defaultCal adds schedule-default-calendar-URL (inbox only, RFC 6638 §9.2).
func writeScheduleCollectionPropfind(w io.Writer, href, kind, displayName, defaultCal string) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)

	dav := func(local string) xml.Name { return xml.Name{Space: nsDAV, Local: local} }
	caldav := func(local string) xml.Name { return xml.Name{Space: nsCalDAV, Local: local} }

	start := xml.StartElement{Name: dav("multistatus")}
	enc.EncodeToken(start)
	resp := xml.StartElement{Name: dav("response")}
	enc.EncodeToken(resp)
	enc.EncodeElement(href, xml.StartElement{Name: dav("href")})

	ps := xml.StartElement{Name: dav("propstat")}
	enc.EncodeToken(ps)
	prop := xml.StartElement{Name: dav("prop")}
	enc.EncodeToken(prop)

	// resourcetype: collection + schedule-inbox|schedule-outbox (RFC 6638).
	rt := xml.StartElement{Name: dav("resourcetype")}
	enc.EncodeToken(rt)
	for _, n := range []xml.Name{dav("collection"), caldav(kind)} {
		el := xml.StartElement{Name: n}
		enc.EncodeToken(el)
		enc.EncodeToken(el.End())
	}
	enc.EncodeToken(rt.End())

	enc.EncodeElement(displayName, xml.StartElement{Name: dav("displayname")})

	// Static getctag: the collection is PERMANENTLY empty, its content never
	// changes — a constant tag says exactly that to the client.
	enc.EncodeElement("empty-1", xml.StartElement{Name: xml.Name{Space: nsCalServer, Local: "getctag"}})

	if defaultCal != "" {
		el := xml.StartElement{Name: caldav("schedule-default-calendar-URL")}
		enc.EncodeToken(el)
		enc.EncodeElement(defaultCal, xml.StartElement{Name: dav("href")})
		enc.EncodeToken(el.End())
	}

	enc.EncodeToken(prop.End())
	enc.EncodeElement("HTTP/1.1 200 OK", xml.StartElement{Name: dav("status")})
	enc.EncodeToken(ps.End())

	enc.EncodeToken(resp.End())
	enc.EncodeToken(start.End())
	enc.Flush()
}

// writeEmptyMultistatus emits a multistatus with no response (REPORT on an
// empty collection).
func writeEmptyMultistatus(w io.Writer) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)
	start := xml.StartElement{Name: xml.Name{Space: nsDAV, Local: "multistatus"}}
	enc.EncodeToken(start)
	enc.EncodeToken(start.End())
	enc.Flush()
}
