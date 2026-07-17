package caldav

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/icaltime"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// prodID identifies this server in the iCalendar streams it produces.
const prodID = "-//cal-gateway//cal-gateway//EN"

// EventToICal serializes a decrypted Proton event into a complete iCalendar
// object (VCALENDAR + VEVENT), as served to the CalDAV client.
//
// Times: served in the event's ORIGINAL IANA zone (ev.TZ / ev.EndTZ →
// DTSTART;TZID=… in local wall time + VTIMEZONE block), UTC fallback ("Z"
// form) when the zone is empty, UTC or unknown. This is the root fix for the
// DST bug (2026-07-16): a recurring event served in bare Z was re-expanded by
// Apple at a FIXED UTC time all year, while the RECURRENCE-ID/EXDATE (Proton
// epochs) follow wall time across DST → no match, "Error 2" and deleted
// occurrences still visible. The internal instants (Event.Start/End/ExDates,
// store) stay UTC — only the PRESENTATION changes.
func EventToICal(ev proton.Event) (*ical.Calendar, error) {
	return SeriesToICal([]proton.Event{ev})
}

// SeriesToICal serializes a GROUP of same-UID rows (master + exception-rows)
// into ONE iCalendar resource: the VTIMEZONE blocks of the referenced zones,
// then the master VEVENT (RRULE/EXDATE) followed by one VEVENT per exception
// with RECURRENCE-ID — RFC 4791: one UID = a single resource per collection
// (the M4 folding, root cause of "Error 2": 11 same-UID resources for the
// recurring-master corruption case). The caller supplies the rows in
// master-first order (proton.Account.ListEventsByUID / store); an orphan group
// (without a master) is serialized as-is, each row with its RECURRENCE-ID.
func SeriesToICal(events []proton.Event) (*ical.Calendar, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("caldav: empty event group")
	}
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, prodID)
	cal.Props.SetText(ical.PropVersion, "2.0")

	// Zone of the MASTER's DTSTART: RECURRENCE-ID and EXDATE must be served in
	// the SAME zone as it (RFC 5545 §3.8.4.4 / §3.8.5.1); an orphan group
	// (without a master) falls back to each row's own zone.
	masterTZ := ""
	for _, ev := range events {
		if ev.RecurrenceID == 0 {
			masterTZ = ev.TZ
			break
		}
	}

	used := make(map[string]bool) // zones actually emitted as TZID
	vevents := make([]*ical.Component, 0, len(events))
	for _, ev := range events {
		vevent, err := eventToVEvent(ev, masterTZ, used)
		if err != nil {
			return nil, err
		}
		vevents = append(vevents, vevent.Component)
	}
	// VTIMEZONE: one block per referenced non-UTC TZID, BEFORE the first VEVENT
	// (RFC 5545 §3.6.5). A zone unknown to the table/tzdb was never emitted as
	// TZID (Z fallback in inServeZone) — so failure here is impossible, but we
	// stay lenient (never a broken resource for one block).
	tzids := make([]string, 0, len(used))
	for tzid := range used {
		tzids = append(tzids, tzid)
	}
	sort.Strings(tzids)
	for _, tzid := range tzids {
		if vtz, err := vtimezoneComponent(tzid); err == nil {
			cal.Children = append(cal.Children, vtz)
		}
	}
	cal.Children = append(cal.Children, vevents...)
	return cal, nil
}

// inServeZone returns the instant in the IANA zone served as TZID — go-ical
// sets the TZID parameter automatically as soon as the Location is not UTC
// (Prop.SetDateTime) — and records it in used for emitting the VTIMEZONE
// block. Empty, UTC or unknown zone: UTC fallback ("Z" form).
func inServeZone(t time.Time, tzid string, used map[string]bool) time.Time {
	loc, ok := icaltime.LoadZone(tzid)
	if !ok {
		return t.UTC()
	}
	used[tzid] = true
	return t.In(loc)
}

// eventToVEvent builds the VEVENT component of a Proton row. An exception-row
// (RecurrenceID != 0) carries RECURRENCE-ID and NEVER an RRULE/EXDATE: copying
// the master's EXDATE onto the children makes the edited occurrence vanish on
// some clients (Radicale #1635 pitfall, documented in FEATURE-MATRIX).
// masterTZ is the zone of the group master's DTSTART (form of the
// RECURRENCE-ID); used collects the emitted TZIDs (VTIMEZONE blocks).
func eventToVEvent(ev proton.Event, masterTZ string, used map[string]bool) (*ical.Event, error) {
	if ev.UID == "" {
		return nil, fmt.Errorf("caldav: event %s has no UID", ev.ID)
	}
	child := ev.RecurrenceID != 0

	vevent := ical.NewEvent()
	vevent.Props.SetText(ical.PropUID, ev.UID)
	// DTSTAMP is mandatory (RFC 5545); the last Proton edit is the best
	// available timestamp and stays stable between two GETs.
	stamp := ev.LastEdit
	if stamp.IsZero() {
		stamp = time.Unix(0, 0)
	}
	vevent.Props.SetDateTime(ical.PropDateTimeStamp, stamp.UTC())

	if ev.AllDay {
		// All-day: DATE values, exclusive DTEND (already the case on the Proton
		// side, whose all-day bounds are UTC midnights).
		vevent.Props.SetDate(ical.PropDateTimeStart, ev.Start.UTC())
		vevent.Props.SetDate(ical.PropDateTimeEnd, ev.End.UTC())
	} else {
		// Local wall times (TZID) when the row carries a zone: a recurring
		// event served in bare Z would be re-expanded at a fixed UTC time
		// across DST (THE bug of 2026-07-16). Separate end zone if present.
		endTZ := ev.EndTZ
		if endTZ == "" {
			endTZ = ev.TZ
		}
		vevent.Props.SetDateTime(ical.PropDateTimeStart, inServeZone(ev.Start, ev.TZ, used))
		vevent.Props.SetDateTime(ical.PropDateTimeEnd, inServeZone(ev.End, endTZ, used))
	}

	if child {
		// RECURRENCE-ID = the ORIGINAL occurrence (the row's API column), in
		// the SAME form as the MASTER's DTSTART (RFC 5545 §3.8.4.4: same value
		// type and same zone) — DATE for an all-day event.
		occ := time.Unix(ev.RecurrenceID, 0).UTC()
		ridTZ := masterTZ
		if ridTZ == "" {
			ridTZ = ev.TZ // orphan group: the row's own zone
		}
		if ev.AllDay {
			vevent.Props.SetDate(ical.PropRecurrenceID, occ)
		} else {
			vevent.Props.SetDateTime(ical.PropRecurrenceID, inServeZone(occ, ridTZ, used))
		}
	}

	if ev.Title != "" {
		vevent.Props.SetText(ical.PropSummary, ev.Title)
	}
	if ev.Description != "" {
		vevent.Props.SetText(ical.PropDescription, ev.Description)
	}
	if ev.Location != "" {
		vevent.Props.SetText(ical.PropLocation, ev.Location)
	}
	// STATUS / TRANSP (signed CalendarEvents card): served as stored; when
	// absent, the RFC 5545 defaults (CONFIRMED/OPAQUE) apply on the client.
	if ev.Status != "" {
		vevent.Props.SetText(ical.PropStatus, ev.Status)
	}
	if ev.Transp != "" {
		vevent.Props.SetText(ical.PropTransparency, ev.Transp)
	}
	if ev.RRule != "" && !child {
		// RRULE is a structured value kept verbatim from Proton; no TEXT
		// escaping. Never on an exception-row (defensive: an exception has no
		// RRULE on the Proton side).
		prop := ical.NewProp(ical.PropRecurrenceRule)
		prop.Value = ev.RRule
		vevent.Props.Set(prop)
	}
	// EXDATE: serve the occurrences that Proton deleted, in the SAME form as
	// DTSTART (RFC 5545 §3.8.5.1: same value type and same zone) — otherwise
	// the client displays occurrences that no longer exist, or fails to match
	// its own occurrences re-expanded across DST. NEVER on a child VEVENT
	// (Radicale #1635 pitfall, cf. eventToVEvent).
	if !child {
		for _, ex := range ev.ExDates {
			prop := ical.NewProp(ical.PropExceptionDates)
			if ev.AllDay {
				prop.SetDate(ex.UTC())
			} else {
				prop.SetDateTime(inServeZone(ex, ev.TZ, used))
			}
			vevent.Props.Add(prop)
		}
	}

	// ORGANIZER / ATTENDEE (M5a): served so the client sees its write
	// confirmed (and the live RSVPs — PARTSTAT derived from the API's clear
	// Status). The X-PM-TOKEN is internal to Proton: never served to the
	// client.
	if ev.Organizer != "" {
		prop := ical.NewProp(ical.PropOrganizer)
		prop.Value = "mailto:" + ev.Organizer
		vevent.Props.Set(prop)
	}
	for _, at := range ev.Attendees {
		if at.Email == "" {
			continue
		}
		prop := ical.NewProp(ical.PropAttendee)
		if at.CN != "" {
			prop.Params.Set(ical.ParamCommonName, at.CN)
		}
		prop.Params.Set(ical.ParamRole, "REQ-PARTICIPANT")
		prop.Params.Set(ical.ParamParticipationStatus, partstatFromStatus(at.Status))
		prop.Params.Set(ical.ParamRSVP, "TRUE")
		prop.Value = "mailto:" + at.Email
		vevent.Props.Add(prop)
	}

	// Reminders (API Notifications column, in clear) → VALARM. Type DEVICE →
	// ACTION:DISPLAY, EMAIL → ACTION:EMAIL; the Proton Trigger is already a
	// duration relative to the DTSTART, served verbatim. An unreadable trigger
	// is skipped (never a whole VEVENT broken for a corrupted alarm).
	for _, n := range ev.Notifications {
		if !n.Valid() {
			continue
		}
		alarm := ical.NewComponent(ical.CompAlarm)
		action := "DISPLAY"
		if n.Type == proton.NotificationEmail {
			action = "EMAIL"
		}
		alarm.Props.SetText(ical.PropAction, action)
		trigger := ical.NewProp(ical.PropTrigger)
		trigger.Value = n.Trigger // structured duration, no TEXT escaping
		alarm.Props.Set(trigger)
		// DESCRIPTION is mandatory for DISPLAY/EMAIL (RFC 5545 §3.6.6); Proton
		// stores no alarm text, so we synthesize a neutral one.
		alarm.Props.SetText(ical.PropDescription, "Reminder")
		if action == "EMAIL" {
			alarm.Props.SetText(ical.PropSummary, "Reminder")
		}
		vevent.Children = append(vevent.Children, alarm)
	}

	return vevent, nil
}

// errICalRefused is the root of the ingestion gatekeeping refusals: the
// backend maps everything that wraps it to an honest 403 (never a 2xx no-op
// nor a silent distortion — FEATURE-MATRIX §0). The CalDAV client keeps its
// copy and reverts cleanly.
var errICalRefused = errors.New("caldav: calendar data refused")

// errThisAndFuture: a RANGE=THISANDFUTURE override has no Proton equivalent
// (SINGLE_EDIT_UNSUPPORTED); the emulation (series split) is the M5 design —
// until then, an honest refusal (FEATURE-MATRIX op. 5).
var errThisAndFuture = fmt.Errorf("%w: RECURRENCE-ID;RANGE=THISANDFUTURE overrides are not supported by Proton Calendar", errICalRefused)

// errChildRRule: a child VEVENT (RECURRENCE-ID) carrying an RRULE is
// contradictory — refusal rather than a risky interpretation.
var errChildRRule = fmt.Errorf("%w: a VEVENT with RECURRENCE-ID cannot carry its own RRULE", errICalRefused)

// errOrphanOverride: an override with no master, neither in the PUT nor on the
// Proton side, cannot be attached to a series — honest refusal (never an
// exception-row created in a vacuum).
var errOrphanOverride = fmt.Errorf("%w: RECURRENCE-ID override without a recurring master event", errICalRefused)

// errFloatingTime: a "floating" time (neither TZID nor Z suffix) has no
// absolute instant — Proton refuses it (UNEXPECTED_FLOATING_TIME); we align
// rather than silently reinterpret it as UTC.
var errFloatingTime = fmt.Errorf("%w: floating date-time (no TZID and no UTC designator) is not supported by Proton Calendar", errICalRefused)

// Proton RRULE limits (WebClients recurrence/rrule.ts::getIsRruleSupported:
// FREQUENCY_COUNT_MAX = 49, MAXIMUM_DATE = 2037-12-31). Beyond these, the
// owner's Proton app could no longer display/edit the series — refuse at
// ingestion.
const (
	rruleCountMax = 49
	rruleUntilMax = "20371231" // yyyymmdd, lexical comparison
)

// childInput is a child VEVENT of a folded PUT: the EventInput ready to write
// (RecurrenceID set) and the ORIGINAL instant of the occurrence (key for
// matching against the RecurrenceID column of the Proton exception-rows).
type childInput struct {
	in         proton.EventInput
	occurrence time.Time
}

// seriesInput is the result of parsing a PUT: the master (nil if the PUT
// carries only overrides — orphan-resource case) and the RECURRENCE-ID
// children. Apple always sends the COMPLETE STATE of the resource.
type seriesInput struct {
	uid      string
	master   *proton.EventInput
	children []childInput
}

// icalToSeriesInput extracts from the incoming ICS ALL the VEVENTs (master +
// RECURRENCE-ID overrides), ready for write routing (FEATURE-MATRIX op. 4).
// Honest refusals (errICalRefused → 403): RANGE=THISANDFUTURE (op. 5, M5
// design), RRULE on a child. Mixed UIDs or a double master = malformed ICS
// (bare error → 400).
func icalToSeriesInput(cal *ical.Calendar) (seriesInput, error) {
	var out seriesInput
	seen := make(map[int64]bool)
	for _, comp := range cal.Children {
		if comp.Name != ical.CompEvent {
			continue
		}
		in, uid, err := veventToInput(comp)
		if err != nil {
			return seriesInput{}, err
		}
		if out.uid == "" {
			out.uid = uid
		} else if uid != out.uid {
			return seriesInput{}, fmt.Errorf("caldav: mixed UIDs in one calendar object (%s and %s)", out.uid, uid)
		}

		rid := comp.Props.Get(ical.PropRecurrenceID)
		if rid == nil {
			if out.master != nil {
				return seriesInput{}, fmt.Errorf("caldav: two master VEVENTs (no RECURRENCE-ID) for UID %s", uid)
			}
			m := in
			out.master = &m
			continue
		}

		// Override of one occurrence.
		if strings.EqualFold(rid.Params.Get("RANGE"), "THISANDFUTURE") {
			return seriesInput{}, errThisAndFuture
		}
		if in.RRule != "" {
			return seriesInput{}, errChildRRule
		}
		occ, _, _, err := parseICalDate(rid)
		if err != nil {
			return seriesInput{}, fmt.Errorf("caldav: parsing RECURRENCE-ID of %s: %w", uid, err)
		}
		if seen[occ.Unix()] {
			return seriesInput{}, fmt.Errorf("caldav: duplicate RECURRENCE-ID override for UID %s", uid)
		}
		seen[occ.Unix()] = true
		// An exception never carries an EXDATE (the set lives on the master) —
		// defensive strip, mirror of the Radicale #1635 pitfall on the write
		// side.
		in.ExDates = nil
		o := occ
		in.RecurrenceID = &o
		out.children = append(out.children, childInput{in: in, occurrence: occ})
	}
	if out.master == nil && len(out.children) == 0 {
		return seriesInput{}, fmt.Errorf("caldav: no VEVENT in calendar object")
	}
	return out, nil
}

// icalToEventInput is the historical single-VEVENT path (M2/M3), kept for
// simple PUTs and tests: exactly one master VEVENT expected.
func icalToEventInput(cal *ical.Calendar) (proton.EventInput, string, error) {
	series, err := icalToSeriesInput(cal)
	if err != nil {
		return proton.EventInput{}, "", err
	}
	if series.master == nil || len(series.children) != 0 {
		return proton.EventInput{}, "", fmt.Errorf("caldav: expected exactly one master VEVENT")
	}
	return *series.master, series.uid, nil
}

// veventToInput extracts from ONE VEVENT component its fields, ready for
// proton.CreateEvent / UpdateEvent. Also returns the UID.
// A missing DTEND falls back to DTSTART + 1h (timed) or +1 day (all-day).
func veventToInput(vevent *ical.Component) (proton.EventInput, string, error) {
	uid, err := vevent.Props.Text(ical.PropUID)
	if err != nil || uid == "" {
		return proton.EventInput{}, "", fmt.Errorf("caldav: VEVENT has no UID")
	}

	startProp := vevent.Props.Get(ical.PropDateTimeStart)
	if startProp == nil {
		return proton.EventInput{}, "", fmt.Errorf("caldav: VEVENT %s has no DTSTART", uid)
	}
	start, tzid, allDay, err := parseICalDate(startProp)
	if err != nil {
		return proton.EventInput{}, "", fmt.Errorf("caldav: parsing DTSTART of %s: %w", uid, err)
	}

	var end time.Time
	var endTZID string
	if endProp := vevent.Props.Get(ical.PropDateTimeEnd); endProp != nil {
		end, endTZID, _, err = parseICalDate(endProp)
		if err != nil {
			return proton.EventInput{}, "", fmt.Errorf("caldav: parsing DTEND of %s: %w", uid, err)
		}
	} else if durProp := vevent.Props.Get(ical.PropDuration); durProp != nil {
		// DURATION instead of DTEND (RFC 5545 §3.8.2.5): Proton only stores
		// start/end, so we convert at ingestion.
		dur, derr := durProp.Duration()
		if derr != nil {
			return proton.EventInput{}, "", fmt.Errorf("caldav: parsing DURATION of %s: %w", uid, derr)
		}
		end = start.Add(dur)
	} else if allDay {
		end = start.Add(24 * time.Hour)
	} else {
		end = start.Add(time.Hour)
	}

	in := proton.EventInput{
		UID:     uid,
		Start:   start,
		End:     end,
		TZID:    tzid,
		EndTZID: endTZID, // "" (DTEND absent / Z form) = same zone as TZID
		AllDay:  allDay,
	}
	if v, err := vevent.Props.Text(ical.PropSummary); err == nil {
		in.Title = v
	}
	if v, err := vevent.Props.Text(ical.PropDescription); err == nil {
		in.Description = v
	}
	if v, err := vevent.Props.Text(ical.PropLocation); err == nil {
		in.Location = v
	}
	if rr := vevent.Props.Get(ical.PropRecurrenceRule); rr != nil {
		if err := validateRRuleLimits(rr.Value); err != nil {
			return proton.EventInput{}, "", fmt.Errorf("caldav: RRULE of %s: %w", uid, err)
		}
		in.RRule = rr.Value // structured value kept verbatim
	}
	exProps := vevent.Props[ical.PropExceptionDates]
	for i := range exProps {
		exs, err := parseICalExDates(&exProps[i])
		if err != nil {
			return proton.EventInput{}, "", fmt.Errorf("caldav: parsing EXDATE of %s: %w", uid, err)
		}
		in.ExDates = append(in.ExDates, exs...)
	}

	// STATUS / TRANSP: passthrough to the signed CalendarEvents card.
	// VERIFIED LIVE (2026-07-16, test calendar): the Proton server VALIDATES
	// the enum — CONFIRMED and CANCELLED accepted, TENTATIVE rejected (code
	// 2000 "Unknown EventStatus"). TENTATIVE and any non-RFC value are
	// therefore stripped (the CONFIRMED default applies), never a refusal for
	// a cosmetic property — same posture as the official ICS import, which
	// does not keep STATUS.
	if v, err := vevent.Props.Text(ical.PropStatus); err == nil {
		switch s := strings.ToUpper(strings.TrimSpace(v)); s {
		case "CONFIRMED", "CANCELLED":
			in.Status = s
		}
	}
	if v, err := vevent.Props.Text(ical.PropTransparency); err == nil {
		switch s := strings.ToUpper(strings.TrimSpace(v)); s {
		case "OPAQUE", "TRANSPARENT":
			in.Transp = s
		}
	}

	// ORGANIZER / ATTENDEE (M5a): captured into the EventInput — the POLICY
	// (outgoing invitation vs incoming booking, create vs update) is decided
	// by the backend, which knows whether the UID exists and whether the
	// ORGANIZER is an address of the account. The incoming PARTSTAT is
	// captured (M6b): at creation it stays ignored (NEEDS-ACTION on the Proton
	// side), but the backend needs it to detect a RESPONSE from the account
	// owner to a received invitation. The organizer also listed as an ATTENDEE
	// (Apple habit) is deduplicated — Proton never puts it in the attendee
	// list.
	if org := vevent.Props.Get(ical.PropOrganizer); org != nil {
		if addr := mailtoCalAddress(org.Value); addr != "" {
			in.Organizer = addr
			in.OrganizerCN = org.Params.Get(ical.ParamCommonName)
		}
	}
	for _, p := range vevent.Props[ical.PropAttendee] {
		addr := mailtoCalAddress(p.Value)
		if addr == "" || strings.EqualFold(addr, in.Organizer) {
			continue
		}
		dup := false
		for _, at := range in.Attendees {
			if strings.EqualFold(at.Email, addr) {
				dup = true
				break
			}
		}
		if !dup {
			in.Attendees = append(in.Attendees, proton.AttendeeInput{
				Email:    addr,
				CN:       p.Params.Get(ical.ParamCommonName),
				Partstat: p.Params.Get(ical.ParamParticipationStatus),
			})
		}
	}

	// VALARM → Notifications (Proton rules, cf. proton.NotificationFromAlarm):
	// an unsupported alarm is dropped SILENTLY — the same posture as Proton's
	// official ICS import, never a refusal of the whole PUT. At most
	// MaxNotifications survive.
	for _, child := range vevent.Children {
		if child.Name != ical.CompAlarm || len(in.Notifications) >= proton.MaxNotifications {
			continue
		}
		action := ""
		if p := child.Props.Get(ical.PropAction); p != nil {
			action = p.Value
		}
		trigProp := child.Props.Get(ical.PropTrigger)
		if trigProp == nil {
			continue // TRIGGER mandatory (getIsValidAlarm)
		}
		absolute := strings.EqualFold(trigProp.Params.Get(ical.ParamValue), "DATE-TIME")
		related := trigProp.Params.Get(ical.ParamRelated)
		if n, ok := proton.NotificationFromAlarm(action, trigProp.Value, related, absolute, allDay); ok {
			in.Notifications = append(in.Notifications, n)
		}
	}
	return in, uid, nil
}

// partstatFromStatus maps the Proton API's clear Status (the row's Attendees
// array) to the iCalendar PARTSTAT: 0=NEEDS-ACTION, 1=TENTATIVE, 2=DECLINED,
// 3=ACCEPTED. Unknown value = NEEDS-ACTION (RFC 5545 default).
func partstatFromStatus(status int) string {
	switch status {
	case 1:
		return "TENTATIVE"
	case 2:
		return "DECLINED"
	case 3:
		return "ACCEPTED"
	default:
		return "NEEDS-ACTION"
	}
}

// statusFromPartstat is the inverse of partstatFromStatus: maps the incoming
// iCalendar PARTSTAT to the Proton API's clear Status (0=NEEDS-ACTION,
// 1=TENTATIVE, 2=DECLINED, 3=ACCEPTED). Empty/unknown value = NEEDS-ACTION.
func statusFromPartstat(partstat string) int {
	switch strings.ToUpper(strings.TrimSpace(partstat)) {
	case "TENTATIVE":
		return 1
	case "DECLINED":
		return 2
	case "ACCEPTED":
		return 3
	default:
		return 0
	}
}

// mailtoCalAddress extracts the email address from a CAL-ADDRESS value
// ("mailto:user@…", case-insensitive prefix), "" otherwise.
func mailtoCalAddress(value string) string {
	v := strings.TrimSpace(value)
	if len(v) < len("mailto:") || !strings.EqualFold(v[:len("mailto:")], "mailto:") {
		return ""
	}
	return strings.TrimSpace(v[len("mailto:"):])
}

// validateRRuleLimits refuses recurrences the Proton app could not
// display/edit: COUNT > 49 and UNTIL beyond 2037-12-31 (limits of the
// official web client). The RRULE value stays verbatim otherwise.
func validateRRuleLimits(rrule string) error {
	for _, part := range strings.Split(rrule, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "COUNT":
			if n, err := strconv.Atoi(v); err == nil && n > rruleCountMax {
				return fmt.Errorf("%w: RRULE COUNT=%d exceeds the Proton maximum of %d occurrences", errICalRefused, n, rruleCountMax)
			}
		case "UNTIL":
			// DATE (20380101) and DATE-TIME (20380101T000000Z) forms: the date
			// portion is enough for the comparison.
			if len(v) >= 8 && v[:8] > rruleUntilMax {
				return fmt.Errorf("%w: RRULE UNTIL=%s is beyond the Proton maximum date of 2037-12-31", errICalRefused, v)
			}
		}
	}
	return nil
}

// parseICalExDates reads an EXDATE property (multiple comma-separated values,
// the same three forms as parseICalDate) into UTC instants.
func parseICalExDates(p *ical.Prop) ([]time.Time, error) {
	var out []time.Time
	for _, v := range strings.Split(p.Value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		one := *p // shallow copy: Params shared, read-only
		one.Value = v
		t, _, _, err := parseICalDate(&one)
		if err != nil {
			return nil, err
		}
		out = append(out, t.UTC())
	}
	return out, nil
}

// parseICalDate reads a DTSTART/DTEND property in the three forms emitted by
// clients: VALUE=DATE (all-day), UTC datetime (Z suffix) or local datetime
// with TZID. Returns an absolute instant, the IANA zone (empty for
// UTC/all-day) and the all-day flag.
//
// A time without TZID nor Z ("floating") is REFUSED (errFloatingTime → 403),
// as Proton does (UNEXPECTED_FLOATING_TIME) — reinterpreting it as UTC would
// silently shift the event. A TZID that is PRESENT but non-IANA falls back to
// UTC (strip posture, distinct from floating).
func parseICalDate(p *ical.Prop) (t time.Time, tzid string, allDay bool, err error) {
	v := strings.TrimSpace(p.Value)
	tzid = p.Params.Get("TZID")

	switch {
	case p.Params.Get("VALUE") == "DATE" || len(v) == 8:
		t, err = time.Parse(icaltime.LayoutDate, v)
		return t, "", true, err
	case strings.HasSuffix(v, "Z"):
		t, err = time.Parse(icaltime.LayoutDateTimeUTC, v)
		return t, "", false, err
	case tzid == "":
		return time.Time{}, "", false, errFloatingTime
	default:
		loc, ok := icaltime.LoadZone(tzid)
		if !ok {
			tzid = "" // unknown zone: documented UTC fallback
		}
		t, err = time.ParseInLocation(icaltime.LayoutDateTime, v, loc)
		return t, tzid, false, err
	}
}
