package caldav

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/proton"
)

// roundTrip encodes the produced iCalendar object then re-decodes it with
// go-ical, as a CalDAV client would.
func roundTrip(t *testing.T, ev proton.Event) *ical.Calendar {
	t.Helper()
	cal, err := EventToICal(ev)
	if err != nil {
		t.Fatalf("EventToICal: %v", err)
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := ical.NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatalf("decode: %v\nics:\n%s", err, buf.String())
	}
	return decoded
}

func singleEvent(t *testing.T, cal *ical.Calendar) ical.Event {
	t.Helper()
	events := cal.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	return events[0]
}

func TestEventToICalRoundTripTimed(t *testing.T) {
	start := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	end := start.Add(45 * time.Minute)
	ev := proton.Event{
		ID:          "row1",
		UID:         "uid-1@proton.me",
		CalendarID:  "cal1",
		Title:       "Weekly sync, coffee & croissants; room B",
		Description: "Agenda:\nline 1\nline 2",
		Location:    "12 rue de la Paix, Paris",
		Start:       start,
		End:         end,
		TZ:          "Europe/Paris",
		LastEdit:    time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC),
		RRule:       "FREQ=WEEKLY;BYDAY=MO",
	}

	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)

	if got, _ := vevent.Props.Text(ical.PropUID); got != ev.UID {
		t.Errorf("UID = %q, want %q", got, ev.UID)
	}
	if got, _ := vevent.Props.Text(ical.PropSummary); got != ev.Title {
		t.Errorf("SUMMARY = %q, want %q", got, ev.Title)
	}
	if got, _ := vevent.Props.Text(ical.PropDescription); got != ev.Description {
		t.Errorf("DESCRIPTION = %q, want %q", got, ev.Description)
	}
	if got, _ := vevent.Props.Text(ical.PropLocation); got != ev.Location {
		t.Errorf("LOCATION = %q, want %q", got, ev.Location)
	}

	gotStart, err := vevent.DateTimeStart(time.UTC)
	if err != nil {
		t.Fatalf("DateTimeStart: %v", err)
	}
	if !gotStart.Equal(start) {
		t.Errorf("DTSTART = %v, want %v", gotStart, start)
	}
	gotEnd, err := vevent.DateTimeEnd(time.UTC)
	if err != nil {
		t.Fatalf("DateTimeEnd: %v", err)
	}
	if !gotEnd.Equal(end) {
		t.Errorf("DTEND = %v, want %v", gotEnd, end)
	}

	if got := vevent.Props.Get(ical.PropRecurrenceRule); got == nil || got.Value != ev.RRule {
		t.Errorf("RRULE = %v, want %q", got, ev.RRule)
	}
	if vevent.Props.Get(ical.PropDateTimeStamp) == nil {
		t.Error("DTSTAMP missing (required by RFC 5545)")
	}

	// v2 (DST fix 2026-07-16): the served form is the local WALL-CLOCK time +
	// TZID — never bare Z for a zoned event — and the VCALENDAR embeds the
	// matching VTIMEZONE block.
	startProp := vevent.Props.Get(ical.PropDateTimeStart)
	if got := startProp.Params.Get(ical.ParamTimezoneID); got != "Europe/Paris" {
		t.Errorf("DTSTART TZID = %q, want Europe/Paris", got)
	}
	if startProp.Value != "20260720T113000" { // 09:30Z = 11:30 CEST (summer)
		t.Errorf("DTSTART value = %q, want 20260720T113000", startProp.Value)
	}
	if !hasVTimezone(decoded, "Europe/Paris") {
		t.Error("VTIMEZONE Europe/Paris missing")
	}
}

// hasVTimezone looks for a VTIMEZONE block carrying the given TZID in the
// decoded VCALENDAR.
func hasVTimezone(cal *ical.Calendar, tzid string) bool {
	for _, comp := range cal.Children {
		if comp.Name != ical.CompTimezone {
			continue
		}
		if got, _ := comp.Props.Text(ical.PropTimezoneID); got == tzid {
			return true
		}
	}
	return false
}

func TestEventToICalRoundTripAllDay(t *testing.T) {
	// Proton all-day: bounds = UTC midnights, DTEND exclusive.
	start := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	ev := proton.Event{
		ID:         "row2",
		UID:        "uid-2@proton.me",
		CalendarID: "cal1",
		Title:      "Birthday",
		Start:      start,
		End:        end,
		AllDay:     true,
		LastEdit:   time.Unix(1750000000, 0),
	}

	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)

	startProp := vevent.Props.Get(ical.PropDateTimeStart)
	if startProp == nil {
		t.Fatal("DTSTART missing")
	}
	if got := startProp.ValueType(); got != ical.ValueDate {
		t.Errorf("DTSTART value type = %q, want DATE", got)
	}
	gotStart, err := startProp.DateTime(time.UTC)
	if err != nil {
		t.Fatalf("DTSTART parse: %v", err)
	}
	if !gotStart.Equal(start) {
		t.Errorf("DTSTART = %v, want %v", gotStart, start)
	}

	endProp := vevent.Props.Get(ical.PropDateTimeEnd)
	if endProp == nil {
		t.Fatal("DTEND missing")
	}
	if got := endProp.ValueType(); got != ical.ValueDate {
		t.Errorf("DTEND value type = %q, want DATE", got)
	}
	gotEnd, err := endProp.DateTime(time.UTC)
	if err != nil {
		t.Fatalf("DTEND parse: %v", err)
	}
	if !gotEnd.Equal(end) {
		t.Errorf("DTEND = %v, want %v", gotEnd, end)
	}
}

func TestEventToICalRejectsMissingUID(t *testing.T) {
	_, err := EventToICal(proton.Event{ID: "row3"})
	if err == nil || !strings.Contains(err.Error(), "UID") {
		t.Fatalf("err = %v, want missing-UID error", err)
	}
}

// TestEventToICalExDates: occurrences deleted on the Proton side must be
// served as EXDATE in the SAME form as DTSTART (TZID, RFC 5545 §3.8.5.1),
// the WALL-CLOCK time staying stable across DST — winter and summer. This is
// the production-bug scenario (2026-07-16): served as bare Z, the summer
// EXDATE never matched the occurrences re-expanded by Apple.
func TestEventToICalExDates(t *testing.T) {
	// Weekly master set in WINTER: 09:00 Paris = 08:00Z (CET).
	start := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	exWinter := time.Date(2026, 1, 12, 8, 0, 0, 0, time.UTC) // 09:00 CET
	exSummer := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC) // 09:00 CEST
	ev := proton.Event{
		ID: "rowex", UID: "uid-ex@proton.me", CalendarID: "cal1",
		Title: "Weekly Sync", Start: start, End: start.Add(time.Hour),
		TZ:       "Europe/Paris",
		RRule:    "FREQ=WEEKLY;BYDAY=MO",
		ExDates:  []time.Time{exWinter, exSummer},
		LastEdit: time.Unix(1750000000, 0),
	}

	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)

	exProps := vevent.Props[ical.PropExceptionDates]
	if len(exProps) != 2 {
		t.Fatalf("got %d EXDATE props, want 2", len(exProps))
	}
	// Wall-clock stable: 09:00 local on both sides of DST, DST-correct UTC
	// instants (08:00Z winter / 07:00Z summer).
	wantValues := []string{"20260112T090000", "20260713T090000"}
	wantInstants := []time.Time{exWinter, exSummer}
	for i := range exProps {
		if got := exProps[i].Params.Get(ical.ParamTimezoneID); got != "Europe/Paris" {
			t.Errorf("EXDATE[%d] TZID = %q, want Europe/Paris (same zone as DTSTART)", i, got)
		}
		if exProps[i].Value != wantValues[i] {
			t.Errorf("EXDATE[%d] = %q, want %q (wall-clock stable)", i, exProps[i].Value, wantValues[i])
		}
		got, err := exProps[i].DateTime(time.UTC)
		if err != nil {
			t.Fatalf("EXDATE[%d] parse: %v", i, err)
		}
		if !got.Equal(wantInstants[i]) {
			t.Errorf("EXDATE[%d] = %v, want %v", i, got, wantInstants[i])
		}
	}
}

// TestSeriesToICalRecurrenceIDZone: THE test that would have caught the root
// bug — weekly TZID Europe/Paris master set in winter, SUMMER exception: the
// served RECURRENCE-ID carries the SAME zone as the master's DTSTART (RFC 5545
// §3.8.4.4) and the same wall-clock time as the occurrences Apple re-expands
// from this master — zero instant divergence.
func TestSeriesToICalRecurrenceIDZone(t *testing.T) {
	start := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC) // 09:00 CET (winter)
	occ := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)  // 09:00 CEST (summer)
	master := proton.Event{
		ID: "m1", UID: "uid-s@proton.me", CalendarID: "cal1", Title: "Sync",
		Start: start, End: start.Add(time.Hour), TZ: "Europe/Paris",
		RRule: "FREQ=WEEKLY;BYDAY=MO", LastEdit: time.Unix(1750000000, 0),
	}
	child := proton.Event{
		ID: "c1", UID: "uid-s@proton.me", CalendarID: "cal1", Title: "Sync (moved)",
		Start: occ.Add(2 * time.Hour), End: occ.Add(3 * time.Hour), TZ: "Europe/Paris",
		RecurrenceID: occ.Unix(), LastEdit: time.Unix(1750000000, 0),
	}

	cal, err := SeriesToICal([]proton.Event{master, child})
	if err != nil {
		t.Fatalf("SeriesToICal: %v", err)
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := ical.NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatalf("decode: %v\nics:\n%s", err, buf.String())
	}
	events := decoded.Events()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	rid := events[1].Props.Get(ical.PropRecurrenceID)
	if rid == nil {
		t.Fatal("RECURRENCE-ID missing")
	}
	if got := rid.Params.Get(ical.ParamTimezoneID); got != "Europe/Paris" {
		t.Errorf("RECURRENCE-ID TZID = %q, want Europe/Paris (master's zone)", got)
	}
	if rid.Value != "20260713T090000" { // same wall-clock time as the master
		t.Errorf("RECURRENCE-ID = %q, want 20260713T090000", rid.Value)
	}
	if got, err := rid.DateTime(time.UTC); err != nil || !got.Equal(occ) {
		t.Errorf("RECURRENCE-ID instant = %v (%v), want %v", got, err, occ)
	}
	// A single VTIMEZONE block (deduplicated zone), BEFORE the first VEVENT.
	nTZ, firstVEvent := 0, -1
	for i, comp := range decoded.Children {
		switch comp.Name {
		case ical.CompTimezone:
			nTZ++
			if firstVEvent >= 0 {
				t.Error("VTIMEZONE after a VEVENT")
			}
		case ical.CompEvent:
			if firstVEvent < 0 {
				firstVEvent = i
			}
		}
	}
	if nTZ != 1 {
		t.Errorf("got %d VTIMEZONE, want 1", nTZ)
	}
}

// TestEventToICalEndTZ: a distinct END zone (Proton EndTimezone column) is
// served on the DTEND, with its own VTIMEZONE block.
func TestEventToICalEndTZ(t *testing.T) {
	// Paris → New York flight: departure 10:00 CET, arrival 13:00 EST.
	start := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 5, 18, 0, 0, 0, time.UTC)
	ev := proton.Event{
		ID: "rowtz", UID: "uid-tz@proton.me", CalendarID: "cal1", Title: "Flight",
		Start: start, End: end, TZ: "Europe/Paris", EndTZ: "America/New_York",
		LastEdit: time.Unix(1750000000, 0),
	}
	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)
	endProp := vevent.Props.Get(ical.PropDateTimeEnd)
	if got := endProp.Params.Get(ical.ParamTimezoneID); got != "America/New_York" {
		t.Errorf("DTEND TZID = %q, want America/New_York", got)
	}
	if endProp.Value != "20260105T130000" { // 18:00Z = 13:00 EST
		t.Errorf("DTEND = %q, want 20260105T130000", endProp.Value)
	}
	for _, tz := range []string{"Europe/Paris", "America/New_York"} {
		if !hasVTimezone(decoded, tz) {
			t.Errorf("VTIMEZONE %s missing", tz)
		}
	}
	if gotEnd, err := vevent.DateTimeEnd(time.UTC); err != nil || !gotEnd.Equal(end) {
		t.Errorf("DTEND instant = %v (%v), want %v", gotEnd, err, end)
	}
}

// TestEventToICalUnknownTZServedUTC: a zone unknown to the tzdb falls back to
// the "Z" form (never an unsolvable TZID nor a broken VTIMEZONE).
func TestEventToICalUnknownTZServedUTC(t *testing.T) {
	start := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	ev := proton.Event{
		ID: "rowu", UID: "uid-u@proton.me", CalendarID: "cal1", Title: "X",
		Start: start, End: start.Add(time.Hour), TZ: "Mars/Olympus",
		LastEdit: time.Unix(1750000000, 0),
	}
	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)
	startProp := vevent.Props.Get(ical.PropDateTimeStart)
	if startProp.Params.Get(ical.ParamTimezoneID) != "" || !strings.HasSuffix(startProp.Value, "Z") {
		t.Errorf("DTSTART = %+v, want Z form (unknown zone)", startProp)
	}
	for _, comp := range decoded.Children {
		if comp.Name == ical.CompTimezone {
			t.Error("VTIMEZONE emitted for an unknown zone")
		}
	}
}

// TestEventToICalStatusTranspAlarms: stored STATUS/TRANSP and reminders
// (Notifications column) must be served in the VEVENT — otherwise any alert
// set on the Proton side is invisible in Apple Calendar.
func TestEventToICalStatusTranspAlarms(t *testing.T) {
	start := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	ev := proton.Event{
		ID: "row-al", UID: "uid-al@proton.me", CalendarID: "cal1",
		Title: "Appointment", Start: start, End: start.Add(time.Hour),
		Status: "TENTATIVE", Transp: "TRANSPARENT",
		Notifications: []proton.Notification{
			{Type: proton.NotificationDevice, Trigger: "-PT15M"},
			{Type: proton.NotificationEmail, Trigger: "-PT1H"},
			{Type: proton.NotificationDevice, Trigger: "NOT-A-DURATION"}, // corrupted: skipped
		},
		LastEdit: time.Unix(1750000000, 0),
	}

	decoded := roundTrip(t, ev)
	vevent := singleEvent(t, decoded)

	if got, _ := vevent.Props.Text(ical.PropStatus); got != "TENTATIVE" {
		t.Errorf("STATUS = %q, want TENTATIVE", got)
	}
	if got, _ := vevent.Props.Text(ical.PropTransparency); got != "TRANSPARENT" {
		t.Errorf("TRANSP = %q, want TRANSPARENT", got)
	}

	var alarms []*ical.Component
	for _, child := range vevent.Children {
		if child.Name == ical.CompAlarm {
			alarms = append(alarms, child)
		}
	}
	if len(alarms) != 2 {
		t.Fatalf("got %d VALARM, want 2 (corrupted trigger skipped)", len(alarms))
	}
	if a, _ := alarms[0].Props.Text(ical.PropAction); a != "DISPLAY" {
		t.Errorf("alarm[0] ACTION = %q, want DISPLAY", a)
	}
	if tr := alarms[0].Props.Get(ical.PropTrigger); tr == nil || tr.Value != "-PT15M" {
		t.Errorf("alarm[0] TRIGGER = %v, want -PT15M", tr)
	}
	if d, _ := alarms[0].Props.Text(ical.PropDescription); d == "" {
		t.Error("alarm[0] DESCRIPTION missing (required by RFC 5545 for DISPLAY)")
	}
	if a, _ := alarms[1].Props.Text(ical.PropAction); a != "EMAIL" {
		t.Errorf("alarm[1] ACTION = %q, want EMAIL", a)
	}

	// Absent: nothing is served (RFC defaults apply on the client side).
	bare := roundTrip(t, proton.Event{
		ID: "row-b", UID: "uid-b@proton.me", Start: start, End: start.Add(time.Hour),
		LastEdit: time.Unix(1750000000, 0),
	})
	vb := singleEvent(t, bare)
	if vb.Props.Get(ical.PropStatus) != nil || vb.Props.Get(ical.PropTransparency) != nil {
		t.Error("STATUS/TRANSP served although absent from the cards")
	}
	if len(vb.Children) != 0 {
		t.Errorf("VALARM served without notifications: %v", vb.Children)
	}
}

// newTestVEvent builds the UTC-timestamped VEVENT skeleton for the
// ingestion tests.
func newTestVEvent(uid string) *ical.Event {
	ev := ical.NewEvent()
	ev.Props.SetText(ical.PropUID, uid)
	ev.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	ev.Props.SetDateTime(ical.PropDateTimeStart, time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC))
	ev.Props.SetDateTime(ical.PropDateTimeEnd, time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC))
	return ev
}

func wrapCalendar(ev *ical.Event) *ical.Calendar {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Children = append(cal.Children, ev.Component)
	return cal
}

func addAlarm(ev *ical.Event, action, trigger string, params map[string]string) {
	alarm := ical.NewComponent(ical.CompAlarm)
	alarm.Props.SetText(ical.PropAction, action)
	tr := ical.NewProp(ical.PropTrigger)
	tr.Value = trigger
	for k, v := range params {
		tr.Params.Set(k, v)
	}
	alarm.Props.Set(tr)
	ev.Children = append(ev.Children, alarm)
}

// TestICalToEventInputStatusTranspAlarms: STATUS/TRANSP passthrough (non-RFC
// values ignored) and VALARM → Notifications mapping with the Proton drops.
func TestICalToEventInputStatusTranspAlarms(t *testing.T) {
	ev := newTestVEvent("uid-in")
	ev.Props.SetText(ical.PropStatus, "cancelled") // tolerated case
	ev.Props.SetText(ical.PropTransparency, "TRANSPARENT")
	addAlarm(ev, "DISPLAY", "-PT15M", nil)
	addAlarm(ev, "AUDIO", "-PT5M", nil)                                                          // AUDIO → DEVICE
	addAlarm(ev, "EMAIL", "-PT1H", nil)                                                          // EMAIL → Type 0
	addAlarm(ev, "NONE", "-PT15M", nil)                                                          // Apple's "no alert": dropped
	addAlarm(ev, "DISPLAY", "PT10M", nil)                                                        // after the start: dropped
	addAlarm(ev, "DISPLAY", "20260720T080000Z", map[string]string{ical.ParamValue: "DATE-TIME"}) // absolute: dropped
	addAlarm(ev, "DISPLAY", "-PT10M", map[string]string{ical.ParamRelated: "END"})               // end: dropped

	in, _, err := icalToEventInput(wrapCalendar(ev))
	if err != nil {
		t.Fatalf("icalToEventInput: %v", err)
	}
	if in.Status != "CANCELLED" || in.Transp != "TRANSPARENT" {
		t.Errorf("Status/Transp = %q/%q", in.Status, in.Transp)
	}
	want := []proton.Notification{
		{Type: proton.NotificationDevice, Trigger: "-PT15M"},
		{Type: proton.NotificationDevice, Trigger: "-PT5M"},
		{Type: proton.NotificationEmail, Trigger: "-PT1H"},
	}
	if len(in.Notifications) != len(want) {
		t.Fatalf("Notifications = %+v, want %d entries", in.Notifications, len(want))
	}
	for i := range want {
		if in.Notifications[i] != want[i] {
			t.Errorf("Notifications[%d] = %+v, want %+v", i, in.Notifications[i], want[i])
		}
	}

	// STATUS outside the server enum: ignored (default on write), never a refusal.
	// TENTATIVE is part of it — rejected by the Proton API (verified live).
	for _, unsupported := range []string{"MAYBE", "TENTATIVE"} {
		ev2 := newTestVEvent("uid-in2")
		ev2.Props.SetText(ical.PropStatus, unsupported)
		in2, _, err := icalToEventInput(wrapCalendar(ev2))
		if err != nil || in2.Status != "" {
			t.Errorf("STATUS %q: in.Status=%q err=%v, want stripped", unsupported, in2.Status, err)
		}
	}

	// Proton cap: at most 10 surviving alarms.
	ev3 := newTestVEvent("uid-in3")
	for i := 0; i < 14; i++ {
		addAlarm(ev3, "DISPLAY", "-PT15M", nil)
	}
	in3, _, err := icalToEventInput(wrapCalendar(ev3))
	if err != nil {
		t.Fatalf("icalToEventInput: %v", err)
	}
	if len(in3.Notifications) != proton.MaxNotifications {
		t.Errorf("got %d notifications, want capped at %d", len(in3.Notifications), proton.MaxNotifications)
	}
}

// TestICalToEventInputDuration: DURATION without DTEND is converted to
// start/end bounds (Proton does not store a duration).
func TestICalToEventInputDuration(t *testing.T) {
	ev := newTestVEvent("uid-dur")
	ev.Props.Del(ical.PropDateTimeEnd)
	dur := ical.NewProp(ical.PropDuration)
	dur.Value = "PT1H30M"
	ev.Props.Set(dur)

	in, _, err := icalToEventInput(wrapCalendar(ev))
	if err != nil {
		t.Fatalf("icalToEventInput: %v", err)
	}
	wantEnd := time.Date(2026, 7, 20, 10, 30, 0, 0, time.UTC)
	if !in.End.Equal(wantEnd) {
		t.Errorf("End = %v, want %v (start + PT1H30M)", in.End, wantEnd)
	}
}

// TestICalToEventInputRefusesFloating: a floating time (neither TZID nor Z) is
// refused as on Proton (UNEXPECTED_FLOATING_TIME) — never silently
// reinterpreted as UTC. The refusal wraps errICalRefused (→ 403).
func TestICalToEventInputRefusesFloating(t *testing.T) {
	ev := newTestVEvent("uid-float")
	ev.Props.Del(ical.PropDateTimeStart)
	p := ical.NewProp(ical.PropDateTimeStart)
	p.Value = "20260720T093000" // floating
	ev.Props.Set(p)

	_, _, err := icalToEventInput(wrapCalendar(ev))
	if !errors.Is(err, errICalRefused) || !errors.Is(err, errFloatingTime) {
		t.Fatalf("err = %v, want errFloatingTime wrapping errICalRefused", err)
	}

	// The same time WITH TZID passes.
	ev2 := newTestVEvent("uid-float2")
	ev2.Props.Del(ical.PropDateTimeStart)
	p2 := ical.NewProp(ical.PropDateTimeStart)
	p2.Params.Set(ical.ParamTimezoneID, "Europe/Paris")
	p2.Value = "20260720T113000"
	ev2.Props.Set(p2)
	in, _, err := icalToEventInput(wrapCalendar(ev2))
	if err != nil {
		t.Fatalf("TZID form refused: %v", err)
	}
	if want := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC); !in.Start.Equal(want) {
		t.Errorf("Start = %v, want %v", in.Start, want)
	}
}

// TestICalToEventInputRRuleLimits: COUNT > 49 and UNTIL > 2037-12-31 are the
// Proton client's caps — beyond, an honest refusal (403), not a 201 that
// would break the account owner's app.
func TestICalToEventInputRRuleLimits(t *testing.T) {
	setRRule := func(ev *ical.Event, rule string) {
		rr := ical.NewProp(ical.PropRecurrenceRule)
		rr.Value = rule
		ev.Props.Set(rr)
	}

	for _, refuse := range []string{
		"FREQ=DAILY;COUNT=50",
		"FREQ=WEEKLY;UNTIL=20380101T000000Z",
		"FREQ=YEARLY;UNTIL=20400101",
	} {
		ev := newTestVEvent("uid-rr")
		setRRule(ev, refuse)
		if _, _, err := icalToEventInput(wrapCalendar(ev)); !errors.Is(err, errICalRefused) {
			t.Errorf("RRULE %q: err = %v, want errICalRefused", refuse, err)
		}
	}
	for _, pass := range []string{
		"FREQ=DAILY;COUNT=49",
		"FREQ=WEEKLY;UNTIL=20371231T235959Z",
		"FREQ=WEEKLY;BYDAY=MO,TH",
	} {
		ev := newTestVEvent("uid-rr-ok")
		setRRule(ev, pass)
		in, _, err := icalToEventInput(wrapCalendar(ev))
		if err != nil {
			t.Errorf("RRULE %q refused: %v", pass, err)
		} else if in.RRule != pass {
			t.Errorf("RRULE %q not verbatim: %q", pass, in.RRule)
		}
	}
}

// TestICalToEventInputExDates: Apple's PUT carries the EXDATE in the three
// possible forms; all must surface as absolute instants.
func TestICalToEventInputExDates(t *testing.T) {
	ev := ical.NewEvent()
	ev.Props.SetText(ical.PropUID, "uid-ex")
	ev.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	ev.Props.SetDateTime(ical.PropDateTimeStart, time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC))
	ev.Props.SetDateTime(ical.PropDateTimeEnd, time.Date(2022, 3, 7, 10, 0, 0, 0, time.UTC))
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = "FREQ=WEEKLY;BYDAY=MO,TH"
	ev.Props.Set(rr)

	// UTC-Z form, multi-value.
	exZ := ical.NewProp(ical.PropExceptionDates)
	exZ.Value = "20260713T090000Z,20260716T090000Z"
	ev.Props.Add(exZ)
	// TZID form (Apple often re-emits in local zone).
	exTZ := ical.NewProp(ical.PropExceptionDates)
	exTZ.Params.Set(ical.ParamTimezoneID, "Europe/Paris")
	exTZ.Value = "20260720T110000"
	ev.Props.Add(exTZ)

	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Children = append(cal.Children, ev.Component)

	in, _, err := icalToEventInput(cal)
	if err != nil {
		t.Fatalf("icalToEventInput: %v", err)
	}
	want := []time.Time{
		time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC), // 11:00 Paris summer = 09:00Z
	}
	if len(in.ExDates) != len(want) {
		t.Fatalf("ExDates = %v, want %d entries", in.ExDates, len(want))
	}
	for i := range want {
		if !in.ExDates[i].Equal(want[i]) {
			t.Errorf("ExDates[%d] = %v, want %v", i, in.ExDates[i], want[i])
		}
	}
}

// TestSeriesInputRefusals: the error cases of the multi-VEVENT parse — mixed
// UID (400, malformed ICS), RRULE on a child (403), double master (400),
// double RECURRENCE-ID (400).
func TestSeriesInputRefusals(t *testing.T) {
	start := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	newChild := func(uid string, occ time.Time) *ical.Component {
		c := ical.NewEvent()
		c.Props.SetText(ical.PropUID, uid)
		c.Props.SetDateTime(ical.PropDateTimeStamp, start)
		c.Props.SetDateTime(ical.PropDateTimeStart, occ.Add(time.Hour))
		c.Props.SetDateTime(ical.PropDateTimeEnd, occ.Add(2*time.Hour))
		rid := ical.NewProp(ical.PropRecurrenceID)
		rid.SetDateTime(occ)
		c.Props.Set(rid)
		return c.Component
	}
	master := func(uid string) *ical.Component {
		m := ical.NewEvent()
		m.Props.SetText(ical.PropUID, uid)
		m.Props.SetDateTime(ical.PropDateTimeStamp, start)
		m.Props.SetDateTime(ical.PropDateTimeStart, start)
		m.Props.SetDateTime(ical.PropDateTimeEnd, start.Add(time.Hour))
		rr := ical.NewProp(ical.PropRecurrenceRule)
		rr.Value = "FREQ=WEEKLY"
		m.Props.Set(rr)
		return m.Component
	}
	wrap := func(comps ...*ical.Component) *ical.Calendar {
		cal := ical.NewCalendar()
		cal.Props.SetText(ical.PropProductID, "-//test//EN")
		cal.Props.SetText(ical.PropVersion, "2.0")
		cal.Children = append(cal.Children, comps...)
		return cal
	}
	occ := start.Add(7 * 24 * time.Hour)

	// Mixed UID → bare error (400 on the backend side).
	if _, err := icalToSeriesInput(wrap(master("a"), newChild("b", occ))); err == nil || errors.Is(err, errICalRefused) {
		t.Errorf("mixed UID: err = %v, want bare error (400)", err)
	}
	// Two same-UID masters → bare error.
	if _, err := icalToSeriesInput(wrap(master("a"), master("a"))); err == nil || errors.Is(err, errICalRefused) {
		t.Errorf("double master: err = %v, want bare error (400)", err)
	}
	// Double override of the same occurrence → bare error.
	if _, err := icalToSeriesInput(wrap(master("a"), newChild("a", occ), newChild("a", occ))); err == nil {
		t.Error("double RECURRENCE-ID accepted")
	}
	// RRULE on a child → 403 refusal (errICalRefused).
	bad := newChild("a", occ)
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = "FREQ=DAILY"
	bad.Props.Set(rr)
	if _, err := icalToSeriesInput(wrap(master("a"), bad)); !errors.Is(err, errICalRefused) {
		t.Errorf("RRULE on child: err = %v, want errICalRefused", err)
	}
	// Nominal case: master + child, child's EXDATE stripped.
	okChild := newChild("a", occ)
	exp := ical.NewProp(ical.PropExceptionDates)
	exp.SetDateTime(occ)
	okChild.Props.Add(exp)
	series, err := icalToSeriesInput(wrap(master("a"), okChild))
	if err != nil {
		t.Fatalf("nominal series: %v", err)
	}
	if series.master == nil || len(series.children) != 1 {
		t.Fatalf("series = %+v", series)
	}
	if !series.children[0].occurrence.Equal(occ) || series.children[0].in.RecurrenceID == nil {
		t.Errorf("child occurrence = %+v", series.children[0])
	}
	if len(series.children[0].in.ExDates) != 0 {
		t.Error("a child's EXDATE must be stripped (Radicale #1635 trap)")
	}
}
