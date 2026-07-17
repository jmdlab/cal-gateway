package caldav

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	webcaldav "github.com/emersion/go-webdav/caldav"

	"github.com/jmdlab/cal-gateway/internal/proton"
)

// fakeSource simulates internal/proton to test the backend without crypto or network.
type fakeSource struct {
	calendars []proton.Calendar
	events    map[string][]proton.Event // calID -> events
	created   int                       // ID counter for CreateEvent
	updated   int                       // UpdateEvent call counter
}

func (f *fakeSource) ListCalendars(ctx context.Context) ([]proton.Calendar, error) {
	return f.calendars, nil
}

func (f *fakeSource) ListEvents(ctx context.Context, calID string, start, end time.Time) ([]proton.Event, error) {
	evs, ok := f.events[calID]
	if !ok {
		return nil, fmt.Errorf("no such calendar %s", calID)
	}
	var out []proton.Event
	for _, ev := range evs {
		if ev.Start.Before(end) && ev.End.After(start) {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (f *fakeSource) GetEvent(ctx context.Context, calID, eventID string) (*proton.Event, error) {
	for _, ev := range f.events[calID] {
		if ev.ID == eventID {
			return &ev, nil
		}
	}
	// Same error shape as the real internal/proton (Code 2501 wrapped):
	// the backend must map it to a clean 404.
	return nil, fmt.Errorf("proton: event %s/%s: %w", calID, eventID, proton.ErrEventNotFound)
}

// nextID feeds the row IDs of events created in the fake.
func (f *fakeSource) CreateEvent(ctx context.Context, calID string, in proton.EventInput) (string, error) {
	if _, ok := f.events[calID]; !ok {
		return "", fmt.Errorf("no such calendar %s", calID)
	}
	f.created++
	id := fmt.Sprintf("new%d", f.created)
	ev := proton.Event{
		ID: id, UID: in.UID, CalendarID: calID, Title: in.Title,
		Description: in.Description, Location: in.Location,
		Start: in.Start.UTC(), End: in.End.UTC(), AllDay: in.AllDay, RRule: in.RRule,
		TZ: in.TZID, EndTZ: in.EndTZID, // StartTimezone/EndTimezone columns
		ExDates: in.ExDates, Sequence: in.Sequence,
		LastEdit: time.Now().UTC(),
	}
	if in.RecurrenceID != nil {
		ev.RecurrenceID = in.RecurrenceID.Unix() // exception-row (API column)
	}
	// Invitation (M5a): the fake materializes organizer + attendees like the
	// real CreateEvent (Status 0 = NEEDS-ACTION, simplified derived token).
	ev.Organizer = in.Organizer
	for _, at := range in.Attendees {
		ev.Attendees = append(ev.Attendees, proton.Attendee{
			Email: at.Email, CN: at.CN, Token: "tok-" + at.Email,
		})
	}
	f.events[calID] = append(f.events[calID], ev)
	return id, nil
}

func (f *fakeSource) FindEventByUID(ctx context.Context, calID, uid string) (string, bool, error) {
	for _, ev := range f.events[calID] {
		if ev.UID == uid {
			return ev.ID, true, nil
		}
	}
	return "", false, nil
}

// ListEventsByUID / AuthoritativeEventsByUID: all rows of a UID,
// master first — same contract as the real internal/proton.
func (f *fakeSource) ListEventsByUID(ctx context.Context, calID, uid string) ([]proton.Event, error) {
	var out []proton.Event
	for _, ev := range f.events[calID] {
		if ev.UID == uid {
			out = append(out, ev)
		}
	}
	return sortSeriesRows(out), nil
}

func (f *fakeSource) AuthoritativeEventsByUID(ctx context.Context, calID, uid string) ([]proton.Event, error) {
	return f.ListEventsByUID(ctx, calID, uid)
}

// UpdateEvent applies the modeled fields onto the existing event (the fake
// mimics the merge of the real UpdateEvent).
func (f *fakeSource) UpdateEvent(ctx context.Context, calID, eventID string, in proton.EventInput) error {
	evs := f.events[calID]
	for i := range evs {
		if evs[i].ID == eventID {
			evs[i].Title = in.Title
			evs[i].Description = in.Description
			evs[i].Location = in.Location
			evs[i].Start = in.Start.UTC()
			evs[i].End = in.End.UTC()
			evs[i].AllDay = in.AllDay
			evs[i].RRule = in.RRule
			evs[i].ExDates = in.ExDates
			// Mirror of the real path (proton.writeTZ): the original TZID form
			// is never overwritten by an empty TZID (client's Z form).
			if in.TZID != "" {
				evs[i].TZ = in.TZID
			}
			if in.EndTZID != "" {
				evs[i].EndTZ = in.EndTZID
			}
			// Mirror of M5b (proton.planAttendeeUpdate): AttendeesReplace
			// rewrites the list — Status of kept ones preserved (matched
			// by email here, by token in the real one), added ones at NEEDS-ACTION.
			if in.AttendeesReplace {
				old := make(map[string]proton.Attendee, len(evs[i].Attendees))
				for _, at := range evs[i].Attendees {
					old[strings.ToLower(at.Email)] = at
				}
				var atts []proton.Attendee
				for _, at := range in.Attendees {
					na := proton.Attendee{Email: at.Email, CN: at.CN, Token: "tok-" + at.Email}
					if o, ok := old[strings.ToLower(at.Email)]; ok {
						na.Status, na.Token = o.Status, o.Token
					}
					atts = append(atts, na)
				}
				evs[i].Attendees = atts
				switch {
				case len(atts) == 0:
					evs[i].Organizer = "" // last attendee removed: ORGANIZER removed
				case evs[i].Organizer == "":
					evs[i].Organizer = in.Organizer // first attendees: ORGANIZER set
				}
			}
			evs[i].Sequence++
			evs[i].LastEdit = time.Now().UTC()
			f.updated++
			return nil
		}
	}
	return fmt.Errorf("proton: event %s/%s: %w", calID, eventID, proton.ErrEventNotFound)
}

// DeleteEvent mimics the same-UID batch of the real proton.DeleteEvent: the
// deletion of a master takes all its exception-rows with it.
func (f *fakeSource) DeleteEvent(ctx context.Context, calID, eventID string) error {
	evs := f.events[calID]
	for _, ev := range evs {
		if ev.ID != eventID {
			continue
		}
		keep := evs[:0]
		for _, e := range evs {
			if e.ID == eventID || (ev.RecurrenceID == 0 && e.UID == ev.UID) {
				continue
			}
			keep = append(keep, e)
		}
		f.events[calID] = keep
		return nil
	}
	return fmt.Errorf("proton: event %s/%s: %w", calID, eventID, proton.ErrEventNotFound)
}

func newTestBackend() (*Backend, *fakeSource) {
	now := time.Now().UTC().Truncate(time.Hour)
	src := &fakeSource{
		calendars: []proton.Calendar{
			{ID: "cal1", Name: "Personal"},
			{ID: "cal2", Name: "Work", Description: "Meta"},
		},
		events: map[string][]proton.Event{
			"cal1": {
				{
					ID: "ev1", UID: "uid-ev1", CalendarID: "cal1", Title: "Tomorrow",
					Start: now.Add(24 * time.Hour), End: now.Add(25 * time.Hour),
					LastEdit: now,
				},
				{
					ID: "ev2", UID: "uid-ev2", CalendarID: "cal1", Title: "Two years ago",
					Start: now.Add(-2 * 365 * 24 * time.Hour), End: now.Add(-2*365*24*time.Hour + time.Hour),
					LastEdit: now,
				},
			},
			"cal2": {},
		},
	}
	return NewBackend(src, "alice"), src
}

func TestPrincipalAndHomeSet(t *testing.T) {
	b, _ := newTestBackend()
	ctx := context.Background()
	// go-webdav v0.7.0 routes by depth: principal = 1 segment,
	// home set = 2 segments. Never "/".
	if p, err := b.CurrentUserPrincipal(ctx); err != nil || p != "/alice/" {
		t.Errorf("CurrentUserPrincipal = %q, %v", p, err)
	}
	if h, err := b.CalendarHomeSetPath(ctx); err != nil || h != "/alice/calendars/" {
		t.Errorf("CalendarHomeSetPath = %q, %v", h, err)
	}
}

func TestListAndGetCalendar(t *testing.T) {
	b, _ := newTestBackend()
	ctx := context.Background()

	cals, err := b.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	if len(cals) != 2 || cals[0].Path != "/alice/calendars/cal1/" || cals[1].Path != "/alice/calendars/cal2/" {
		t.Fatalf("calendars = %+v", cals)
	}
	if cals[0].SupportedComponentSet[0] != "VEVENT" {
		t.Errorf("component set = %v", cals[0].SupportedComponentSet)
	}

	cal, err := b.GetCalendar(ctx, "/alice/calendars/cal2/")
	if err != nil {
		t.Fatalf("GetCalendar: %v", err)
	}
	if cal.Name != "Work" || cal.Description != "Meta" {
		t.Errorf("calendar = %+v", cal)
	}

	if _, err := b.GetCalendar(ctx, "/alice/calendars/nope/"); !isHTTPStatus(err, http.StatusNotFound) {
		t.Errorf("missing calendar: err = %v, want 404", err)
	}
}

func TestGetCalendarObject(t *testing.T) {
	b, _ := newTestBackend()
	ctx := context.Background()

	obj, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/ev1.ics", nil)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}
	if obj.Path != "/alice/calendars/cal1/ev1.ics" {
		t.Errorf("path = %q", obj.Path)
	}
	if obj.ETag == "" || obj.ModTime.IsZero() {
		t.Errorf("etag/modtime missing: %q %v", obj.ETag, obj.ModTime)
	}
	events := obj.Data.Events()
	if len(events) != 1 {
		t.Fatalf("object has %d events", len(events))
	}
	if got, _ := events[0].Props.Text("SUMMARY"); got != "Tomorrow" {
		t.Errorf("SUMMARY = %q", got)
	}

	// A collection path is not an object.
	if _, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/", nil); !isHTTPStatus(err, http.StatusNotFound) {
		t.Errorf("collection as object: err = %v, want 404", err)
	}
}

func TestListCalendarObjectsWindow(t *testing.T) {
	b, _ := newTestBackend()
	objs, err := b.ListCalendarObjects(context.Background(), "/alice/calendars/cal1/", nil)
	if err != nil {
		t.Fatalf("ListCalendarObjects: %v", err)
	}
	// ev2 (two years ago) is outside the default window (-6 months).
	if len(objs) != 1 || objs[0].Path != "/alice/calendars/cal1/ev1.ics" {
		t.Fatalf("objects = %+v", objs)
	}
}

func TestQueryCalendarObjectsTimeRange(t *testing.T) {
	b, _ := newTestBackend()
	now := time.Now().UTC()
	query := &webcaldav.CalendarQuery{
		CompFilter: webcaldav.CompFilter{
			Name: "VCALENDAR",
			Comps: []webcaldav.CompFilter{{
				Name:  "VEVENT",
				Start: now.Add(-3 * 365 * 24 * time.Hour),
				End:   now.Add(365 * 24 * time.Hour),
			}},
		},
	}
	objs, err := b.QueryCalendarObjects(context.Background(), "/alice/calendars/cal1/", query)
	if err != nil {
		t.Fatalf("QueryCalendarObjects: %v", err)
	}
	// The filter's widened window must bring back ev1 AND ev2.
	if len(objs) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(objs), objs)
	}
}

func TestParsePath(t *testing.T) {
	b, _ := newTestBackend()
	cases := []struct {
		in            string
		calID, evID   string
		wantErrStatus int
	}{
		{in: "/alice/calendars/cal1/", calID: "cal1"},
		{in: "/alice/calendars/cal1", calID: "cal1"},
		{in: "/alice/calendars/cal1/ev1.ics", calID: "cal1", evID: "ev1"},
		{in: "/alice/calendars/", wantErrStatus: http.StatusNotFound},
		{in: "/elsewhere/x", wantErrStatus: http.StatusNotFound},
		{in: "/alice/calendars/cal1/ev1", wantErrStatus: http.StatusNotFound},
		{in: "/alice/calendars/cal1/sub/ev1.ics", wantErrStatus: http.StatusNotFound},
	}
	for _, tc := range cases {
		calID, evID, err := b.parsePath(tc.in)
		if tc.wantErrStatus != 0 {
			if !isHTTPStatus(err, tc.wantErrStatus) {
				t.Errorf("parsePath(%q): err = %v, want status %d", tc.in, err, tc.wantErrStatus)
			}
			continue
		}
		if err != nil || calID != tc.calID || evID != tc.evID {
			t.Errorf("parsePath(%q) = (%q, %q, %v), want (%q, %q)", tc.in, calID, evID, err, tc.calID, tc.evID)
		}
	}
}

// isHTTPStatus checks that an error carries the expected HTTP status. The
// concrete type (go-webdav's internal.HTTPError) is not importable; its
// message begins with "<code> <status text>" — we rely on that.
func isHTTPStatus(err error, status int) bool {
	if err == nil {
		return false
	}
	prefix := strconv.Itoa(status) + " " + http.StatusText(status)
	return strings.HasPrefix(err.Error(), prefix)
}

// buildICS assembles a minimal ICS (VEVENT) to test the write path.
func buildICS(t *testing.T, uid, summary string, start, end time.Time, method bool) *ical.Calendar {
	t.Helper()
	ev := ical.NewEvent()
	ev.Props.SetText(ical.PropUID, uid)
	ev.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	ev.Props.SetDateTime(ical.PropDateTimeStart, start.UTC())
	ev.Props.SetDateTime(ical.PropDateTimeEnd, end.UTC())
	ev.Props.SetText(ical.PropSummary, summary)
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	cal.Props.SetText(ical.PropVersion, "2.0")
	if method {
		cal.Props.SetText(ical.PropMethod, "PUBLISH") // third-party booking invite
	}
	cal.Children = append(cal.Children, ev.Component)
	return cal
}

func TestPutCalendarObjectCreate(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildICS(t, "booking-uid-1", "TEST BookingService", start, start.Add(time.Hour), true)

	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/whatever.ics", cal, &webcaldav.PutCalendarObjectOptions{})
	if err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}
	if obj.ETag == "" || obj.Path == "" {
		t.Fatalf("PutCalendarObject returned empty object: %+v", obj)
	}
	// The event must be created and readable back.
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "booking-uid-1"); !found {
		t.Fatalf("event not created in source")
	}
}

func TestPutCalendarObjectUpdateNotDuplicate(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)

	before := len(src.events["cal1"])
	cal := buildICS(t, "dup-uid", "First", start, start.Add(time.Hour), false)
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("first PUT: %v", err)
	}
	// Second PUT of the same UID: REAL update (M3), not a duplicate nor a no-op.
	cal2 := buildICS(t, "dup-uid", "Second", start, start.Add(time.Hour), false)
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal2, nil); err != nil {
		t.Fatalf("second PUT: %v", err)
	}
	if got := len(src.events["cal1"]); got != before+1 {
		t.Fatalf("update PUT created duplicates: before=%d after=%d", before, got)
	}
	if src.updated != 1 {
		t.Fatalf("updated = %d, want 1 (the lying no-op is back)", src.updated)
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "dup-uid")
	ev, _ := src.GetEvent(ctx, "cal1", id)
	if ev.Title != "Second" {
		t.Fatalf("title after update = %q, want Second", ev.Title)
	}
}

// TestPutCalendarObjectUpdateExdate is THE production-bug scenario: Apple
// deletes an occurrence of a recurring event by PUTting the master with an
// added EXDATE — the PUT must write the EXDATE and return a fresh ETag.
func TestPutCalendarObjectUpdateExdate(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()

	// Existing recurring master on the Proton side (the recurring-master corruption case).
	start := time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "rec1", UID: "uid-rec", CalendarID: "cal1", Title: "Weekly Sync",
		Start: start, End: start.Add(time.Hour),
		RRule:    "FREQ=WEEKLY;BYDAY=MO,TH",
		LastEdit: time.Now().Add(-time.Hour).UTC(),
	})

	// PUT of the master with an EXDATE (deleted occurrence): same UID.
	cal := buildICS(t, "uid-rec", "Weekly Sync", start, start.Add(time.Hour), false)
	vevent := cal.Children[0]
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = "FREQ=WEEKLY;BYDAY=MO,TH"
	vevent.Props.Set(rr)
	ex := ical.NewProp(ical.PropExceptionDates)
	ex.SetDateTime(time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC))
	vevent.Props.Add(ex)

	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", cal, nil)
	if err != nil {
		t.Fatalf("PUT master+EXDATE: %v", err)
	}
	if obj.ETag == "" {
		t.Fatalf("no fresh ETag returned")
	}
	ev, _ := src.GetEvent(ctx, "cal1", "rec1")
	if len(ev.ExDates) != 1 || !ev.ExDates[0].Equal(time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("EXDATE not persisted: %v", ev.ExDates)
	}
	if ev.RRule != "FREQ=WEEKLY;BYDAY=MO,TH" {
		t.Fatalf("RRULE lost on update: %q", ev.RRule)
	}
}

// seedSeries installs THE production case (recurring-master corruption case) in
// the fake, in miniature: a weekly master + an exception-row (moved occurrence).
func seedSeries(src *fakeSource) (master, exception proton.Event) {
	start := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC) // a Monday
	occ2 := start.Add(7 * 24 * time.Hour)
	master = proton.Event{
		ID: "rec1", UID: "uid-rec", CalendarID: "cal1", Title: "Weekly Sync",
		Start: start, End: start.Add(time.Hour),
		RRule: "FREQ=WEEKLY;BYDAY=MO", Sequence: 1,
		LastEdit: time.Now().Add(-2 * time.Hour).UTC(),
	}
	exception = proton.Event{
		ID: "exc1", UID: "uid-rec", CalendarID: "cal1", Title: "Weekly Sync (moved)",
		Start: occ2.Add(2 * time.Hour), End: occ2.Add(3 * time.Hour),
		RecurrenceID: occ2.Unix(), Sequence: 1,
		LastEdit: time.Now().Add(-time.Hour).UTC(),
	}
	src.events["cal1"] = append(src.events["cal1"], master, exception)
	return master, exception
}

// buildSeriesICS assembles Apple's folded PUT: master (RRULE [+ EXDATEs]) +
// one child VEVENT per modified occurrence (RECURRENCE-ID, without RRULE).
func buildSeriesICS(t *testing.T, uid string, start time.Time, rrule string, exdates []time.Time, children []struct{ occ, start time.Time }) *ical.Calendar {
	t.Helper()
	cal := buildICS(t, uid, "Weekly Sync", start, start.Add(time.Hour), false)
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = rrule
	cal.Children[0].Props.Set(rr)
	for _, ex := range exdates {
		p := ical.NewProp(ical.PropExceptionDates)
		p.SetDateTime(ex.UTC())
		cal.Children[0].Props.Add(p)
	}
	for _, c := range children {
		child := ical.NewEvent()
		child.Props.SetText(ical.PropUID, uid)
		child.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
		child.Props.SetDateTime(ical.PropDateTimeStart, c.start.UTC())
		child.Props.SetDateTime(ical.PropDateTimeEnd, c.start.Add(time.Hour).UTC())
		child.Props.SetText(ical.PropSummary, "Weekly Sync (moved)")
		rid := ical.NewProp(ical.PropRecurrenceID)
		rid.SetDateTime(c.occ.UTC())
		child.Props.Set(rid)
		cal.Children = append(cal.Children, child.Component)
	}
	return cal
}

// TestFoldedRead: THE "Error 2" fix — a master + same-UID exception-rows
// series is served as ONE CalDAV resource (RFC 4791), the master with its
// RRULE, the child with RECURRENCE-ID and WITHOUT RRULE or EXDATE (Radicale
// #1635 trap); the exception's href returns 404.
func TestFoldedRead(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	master, exception := seedSeries(src)

	objs, err := b.ListCalendarObjects(ctx, "/alice/calendars/cal1/", nil)
	if err != nil {
		t.Fatalf("ListCalendarObjects: %v", err)
	}
	var folded *webcaldav.CalendarObject
	for i := range objs {
		for _, other := range objs[i].Data.Events() {
			if uid, _ := other.Props.Text("UID"); uid == "uid-rec" {
				folded = &objs[i]
			}
		}
	}
	if folded == nil {
		t.Fatal("series missing from the collection")
	}
	if folded.Path != "/alice/calendars/cal1/rec1.ics" {
		t.Errorf("anchor = %q, want master href", folded.Path)
	}
	events := folded.Data.Events()
	if len(events) != 2 {
		t.Fatalf("folded resource carries %d VEVENT, want 2", len(events))
	}
	// Master first: RRULE present, no RECURRENCE-ID.
	if rr := events[0].Props.Get(ical.PropRecurrenceRule); rr == nil || rr.Value != master.RRule {
		t.Errorf("master RRULE = %v", rr)
	}
	if events[0].Props.Get(ical.PropRecurrenceID) != nil {
		t.Error("master must not carry RECURRENCE-ID")
	}
	// Child: RECURRENCE-ID = original occurrence, never RRULE/EXDATE.
	rid := events[1].Props.Get(ical.PropRecurrenceID)
	if rid == nil {
		t.Fatal("child without RECURRENCE-ID")
	}
	if got, err := rid.DateTime(time.UTC); err != nil || got.Unix() != exception.RecurrenceID {
		t.Errorf("RECURRENCE-ID = %v (%v), want %d", got, err, exception.RecurrenceID)
	}
	if events[1].Props.Get(ical.PropRecurrenceRule) != nil {
		t.Error("child with RRULE")
	}
	if events[1].Props.Get(ical.PropExceptionDates) != nil {
		t.Error("child with EXDATE (Radicale #1635 trap)")
	}

	// GET of the anchor = the same resource; GET of the exception's href = 404.
	got, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", nil)
	if err != nil || len(got.Data.Events()) != 2 || got.ETag != folded.ETag {
		t.Fatalf("GET anchor: %v (events=%d etag=%q vs %q)", err, len(got.Data.Events()), got.ETag, folded.ETag)
	}
	if _, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/exc1.ics", nil); !isHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("GET exception href = %v, want 404", err)
	}
}

// TestFoldedETagTracksEveryRow: the folded resource's ETag changes as soon as
// ANY row of the group changes or disappears.
func TestFoldedETagTracksEveryRow(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	_, exception := seedSeries(src)

	before, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Editing the EXCEPTION alone (the master does not move).
	for i := range src.events["cal1"] {
		if src.events["cal1"][i].ID == exception.ID {
			src.events["cal1"][i].LastEdit = time.Now().Add(time.Hour).UTC()
		}
	}
	after, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", nil)
	if err != nil {
		t.Fatal(err)
	}
	if after.ETag == before.ETag {
		t.Fatal("ETag unchanged after editing an exception-row")
	}
	// Disappearance of the exception: the ETag must change again.
	src.events["cal1"] = src.events["cal1"][:len(src.events["cal1"])-1]
	gone, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", nil)
	if err != nil {
		t.Fatal(err)
	}
	if gone.ETag == after.ETag || gone.ETag == before.ETag {
		t.Fatal("ETag unchanged after deleting an exception-row")
	}
}

// TestOrphanExceptionServed: an exception-row without a master (defensive) stays
// served as a standalone resource rather than lost.
func TestOrphanExceptionServed(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	occ := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "orph1", UID: "uid-orph", CalendarID: "cal1", Title: "Orphan",
		Start: occ.Add(time.Hour), End: occ.Add(2 * time.Hour),
		RecurrenceID: occ.Unix(),
		LastEdit:     time.Now().UTC(),
	})
	obj, err := b.GetCalendarObject(ctx, "/alice/calendars/cal1/orph1.ics", nil)
	if err != nil {
		t.Fatalf("GET orphan: %v", err)
	}
	events := obj.Data.Events()
	if len(events) != 1 || events[0].Props.Get(ical.PropRecurrenceID) == nil {
		t.Fatalf("orphan resource = %d VEVENT, RECURRENCE-ID=%v", len(events), events[0].Props.Get(ical.PropRecurrenceID))
	}
}

// TestPutFoldedSeriesRouting: THE op. 4 routing of the FEATURE-MATRIX —
// (1) PUT master+child on a series without exception → CreateEvent of an
// exception-row (master UID, RecurrenceID, SEQUENCE ≥ master);
// (2) PUT removing the child + EXDATE on the master → DeleteEvent of the row,
// EXDATE written as-is (faithful mirror).
func TestPutFoldedSeriesRouting(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	start := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "rec1", UID: "uid-rec", CalendarID: "cal1", Title: "Weekly Sync",
		Start: start, End: start.Add(time.Hour),
		RRule: "FREQ=WEEKLY;BYDAY=MO", Sequence: 2,
		LastEdit: time.Now().Add(-2 * time.Hour).UTC(),
	})

	// (1) Apple moves the 2nd occurrence: PUT master + RECURRENCE-ID child.
	occ := start.Add(7 * 24 * time.Hour)
	cal := buildSeriesICS(t, "uid-rec", start, "FREQ=WEEKLY;BYDAY=MO", nil,
		[]struct{ occ, start time.Time }{{occ: occ, start: occ.Add(2 * time.Hour)}})
	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", cal, nil)
	if err != nil {
		t.Fatalf("folded PUT: %v", err)
	}
	if obj.Path != "/alice/calendars/cal1/rec1.ics" {
		t.Errorf("response anchored on %q, want master href", obj.Path)
	}
	if len(obj.Data.Events()) != 2 {
		t.Fatalf("PUT response carries %d VEVENT, want 2 (folded re-read)", len(obj.Data.Events()))
	}
	rows, _ := src.ListEventsByUID(ctx, "cal1", "uid-rec")
	if len(rows) != 2 {
		t.Fatalf("Proton rows = %d, want 2 (master + exception)", len(rows))
	}
	exc := rows[1]
	if exc.RecurrenceID != occ.Unix() || exc.UID != "uid-rec" {
		t.Fatalf("exception-row = %+v", exc)
	}
	if exc.Sequence < 2 {
		t.Fatalf("exception SEQUENCE = %d, want ≥ master (2) — code 2001 otherwise", exc.Sequence)
	}
	if !exc.Start.Equal(occ.Add(2 * time.Hour)) {
		t.Fatalf("exception Start = %v", exc.Start)
	}

	// (2) Apple deletes the moved occurrence: PUT master+EXDATE, without child.
	cal2 := buildSeriesICS(t, "uid-rec", start, "FREQ=WEEKLY;BYDAY=MO", []time.Time{occ}, nil)
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", cal2, nil); err != nil {
		t.Fatalf("PUT removing child: %v", err)
	}
	rows, _ = src.ListEventsByUID(ctx, "cal1", "uid-rec")
	if len(rows) != 1 {
		t.Fatalf("exception-row not purged: %d rows", len(rows))
	}
	if len(rows[0].ExDates) != 1 || !rows[0].ExDates[0].Equal(occ) {
		t.Fatalf("master EXDATE = %v, want [%v]", rows[0].ExDates, occ)
	}
}

// TestPutFoldedCreateWithChild: Apple recurrenceput/5-6 payload — a CREATE
// PUT already carrying master + child creates both rows.
func TestPutFoldedCreateWithChild(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	start := time.Date(2026, 9, 7, 14, 0, 0, 0, time.UTC)
	occ := start.Add(2 * 24 * time.Hour)
	cal := buildSeriesICS(t, "uid-new-series", start, "FREQ=DAILY;COUNT=5", nil,
		[]struct{ occ, start time.Time }{{occ: occ, start: occ.Add(time.Hour)}})
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/uid-new-series.ics", cal, nil); err != nil {
		t.Fatalf("folded create PUT: %v", err)
	}
	rows, _ := src.ListEventsByUID(ctx, "cal1", "uid-new-series")
	if len(rows) != 2 || rows[0].RRule == "" || rows[1].RecurrenceID != occ.Unix() {
		t.Fatalf("folded create: rows = %+v", rows)
	}
}

// TestPutThisAndFutureRefused: RANGE=THISANDFUTURE (op. 5) stays a 403 —
// no Proton equivalent, split emulation is the M5 design.
func TestPutThisAndFutureRefused(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	master, _ := seedSeries(src)

	occ := master.Start.Add(14 * 24 * time.Hour)
	cal := buildSeriesICS(t, "uid-rec", master.Start, master.RRule, nil,
		[]struct{ occ, start time.Time }{{occ: occ, start: occ.Add(time.Hour)}})
	// Add RANGE=THISANDFUTURE on the child.
	rid := cal.Children[1].Props.Get(ical.PropRecurrenceID)
	rid.Params.Set("RANGE", "THISANDFUTURE")
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", cal, nil); !isHTTPStatus(err, http.StatusForbidden) {
		t.Fatalf("THISANDFUTURE PUT = %v, want 403", err)
	}
}

// TestDeleteFoldedSeries: DELETE of the folded resource takes the master AND
// all exception-rows with it (zero debris).
func TestDeleteFoldedSeries(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	seedSeries(src)
	if err := b.DeleteCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics"); err != nil {
		t.Fatalf("DELETE series: %v", err)
	}
	if rows, _ := src.ListEventsByUID(ctx, "cal1", "uid-rec"); len(rows) != 0 {
		t.Fatalf("debris after DELETE: %+v", rows)
	}
}

// TestGetCalendarObjectGone: an event deleted on the Proton side (Code 2501)
// must return 404 — the raw 500 made dataaccessd loop after a DELETE.
func TestGetCalendarObjectGone(t *testing.T) {
	b, _ := newTestBackend()
	if _, err := b.GetCalendarObject(context.Background(), "/alice/calendars/cal1/vanished.ics", nil); !isHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("gone event: err = %v, want 404", err)
	}
}

// TestDeleteCalendarObjectGone: DELETE of an already-gone event → clean 404,
// not 500.
func TestDeleteCalendarObjectGone(t *testing.T) {
	b, _ := newTestBackend()
	if err := b.DeleteCalendarObject(context.Background(), "/alice/calendars/cal1/vanished.ics"); !isHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("gone delete: err = %v, want 404", err)
	}
}

func TestDeleteCalendarObject(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	if err := b.DeleteCalendarObject(ctx, "/alice/calendars/cal1/ev1.ics"); err != nil {
		t.Fatalf("DeleteCalendarObject: %v", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-ev1"); found {
		t.Fatalf("event ev1 still present after delete")
	}
}

func TestCreateCalendarRefused(t *testing.T) {
	b, _ := newTestBackend()
	err := b.CreateCalendar(context.Background(), &webcaldav.Calendar{})
	if !isHTTPStatus(err, http.StatusForbidden) {
		t.Fatalf("CreateCalendar err = %v, want 403", err)
	}
}

// TestPutTZIDSeriesRoundTrip: THE end-to-end test that would have caught the
// root bug (2026-07-16) — Apple PUT of a weekly TZID Europe/Paris series set in
// WINTER (09:00 local = 08:00Z) with an EXDATE and a SUMMER exception (09:00
// local = 07:00Z): the written instants are DST-correct, and the GET re-serves
// the SAME TZID + VTIMEZONE form, wall-clock times stable winter/summer — zero
// divergence with the occurrences Apple re-expands from this master.
func TestPutTZIDSeriesRoundTrip(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()

	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
		"BEGIN:VEVENT\r\nUID:uid-tz\r\nDTSTAMP:20260101T000000Z\r\n" +
		"DTSTART;TZID=Europe/Paris:20260105T090000\r\n" +
		"DTEND;TZID=Europe/Paris:20260105T100000\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO\r\n" +
		"EXDATE;TZID=Europe/Paris:20260720T090000\r\n" +
		"SUMMARY:Sync\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:uid-tz\r\nDTSTAMP:20260101T000000Z\r\n" +
		"RECURRENCE-ID;TZID=Europe/Paris:20260713T090000\r\n" +
		"DTSTART;TZID=Europe/Paris:20260713T110000\r\n" +
		"DTEND;TZID=Europe/Paris:20260713T120000\r\n" +
		"SUMMARY:Sync (moved)\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	cal, err := ical.NewDecoder(strings.NewReader(ics)).Decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/uid-tz.ics", cal, nil)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}

	// Stored instants DST-correct (winter +1, summer +2) — not a frozen 08:00Z.
	wantStart := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC) // 09:00 CET
	wantOcc := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)  // 09:00 CEST
	wantEx := time.Date(2026, 7, 20, 7, 0, 0, 0, time.UTC)   // 09:00 CEST
	rows, _ := src.ListEventsByUID(ctx, "cal1", "uid-tz")
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (master + exception)", len(rows))
	}
	if !rows[0].Start.Equal(wantStart) || rows[0].TZ != "Europe/Paris" {
		t.Errorf("master = %v %q, want %v Europe/Paris", rows[0].Start, rows[0].TZ, wantStart)
	}
	if len(rows[0].ExDates) != 1 || !rows[0].ExDates[0].Equal(wantEx) {
		t.Errorf("ExDates = %v, want [%v]", rows[0].ExDates, wantEx)
	}
	if rows[1].RecurrenceID != wantOcc.Unix() {
		t.Errorf("RecurrenceID = %d, want %d", rows[1].RecurrenceID, wantOcc.Unix())
	}

	// GET re-served: same TZID + VTIMEZONE form, wall-clock times stable.
	got, err := b.GetCalendarObject(ctx, obj.Path, nil)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	events := got.Data.Events()
	if len(events) != 2 {
		t.Fatalf("GET carries %d VEVENT, want 2", len(events))
	}
	assertTZIDProp := func(prop *ical.Prop, name, wantValue string, wantInstant time.Time) {
		t.Helper()
		if prop == nil {
			t.Fatalf("%s missing", name)
		}
		if tz := prop.Params.Get(ical.ParamTimezoneID); tz != "Europe/Paris" {
			t.Errorf("%s TZID = %q, want Europe/Paris", name, tz)
		}
		if prop.Value != wantValue {
			t.Errorf("%s = %q, want %q (wall-clock stable)", name, prop.Value, wantValue)
		}
		if inst, perr := prop.DateTime(time.UTC); perr != nil || !inst.Equal(wantInstant) {
			t.Errorf("%s instant = %v (%v), want %v — DST divergence", name, inst, perr, wantInstant)
		}
	}
	assertTZIDProp(events[0].Props.Get(ical.PropDateTimeStart), "DTSTART", "20260105T090000", wantStart)
	exProps := events[0].Props[ical.PropExceptionDates]
	if len(exProps) != 1 {
		t.Fatalf("got %d EXDATE, want 1", len(exProps))
	}
	assertTZIDProp(&exProps[0], "EXDATE", "20260720T090000", wantEx)
	assertTZIDProp(events[1].Props.Get(ical.PropRecurrenceID), "RECURRENCE-ID", "20260713T090000", wantOcc)
	hasTZ := false
	for _, comp := range got.Data.Children {
		if comp.Name == ical.CompTimezone {
			hasTZ = true
		}
	}
	if !hasTZ {
		t.Error("VTIMEZONE missing in served resource")
	}
}

// TestPutSeriesMergesPastExDates: the anti-history-clobber guard
// (2026-07-16) — Apple only sends back the EXDATE of its display horizon;
// Proton's past EXDATE survive the PUT, the client stays owner of
// today/future.
func TestPutSeriesMergesPastExDates(t *testing.T) {
	b, src := newTestBackend()
	ctx := context.Background()
	start := time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC)
	pastEx := time.Date(2025, 5, 5, 9, 0, 0, 0, time.UTC)                             // past cancellation (history)
	futureExKept := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Hour)     // sent back by the client
	futureExRestored := time.Now().UTC().Add(60 * 24 * time.Hour).Truncate(time.Hour) // "restored" on the client side
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "rec1", UID: "uid-rec", CalendarID: "cal1", Title: "Weekly Sync",
		Start: start, End: start.Add(time.Hour),
		RRule:    "FREQ=WEEKLY;BYDAY=MO",
		ExDates:  []time.Time{pastEx, futureExRestored},
		LastEdit: time.Now().Add(-time.Hour).UTC(),
	})

	// Apple PUT: list WITHOUT the past cancellation (purged horizon) nor the
	// restored future, with the kept future.
	cal := buildSeriesICS(t, "uid-rec", start, "FREQ=WEEKLY;BYDAY=MO", []time.Time{futureExKept}, nil)
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/rec1.ics", cal, nil); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	ev, _ := src.GetEvent(ctx, "cal1", "rec1")
	if len(ev.ExDates) != 2 || !ev.ExDates[0].Equal(pastEx) || !ev.ExDates[1].Equal(futureExKept) {
		t.Fatalf("ExDates = %v, want [%v %v] (past kept, client owns the future)",
			ev.ExDates, pastEx, futureExKept)
	}
	for _, ex := range ev.ExDates {
		if ex.Equal(futureExRestored) {
			t.Error("future EXDATE removed by the client survived")
		}
	}
}

// TestETagSchemaVersion: the served content changed shape (TZID +
// VTIMEZONE) without Proton's LastEdit moving — the schema version included
// in ALL ETag computations forces paired clients to re-download
// (self-healing mechanism).
func TestETagSchemaVersion(t *testing.T) {
	single := groupETag([]proton.Event{{ID: "a", LastEdit: time.Unix(1700000000, 0)}})
	if want := fmt.Sprintf("v%d-1700000000", etagSchemaVersion); single != want {
		t.Errorf("single-row etag = %q, want %q", single, want)
	}
	// Group form: different from the unversioned historical hash.
	group := groupETag([]proton.Event{
		{ID: "a", LastEdit: time.Unix(1, 0)},
		{ID: "b", LastEdit: time.Unix(2, 0)},
	})
	h := fnv.New64a()
	fmt.Fprintf(h, "a:1;")
	fmt.Fprintf(h, "b:2;")
	if group == strconv.FormatUint(h.Sum64(), 16) {
		t.Error("group etag identical to the unversioned form (no self-healing)")
	}
}
