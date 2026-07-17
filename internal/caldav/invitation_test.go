package caldav

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/invite"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// ---- Backend M5a policy (create+invitation, refusal, strip) ----

// fakeSender captures the invitations sent (never any SMTP in tests).
type fakeSender struct {
	sent []invite.Message
	fail bool
}

func (f *fakeSender) Send(ctx context.Context, m invite.Message) error {
	f.sent = append(f.sent, m)
	if f.fail {
		return context.DeadlineExceeded // any transport error
	}
	return nil
}

// newInviteBackend: test backend with invitations ENABLED for the
// alice@example.com account.
func newInviteBackend() (*Backend, *fakeSource, *fakeSender) {
	b, src := newTestBackend()
	sender := &fakeSender{}
	b.ConfigureInvites([]string{"alice@example.com"}, "Alice Example", sender)
	return b, src, sender
}

// buildInviteICS assembles the typical Apple PUT of a create with invitees:
// ORGANIZER (account address) + ATTENDEE (the organizer lists herself too,
// Apple habit — she must be deduplicated).
func buildInviteICS(t *testing.T, uid string, start time.Time, organizer string, attendees ...string) *ical.Calendar {
	t.Helper()
	cal := buildICS(t, uid, "Test lunch", start, start.Add(time.Hour), false)
	vevent := cal.Children[0]
	org := ical.NewProp(ical.PropOrganizer)
	org.Params.Set(ical.ParamCommonName, "Alice")
	org.Value = "mailto:" + organizer
	vevent.Props.Set(org)
	for _, email := range append([]string{organizer}, attendees...) {
		p := ical.NewProp(ical.PropAttendee)
		p.Params.Set(ical.ParamCommonName, email)
		p.Params.Set(ical.ParamRSVP, "TRUE")
		p.Value = "mailto:" + email
		vevent.Props.Add(p)
	}
	return cal
}

// TestPutInviteCreate: outgoing create — the event is written WITH the
// invitees, then ONE iMIP email goes out per invitee (From = ORGANIZER, METHOD:REQUEST
// in the ICS, never any X-PM-TOKEN), and the re-read serves ATTENDEE/ORGANIZER.
func TestPutInviteCreate(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-invite-1", start, "alice@example.com", "bob@example.com")

	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/uid-invite-1.ics", cal, nil)
	if err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	// The event carries organizer + invitee (organizer DEDUPLICATED).
	id, found, _ := src.FindEventByUID(ctx, "cal1", "uid-invite-1")
	if !found {
		t.Fatal("event not created")
	}
	ev, _ := src.GetEvent(ctx, "cal1", id)
	if ev.Organizer != "alice@example.com" {
		t.Errorf("Organizer = %q", ev.Organizer)
	}
	if len(ev.Attendees) != 1 || ev.Attendees[0].Email != "bob@example.com" {
		t.Errorf("Attendees = %+v, want [bob@example.com] (organizer deduplicated)", ev.Attendees)
	}

	// ONE email, From = ORGANIZER exactly, compliant iMIP ICS.
	if len(sender.sent) != 1 {
		t.Fatalf("emails sent = %d, want 1", len(sender.sent))
	}
	m := sender.sent[0]
	if m.From != "alice@example.com" || m.To != "bob@example.com" {
		t.Errorf("From/To = %q/%q", m.From, m.To)
	}
	if m.Subject != "Invitation: Test lunch" {
		t.Errorf("Subject = %q", m.Subject)
	}
	ics := string(m.ICS)
	for _, want := range []string{"METHOD:REQUEST", "UID:uid-invite-1", "SEQUENCE:0",
		"ORGANIZER;CN=Alice:mailto:alice@example.com", "PARTSTAT=NEEDS-ACTION", "RSVP=TRUE"} {
		if !strings.Contains(ics, want) {
			t.Errorf("invitation ICS missing %q:\n%s", want, ics)
		}
	}
	if strings.Contains(ics, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN leaked into the email:\n%s", ics)
	}

	// Re-read (the 201 serves the resource): ATTENDEE/ORGANIZER visible so
	// that Apple sees its write confirmed.
	got, err := b.GetCalendarObject(ctx, obj.Path, nil)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}
	var served strings.Builder
	if err := ical.NewEncoder(&served).Encode(got.Data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ORGANIZER:mailto:alice@example.com", "ATTENDEE;", "mailto:bob@example.com", "PARTSTAT=NEEDS-ACTION"} {
		if !strings.Contains(served.String(), want) {
			t.Errorf("re-read missing %q:\n%s", want, served.String())
		}
	}
}

// TestPutInviteSendFailureStill201: the Proton sync succeeded — a send
// failure does NOT fail the PUT (the calendar state is true), it is
// only logged per recipient.
func TestPutInviteSendFailureStill201(t *testing.T) {
	b, src, sender := newInviteBackend()
	sender.fail = true
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-invite-fail", start, "alice@example.com", "bob@example.com")

	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("PUT must return 201 despite the send failure, got %v", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-invite-fail"); !found {
		t.Fatal("event absent (rollback forbidden)")
	}
	if len(sender.sent) != 1 {
		t.Fatalf("send attempts = %d, want 1", len(sender.sent))
	}
}

// TestPutInviteDisabled403: without a sender ([invite] absent/enabled=false), an
// outgoing PUT with ATTENDEE is refused with 403 — the pre-M5a behavior.
func TestPutInviteDisabled403(t *testing.T) {
	b, src := newTestBackend()
	b.ConfigureInvites([]string{"alice@example.com"}, "", nil) // owners without a sender
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-invite-off", start, "alice@example.com", "bob@example.com")

	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); !isHTTPStatus(err, http.StatusForbidden) {
		t.Fatalf("outgoing PUT without [invite] = %v, want 403", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-invite-off"); found {
		t.Fatal("event created although the PUT should have been refused")
	}
}

// TestPutInviteRecurringSeriesCreate (C-3): creating a WHOLE SERIES
// with invitees is accepted — the invitation ICS carries the recurrence (RRULE).
func TestPutInviteRecurringSeriesCreate(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-invite-rec", start, "alice@example.com", "bob@example.com")
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = "FREQ=WEEKLY"
	cal.Children[0].Props.Set(rr)

	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("invited series create: %v", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-invite-rec"); !found {
		t.Fatal("invited series not created")
	}
	if len(sender.sent) != 1 {
		t.Fatalf("emails sent = %d, want 1", len(sender.sent))
	}
	if ics := string(sender.sent[0].ICS); !strings.Contains(ics, "RRULE:FREQ=WEEKLY") {
		t.Errorf("a series invitation must carry the RRULE:\n%s", ics)
	}
}

// TestPutInviteOccurrenceEdit403: editing ONE occurrence of an invited
// series (RECURRENCE-ID child) stays refused — the per-occurrence REQUEST
// is M6.
func TestPutInviteOccurrenceEdit403(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-invite-occ", start, "alice@example.com", "bob@example.com")
	rr := ical.NewProp(ical.PropRecurrenceRule)
	rr.Value = "FREQ=DAILY"
	cal.Children[0].Props.Set(rr)
	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("invited series create: %v", err)
	}
	sender.sent = nil

	// Same series + a RECURRENCE-ID child (occurrence moved by one hour).
	child := ical.NewEvent()
	child.Props.SetText(ical.PropUID, "uid-invite-occ")
	child.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	rid := ical.NewProp(ical.PropRecurrenceID)
	rid.SetDateTime(start.Add(24 * time.Hour))
	child.Props.Set(rid)
	child.Props.SetDateTime(ical.PropDateTimeStart, start.Add(25*time.Hour))
	child.Props.SetDateTime(ical.PropDateTimeEnd, start.Add(26*time.Hour))
	cal.Children = append(cal.Children, child.Component)

	err := putCal1(ctx, b, cal)
	if !isHTTPStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "ATTENDEE-RECURRING") {
		t.Fatalf("editing an occurrence of an invited series = %v, want 403 ATTENDEE-RECURRING", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("emails sent = %d, want 0", len(sender.sent))
	}
	// The series did not move (no exception row created).
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-invite-occ")
	rows, _ := src.ListEventsByUID(ctx, "cal1", "uid-invite-occ")
	if len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("exception row created despite the refusal: %+v", rows)
	}
}

// createInvitedEvent: shortcut — outgoing create for the given uid with invitees,
// email counter reset to zero.
func createInvitedEvent(t *testing.T, b *Backend, sender *fakeSender, uid string, start time.Time, attendees ...string) {
	t.Helper()
	cal := buildInviteICS(t, uid, start, "alice@example.com", attendees...)
	if _, err := b.PutCalendarObject(context.Background(), "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("invited create: %v", err)
	}
	sender.sent = nil
}

// TestPutInviteUpdateSignificant: moving an invited event (DTSTART/DTEND)
// is ACCEPTED — an "update" REQUEST to the kept invitees, SEQUENCE+1 in
// the ICS, invitee list intact.
func TestPutInviteUpdateSignificant(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-up-sig", start, "bob@example.com")

	cal := buildInviteICS(t, "uid-up-sig", start.Add(2*time.Hour), "alice@example.com", "bob@example.com")
	if err := putCal1(ctx, b, cal); err != nil {
		t.Fatalf("significant update refused: %v", err)
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-up-sig")
	ev, _ := src.GetEvent(ctx, "cal1", id)
	if !ev.Start.Equal(start.Add(2 * time.Hour)) {
		t.Errorf("Start = %v, want %v", ev.Start, start.Add(2*time.Hour))
	}
	if len(ev.Attendees) != 1 || ev.Attendees[0].Email != "bob@example.com" || ev.Organizer != "alice@example.com" {
		t.Errorf("invitee list degraded by the update: %+v (org %q)", ev.Attendees, ev.Organizer)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("emails = %d, want 1 (REQUEST to the kept invitee)", len(sender.sent))
	}
	m := sender.sent[0]
	if m.To != "bob@example.com" || m.Method != "REQUEST" || !strings.HasPrefix(m.Subject, "Updated invitation") {
		t.Errorf("email = To %q Method %q Subject %q", m.To, m.Method, m.Subject)
	}
	ics := string(m.ICS)
	for _, want := range []string{"METHOD:REQUEST", "SEQUENCE:1", "UID:uid-up-sig"} {
		if !strings.Contains(ics, want) {
			t.Errorf("ICS missing %q:\n%s", want, ics)
		}
	}
}

// TestPutInviteUpdateCosmetic: SUMMARY/DESCRIPTION only → update accepted
// WITHOUT re-notification (stance of the big calendars).
func TestPutInviteUpdateCosmetic(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-up-cosm", start, "bob@example.com")

	cal := buildInviteICS(t, "uid-up-cosm", start, "alice@example.com", "bob@example.com")
	cal.Children[0].Props.SetText(ical.PropSummary, "Corrected title")
	if err := putCal1(ctx, b, cal); err != nil {
		t.Fatalf("cosmetic update refused: %v", err)
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-up-cosm")
	if ev, _ := src.GetEvent(ctx, "cal1", id); ev.Title != "Corrected title" || len(ev.Attendees) != 1 {
		t.Errorf("cosmetic update applied incorrectly: %+v", ev)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("emails = %d, want 0 (cosmetic = no re-notification)", len(sender.sent))
	}
}

// TestPutInviteAddAttendee: attendee ADDED → REQUEST to the new one ONLY
// (the event did not move for the kept ones), list rewritten.
func TestPutInviteAddAttendee(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-up-add", start, "bob@example.com")

	cal := buildInviteICS(t, "uid-up-add", start, "alice@example.com", "bob@example.com", "carol@example.com")
	if err := putCal1(ctx, b, cal); err != nil {
		t.Fatalf("adding an invitee refused: %v", err)
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-up-add")
	ev, _ := src.GetEvent(ctx, "cal1", id)
	if len(ev.Attendees) != 2 {
		t.Fatalf("Attendees = %+v, want 2", ev.Attendees)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("emails = %d, want 1 (REQUEST to the only added one)", len(sender.sent))
	}
	m := sender.sent[0]
	if m.To != "carol@example.com" || m.Method != "REQUEST" || !strings.HasPrefix(m.Subject, "Invitation:") {
		t.Errorf("email = To %q Method %q Subject %q", m.To, m.Method, m.Subject)
	}
	// The new one's ICS lists EVERYONE (it sees who is invited) and carries
	// the bumped SEQUENCE (invitee diff = structural for the invitation).
	ics := string(m.ICS)
	for _, want := range []string{"mailto:bob@example.com", "mailto:carol@example.com", "SEQUENCE:1"} {
		if !strings.Contains(ics, want) {
			t.Errorf("ICS missing %q:\n%s", want, ics)
		}
	}
}

// TestPutInviteRemoveAttendee: attendee REMOVED → CANCEL to the removed one only
// (STATUS:CANCELLED, never any RSVP), list reduced; removing the LAST
// invitee makes the event bare (ORGANIZER removed).
func TestPutInviteRemoveAttendee(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-up-rm", start, "bob@example.com", "carol@example.com")

	// Removing carol: CANCEL to carol only.
	cal := buildInviteICS(t, "uid-up-rm", start, "alice@example.com", "bob@example.com")
	if err := putCal1(ctx, b, cal); err != nil {
		t.Fatalf("removing an invitee refused: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("emails = %d, want 1 (CANCEL to the only removed one)", len(sender.sent))
	}
	m := sender.sent[0]
	if m.To != "carol@example.com" || m.Method != "CANCEL" || !strings.HasPrefix(m.Subject, "Cancelled") {
		t.Errorf("email = To %q Method %q Subject %q", m.To, m.Method, m.Subject)
	}
	ics := string(m.ICS)
	for _, want := range []string{"METHOD:CANCEL", "STATUS:CANCELLED", "SEQUENCE:1", "mailto:carol@example.com"} {
		if !strings.Contains(ics, want) {
			t.Errorf("CANCEL ICS missing %q:\n%s", want, ics)
		}
	}
	if strings.Contains(ics, "mailto:bob@example.com") || strings.Contains(ics, "RSVP=TRUE") {
		t.Errorf("the CANCEL lists only the cancelled ones, without RSVP:\n%s", ics)
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-up-rm")
	if ev, _ := src.GetEvent(ctx, "cal1", id); len(ev.Attendees) != 1 || ev.Attendees[0].Email != "bob@example.com" {
		t.Fatalf("Attendees = %+v, want [bob@example.com]", ev.Attendees)
	}

	// Removing the last invitee (PUT without ATTENDEE): CANCEL to bob, bare event.
	sender.sent = nil
	cal2 := buildICS(t, "uid-up-rm", "Test lunch", start, start.Add(time.Hour), false)
	if err := putCal1(ctx, b, cal2); err != nil {
		t.Fatalf("removing the last invitee refused: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0].To != "bob@example.com" || sender.sent[0].Method != "CANCEL" {
		t.Fatalf("emails = %+v, want 1 CANCEL to bob@example.com", sender.sent)
	}
	if ev, _ := src.GetEvent(ctx, "cal1", id); len(ev.Attendees) != 0 || ev.Organizer != "" {
		t.Fatalf("event did not become bare again: attendees=%+v org=%q", ev.Attendees, ev.Organizer)
	}
}

// TestPutInviteUpdateForeign403: invited event organized by a THIRD PARTY
// (synced from the Proton app) → any change via the gateway is
// refused (it would falsify the state on the organizer's side).
func TestPutInviteUpdateForeign403(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "evF", UID: "uid-foreign", CalendarID: "cal1", Title: "External meeting",
		Start: start, End: start.Add(time.Hour), LastEdit: start,
		Organizer: "boss@extern.com",
		Attendees: []proton.Attendee{{Email: "alice@example.com", Token: "tokA", Status: 3}},
	})

	cal := buildICS(t, "uid-foreign", "Moved meeting", start.Add(time.Hour), start.Add(2*time.Hour), false)
	err := putCal1(ctx, b, cal)
	if !isHTTPStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "ATTENDEE-FOREIGN") {
		t.Fatalf("update of a received invitation = %v, want 403 ATTENDEE-FOREIGN", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("emails = %d, want 0", len(sender.sent))
	}
}

// TestPutInviteUpdateDisabled403: [invite] absent + invited event on the
// Proton side → update refused (pre-M5a preserved), nothing sent, nothing written.
func TestPutInviteUpdateDisabled403(t *testing.T) {
	b, src := newTestBackend()
	b.ConfigureInvites([]string{"alice@example.com"}, "", nil) // owners without a sender
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "evD", UID: "uid-dis", CalendarID: "cal1", Title: "Lunch",
		Start: start, End: start.Add(time.Hour), LastEdit: start,
		Organizer: "alice@example.com",
		Attendees: []proton.Attendee{{Email: "bob@example.com", Token: "tokJ"}},
	})
	cal := buildICS(t, "uid-dis", "Lunch", start.Add(time.Hour), start.Add(2*time.Hour), false)
	if err := putCal1(ctx, b, cal); !isHTTPStatus(err, http.StatusForbidden) {
		t.Fatalf("invited update without [invite] = %v, want 403", err)
	}
}

// TestPutInviteAddBeyondLimit403: the maxInviteesPerEvent cap also applies
// to the invitee set of an UPDATE (covers additions).
func TestPutInviteAddBeyondLimit403(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-up-lim", start, "bob@example.com")

	over := make([]string, 0, maxInviteesPerEvent+1)
	for i := 0; i <= maxInviteesPerEvent; i++ {
		over = append(over, fmt.Sprintf("g%02d@example.com", i))
	}
	cal := buildInviteICS(t, "uid-up-lim", start, "alice@example.com", over...)
	err := putCal1(ctx, b, cal)
	if !isHTTPStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "ATTENDEE-LIMIT") {
		t.Fatalf("update beyond the cap = %v, want 403 ATTENDEE-LIMIT", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("emails = %d, want 0", len(sender.sent))
	}
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-up-lim")
	if ev, _ := src.GetEvent(ctx, "cal1", id); len(ev.Attendees) != 1 {
		t.Fatalf("list modified despite the refusal: %+v", ev.Attendees)
	}
}

// TestDeleteInviteCancel: DELETE of an invited event → CANCEL iMIP to each
// invitee (SEQUENCE superseding the last REQUEST), effective deletion.
func TestDeleteInviteCancel(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	createInvitedEvent(t, b, sender, "uid-del", start, "bob@example.com", "carol@example.com")
	id, _, _ := src.FindEventByUID(ctx, "cal1", "uid-del")

	if err := b.DeleteCalendarObject(ctx, "/alice/calendars/cal1/"+id+".ics"); err != nil {
		t.Fatalf("DeleteCalendarObject: %v", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-del"); found {
		t.Fatal("event still present after DELETE")
	}
	if len(sender.sent) != 2 {
		t.Fatalf("emails = %d, want 2 (CANCEL to each invitee)", len(sender.sent))
	}
	tos := map[string]bool{}
	for _, m := range sender.sent {
		tos[m.To] = true
		if m.Method != "CANCEL" || !strings.HasPrefix(m.Subject, "Cancelled") {
			t.Errorf("email = Method %q Subject %q, want CANCEL/Cancelled", m.Method, m.Subject)
		}
		ics := string(m.ICS)
		for _, want := range []string{"METHOD:CANCEL", "STATUS:CANCELLED", "SEQUENCE:1", "UID:uid-del"} {
			if !strings.Contains(ics, want) {
				t.Errorf("CANCEL ICS missing %q:\n%s", want, ics)
			}
		}
	}
	if !tos["bob@example.com"] || !tos["carol@example.com"] {
		t.Errorf("recipients = %v, want bob+carol", tos)
	}
}

// TestDeleteInviteNoSenderStillDeletes: [invite] absent — the DELETE of an
// invited event stays ALLOWED (WARN, no blocking).
func TestDeleteInviteNoSenderStillDeletes(t *testing.T) {
	b, src := newTestBackend()
	b.ConfigureInvites([]string{"alice@example.com"}, "", nil)
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	src.events["cal1"] = append(src.events["cal1"], proton.Event{
		ID: "evND", UID: "uid-nd", CalendarID: "cal1",
		Start: start, End: start.Add(time.Hour), LastEdit: start,
		Organizer: "alice@example.com",
		Attendees: []proton.Attendee{{Email: "bob@example.com", Token: "tokJ"}},
	})
	if err := b.DeleteCalendarObject(ctx, "/alice/calendars/cal1/evND.ics"); err != nil {
		t.Fatalf("DELETE must stay allowed without a sender: %v", err)
	}
	if _, found, _ := src.FindEventByUID(ctx, "cal1", "uid-nd"); found {
		t.Fatal("event still present")
	}
}

// putCal1: test shortcut (PUT on cal1, fixed path).
func putCal1(ctx context.Context, b *Backend, cal *ical.Calendar) error {
	_, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/y.ics", cal, nil)
	return err
}

// TestPutIncomingInviteStripped: RECEIVED booking (third-party ORGANIZER,
// third-party booking case) — the invitees are STRIPPED and the BARE event is stored, no
// email: the M3 behavior, unchanged.
func TestPutIncomingInviteStripped(t *testing.T) {
	b, src, sender := newInviteBackend()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	cal := buildInviteICS(t, "uid-booking", start, "noreply@bookingservice.example", "alice@example.com")

	if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/x.ics", cal, nil); err != nil {
		t.Fatalf("incoming PUT: %v", err)
	}
	id, found, _ := src.FindEventByUID(ctx, "cal1", "uid-booking")
	if !found {
		t.Fatal("incoming event not created")
	}
	ev, _ := src.GetEvent(ctx, "cal1", id)
	if ev.Organizer != "" || len(ev.Attendees) != 0 {
		t.Errorf("incoming event not stripped: organizer=%q attendees=%+v", ev.Organizer, ev.Attendees)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("email sent on an incoming booking: %+v", sender.sent)
	}
}

// ---- Invitation ICS ----

// TestInvitationICS: METHOD:REQUEST, VTIMEZONE for the zone, DTSTART;TZID,
// SEQUENCE:0, compliant ORGANIZER/ATTENDEE, never any X-PM-TOKEN.
func TestInvitationICS(t *testing.T) {
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	in := proton.EventInput{
		UID:         "uid-imip",
		Title:       "Lunch",
		Location:    "Toulouse",
		Description: "Celebrating M5a",
		Start:       start, End: start.Add(time.Hour),
		TZID:        "Europe/Paris",
		Organizer:   "alice@example.com",
		OrganizerCN: "Alice",
		Attendees:   []proton.AttendeeInput{{Email: "bob@example.com", CN: "Bob"}},
	}
	raw, err := InvitationICS(in, "REQUEST", 0, time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("InvitationICS: %v", err)
	}
	ics := string(raw)
	for _, want := range []string{
		"METHOD:REQUEST",
		"BEGIN:VTIMEZONE", "TZID:Europe/Paris",
		"DTSTART;TZID=Europe/Paris:20260915T140000", // 12:00Z = 14:00 Paris (summer)
		"SEQUENCE:0",
		"SUMMARY:Lunch", "LOCATION:Toulouse",
		"ORGANIZER;CN=Alice:mailto:alice@example.com",
		"mailto:bob@example.com",
		"PARTSTAT=NEEDS-ACTION", "RSVP=TRUE", "ROLE=REQ-PARTICIPANT",
		"UID:uid-imip", "DTSTAMP:20260901T080000Z",
	} {
		if !strings.Contains(ics, want) {
			t.Errorf("invitation missing %q:\n%s", want, ics)
		}
	}
	if strings.Contains(ics, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN in the invitation:\n%s", ics)
	}
	// The ICS must stay decodable (valid structure).
	if _, err := ical.NewDecoder(strings.NewReader(ics)).Decode(); err != nil {
		t.Fatalf("invitation not decodable: %v", err)
	}

	// Text body: Europe/Paris time range.
	text := invitationText(in, "Invitation")
	for _, want := range []string{"Lunch", "Tuesday 15 September 2026", "14:00", "15:00", "Europe/Paris", "Toulouse"} {
		if !strings.Contains(text, want) {
			t.Errorf("text body missing %q:\n%s", want, text)
		}
	}
}

// ---- Rendering / parsing ATTENDEE + ORGANIZER (ics.go) ----

// TestEventToICalAttendees: PARTSTAT derived from the plaintext Status (0..3), ORGANIZER
// served, X-PM-TOKEN never exposed to the CalDAV client.
func TestEventToICalAttendees(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Hour)
	ev := proton.Event{
		ID: "evt-att", UID: "uid-att", CalendarID: "cal1", Title: "Lunch",
		Start: now, End: now.Add(time.Hour), LastEdit: now,
		Organizer: "alice@example.com",
		Attendees: []proton.Attendee{
			{Email: "bob@example.com", CN: "Bob", Status: 0, Token: "secret-token"},
			{Email: "a@x.co", Status: 1}, {Email: "b@x.co", Status: 2}, {Email: "c@x.co", Status: 3},
		},
	}
	cal, err := EventToICal(ev)
	if err != nil {
		t.Fatalf("EventToICal: %v", err)
	}
	var buf strings.Builder
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"ORGANIZER:mailto:alice@example.com",
		"CN=Bob", "PARTSTAT=NEEDS-ACTION", "RSVP=TRUE", "ROLE=REQ-PARTICIPANT",
		"PARTSTAT=TENTATIVE", "PARTSTAT=DECLINED", "PARTSTAT=ACCEPTED",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret-token") || strings.Contains(got, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN served to the client:\n%s", got)
	}
}

// TestICalToEventInputAttendees: parses ORGANIZER (mailto+CN) and ATTENDEE
// (deduplicated, organizer excluded), incoming PARTSTAT ignored.
func TestICalToEventInputAttendees(t *testing.T) {
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-parse\r\nDTSTAMP:20260901T080000Z\r\n" +
		"DTSTART:20260915T120000Z\r\nDTEND:20260915T130000Z\r\n" +
		"ORGANIZER;CN=Alice:mailto:Alice@example.com\r\n" +
		"ATTENDEE;CN=Alice;PARTSTAT=ACCEPTED:mailto:alice@example.com\r\n" +
		"ATTENDEE;CN=Bob;PARTSTAT=DECLINED;RSVP=TRUE:mailto:bob@example.com\r\n" +
		"ATTENDEE;CN=Bob bis:mailto:Bob@example.com\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR\r\n"
	cal, err := ical.NewDecoder(strings.NewReader(ics)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := icalToEventInput(cal)
	if err != nil {
		t.Fatalf("icalToEventInput: %v", err)
	}
	if in.Organizer != "Alice@example.com" || in.OrganizerCN != "Alice" {
		t.Errorf("Organizer = %q (CN %q)", in.Organizer, in.OrganizerCN)
	}
	// The organizer (case-insensitive) and the Bob duplicate are excluded.
	if len(in.Attendees) != 1 || in.Attendees[0].Email != "bob@example.com" || in.Attendees[0].CN != "Bob" {
		t.Errorf("Attendees = %+v, want [{bob@example.com Bob}]", in.Attendees)
	}
}
