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

// UpdateAttendeeStatus makes fakeSource implement AttendeeStatusUpdater:
// patches the Status of the TARGETED attendee row (by ID), never another —
// mirror of the dedicated Proton endpoint (M6b).
func (f *fakeSource) UpdateAttendeeStatus(ctx context.Context, calID, eventID, attendeeID string, status int) error {
	for i := range f.events[calID] {
		if f.events[calID][i].ID != eventID {
			continue
		}
		for j := range f.events[calID][i].Attendees {
			if f.events[calID][i].Attendees[j].ID == attendeeID {
				f.events[calID][i].Attendees[j].Status = status
				return nil
			}
		}
		return fmt.Errorf("proton: attendee %s: %w", attendeeID, proton.ErrEventNotFound)
	}
	return fmt.Errorf("proton: event %s/%s: %w", calID, eventID, proton.ErrEventNotFound)
}

// receivedInvitationBackend: backend with invitations ENABLED for the account
// owner's account, with a RECEIVED event (organized by the third party bob@example.com) in the
// calendar, the account owner as invitee at NEEDS-ACTION.
func receivedInvitationBackend(t *testing.T) (*Backend, *fakeSource, *fakeSender, string) {
	t.Helper()
	const alice = "alice@example.com"
	const organizer = "bob@example.com"
	now := time.Now().UTC().Truncate(time.Hour)
	src := &fakeSource{
		calendars: []proton.Calendar{{ID: "cal1", Name: "Personal"}},
		events: map[string][]proton.Event{
			"cal1": {
				{
					ID: "recv1", UID: "uid-recv1", CalendarID: "cal1", Title: "Third-party lunch",
					Start: now.Add(48 * time.Hour), End: now.Add(49 * time.Hour),
					Organizer: organizer, LastEdit: now,
					Attendees: []proton.Attendee{
						{Email: alice, CN: "Alice", Status: 0, Token: "tok-alice", ID: "att-alice"},
					},
				},
			},
		},
	}
	b := NewBackend(src, "alice")
	sender := &fakeSender{}
	b.ConfigureInvites([]string{alice}, "Alice", sender)
	return b, src, sender, organizer
}

// receivedPUT reconstructs the COMPLETE state Apple sends back for the received event,
// with the account owner's PARTSTAT set to the desired value (and an optional mutation
// for the negative tests, via mutate).
func receivedPUT(t *testing.T, partstat string, mutate func(*ical.Component)) *ical.Calendar {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Hour)
	cal := buildICS(t, "uid-recv1", "Third-party lunch", now.Add(48*time.Hour), now.Add(49*time.Hour), false)
	vevent := cal.Children[0]
	org := ical.NewProp(ical.PropOrganizer)
	org.Value = "mailto:bob@example.com"
	vevent.Props.Set(org)
	att := ical.NewProp(ical.PropAttendee)
	att.Params.Set(ical.ParamCommonName, "Alice")
	att.Params.Set(ical.ParamParticipationStatus, partstat)
	att.Value = "mailto:alice@example.com"
	vevent.Props.Add(att)
	if mutate != nil {
		mutate(vevent)
	}
	return cal
}

// TestRSVPOutgoingReply: the account owner accepts a received invitation → iMIP REPLY emitted
// (From=account owner, To=organizer, METHOD:REPLY, a single ATTENDEE line for the account owner at
// PARTSTAT=ACCEPTED, no X-PM-TOKEN) + its Proton Status goes to 3, without
// rewriting the third party's event (no Create/Update call).
func TestRSVPOutgoingReply(t *testing.T) {
	b, src, sender, organizer := receivedInvitationBackend(t)
	ctx := context.Background()

	obj, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/recv1.ics", receivedPUT(t, "ACCEPTED", nil), nil)
	if err != nil {
		t.Fatalf("PUT RSVP: %v (403 expected ONLY on another change)", err)
	}
	if obj == nil || obj.ETag == "" {
		t.Fatalf("empty PUT response: %+v", obj)
	}
	// The third party's event was never rewritten.
	if src.updated != 0 || src.created != 0 {
		t.Errorf("third party's event rewritten (created=%d updated=%d) — forbidden", src.created, src.updated)
	}
	// The account owner's Status on the Proton side moved to ACCEPTED (3).
	ev, _ := src.GetEvent(ctx, "cal1", "recv1")
	if len(ev.Attendees) != 1 || ev.Attendees[0].Status != 3 {
		t.Fatalf("account owner's Status = %+v, want 3 (ACCEPTED)", ev.Attendees)
	}
	// An iMIP REPLY was emitted to the organizer.
	if len(sender.sent) != 1 {
		t.Fatalf("emails = %d, want 1 (REPLY)", len(sender.sent))
	}
	m := sender.sent[0]
	if m.Method != invite.MethodReply {
		t.Errorf("Method = %q, want REPLY", m.Method)
	}
	if m.From != "alice@example.com" {
		t.Errorf("From = %q, want alice@example.com (the account owner, never the organizer)", m.From)
	}
	if m.To != organizer {
		t.Errorf("To = %q, want %q (the third-party organizer)", m.To, organizer)
	}
	ics := strings.ReplaceAll(string(m.ICS), "\r\n ", "")
	for _, want := range []string{
		"METHOD:REPLY",
		"UID:uid-recv1",
		"ORGANIZER:mailto:bob@example.com",
		"PARTSTAT=ACCEPTED",
		"mailto:alice@example.com",
	} {
		if !strings.Contains(ics, want) {
			t.Errorf("REPLY ICS missing %q:\n%s", want, ics)
		}
	}
	if strings.Contains(ics, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN leaked into the REPLY:\n%s", ics)
	}
	// A single ATTENDEE line (the account owner's).
	if n := strings.Count(ics, "ATTENDEE"); n != 1 {
		t.Errorf("REPLY carries %d ATTENDEE, want 1 (the account owner alone)", n)
	}
	// The MIME carries method=REPLY (content-type text/calendar).
	var eml strings.Builder
	if err := invite.WriteEML(m, &eml); err != nil {
		t.Fatalf("WriteEML: %v", err)
	}
	if !strings.Contains(eml.String(), "method=REPLY") {
		t.Errorf(".eml missing content-type method=REPLY:\n%s", eml.String())
	}
}

// TestRSVPDeclineAndTentative covers the two other verbs (2=DECLINED,
// 1=TENTATIVE) and their Status mapping.
func TestRSVPDeclineAndTentative(t *testing.T) {
	for _, tc := range []struct {
		partstat string
		status   int
	}{
		{"DECLINED", 2},
		{"TENTATIVE", 1},
	} {
		t.Run(tc.partstat, func(t *testing.T) {
			b, src, sender, _ := receivedInvitationBackend(t)
			ctx := context.Background()
			if _, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/recv1.ics", receivedPUT(t, tc.partstat, nil), nil); err != nil {
				t.Fatalf("PUT %s: %v", tc.partstat, err)
			}
			ev, _ := src.GetEvent(ctx, "cal1", "recv1")
			if ev.Attendees[0].Status != tc.status {
				t.Errorf("Status = %d, want %d", ev.Attendees[0].Status, tc.status)
			}
			if len(sender.sent) != 1 || !strings.Contains(string(sender.sent[0].ICS), "PARTSTAT="+tc.partstat) {
				t.Errorf("REPLY %s missing", tc.partstat)
			}
		})
	}
}

// TestRSVPOtherEditStays403: a change OTHER than the account owner's PARTSTAT (here the
// title) on an event with a third-party organizer stays a 403 ATTENDEE-FOREIGN —
// never a rewrite of the third party's event, never a REPLY.
func TestRSVPOtherEditStays403(t *testing.T) {
	cases := map[string]func(*ical.Component){
		"title changed": func(v *ical.Component) {
			v.Props.SetText(ical.PropSummary, "Title changed by the account owner")
		},
		"time changed": func(v *ical.Component) {
			now := time.Now().UTC().Truncate(time.Hour)
			v.Props.SetDateTime(ical.PropDateTimeStart, now.Add(72*time.Hour))
			v.Props.SetDateTime(ical.PropDateTimeEnd, now.Add(73*time.Hour))
		},
		"attendee added": func(v *ical.Component) {
			p := ical.NewProp(ical.PropAttendee)
			p.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
			p.Value = "mailto:tiers@example.com"
			v.Props.Add(p)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, src, sender, _ := receivedInvitationBackend(t)
			ctx := context.Background()
			// Account owner's PARTSTAT unchanged (NEEDS-ACTION) + another change.
			_, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/recv1.ics", receivedPUT(t, "NEEDS-ACTION", mutate), nil)
			if !isHTTPStatus(err, http.StatusForbidden) {
				t.Fatalf("err = %v, want 403 ATTENDEE-FOREIGN", err)
			}
			if !strings.Contains(err.Error(), "ATTENDEE-FOREIGN") {
				t.Errorf("403 without ATTENDEE-FOREIGN: %v", err)
			}
			if len(sender.sent) != 0 {
				t.Errorf("REPLY emitted wrongly (%d)", len(sender.sent))
			}
			if src.updated != 0 || src.created != 0 {
				t.Errorf("event rewritten (created=%d updated=%d)", src.created, src.updated)
			}
		})
	}
}

// TestRSVPCannotAnswerForOthers: the account owner cannot reply for ANOTHER
// invitee (change a third party's PARTSTAT) — stays 403, no REPLY.
func TestRSVPCannotAnswerForOthers(t *testing.T) {
	const alice = "alice@example.com"
	const organizer = "bob@example.com"
	now := time.Now().UTC().Truncate(time.Hour)
	src := &fakeSource{
		calendars: []proton.Calendar{{ID: "cal1", Name: "Personal"}},
		events: map[string][]proton.Event{
			"cal1": {{
				ID: "recv1", UID: "uid-recv1", CalendarID: "cal1", Title: "Third-party lunch",
				Start: now.Add(48 * time.Hour), End: now.Add(49 * time.Hour),
				Organizer: organizer, LastEdit: now,
				Attendees: []proton.Attendee{
					{Email: alice, CN: "Alice", Status: 0, Token: "tok-alice", ID: "att-alice"},
					{Email: "carol@example.com", Status: 0, Token: "tok-carol", ID: "att-carol"},
				},
			}},
		},
	}
	b := NewBackend(src, "alice")
	sender := &fakeSender{}
	b.ConfigureInvites([]string{alice}, "Alice", sender)
	ctx := context.Background()

	// The account owner keeps her PARTSTAT at NEEDS-ACTION but tries to ACCEPT for Carol.
	cal := buildICS(t, "uid-recv1", "Third-party lunch", now.Add(48*time.Hour), now.Add(49*time.Hour), false)
	v := cal.Children[0]
	org := ical.NewProp(ical.PropOrganizer)
	org.Value = "mailto:bob@example.com"
	v.Props.Set(org)
	for _, a := range []struct{ email, ps string }{{alice, "NEEDS-ACTION"}, {"carol@example.com", "ACCEPTED"}} {
		p := ical.NewProp(ical.PropAttendee)
		p.Params.Set(ical.ParamParticipationStatus, a.ps)
		p.Value = "mailto:" + a.email
		v.Props.Add(p)
	}
	_, err := b.PutCalendarObject(ctx, "/alice/calendars/cal1/recv1.ics", cal, nil)
	if !isHTTPStatus(err, http.StatusForbidden) {
		t.Fatalf("err = %v, want 403 (the account owner only replies for herself)", err)
	}
	if len(sender.sent) != 0 {
		t.Errorf("REPLY emitted wrongly for a third party (%d)", len(sender.sent))
	}
}
