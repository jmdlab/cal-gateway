package caldav

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/icaltime"
	"github.com/jmdlab/cal-gateway/internal/invite"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// Construction of the outgoing iMIP content (M5a creation, M5b lifecycle): the
// VCALENDAR embedded in the email (inline text/calendar + invite.ics
// attachment — see internal/invite), and the human-readable text bodies.
//
// The email's VEVENT carries the SAME UID as the Proton event (the correlation
// key for future REPLYs), the SEQUENCE of the Proton state (0 at creation,
// incremented on a structural change — RFC 5546), the ATTENDEEs in
// PARTSTAT=NEEDS-ACTION;RSVP=TRUE (REQUEST) — and NEVER an X-PM-TOKEN (Proton
// internal). A CANCEL carries STATUS:CANCELLED and the cancelled attendees.

// InvitationICS serializes the iMIP VCALENDAR of an event: gateway PRODID,
// VTIMEZONE of the referenced zones (vtimezone.go generator), complete VEVENT
// (RRULE/EXDATE included for a series — the invitation carries the recurrence,
// C-3). in is the Proton state (UID/Organizer/Attendees populated); method is
// REQUEST (creation / update) or CANCEL (RFC 5546: UID + ORGANIZER + SEQUENCE
// + DTSTAMP + cancelled ATTENDEEs, STATUS:CANCELLED); sequence is the SEQUENCE
// of the Proton state AFTER the operation; now is the DTSTAMP.
func InvitationICS(in proton.EventInput, method string, sequence int, now time.Time) ([]byte, error) {
	cancel := method == "CANCEL"
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, prodID)
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropMethod, method)

	used := make(map[string]bool)
	vevent := ical.NewEvent()
	vevent.Props.SetText(ical.PropUID, in.UID)
	vevent.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	if in.AllDay {
		vevent.Props.SetDate(ical.PropDateTimeStart, in.Start.UTC())
		vevent.Props.SetDate(ical.PropDateTimeEnd, in.End.UTC())
	} else {
		endTZ := in.EndTZID
		if endTZ == "" {
			endTZ = in.TZID
		}
		vevent.Props.SetDateTime(ical.PropDateTimeStart, inServeZone(in.Start, in.TZID, used))
		vevent.Props.SetDateTime(ical.PropDateTimeEnd, inServeZone(in.End, endTZ, used))
	}
	seq := ical.NewProp(ical.PropSequence)
	seq.Value = strconv.Itoa(sequence)
	vevent.Props.Set(seq)
	if in.RRule != "" {
		// Invited series (C-3): the invitation carries the full recurrence —
		// RRULE verbatim + EXDATE in the SAME form as the DTSTART (RFC 5545
		// §3.8.5.1), so the invitee's client expands the same occurrences as
		// Proton.
		rr := ical.NewProp(ical.PropRecurrenceRule)
		rr.Value = in.RRule
		vevent.Props.Set(rr)
		for _, ex := range in.ExDates {
			exProp := ical.NewProp(ical.PropExceptionDates)
			if in.AllDay {
				exProp.SetDate(ex.UTC())
			} else {
				exProp.SetDateTime(inServeZone(ex, in.TZID, used))
			}
			vevent.Props.Add(exProp)
		}
	}
	if cancel {
		// RFC 5546 §3.2.9: a CANCEL carries STATUS:CANCELLED — this is what
		// makes the event be removed from the invitee's calendar.
		vevent.Props.SetText(ical.PropStatus, "CANCELLED")
	}
	// Non-empty SUMMARY always: an empty/absent one shows as "untitled" in the
	// recipient's calendar (belt-and-suspenders behind the decrypt fix).
	vevent.Props.SetText(ical.PropSummary, titleOrDefault(in.Title))
	if in.Location != "" {
		vevent.Props.SetText(ical.PropLocation, in.Location)
	}
	if in.Description != "" {
		vevent.Props.SetText(ical.PropDescription, in.Description)
	}
	org := ical.NewProp(ical.PropOrganizer)
	if cn := in.OrganizerCN; cn != "" {
		org.Params.Set(ical.ParamCommonName, cn)
	} else {
		org.Params.Set(ical.ParamCommonName, in.Organizer)
	}
	org.Value = "mailto:" + in.Organizer
	vevent.Props.Set(org)
	for _, at := range in.Attendees {
		prop := ical.NewProp(ical.PropAttendee)
		if cn := at.CN; cn != "" {
			prop.Params.Set(ical.ParamCommonName, cn)
		} else {
			prop.Params.Set(ical.ParamCommonName, at.Email)
		}
		prop.Params.Set(ical.ParamRole, "REQ-PARTICIPANT")
		if !cancel {
			// A cancellation asks for no response — PARTSTAT/RSVP are
			// REQUEST-only parameters.
			prop.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
			prop.Params.Set(ical.ParamRSVP, "TRUE")
		}
		prop.Value = "mailto:" + at.Email
		vevent.Props.Add(prop) // multi-valued property: one line per invitee
	}

	// VTIMEZONE of the zones actually emitted as TZID, BEFORE the VEVENT
	// (RFC 5545 §3.6.5) — same mechanics as SeriesToICal.
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
	cal.Children = append(cal.Children, vevent.Component)

	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("caldav: encoding invitation ics: %w", err)
	}
	return buf.Bytes(), nil
}

// ReplyICS serializes the iMIP METHOD:REPLY VCALENDAR of the account owner
// responding to a RECEIVED invitation (M6b, outgoing RSVP) — RFC 5546 §3.2.3.
// The VEVENT carries the SAME UID as the third party's event, the ORGANIZER
// (the third party, the routing key of their mailbox), a SINGLE ATTENDEE line
// = the account owner with their new PARTSTAT (ACCEPTED/DECLINED/TENTATIVE),
// the SEQUENCE of the Proton state and the DTSTAMP. NO other attendee is
// listed (one speaks only for oneself) — and never an X-PM-TOKEN. in carries
// the event state (Organizer + bounds); attendee is the account owner's line
// (email + CN). Any value flowing into the card is stripCtrl'd (anti-injection,
// same discipline as the write path).
func ReplyICS(in proton.EventInput, attendee proton.AttendeeInput, partstat string, sequence int, now time.Time) ([]byte, error) {
	if in.Organizer == "" {
		return nil, fmt.Errorf("caldav: REPLY needs the third-party ORGANIZER")
	}
	if attendee.Email == "" {
		return nil, fmt.Errorf("caldav: REPLY needs the replying attendee address")
	}
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropProductID, prodID)
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropMethod, invite.MethodReply)

	used := make(map[string]bool)
	vevent := ical.NewEvent()
	vevent.Props.SetText(ical.PropUID, stripCtrl(in.UID))
	vevent.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	// Bounds: useful to some organizer clients to hook the response onto the
	// right occurrence — served in the original zone.
	if in.AllDay {
		vevent.Props.SetDate(ical.PropDateTimeStart, in.Start.UTC())
		vevent.Props.SetDate(ical.PropDateTimeEnd, in.End.UTC())
	} else {
		endTZ := in.EndTZID
		if endTZ == "" {
			endTZ = in.TZID
		}
		vevent.Props.SetDateTime(ical.PropDateTimeStart, inServeZone(in.Start, in.TZID, used))
		vevent.Props.SetDateTime(ical.PropDateTimeEnd, inServeZone(in.End, endTZ, used))
	}
	seq := ical.NewProp(ical.PropSequence)
	seq.Value = strconv.Itoa(sequence)
	vevent.Props.Set(seq)
	if in.Title != "" {
		vevent.Props.SetText(ical.PropSummary, stripCtrl(in.Title))
	}

	// ORGANIZER = the third party (never rewritten, simply copied into the
	// reply).
	org := ical.NewProp(ical.PropOrganizer)
	if cn := stripCtrl(in.OrganizerCN); cn != "" {
		org.Params.Set(ical.ParamCommonName, cn)
	}
	org.Value = "mailto:" + stripCtrl(in.Organizer)
	vevent.Props.Set(org)

	// The SINGLE ATTENDEE = the account owner, with their new PARTSTAT. No
	// RSVP=TRUE (a reply does not ask for a reply back).
	at := ical.NewProp(ical.PropAttendee)
	if cn := stripCtrl(attendee.CN); cn != "" {
		at.Params.Set(ical.ParamCommonName, cn)
	}
	at.Params.Set(ical.ParamParticipationStatus, partstat)
	at.Value = "mailto:" + stripCtrl(attendee.Email)
	vevent.Props.Set(at)

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
	cal.Children = append(cal.Children, vevent.Component)

	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("caldav: encoding reply ics: %w", err)
	}
	return buf.Bytes(), nil
}

// replyVerb renders the English verb of an RSVP response based on the PARTSTAT.
func replyVerb(partstat string) string {
	switch strings.ToUpper(strings.TrimSpace(partstat)) {
	case "ACCEPTED":
		return "Accepted"
	case "DECLINED":
		return "Declined"
	case "TENTATIVE":
		return "Tentative"
	default:
		return "Response"
	}
}

// replyText renders the human-readable text body of a response (RSVP): the
// verb + the when/where, addressed to the organizer.
func replyText(partstat string, in proton.EventInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", replyVerb(partstat), titleOrDefault(in.Title))
	b.WriteString("When: " + invitationWhen(in) + "\n")
	if in.Location != "" {
		b.WriteString("Where: " + in.Location + "\n")
	}
	return b.String()
}

// stripCtrl removes every control character (CR/LF/TAB included) from a value
// destined for an iCalendar line — anti-injection, same discipline as the
// proton write path (attendees.go). The emails/CNs of a REPLY come from the
// decrypted Proton state, already clean, but the belt stays fastened.
func stripCtrl(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// invitationText renders the human-readable email body (when / where), using
// the event's own timezone and an English body. prefix opens the message
// ("Invitation", "Updated invitation"). TODO: locale could be made
// configurable.
func invitationText(in proton.EventInput, prefix string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", prefix, titleOrDefault(in.Title))
	b.WriteString("When: " + invitationWhen(in) + "\n")
	if in.Location != "" {
		b.WriteString("Where: " + in.Location + "\n")
	}
	if in.Description != "" {
		b.WriteString("\n" + in.Description + "\n")
	}
	b.WriteString("\nPlease respond via the attached invitation (invite.ics).\n")
	return b.String()
}

// cancellationText renders the text body of a cancellation (attendee removal
// or event deletion) — no response requested.
func cancellationText(in proton.EventInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cancelled: %s\n\n", titleOrDefault(in.Title))
	b.WriteString("This event has been cancelled for you.\n")
	b.WriteString("When: " + invitationWhen(in) + "\n")
	if in.Location != "" {
		b.WriteString("Where: " + in.Location + "\n")
	}
	return b.String()
}

// titleOrDefault applies the fallback title for email bodies/subjects.
func titleOrDefault(title string) string {
	if title == "" {
		return "(no title)"
	}
	return title
}

// invitationWhen formats the time range in the event's own timezone (UTC
// fallback when the local tzdb does not know the zone). TODO: locale could be
// made configurable.
func invitationWhen(in proton.EventInput) string {
	if in.AllDay {
		start := in.Start.UTC()
		// All-day DTEND is exclusive: the last displayed day is end-1d.
		last := in.End.UTC().AddDate(0, 0, -1)
		if !last.After(start) {
			return formatDate(start) + " (all day)"
		}
		return fmt.Sprintf("from %s to %s (all day)", formatDate(start), formatDate(last))
	}
	loc, ok := icaltime.LoadZone(in.TZID)
	tzName := "UTC"
	if ok {
		tzName = in.TZID
	}
	s, e := in.Start.In(loc), in.End.In(loc)
	if s.Year() == e.Year() && s.YearDay() == e.YearDay() {
		return fmt.Sprintf("%s from %s to %s (%s)",
			formatDate(s), s.Format("15:04"), e.Format("15:04"), tzName)
	}
	return fmt.Sprintf("from %s %s to %s %s (%s)",
		formatDate(s), s.Format("15:04"), formatDate(e), e.Format("15:04"), tzName)
}

// formatDate renders a date in English, e.g. "Tuesday 21 July 2026".
func formatDate(t time.Time) string {
	return t.Format("Monday 2 January 2006")
}
