package proton

import (
	"encoding/json"
	"sort"
	"strings"
)

// This file implements the event NOTIFICATIONS model (M4) — the alerts/
// reminders. On the Proton side they do NOT live in the iCalendar cards: it is
// the top-level API column `Notifications`, in CLEARTEXT, an array of
// {Type, Trigger}. Rules ported from the official web client (WebClients,
// packages/shared/lib/calendar/icsSurgery/valarm.ts + alarms/trigger.ts +
// veventHelper.ts::toApiNotifications), never copied, reimplemented:
//
//   - Type: 0 = EMAIL, 1 = DEVICE (NOTIFICATION_TYPE_API). ACTION:EMAIL →
//     EMAIL; DISPLAY and AUDIO → DEVICE; any other ACTION → invalid alarm,
//     dropped silently (same posture as the official ICS import).
//   - Trigger: RFC 5545 duration RELATIVE to DTSTART, serialized like
//     ICAL.Duration.toString ("-PT15M", "PT0S", "-P1D", "-P1W"…). ABSOLUTE
//     triggers (VALUE=DATE-TIME) and RELATED=END are dropped silently.
//   - A trigger AFTER the start is dropped (timed event); for an all-day event,
//     a positive trigger < 24 h is ACCEPTED ("the same day at 9:00" = +PT9H
//     after midnight), beyond that it is dropped.
//   - Per-unit bounds after normalization: weeks ≤ 999, days ≤ 6999,
//     hours ≤ 999, minutes ≤ 9999, seconds always 0
//     (NOTIFICATION_UNITS_MAX).
//   - At most MaxNotifications (10) alarms per event (MAX_NOTIFICATIONS).
//
// The column's tri-state remains meaningful: null = inherit the calendar's
// default reminders, [] = no reminder, array = explicit reminders.

// NotificationType is the API Type of a notification (NOTIFICATION_TYPE_API).
type NotificationType int

const (
	// NotificationEmail: email reminder (ACTION:EMAIL).
	NotificationEmail NotificationType = 0
	// NotificationDevice: on-device notification (ACTION:DISPLAY/AUDIO).
	NotificationDevice NotificationType = 1
)

// MaxNotifications is the Proton cap on reminders per event
// (MAX_NOTIFICATIONS = 10 on the WebClients side); beyond it, dropped silently.
const MaxNotifications = 10

// Notification is an entry of the API Notifications column: a reminder, with
// its Trigger verbatim (RFC 5545 duration relative to DTSTART).
type Notification struct {
	Type    NotificationType `json:"Type"`
	Trigger string           `json:"Trigger"`
}

// Valid checks that the Trigger is a readable iCalendar duration — a guardrail
// before serving a VALARM (a corrupted column must not break the whole
// VEVENT).
func (n Notification) Valid() bool {
	_, ok := parseICalDuration(n.Trigger)
	return ok
}

// parseNotifications decodes the raw JSON column into reminders. null, absent,
// empty or unreadable → nil (lenient read, like the rest of the read path).
func parseNotifications(raw json.RawMessage) []Notification {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var out []Notification
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// marshalNotifications encodes reminders to the API column. nil/empty → []
// ("no reminder", the same value the official ICS import emits when the VEVENT
// has no VALARM) — never null here: null (inherit) is reserved for the update
// path that preserves the original column (notificationsPayload).
func marshalNotifications(list []Notification) json.RawMessage {
	if len(list) == 0 {
		return json.RawMessage("[]")
	}
	b, err := json.Marshal(list)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// notificationsPayload computes the Notifications column of an UPDATE body from
// the original column (raw JSON from the GET) and the COMPLETE state wanted by
// the client. Anti-loss: the original tri-state is degraded only if the client
// actually changed something.
//
//   - wanted empty + null column (inherit) → null kept: the client cannot
//     delete reminders that were never served to it;
//   - wanted empty + array column → [] (the client removed its alarms);
//   - wanted identical (same types + same offsets) → original JSON verbatim
//     (the original trigger forms survive, e.g. "-P1DT0H0M0S");
//   - otherwise → new array.
func notificationsPayload(rowRaw json.RawMessage, want []Notification) json.RawMessage {
	cur := parseNotifications(rowRaw)
	if len(want) == 0 {
		if len(cur) == 0 {
			return rawOrNull(rowRaw) // original null or [], kept as-is
		}
		return json.RawMessage("[]")
	}
	if notificationSetsEqual(cur, want) {
		return rowRaw
	}
	return marshalNotifications(want)
}

// notificationSetsEqual compares two reminder sets by SEMANTICS (Type + signed
// offset in seconds), regardless of order and of the trigger's textual form
// ("-P1D" ≡ "-PT24H") — Apple reorders and re-serializes freely.
func notificationSetsEqual(a, b []Notification) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		typ    NotificationType
		offset int64
	}
	keys := func(list []Notification) ([]key, bool) {
		out := make([]key, 0, len(list))
		for _, n := range list {
			d, ok := parseICalDuration(n.Trigger)
			if !ok {
				return nil, false
			}
			out = append(out, key{n.Type, d.signedSeconds()})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].typ != out[j].typ {
				return out[i].typ < out[j].typ
			}
			return out[i].offset < out[j].offset
		})
		return out, true
	}
	ka, ok := keys(a)
	if !ok {
		return false
	}
	kb, ok := keys(b)
	if !ok {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// NotificationFromAlarm converts an incoming VALARM into a Notification per the
// Proton rules (see the file header). ok=false = unsupported alarm, to be
// dropped SILENTLY — the same posture as the official ICS import, never a
// rejection of the whole PUT.
//
// action/trigger/related are the component's raw values; triggerAbsolute
// indicates a TRIGGER;VALUE=DATE-TIME (absolute instant).
func NotificationFromAlarm(action, trigger, related string, triggerAbsolute, allDay bool) (Notification, bool) {
	// Supported ACTIONs: DISPLAY, EMAIL, AUDIO (getIsValidAlarm). ACTION:NONE
	// (Apple's default "none" alarm) and the rest are dropped.
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DISPLAY", "AUDIO", "EMAIL":
	default:
		return Notification{}, false
	}
	typ := NotificationDevice
	if strings.EqualFold(strings.TrimSpace(action), "EMAIL") {
		typ = NotificationEmail
	}

	// Absolute triggers and RELATED=END: outside the Proton model, dropped.
	if triggerAbsolute {
		return Notification{}, false
	}
	if strings.EqualFold(strings.TrimSpace(related), "END") {
		return Notification{}, false
	}

	d, ok := parseICalDuration(trigger)
	if !ok {
		return Notification{}, false
	}
	d = normalizeTriggerDuration(d, allDay)

	// Trigger "in the future" (after the start): dropped — except for an
	// all-day event where "the same day at HH:MM" (positive < 24 h) is accepted.
	total := d.totalSeconds()
	if allDay {
		if !d.negative && total >= 24*3600 {
			return Notification{}, false
		}
	} else if !d.negative && total != 0 {
		return Notification{}, false
	}
	// Per-unit bounds (NOTIFICATION_UNITS_MAX); seconds always 0 after
	// normalization.
	if d.seconds != 0 || d.minutes > 9999 || d.hours > 999 || d.days > 6999 || d.weeks > 999 {
		return Notification{}, false
	}

	return Notification{Type: typ, Trigger: d.String()}, true
}

// ---- iCalendar durations (RFC 5545 §3.3.6) ----

// icalDuration is a decomposed duration, mirror of the web VcalDurationValue.
type icalDuration struct {
	weeks, days, hours, minutes, seconds int
	negative                             bool
}

// parseICalDuration reads an RFC 5545 dur-value: [+/-] "P" [nW] [nD]
// ["T" [nH] [nM] [nS]]. Tolerates weeks+days combinations (like ical.js).
func parseICalDuration(v string) (icalDuration, bool) {
	var d icalDuration
	s := strings.TrimSpace(v)
	if s == "" {
		return d, false
	}
	switch s[0] {
	case '-':
		d.negative = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if len(s) == 0 || (s[0] != 'P' && s[0] != 'p') {
		return d, false
	}
	s = s[1:]

	inTime := false
	sawComponent := false
	n := 0
	haveN := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			n = n*10 + int(c-'0')
			haveN = true
		case c == 'T' || c == 't':
			if haveN {
				return d, false // digit without a unit before the T
			}
			inTime = true
		default:
			if !haveN {
				return d, false
			}
			switch c {
			case 'W', 'w':
				d.weeks = n
			case 'D', 'd':
				d.days = n
			case 'H', 'h':
				if !inTime {
					return d, false
				}
				d.hours = n
			case 'M', 'm':
				if !inTime {
					return d, false
				}
				d.minutes = n
			case 'S', 's':
				if !inTime {
					return d, false
				}
				d.seconds = n
			default:
				return d, false
			}
			n = 0
			haveN = false
			sawComponent = true
		}
	}
	if haveN || !sawComponent {
		return d, false // orphan digits, or bare "P"
	}
	return d, true
}

// totalSeconds returns the absolute duration in seconds.
func (d icalDuration) totalSeconds() int64 {
	return int64(d.weeks)*7*24*3600 + int64(d.days)*24*3600 +
		int64(d.hours)*3600 + int64(d.minutes)*60 + int64(d.seconds)
}

// signedSeconds returns the signed offset (negative = before the start).
func (d icalDuration) signedSeconds() int64 {
	if d.negative {
		return -d.totalSeconds()
	}
	return d.totalSeconds()
}

// String serializes the duration into a canonical dur-value, the same family
// of forms as ICAL.Duration.toString on the web side: "P{n}W" if the duration
// is a whole number of weeks alone, otherwise "P[nD][T[nH][nM][nS]]" (zeros
// omitted, weeks folded into days), and "PT0S" for zero.
func (d icalDuration) String() string {
	var b strings.Builder
	if d.negative && d.totalSeconds() != 0 {
		b.WriteByte('-')
	}
	b.WriteByte('P')
	if d.weeks != 0 && d.days == 0 && d.hours == 0 && d.minutes == 0 && d.seconds == 0 {
		writeInt(&b, d.weeks)
		b.WriteByte('W')
		return b.String()
	}
	days := d.days + 7*d.weeks
	if days != 0 {
		writeInt(&b, days)
		b.WriteByte('D')
	}
	if d.hours != 0 || d.minutes != 0 || d.seconds != 0 {
		b.WriteByte('T')
		if d.hours != 0 {
			writeInt(&b, d.hours)
			b.WriteByte('H')
		}
		if d.minutes != 0 {
			writeInt(&b, d.minutes)
			b.WriteByte('M')
		}
		if d.seconds != 0 {
			writeInt(&b, d.seconds)
			b.WriteByte('S')
		}
	}
	if days == 0 && d.hours == 0 && d.minutes == 0 && d.seconds == 0 {
		b.WriteString("T0S")
	}
	return b.String()
}

func writeInt(b *strings.Builder, n int) {
	var buf [12]byte
	i := len(buf)
	if n == 0 {
		b.WriteByte('0')
		return
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	b.Write(buf[i:])
}

// normalizeTriggerDuration is the mirror of normalizeRelativeTrigger (web):
//   - all-day: the hours/minutes encode "at HH:MM", weeks kept only in the
//     canonical forms (days == 0, or days == 6 for a negative non-midnight
//     trigger), otherwise folded into days;
//   - timed: a single non-zero component allowed, otherwise fold onto the
//     largest unit that divides exactly (minutes → hours → days → weeks).
//
// Seconds are always overwritten to 0 (the Proton UI does not model them).
func normalizeTriggerDuration(d icalDuration, allDay bool) icalDuration {
	if allDay {
		isMidnight := d.hours == 0 && d.minutes == 0
		var keepWeeks bool
		if !d.negative || isMidnight {
			keepWeeks = d.days == 0
		} else {
			keepWeeks = d.days == 6
		}
		if keepWeeks {
			d.seconds = 0
			return d
		}
		d.days += 7 * d.weeks
		d.weeks = 0
		d.seconds = 0
		return d
	}

	nonZero := 0
	for _, v := range [...]int{d.minutes, d.hours, d.days, d.weeks} {
		if v != 0 {
			nonZero++
		}
	}
	if nonZero <= 1 {
		d.seconds = 0
		return d
	}
	out := icalDuration{negative: d.negative}
	totalMinutes := d.weeks*7*24*60 + d.days*24*60 + d.hours*60 + d.minutes + d.seconds/60
	if totalMinutes%60 != 0 {
		out.minutes = totalMinutes
		return out
	}
	totalHours := totalMinutes / 60
	if totalHours%24 != 0 {
		out.hours = totalHours
		return out
	}
	totalDays := totalHours / 24
	if totalDays%7 != 0 {
		out.days = totalDays
		return out
	}
	out.weeks = totalDays / 7
	return out
}
