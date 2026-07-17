package proton

import (
	"encoding/json"
	"testing"
)

// Tests of the Notifications model (M4): parsing/serialization of iCalendar
// durations, VALARM → Notification conversion rules (ported from WebClients),
// and preservation of the column's tri-state on update.

func TestParseICalDuration(t *testing.T) {
	cases := []struct {
		in   string
		want icalDuration
		ok   bool
	}{
		{"-PT15M", icalDuration{minutes: 15, negative: true}, true},
		{"PT0S", icalDuration{}, true},
		{"-P1D", icalDuration{days: 1, negative: true}, true},
		{"-P1W", icalDuration{weeks: 1, negative: true}, true},
		{"-P1DT9H30M", icalDuration{days: 1, hours: 9, minutes: 30, negative: true}, true},
		{"+PT1H", icalDuration{hours: 1}, true},
		{"-P1DT0H0M0S", icalDuration{days: 1, negative: true}, true},
		{"", icalDuration{}, false},
		{"P", icalDuration{}, false},
		{"PT15", icalDuration{}, false},             // orphan digits
		{"-P15M", icalDuration{}, false},            // minutes outside the T section
		{"20260101T000000Z", icalDuration{}, false}, // date-time, not a duration
	}
	for _, c := range cases {
		got, ok := parseICalDuration(c.in)
		if ok != c.ok {
			t.Errorf("parseICalDuration(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseICalDuration(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestICalDurationString(t *testing.T) {
	cases := []struct {
		in   icalDuration
		want string
	}{
		{icalDuration{minutes: 15, negative: true}, "-PT15M"},
		{icalDuration{}, "PT0S"},
		{icalDuration{negative: true}, "PT0S"}, // zero never signed
		{icalDuration{weeks: 2, negative: true}, "-P2W"},
		{icalDuration{days: 1, negative: true}, "-P1D"},
		{icalDuration{weeks: 1, days: 6, hours: 15, negative: true}, "-P13DT15H"}, // weeks folded
		{icalDuration{hours: 9}, "PT9H"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("(%+v).String() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeTriggerDuration(t *testing.T) {
	// Timed, single component: unchanged (seconds overwritten).
	d := normalizeTriggerDuration(icalDuration{minutes: 90, negative: true}, false)
	if d != (icalDuration{minutes: 90, negative: true}) {
		t.Errorf("single component = %+v", d)
	}
	// Timed, multi-component: fold onto the largest exact unit.
	d = normalizeTriggerDuration(icalDuration{hours: 1, minutes: 30, negative: true}, false)
	if d != (icalDuration{minutes: 90, negative: true}) {
		t.Errorf("1h30 fold = %+v, want 90 minutes", d)
	}
	d = normalizeTriggerDuration(icalDuration{days: 1, hours: 24, negative: true}, false)
	if d != (icalDuration{days: 2, negative: true}) {
		t.Errorf("P1DT24H fold = %+v, want 2 days", d)
	}
	// All-day, "the day before at 15:00": days kept, no fold.
	d = normalizeTriggerDuration(icalDuration{hours: 15, negative: true}, true)
	if d != (icalDuration{hours: 15, negative: true}) {
		t.Errorf("all-day -PT15H = %+v", d)
	}
	// All-day negative non-midnight with weeks and days != 6: folded.
	d = normalizeTriggerDuration(icalDuration{weeks: 1, days: 1, hours: 9, negative: true}, true)
	if d != (icalDuration{days: 8, hours: 9, negative: true}) {
		t.Errorf("all-day fold = %+v, want 8 days 9 hours", d)
	}
}

func TestNotificationFromAlarm(t *testing.T) {
	// DISPLAY -15 min: the nominal Apple case.
	n, ok := NotificationFromAlarm("DISPLAY", "-PT15M", "", false, false)
	if !ok || n.Type != NotificationDevice || n.Trigger != "-PT15M" {
		t.Errorf("DISPLAY -PT15M = %+v ok=%v", n, ok)
	}
	// AUDIO → DEVICE (same mapping as the web client).
	if n, ok := NotificationFromAlarm("AUDIO", "-PT5M", "", false, false); !ok || n.Type != NotificationDevice {
		t.Errorf("AUDIO = %+v ok=%v", n, ok)
	}
	// EMAIL → Type 0.
	if n, ok := NotificationFromAlarm("EMAIL", "-PT1H", "", false, false); !ok || n.Type != NotificationEmail {
		t.Errorf("EMAIL = %+v ok=%v", n, ok)
	}
	// ACTION:NONE (Apple's "no alert"): dropped.
	if _, ok := NotificationFromAlarm("NONE", "-PT15M", "", false, false); ok {
		t.Error("ACTION:NONE must be dropped")
	}
	// Absolute trigger: dropped (gateway posture, cf. FEATURE-MATRIX §3).
	if _, ok := NotificationFromAlarm("DISPLAY", "20260101T000000Z", "", true, false); ok {
		t.Error("absolute trigger must be dropped")
	}
	// RELATED=END: outside the Proton model.
	if _, ok := NotificationFromAlarm("DISPLAY", "-PT15M", "END", false, false); ok {
		t.Error("RELATED=END must be dropped")
	}
	// After the start (timed): dropped; "at the moment of the event" accepted.
	if _, ok := NotificationFromAlarm("DISPLAY", "PT10M", "", false, false); ok {
		t.Error("future trigger on timed event must be dropped")
	}
	if n, ok := NotificationFromAlarm("DISPLAY", "PT0S", "", false, false); !ok || n.Trigger != "PT0S" {
		t.Errorf("at-start trigger = %+v ok=%v", n, ok)
	}
	// All-day: "the same day at 9:00" (+PT9H) accepted, +P1D dropped.
	if n, ok := NotificationFromAlarm("DISPLAY", "PT9H", "", false, true); !ok || n.Trigger != "PT9H" {
		t.Errorf("all-day same-day trigger = %+v ok=%v", n, ok)
	}
	if _, ok := NotificationFromAlarm("DISPLAY", "P1D", "", false, true); ok {
		t.Error("all-day trigger ≥ 24h after start must be dropped")
	}
	// Unit bounds: 10000 minutes > NOTIFICATION_UNITS_MAX.
	if _, ok := NotificationFromAlarm("DISPLAY", "-PT10000M", "", false, false); ok {
		t.Error("trigger above unit maximum must be dropped")
	}
	// Multi-component: normalized before serialization (-P1DT24H ≡ -P2D).
	if n, ok := NotificationFromAlarm("DISPLAY", "-P1DT24H", "", false, false); !ok || n.Trigger != "-P2D" {
		t.Errorf("normalized trigger = %+v ok=%v, want -P2D", n, ok)
	}
}

func TestNotificationsPayloadTriState(t *testing.T) {
	// null column (inherit) + nothing wanted: null kept — the client cannot
	// delete reminders that were never served to it.
	if got := string(notificationsPayload(json.RawMessage("null"), nil)); got != "null" {
		t.Errorf("null+empty = %s, want null", got)
	}
	if got := string(notificationsPayload(nil, nil)); got != "null" {
		t.Errorf("absent+empty = %s, want null", got)
	}

	// Existing array + nothing wanted: the client removed its alarms → [].
	arr := json.RawMessage(`[{"Type":1,"Trigger":"-PT15M"}]`)
	if got := string(notificationsPayload(arr, nil)); got != "[]" {
		t.Errorf("arr+empty = %s, want []", got)
	}

	// Identical by SEMANTICS (different textual form): original JSON verbatim —
	// the Proton form "-PT24H" survives an Apple echo "-P1D".
	arr24 := json.RawMessage(`[{"Type":1,"Trigger":"-PT24H"}]`)
	got := notificationsPayload(arr24, []Notification{{Type: NotificationDevice, Trigger: "-P1D"}})
	if string(got) != string(arr24) {
		t.Errorf("semantically equal = %s, want original raw", got)
	}

	// Changed: new array.
	got = notificationsPayload(arr, []Notification{{Type: NotificationDevice, Trigger: "-PT30M"}})
	var decoded []Notification
	if err := json.Unmarshal(got, &decoded); err != nil || len(decoded) != 1 || decoded[0].Trigger != "-PT30M" {
		t.Errorf("changed = %s", got)
	}

	// null + added alarms: explicit array.
	got = notificationsPayload(json.RawMessage("null"), []Notification{{Type: NotificationEmail, Trigger: "-PT1H"}})
	if err := json.Unmarshal(got, &decoded); err != nil || len(decoded) != 1 || decoded[0].Type != NotificationEmail {
		t.Errorf("null+added = %s", got)
	}
}

func TestParseAndMarshalNotifications(t *testing.T) {
	if got := parseNotifications(json.RawMessage("null")); got != nil {
		t.Errorf("parse null = %v", got)
	}
	if got := parseNotifications(json.RawMessage(`[{"Type":0,"Trigger":"-PT15M"}]`)); len(got) != 1 || got[0].Type != NotificationEmail {
		t.Errorf("parse array = %v", got)
	}
	if got := parseNotifications(json.RawMessage(`{corrupt`)); got != nil {
		t.Errorf("parse garbage = %v, want nil (lenient)", got)
	}
	if got := string(marshalNotifications(nil)); got != "[]" {
		t.Errorf("marshal nil = %s, want []", got)
	}
	b := marshalNotifications([]Notification{{Type: NotificationDevice, Trigger: "-PT15M"}})
	if string(b) != `[{"Type":1,"Trigger":"-PT15M"}]` {
		t.Errorf("marshal = %s", b)
	}
}
