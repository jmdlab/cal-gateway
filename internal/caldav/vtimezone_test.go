package caldav

import (
	"bytes"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/proton"
)

// TestVTimezoneCanonicalAndProbed: block structure — canonical table
// (DAYLIGHT/STANDARD pair with yearly RRULEs) and probed fallback (zone without
// DST = a single STANDARD; zone with DST outside the table = a pair; half-hour
// offsets correct; unknown zone = error, the caller then never emits the TZID).
func TestVTimezoneCanonicalAndProbed(t *testing.T) {
	// Canonical: Europe/Paris — exact offsets and RRULE (tzurl.org form).
	comp, err := vtimezoneComponent("Europe/Paris")
	if err != nil {
		t.Fatalf("Europe/Paris: %v", err)
	}
	if got, _ := comp.Props.Text(ical.PropTimezoneID); got != "Europe/Paris" {
		t.Errorf("TZID = %q", got)
	}
	if len(comp.Children) != 2 {
		t.Fatalf("Europe/Paris: %d sub-components, want 2", len(comp.Children))
	}
	daylight := comp.Children[0]
	if daylight.Name != ical.CompTimezoneDaylight {
		t.Fatalf("first sub-component = %q, want DAYLIGHT", daylight.Name)
	}
	if got := daylight.Props.Get(ical.PropTimezoneOffsetTo); got == nil || got.Value != "+0200" {
		t.Errorf("DAYLIGHT TZOFFSETTO = %v, want +0200", got)
	}
	if got := daylight.Props.Get(ical.PropRecurrenceRule); got == nil || got.Value != "FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU" {
		t.Errorf("DAYLIGHT RRULE = %v", got)
	}
	// No stray VALUE=TEXT on the offsets (default type UTC-OFFSET).
	if p := daylight.Props.Get(ical.PropTimezoneOffsetTo); p.Params.Get(ical.ParamValue) != "" {
		t.Errorf("TZOFFSETTO carries a stray VALUE param: %v", p.Params)
	}

	// Probed fallback without DST: Asia/Tokyo — a single STANDARD, +0900.
	comp, err = vtimezoneComponent("Asia/Tokyo")
	if err != nil {
		t.Fatalf("Asia/Tokyo: %v", err)
	}
	if len(comp.Children) != 1 || comp.Children[0].Name != ical.CompTimezoneStandard {
		t.Fatalf("Asia/Tokyo: sub-components = %+v, want 1 STANDARD", comp.Children)
	}
	if got := comp.Children[0].Props.Get(ical.PropTimezoneOffsetTo); got == nil || got.Value != "+0900" {
		t.Errorf("Tokyo TZOFFSETTO = %v, want +0900", got)
	}

	// Probed fallback with DST outside the table: Australia/Sydney — a pair, +1000/+1100.
	comp, err = vtimezoneComponent("Australia/Sydney")
	if err != nil {
		t.Fatalf("Australia/Sydney: %v", err)
	}
	if len(comp.Children) != 2 {
		t.Fatalf("Australia/Sydney: %d sub-components, want 2", len(comp.Children))
	}
	offsets := map[string]bool{}
	for _, sub := range comp.Children {
		if p := sub.Props.Get(ical.PropTimezoneOffsetTo); p != nil {
			offsets[p.Value] = true
		}
	}
	if !offsets["+1000"] || !offsets["+1100"] {
		t.Errorf("Sydney offsets = %v, want +1000 and +1100", offsets)
	}

	// Half-hour offset: Asia/Kolkata +0530.
	comp, err = vtimezoneComponent("Asia/Kolkata")
	if err != nil {
		t.Fatalf("Asia/Kolkata: %v", err)
	}
	if got := comp.Children[0].Props.Get(ical.PropTimezoneOffsetTo); got == nil || got.Value != "+0530" {
		t.Errorf("Kolkata TZOFFSETTO = %v, want +0530", got)
	}

	// Unknown zone: error.
	if _, err := vtimezoneComponent("Mars/Olympus"); err == nil {
		t.Error("unknown zone accepted")
	}
}

// TestVTimezoneEncodes: each block (canonical and probed) must pass the go-ical
// encoder's VALIDATION (≥ 1 STANDARD/DAYLIGHT each carrying DTSTART +
// TZOFFSETFROM + TZOFFSETTO) within a complete resource.
func TestVTimezoneEncodes(t *testing.T) {
	start := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	for _, tzid := range []string{
		"Europe/Paris", "Europe/Lisbon", "America/Los_Angeles",
		"America/New_York", "Australia/Sydney", "Asia/Tokyo",
	} {
		cal, err := EventToICal(proton.Event{
			ID: "r", UID: "uid-vtz@proton.me", CalendarID: "cal1", Title: "X",
			Start: start, End: start.Add(time.Hour), TZ: tzid,
			LastEdit: time.Unix(1750000000, 0),
		})
		if err != nil {
			t.Fatalf("%s: EventToICal: %v", tzid, err)
		}
		var buf bytes.Buffer
		if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
			t.Fatalf("%s: encode: %v", tzid, err)
		}
		decoded, err := ical.NewDecoder(&buf).Decode()
		if err != nil {
			t.Fatalf("%s: decode: %v\nics:\n%s", tzid, err, buf.String())
		}
		if !hasVTimezone(decoded, tzid) {
			t.Errorf("%s: VTIMEZONE missing after round-trip", tzid)
		}
	}
}
