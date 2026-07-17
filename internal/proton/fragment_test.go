package proton

import (
	"testing"
	"time"
)

func TestParseFragmentBasics(t *testing.T) {
	// Proton-style fragment: no VERSION/PRODID, CRLF, properties with
	// parameters, escaped text and a folded SUMMARY line (RFC 5545 §3.1).
	data := "BEGIN:VCALENDAR\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:abc@proton.me\r\n" +
		"DTSTART;TZID=Europe/Paris:20260720T093000\r\n" +
		"SUMMARY:Budget meeting\r\n  2026 — tradeoffs\r\n" +
		"DESCRIPTION:line 1\\nline 2\\, with comma\\; and semicolon \\\\end\r\n" +
		"LOCATION:Room \"Ampere\"\\, Paris\r\n" +
		"RRULE:FREQ=MONTHLY;BYMONTHDAY=15\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR"

	frag, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment: %v", err)
	}

	if frag.summary == nil || *frag.summary != "Budget meeting 2026 — tradeoffs" {
		t.Errorf("summary = %v", frag.summary)
	}
	wantDesc := "line 1\nline 2, with comma; and semicolon \\end"
	if frag.description == nil {
		t.Errorf("description = nil, want %q", wantDesc)
	} else if *frag.description != wantDesc {
		t.Errorf("description = %q, want %q", *frag.description, wantDesc)
	}
	if frag.location == nil || *frag.location != `Room "Ampere", Paris` {
		t.Errorf("location = %v", frag.location)
	}
	if frag.rrule != "FREQ=MONTHLY;BYMONTHDAY=15" {
		t.Errorf("rrule = %q", frag.rrule)
	}
}

func TestParseFragmentAbsentVsEmpty(t *testing.T) {
	// A card carrying only SUMMARY must not pretend to carry the other
	// properties (nil pointers), and an empty SUMMARY stays distinct from absent.
	frag, err := parseFragment("BEGIN:VEVENT\r\nSUMMARY:\r\nEND:VEVENT")
	if err != nil {
		t.Fatalf("parseFragment: %v", err)
	}
	if frag.summary == nil || *frag.summary != "" {
		t.Errorf("summary = %v, want present-but-empty", frag.summary)
	}
	if frag.description != nil || frag.location != nil || frag.rrule != "" {
		t.Errorf("unexpected fields: %+v", frag)
	}
}

func TestParseFragmentGarbage(t *testing.T) {
	if _, err := parseFragment("not iCalendar at all"); err == nil {
		t.Fatal("want error on non-iCalendar data")
	}
}

func TestParseFragmentExDatesAndSequence(t *testing.T) {
	// The three EXDATE forms (UTC-Z multi-value, TZID, VALUE=DATE) + SEQUENCE.
	data := "BEGIN:VCALENDAR\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:abc@proton.me\r\n" +
		"DTSTART:20220307T090000Z\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO,TH\r\n" +
		"EXDATE:20260713T090000Z,20260716T090000Z\r\n" +
		"EXDATE;TZID=Europe/Paris:20260720T110000\r\n" +
		"EXDATE;VALUE=DATE:20260801\r\n" +
		"SEQUENCE:3\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR"

	frag, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment: %v", err)
	}
	want := []time.Time{
		time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC), // 11:00 Paris summer = 09:00Z
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),  // all-day
	}
	if len(frag.exdates) != len(want) {
		t.Fatalf("exdates = %v, want %d entries", frag.exdates, len(want))
	}
	for i := range want {
		if !frag.exdates[i].Equal(want[i]) {
			t.Errorf("exdates[%d] = %v, want %v", i, frag.exdates[i], want[i])
		}
	}
	if frag.sequence == nil || *frag.sequence != 3 {
		t.Errorf("sequence = %v, want 3", frag.sequence)
	}
}
