package icaltime

import (
	"testing"
	"time"
)

func TestLoadZone(t *testing.T) {
	cases := []struct {
		tzid     string
		wantUTC  bool // expect the UTC fallback
		wantName string
	}{
		{"", true, "UTC"},
		{"UTC", true, "UTC"},
		{"Europe/Paris", false, "Europe/Paris"},
		{"America/Los_Angeles", false, "America/Los_Angeles"},
		{"Not/AZone", true, "UTC"}, // unresolvable → UTC fallback, never nil
	}
	for _, c := range cases {
		loc, ok := LoadZone(c.tzid)
		if loc == nil {
			t.Fatalf("LoadZone(%q) returned nil location", c.tzid)
		}
		if ok == c.wantUTC {
			t.Errorf("LoadZone(%q) ok=%v, want non-UTC=%v", c.tzid, ok, !c.wantUTC)
		}
		if c.wantUTC && loc != time.UTC {
			t.Errorf("LoadZone(%q) = %v, want UTC", c.tzid, loc)
		}
		if !c.wantUTC && loc.String() != c.wantName {
			t.Errorf("LoadZone(%q) = %v, want %s", c.tzid, loc, c.wantName)
		}
	}
}
