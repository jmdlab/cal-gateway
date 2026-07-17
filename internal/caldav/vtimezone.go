package caldav

import (
	"fmt"
	"time"

	"github.com/emersion/go-ical"
)

// VTIMEZONE generator — go-ical has NO generator (its encoder only VALIDATES:
// a VTIMEZONE must contain >= 1 STANDARD or DAYLIGHT sub-component, each with
// DTSTART + TZOFFSETFROM + TZOFFSETTO). RFC 5545 §3.6.5 requires one VTIMEZONE
// block per TZID referenced in the VCALENDAR; Apple resolves the TZID via its
// system tzdb anyway — the block serves RFC conformance (and strict clients).
//
// Two sources:
//   - a STATIC table of canonical blocks (tzurl.org/vzic form, exact yearly
//     RRULEs) for the zones actually present in the calendar data;
//   - a generic COMPUTED fallback (two probes, January/July, on the
//     time.Location, same approach as the sibling project
//     proton-calendar-sync/sync-utils.ts, validated against Apple Calendar)
//     for any other zone. Assumed approximation: transition dates set
//     US-style, northern hemisphere — the client recomputes on its own tzdb.

// tzObservance is a STANDARD or DAYLIGHT sub-component of a VTIMEZONE.
type tzObservance struct {
	daylight bool
	name     string // TZNAME
	dtstart  string // LOCAL time of the first transition (year 1970, vzic convention)
	from     string // TZOFFSETFROM, ±hhmm
	to       string // TZOFFSETTO, ±hhmm
	rrule    string // yearly transition rule, "" = none (zone without DST)
}

// canonicalVTimezones: exact blocks (tzurl.org form) of the zones present in
// the served data. UTC never appears here: the "Z" form requires no
// VTIMEZONE.
var canonicalVTimezones = map[string][]tzObservance{
	"Europe/Paris": {
		{daylight: true, name: "CEST", dtstart: "19700329T020000", from: "+0100", to: "+0200", rrule: "FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU"},
		{name: "CET", dtstart: "19701025T030000", from: "+0200", to: "+0100", rrule: "FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU"},
	},
	"Europe/Lisbon": {
		{daylight: true, name: "WEST", dtstart: "19700329T010000", from: "+0000", to: "+0100", rrule: "FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU"},
		{name: "WET", dtstart: "19701025T020000", from: "+0100", to: "+0000", rrule: "FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU"},
	},
	"America/Los_Angeles": {
		{daylight: true, name: "PDT", dtstart: "19700308T020000", from: "-0800", to: "-0700", rrule: "FREQ=YEARLY;BYMONTH=3;BYDAY=2SU"},
		{name: "PST", dtstart: "19701101T020000", from: "-0700", to: "-0800", rrule: "FREQ=YEARLY;BYMONTH=11;BYDAY=1SU"},
	},
	"America/New_York": {
		{daylight: true, name: "EDT", dtstart: "19700308T020000", from: "-0500", to: "-0400", rrule: "FREQ=YEARLY;BYMONTH=3;BYDAY=2SU"},
		{name: "EST", dtstart: "19701101T020000", from: "-0400", to: "-0500", rrule: "FREQ=YEARLY;BYMONTH=11;BYDAY=1SU"},
	},
}

// vtimezoneComponent builds the VTIMEZONE component of an IANA zone: canonical
// block if the zone is in the table, otherwise the probed fallback. Error only
// if the zone is unknown to the tzdb (the caller then emits no TZID).
func vtimezoneComponent(tzid string) (*ical.Component, error) {
	obs, ok := canonicalVTimezones[tzid]
	if !ok {
		var err error
		obs, err = probedObservances(tzid)
		if err != nil {
			return nil, err
		}
	}

	comp := ical.NewComponent(ical.CompTimezone)
	comp.Props.SetText(ical.PropTimezoneID, tzid)
	for _, o := range obs {
		name := ical.CompTimezoneStandard
		if o.daylight {
			name = ical.CompTimezoneDaylight
		}
		sub := ical.NewComponent(name)
		// A VTIMEZONE's DTSTART is a bare LOCAL time (never a TZID nor a Z) and
		// the offsets are structured UTC-OFFSET values: raw values, outside
		// go-ical's typed setters (SetText would set an erroneous VALUE=TEXT on
		// a default non-TEXT type).
		setRaw := func(propName, value string) {
			p := ical.NewProp(propName)
			p.Value = value
			sub.Props.Set(p)
		}
		setRaw(ical.PropDateTimeStart, o.dtstart)
		setRaw(ical.PropTimezoneOffsetFrom, o.from)
		setRaw(ical.PropTimezoneOffsetTo, o.to)
		if o.name != "" {
			sub.Props.SetText(ical.PropTimezoneName, o.name)
		}
		if o.rrule != "" {
			rr := ical.NewProp(ical.PropRecurrenceRule)
			rr.Value = o.rrule
			sub.Props.Set(rr)
		}
		comp.Children = append(comp.Children, sub)
	}
	return comp, nil
}

// probedObservances computes a generic VTIMEZONE for a zone outside the table:
// two probes (15 January / 15 July) on the time.Location detect the standard
// and summer offsets. Without DST: a single STANDARD. With DST: a
// STANDARD/DAYLIGHT pair at US transition dates (northern-hemisphere
// approximation — same heuristic as the sibling project, cf. package doc).
func probedObservances(tzid string) ([]tzObservance, error) {
	loc, err := time.LoadLocation(tzid)
	if err != nil {
		return nil, fmt.Errorf("caldav: unknown timezone %q: %w", tzid, err)
	}
	year := time.Now().UTC().Year()
	_, janOff := time.Date(year, time.January, 15, 12, 0, 0, 0, loc).Zone()
	_, julOff := time.Date(year, time.July, 15, 12, 0, 0, 0, loc).Zone()

	if janOff == julOff {
		off := formatUTCOffset(janOff)
		return []tzObservance{
			{name: tzid, dtstart: "19700101T000000", from: off, to: off},
		}, nil
	}
	std, dst := janOff, julOff
	if std > dst {
		std, dst = dst, std
	}
	stdStr, dstStr := formatUTCOffset(std), formatUTCOffset(dst)
	return []tzObservance{
		{daylight: true, name: tzid + " (Daylight)", dtstart: "19700308T020000", from: stdStr, to: dstStr, rrule: "FREQ=YEARLY;BYMONTH=3;BYDAY=2SU"},
		{name: tzid + " (Standard)", dtstart: "19701101T020000", from: dstStr, to: stdStr, rrule: "FREQ=YEARLY;BYMONTH=11;BYDAY=1SU"},
	}, nil
}

// formatUTCOffset renders an offset in seconds in the iCalendar ±hhmm format.
func formatUTCOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	return fmt.Sprintf("%s%02d%02d", sign, seconds/3600, (seconds%3600)/60)
}
