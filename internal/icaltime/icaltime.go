// Package icaltime centralizes the iCalendar date/time primitives that were
// previously duplicated across the read path (internal/caldav), the write path
// (internal/proton), and the VTIMEZONE generator. Keeping a single copy of the
// timezone-loading and layout logic matters here: a DST bug (2026-07-16) was
// caused precisely by these rules diverging between copies, so they live in one
// place with one set of tests.
package icaltime

import (
	"sync"
	"time"
)

// iCalendar value-type layouts (RFC 5545 §3.3.4/§3.3.5), UTC "Z" suffix and
// TZID parameter handled by the caller.
const (
	// LayoutDate is the DATE value type (VALUE=DATE): all-day, no time.
	LayoutDate = "20060102"
	// LayoutDateTime is the local DATE-TIME value type (with TZID or floating).
	LayoutDateTime = "20060102T150405"
	// LayoutDateTimeUTC is the UTC DATE-TIME value type (trailing Z).
	LayoutDateTimeUTC = "20060102T150405Z"
)

// zoneCache memoizes SUCCESSFUL LoadLocation lookups. The stdlib caches only
// UTC/Local — every other call re-opens and re-parses the tzfile from disk
// (~37µs vs ~15ns cached), and the serve path calls LoadZone 2-4× per VEVENT
// per request (perf audit 2026-07-17). Successes are bounded by the system
// tzdb (~600 names); failures are deliberately NOT cached, because the key is
// client-supplied (a stream of bogus TZIDs must not grow the map unbounded).
var zoneCache sync.Map // tzid → *time.Location

// LoadZone resolves an IANA timezone identifier to a *time.Location, falling
// back to UTC when the id is empty, "UTC", or not resolvable by the system
// tzdb. It never returns nil. ok reports whether a real non-UTC zone was
// loaded (callers that must decide between emitting a TZID parameter or a bare
// "Z" form use it).
func LoadZone(tzid string) (loc *time.Location, ok bool) {
	if tzid == "" || tzid == "UTC" {
		return time.UTC, false
	}
	if cached, hit := zoneCache.Load(tzid); hit {
		return cached.(*time.Location), true
	}
	loc, err := time.LoadLocation(tzid)
	if err != nil || loc == nil {
		return time.UTC, false
	}
	zoneCache.Store(tzid, loc)
	return loc, true
}
