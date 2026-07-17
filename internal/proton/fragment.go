package proton

import (
	"errors"
	"github.com/jmdlab/cal-gateway/internal/icaltime"
	"strconv"
	"strings"
	"time"
)

// TOLERANT parser for the iCalendar fragments carried by the event cards.
//
// Why not go-ical? The Proton fragments are not complete iCalendar streams:
// VERSION/PRODID are missing and so is the trailing CRLF, which a strict decoder
// rejects outright (concept verified against the proton-cal study reference,
// which makes the same choice for the same reason). We extract here the strict
// minimum needed for the M1 mirror: SUMMARY, DESCRIPTION, LOCATION, RRULE.
// Anything not understood is ignored without error.

// fragment is the result of parsing a card. The pointers distinguish
// "property absent" from "property empty" (a card carries only a subset of the
// properties; absent must not overwrite).
type fragment struct {
	summary     *string
	description *string
	location    *string
	rrule       string      // verbatim, "" = absent
	exdates     []time.Time // UTC instants of the EXDATE (DATE, Z, TZID forms)
	sequence    *int        // SEQUENCE of the signed card, nil = absent
	status      *string     // STATUS of the signed calendar card (uppercase)
	transp      *string     // TRANSP of the signed calendar card (uppercase)
	organizer   *string     // mailto address of the ORGANIZER (SharedSigned card)
	attendees   []Attendee  // attendees of the AttendeesEvents card (Status not joined here)
}

// parseFragment unfolds then parses a fragment. Errors only if no iCalendar
// content is recognizable (data probably corrupted).
func parseFragment(data string) (fragment, error) {
	var frag fragment
	sawICal := false

	for _, line := range unfoldLines(data) {
		name, params, value, ok := splitContentLineParams(line)
		if !ok {
			continue
		}
		switch name {
		case "BEGIN", "END":
			sawICal = true
		case "SUMMARY":
			v := unescapeText(value)
			frag.summary = &v
			sawICal = true
		case "DESCRIPTION":
			v := unescapeText(value)
			frag.description = &v
			sawICal = true
		case "LOCATION":
			v := unescapeText(value)
			frag.location = &v
			sawICal = true
		case "RRULE":
			// Structured value (not TEXT): kept verbatim.
			frag.rrule = value
			sawICal = true
		case "EXDATE":
			frag.exdates = append(frag.exdates, parseExDateValues(params, value)...)
			sawICal = true
		case "SEQUENCE":
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				frag.sequence = &n
			}
			sawICal = true
		case "STATUS":
			// Enumerated value (not TEXT): normalized to uppercase.
			v := strings.ToUpper(strings.TrimSpace(value))
			frag.status = &v
			sawICal = true
		case "TRANSP":
			v := strings.ToUpper(strings.TrimSpace(value))
			frag.transp = &v
			sawICal = true
		case "ORGANIZER":
			if addr := mailtoValue(value); addr != "" {
				frag.organizer = &addr
			}
			sawICal = true
		case "ATTENDEE":
			// Attendee (AttendeesEvents card): email (mailto value), CN and
			// X-PM-TOKEN (join key of the cleartext Status). A line without a
			// mailto is ignored (lenient reading).
			if addr := mailtoValue(value); addr != "" {
				frag.attendees = append(frag.attendees, Attendee{
					Email: addr,
					CN:    paramValue(params, "CN"),
					Token: strings.ToLower(paramValue(params, "X-PM-TOKEN")),
				})
			}
			sawICal = true
		default:
			sawICal = true
		}
	}
	if !sawICal {
		return fragment{}, errors.New("proton: no iCalendar content in card")
	}
	return frag, nil
}

// unfoldLines splits into content lines, re-joining the RFC 5545 §3.1
// continuations (next line starting with a space or a tab).
func unfoldLines(data string) []string {
	raw := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	var out []string
	for _, line := range raw {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			out[len(out)-1] += line[1:]
			continue
		}
		out = append(out, line)
	}
	return out
}

// splitContentLine separates "NAME;PARAM=X:value" into (NAME, value). The
// parameters are ignored by the M1 callers; the ':' of a quoted parameter is
// handled.
func splitContentLine(line string) (name, value string, ok bool) {
	name, _, value, ok = splitContentLineParams(line)
	return name, value, ok
}

// splitContentLineParams separates "NAME;PARAMS:value" into (NAME, raw
// parameters section without the leading ';', value). The ':' of a quoted
// parameter is handled.
func splitContentLineParams(line string) (name, params, value string, ok bool) {
	inQuotes := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuotes = !inQuotes
		case ':':
			if inQuotes {
				continue
			}
			head := line[:i]
			if j := strings.IndexByte(head, ';'); j >= 0 {
				return strings.ToUpper(strings.TrimSpace(head[:j])), head[j+1:], line[i+1:], true
			}
			return strings.ToUpper(strings.TrimSpace(head)), "", line[i+1:], true
		}
	}
	return "", "", "", false
}

// parseExDateValues parses the value (comma-separated multi-values) of an
// EXDATE property in the three client forms: VALUE=DATE, UTC datetime (Z
// suffix) or local TZID datetime. Returns UTC instants; an unreadable value is
// ignored (lenient reading, like the rest of the parser).
func parseExDateValues(params, value string) []time.Time {
	isDate := strings.EqualFold(paramValue(params, "VALUE"), "DATE")
	loc, _ := icaltime.LoadZone(paramValue(params, "TZID"))
	var out []time.Time
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch {
		case isDate || len(v) == 8:
			if t, err := time.Parse(icaltime.LayoutDate, v); err == nil {
				out = append(out, t.UTC())
			}
		case strings.HasSuffix(v, "Z"):
			if t, err := time.Parse(icaltime.LayoutDateTimeUTC, v); err == nil {
				out = append(out, t.UTC())
			}
		default:
			if t, err := time.ParseInLocation(icaltime.LayoutDateTime, v, loc); err == nil {
				out = append(out, t.UTC())
			}
		}
	}
	return out
}

// paramValue extracts the value of a parameter (case-insensitive name) from a
// raw parameters section "TZID=Europe/Paris;VALUE=DATE"; quoted values are
// unquoted.
func paramValue(params, name string) string {
	inQuotes := false
	start := 0
	scan := func(p string) (string, bool) {
		k, v, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.Trim(v, `"`), true
		}
		return "", false
	}
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case '"':
			inQuotes = !inQuotes
		case ';':
			if !inQuotes {
				if v, ok := scan(params[start:i]); ok {
					return v
				}
				start = i + 1
			}
		}
	}
	if v, ok := scan(params[start:]); ok {
		return v
	}
	return ""
}

// mailtoValue extracts the email address from a CAL-ADDRESS value
// ("mailto:alice@…", case-insensitive prefix), "" if the value is not a mailto.
func mailtoValue(value string) string {
	v := strings.TrimSpace(value)
	if len(v) < len("mailto:") || !strings.EqualFold(v[:len("mailto:")], "mailto:") {
		return ""
	}
	return strings.TrimSpace(v[len("mailto:"):])
}

// unescapeText applies the RFC 5545 §3.3.11 TEXT unescaping:
// \\ \; \, \n \N.
func unescapeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n', 'N':
			b.WriteByte('\n')
		case '\\', ';', ',':
			b.WriteByte(s[i])
		default:
			// Unknown sequence: keep as-is (lenient).
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
