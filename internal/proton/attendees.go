package proton

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Outbound invitations (M5a) — Proton half: on the CREATION of an event with
// attendees, the gateway writes what the official web client would write
// (concepts verified against the WebClients code, never copied):
//
//   - a SINGLE AttendeesEventContent card, Type=3 (ENCRYPTED_AND_SIGNED),
//     encrypted with THE SAME session key as SharedEventContent (the
//     SharedKeyPacket key packet is reused — there is NO AttendeesKeyPacket)
//     and signed with the same address key. Content: UID + one ATTENDEE line
//     per attendee, parameters in the order CN, ROLE, RSVP, PARTSTAT,
//     X-PM-TOKEN;
//   - X-PM-TOKEN = lowercase hex of SHA1(UID + CanonicalEmail), raw
//     concatenation, UID verbatim as written in the card. The CanonicalEmail
//     comes from GET /core/v4/addresses/canonical;
//   - the ORGANIZER property on the EXISTING SharedSigned card (never an
//     X-PM-TOKEN on it), inserted after EXDATE and before SEQUENCE;
//   - the cleartext Attendees array ({Token, Status:0, Comment:null} per
//     attendee) + IsOrganizer:1 at the body level.
//
// Sending the iMIP email does NOT go through here: it lives in internal/invite
// (SMTP bridge), orchestrated by the CalDAV backend AFTER the sync succeeds.

// AttendeeInput is an attendee to write at creation (M5a): email as provided by
// the CalDAV client, CN optional ("" = the email is used as the CN).
// Partstat (M6b) carries the inbound PARTSTAT as read from the PUT (ACCEPTED/
// DECLINED/TENTATIVE/NEEDS-ACTION) — used ONLY to detect the account owner's
// reply to a received invitation; the write path (attendeeLine) ignores it and
// forces NEEDS-ACTION at creation.
type AttendeeInput struct {
	Email    string
	CN       string
	Partstat string
}

// Attendee is a DECRYPTED attendee of an existing event: identity
// (AttendeesEvents card) + RSVP status (cleartext row array, joined by Token).
// Status: 0=NEEDS-ACTION, 1=TENTATIVE, 2=DECLINED, 3=ACCEPTED — the cleartext
// API enum (CalendarAttendeeStatus). ID is the identifier of the attendee row
// (cleartext column, joined by Token) — the key for the dedicated endpoint that
// patches the PARTSTAT (M6b, outbound RSVP). Zero-values are JSON-store
// backward-compatible.
type Attendee struct {
	Email  string
	CN     string
	Status int
	Token  string
	ID     string
}

// attendeeCNMax is the maximum length of a CN written into the card (the
// official web client's truncation).
const attendeeCNMax = 190

// attendeeToken computes an attendee's X-PM-TOKEN: lowercase hex of
// SHA1(UID + CanonicalEmail), raw concatenation (UID verbatim as written in the
// card).
func attendeeToken(uid, canonicalEmail string) string {
	sum := sha1.Sum([]byte(uid + canonicalEmail))
	return hex.EncodeToString(sum[:])
}

// canonicalResponse is the response of GET /core/v4/addresses/canonical:
// multi-status (Code 1001) with one entry per requested email.
type canonicalResponse struct {
	Code      int
	Responses []struct {
		Email    string
		Response struct {
			Code           int
			Error          string
			CanonicalEmail string
		}
	}
}

// canonicalEmails resolves the canonical form of each attendee email (the
// basis of the SHA1 token — the web client canonicalizes before hashing). Any
// failed entry is a hard error: a token computed on a non-canonical form would
// never match the one from Proton clients.
func (a *Account) canonicalEmails(ctx context.Context, emails []string) (map[string]string, error) {
	if len(emails) == 0 {
		return map[string]string{}, nil
	}
	q := url.Values{}
	for _, e := range emails {
		q.Add("Emails[]", e)
	}
	var resp canonicalResponse
	if err := a.doAuthed(ctx, http.MethodGet, "/core/v4/addresses/canonical?"+q.Encode(), nil, &resp); err != nil {
		return nil, fmt.Errorf("proton: canonicalizing attendee emails: %w", err)
	}
	out := make(map[string]string, len(resp.Responses))
	for _, r := range resp.Responses {
		if r.Response.Code != codeSuccess || r.Response.CanonicalEmail == "" {
			return nil, fmt.Errorf("proton: canonicalizing %q: code %d %s", r.Email, r.Response.Code, r.Response.Error)
		}
		out[r.Email] = r.Response.CanonicalEmail
	}
	for _, e := range emails {
		if _, ok := out[e]; !ok {
			return nil, fmt.Errorf("proton: no canonical form returned for %q", e)
		}
	}
	return out, nil
}

// attendeeLine renders an attendee's ATTENDEE line for the
// AttendeesEventContent card — the EXACT web-client parameter order:
// CN, ROLE, RSVP, PARTSTAT, X-PM-TOKEN. The email is stripped of control
// characters (same anti-injection discipline as the parameter values: the card
// is SIGNED by the account owner's key).
func attendeeLine(in AttendeeInput, token string) string {
	return "ATTENDEE;CN=" + icalParamValue(cnOrEmail(in.CN, in.Email)) +
		";ROLE=REQ-PARTICIPANT;RSVP=TRUE;PARTSTAT=NEEDS-ACTION" +
		";X-PM-TOKEN=" + token + ":mailto:" + stripCtrl(in.Email)
}

// organizerProp renders the ORGANIZER property of the SharedSigned card
// (never an X-PM-TOKEN on it). Email stripped as in attendeeLine.
func organizerProp(cn, email string) string {
	return "ORGANIZER;CN=" + icalParamValue(cnOrEmail(cn, email)) + ":mailto:" + stripCtrl(email)
}

// cnOrEmail applies the default (empty CN = email) and the web client's
// truncation to 190 characters, without cutting a rune.
func cnOrEmail(cn, email string) string {
	if cn == "" {
		cn = email
	}
	if len(cn) > attendeeCNMax {
		cut := attendeeCNMax
		for cut > 0 && cn[cut]&0xC0 == 0x80 { // do not cut in the middle of a rune
			cut--
		}
		cn = cn[:cut]
	}
	return cn
}

// stripCtrl removes every control character (including CR/LF/TAB) from a value
// destined for an iCalendar line or a header. SECURITY: without this, a CR/LF
// in a CN/email/title would inject forged iCal lines into a card SIGNED by the
// account owner's key, or headers into the invitation email
// (security audit 2026-07-16, P1-b/P2-b).
func stripCtrl(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// icalParamValue protects an iCalendar parameter value (RFC 5545 §3.2):
// control characters removed (anti-injection), DQUOTE forbidden (removed), and
// a value containing ':', ';' or ',' must be quoted.
func icalParamValue(v string) string {
	v = stripCtrl(v)
	v = strings.ReplaceAll(v, `"`, "")
	if strings.ContainsAny(v, ":;,") {
		return `"` + v + `"`
	}
	return v
}

// attendeesFragment builds the content of the AttendeesEventContent card:
// standard VCALENDAR/VEVENT wrapper (like the other cards), UID then one
// ATTENDEE line per attendee — NO DTSTAMP (the web client does not set one).
// tokens is aligned with atts.
func attendeesFragment(uid string, atts []AttendeeInput, tokens []string) string {
	lines := make([]string, 0, len(atts)+1)
	lines = append(lines, "UID:"+uid)
	for i, at := range atts {
		lines = append(lines, attendeeLine(at, tokens[i]))
	}
	return icalWrap(lines)
}

// rebuildAttendeesFragment rebuilds the AttendeesEventContent card after an
// attendee diff (M5b, update): the ATTENDEE lines of KEPT attendees are taken
// VERBATIM from the decrypted original card (their PARTSTAT and any parameter
// written by a Proton client survive), those of removed attendees disappear,
// and added ones get a fresh line (attendeeLine). The keep tokens are in
// lowercase hex (attendeeToken form). Returns "" if no attendee remains (the
// card is then removed from the body).
func rebuildAttendeesFragment(oldCard, uid string, keep map[string]bool, added []AttendeeInput, addedTokens []string) string {
	if len(keep) == 0 && len(added) == 0 {
		return ""
	}
	if oldCard == "" {
		// Event previously without attendees: fresh card, same form as at
		// creation.
		return attendeesFragment(uid, added, addedTokens)
	}
	lines := make([]string, 0, len(keep)+len(added)+1)
	sawUID := false
	for _, l := range unfoldLines(oldCard) {
		name, params, _, ok := splitContentLineParams(l)
		if !ok || name == "BEGIN" || name == "END" {
			continue // wrapper re-rendered by icalWrap
		}
		if name == "UID" {
			sawUID = true
		}
		if name == "ATTENDEE" && !keep[strings.ToLower(paramValue(params, "X-PM-TOKEN"))] {
			continue // removed attendee (or line without token: never written by us)
		}
		lines = append(lines, l)
	}
	if !sawUID {
		lines = append([]string{"UID:" + uid}, lines...)
	}
	for i, at := range added {
		lines = append(lines, attendeeLine(at, addedTokens[i]))
	}
	return icalWrap(lines)
}
