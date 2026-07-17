package proton

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jmdlab/cal-gateway/internal/icaltime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// This file implements the WRITE half of the Proton Calendar crypto model
// (M2, the create path), on top of the official gopenpgp + go-proton-api
// primitives. It is the mirror of the read path in crypto.go.
//
// A Proton event carries its iCalendar content in four "cards":
//
//	SharedSigned      UID/DTSTAMP/DTSTART/DTEND/[RRULE]/SEQUENCE   signed cleartext (type 2)
//	SharedEncrypted   UID/DTSTAMP/CREATED/SUMMARY/DESCRIPTION/LOCATION  encrypted+signed (type 3)
//	CalendarSigned    UID/DTSTAMP/STATUS/TRANSP                    signed cleartext (type 2)
//	CalendarEncrypted UID/DTSTAMP/COMMENT                          encrypted+signed (type 3)
//
// Sealing:
//   - signed cards: SignDetached over the EXACT bytes of the fragment (the
//     member's address key). The detached signature covers the plaintext
//     verbatim — the Data field sent MUST be byte-identical to the signed
//     bytes (same folding / escaping / CRLF), otherwise Proton rejects it as
//     "impossible to verify".
//   - encrypted cards: a fresh AES-256 session key per card, EncryptSessionKey
//     to the calendar key (→ key packet), then encryption of the plaintext (data
//     packet) + detached signature of the plaintext. On an UPDATE the original
//     session key must be reused (the server keeps the key packet) — not relevant
//     here, M2 only does CREATE.
//
// The body is PUT to /calendar/v1/{calID}/events/sync. go-proton-api has no
// write for this endpoint: we re-issue the request on its captured *resty.Client
// (see account.rc), reusing its configuration (base URL mail.proton.me/api,
// x-pm-appversion header, APIError parsing).

// Proton API response codes (concept verified against the study reference).
const (
	codeSuccess      = 1000 // per-entry and top-level success
	codeSuccessMulti = 1001 // top-level multi-status of a batch
)

// EventInput is an event to create, fields in cleartext. Start/End are absolute
// instants; TZID (IANA zone, "" or "UTC" → Z form) is used only to re-render the
// local wall time in DTSTART/DTEND — the instant itself does not depend on TZID.
// RRule is verbatim ("" = non-recurring).
type EventInput struct {
	UID string // optional; generated if empty

	Title       string
	Description string
	Location    string

	Start time.Time
	End   time.Time
	TZID  string
	// EndTZID is the IANA zone of DTEND when it differs from TZID ("" = same
	// zone as TZID at render time) — mirror of Proton's EndTimezone column.
	EndTZID string
	AllDay  bool

	RRule string

	// ExDates are the deleted occurrences (EXDATE) of the recurring master,
	// as absolute instants — the COMPLETE state wanted by the client (Apple
	// always sends the entire list), not a delta. Ignored if RRule is empty.
	ExDates []time.Time

	// Status / Transp (signed CalendarEvents card). "" = RFC 5545 defaults
	// (CONFIRMED / OPAQUE), applied at write time.
	Status string
	Transp string

	// Notifications are the wanted reminders (COMPLETE state, cleartext API
	// column), already run through the Proton filter (NotificationFromAlarm).
	// Empty = no reminders — same semantics as the official ICS import ([]),
	// whereas the update path preserves the original tri-state (null = inherit).
	Notifications []Notification

	// RecurrenceID turns the CREATE into an exception-row (editing ONE
	// occurrence of a series): the ORIGINAL instant of the occurrence,
	// serialized as RECURRENCE-ID in the SharedSigned card (the server derives
	// the row's RecurrenceID column from it). UID must then be that of the
	// master. nil = master or plain event.
	RecurrenceID *time.Time

	// Sequence is the SEQUENCE written at CREATE time (0 for a normal event).
	// An exception-row must carry a SEQUENCE ≥ that of its master — otherwise
	// the server rejects it (code 2001, verified against the proton-cal study
	// reference). Ignored by the update path (diffPatches handles the bump).
	Sequence int

	// SeriesManaged lifts the anti-corruption guard of a master update
	// (refusing structural changes when exception-rows exist): the caller —
	// the backend's folded-PUT routing — reconciles the exception-rows ITSELF
	// from the same payload (update/create/delete). Never set it on an
	// isolated update.
	SeriesManaged bool

	// Organizer / OrganizerCN / Attendees (M5a): outbound invitation at CREATE
	// time. Organizer is the organizing address (an address of the account,
	// verified by the caller — the CalDAV backend), "" = no invitation.
	// A non-empty Attendees triggers the AttendeesEventContent card, the
	// cleartext Attendees array and IsOrganizer:1 (see attendees.go).
	Organizer   string
	OrganizerCN string
	Attendees   []AttendeeInput

	// AttendeesReplace (M5b): the UPDATE path rewrites the attendee list from
	// Attendees (the COMPLETE wanted state — the rows of kept attendees survive
	// verbatim, removed ones disappear, added ones are sealed with the shared
	// session key) instead of preserving the card verbatim. SEQUENCE is bumped
	// (structural change of the invitation, RFC 5546). false = historical
	// behavior: card + cleartext array preserved. Ignored by the create path
	// (Attendees is enough there).
	AttendeesReplace bool
}

// statusOrDefault / transpOrDefault apply the RFC 5545 defaults — the same ones
// Proton assumes when the card does not carry the property.
func statusOrDefault(s string) string {
	if s == "" {
		return "CONFIRMED"
	}
	return s
}

func transpOrDefault(s string) string {
	if s == "" {
		return "OPAQUE"
	}
	return s
}

// CreateEvent encrypts and creates an event via the sync endpoint. Returns the
// created Proton row ID (stable, used as the CalDAV resource name).
func (a *Account) CreateEvent(ctx context.Context, calID string, in EventInput) (string, error) {
	if in.Start.IsZero() || in.End.IsZero() {
		return "", errors.New("proton: CreateEvent requires start and end times")
	}
	calKR, signerKR, memberID, err := a.writeContext(ctx, calID)
	if err != nil {
		return "", err
	}

	uid := in.UID
	if uid == "" {
		uid = newUID()
	}
	now := time.Now().UTC()
	frags := buildFragments(uid, now, in)

	// Outbound invitation (M5a): attendees card + cleartext array. The
	// canonicalization is done BEFORE any sealing — a non-canonicalizable email
	// is a hard error (otherwise the token would be invalid), and nothing is
	// written on the Proton side.
	attRows := json.RawMessage("[]")
	if len(in.Attendees) > 0 {
		emails := make([]string, len(in.Attendees))
		for i := range in.Attendees {
			emails[i] = in.Attendees[i].Email
		}
		canon, cerr := a.canonicalEmails(ctx, emails)
		if cerr != nil {
			return "", cerr
		}
		tokens := make([]string, len(in.Attendees))
		rows := make([]attendeeRow, len(in.Attendees))
		for i := range in.Attendees {
			tokens[i] = attendeeToken(uid, canon[in.Attendees[i].Email])
			rows[i] = attendeeRow{Token: tokens[i], Status: 0, Comment: json.RawMessage("null")}
		}
		frags.attendees = attendeesFragment(uid, in.Attendees, tokens)
		if attRows, err = json.Marshal(rows); err != nil {
			return "", fmt.Errorf("proton: encoding attendee rows: %w", err)
		}
	}

	body, err := sealCards(frags, calKR, signerKR)
	if err != nil {
		return "", err
	}
	body.Attendees = attRows
	if len(in.Attendees) > 0 {
		body.IsOrganizer = 1
	}
	// Reminders: cleartext column, outside the cards. [] if none (same value as
	// the official ICS import), never null on a create from a PUT — the CalDAV
	// client provided the complete state, including "no alert".
	body.Notifications = marshalNotifications(in.Notifications)

	isImport := 0
	overwrite := 0
	resp, err := a.putSync(ctx, calID, syncRequest{
		MemberID: memberID,
		IsImport: &isImport,
		Events:   []syncEvent{{Overwrite: &overwrite, Event: body}},
	})
	if err != nil {
		return "", err
	}
	id, err := resp.createdID()
	if err != nil {
		return "", fmt.Errorf("proton: creating event on calendar %s: %w", calID, err)
	}
	return id, nil
}

// FindEventByUID returns the Proton row ID of an event by its iCal UID (server
// filter). found=false if none. Used to detect create vs update. A series can
// carry MULTIPLE same-UID rows (master + exception-rows of the modified
// occurrences): the client PUT always targets the MASTER (RecurrenceID == 0) —
// never an exception picked at random from the server order.
func (a *Account) FindEventByUID(ctx context.Context, calID, uid string) (eventID string, found bool, err error) {
	if rows, lerr := a.listEventRowsByUID(ctx, calID, uid); lerr == nil {
		for i := range rows {
			if rows[i].RecurrenceID == 0 {
				return rows[i].ID, true, nil
			}
		}
		if len(rows) > 0 {
			return rows[0].ID, true, nil
		}
		return "", false, nil
	}
	// Fallback (resty not captured, e.g. offline tests): go-proton-api filter,
	// with no RecurrenceID visibility.
	filter := url.Values{}
	filter.Set("UID", uid)
	rows, err := a.client.GetCalendarEvents(ctx, calID, 0, 1, filter)
	if err != nil {
		return "", false, fmt.Errorf("proton: looking up event by UID on calendar %s: %w", calID, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0].ID, true, nil
}

// DeleteEvent deletes an event via the sync endpoint (Events:[{ID}] without
// Event). Deleting a recurring MASTER orphans its exception-rows (no server
// cascade — verified against the study reference): we therefore enumerate the
// same-UID rows and batch master + exceptions in a SINGLE sync call. An
// exception-row targeted directly is deleted on its own.
func (a *Account) DeleteEvent(ctx context.Context, calID, eventID string) error {
	_, _, memberID, err := a.writeContext(ctx, calID)
	if err != nil {
		return err
	}

	ids := []string{eventID}
	// Best-effort enumeration: if it fails, the single-row deletion remains
	// correct for a plain event (by far the majority case) and the sync
	// response will surface any not-found (2501).
	if row, rerr := a.getEventRow(ctx, calID, eventID); rerr == nil && row.RecurrenceID == 0 && row.UID != "" {
		if rows, lerr := a.listEventRowsByUID(ctx, calID, row.UID); lerr == nil {
			seen := map[string]bool{eventID: true}
			for i := range rows {
				if !seen[rows[i].ID] {
					seen[rows[i].ID] = true
					ids = append(ids, rows[i].ID)
				}
			}
		}
	}

	events := make([]syncEvent, 0, len(ids))
	for _, id := range ids {
		events = append(events, syncEvent{ID: id})
	}
	resp, err := a.putSync(ctx, calID, syncRequest{
		MemberID: memberID,
		Events:   events,
	})
	if err != nil {
		return err
	}
	if err := resp.err(); err != nil {
		if resp.firstCode() == codeEventNotFound {
			// Already deleted on the Proton side: clean disappearance (404 on
			// the CalDAV side), not a server error.
			return fmt.Errorf("proton: deleting event %s/%s: %w", calID, eventID, ErrEventNotFound)
		}
		return fmt.Errorf("proton: deleting event %s/%s: %w", calID, eventID, err)
	}
	return nil
}

// writeContext gathers the keys needed for writing: the calendar keyring
// (already cached via the read path), the signing address keyring (the address
// of OUR member — Proton verifies the signature against this key) and the
// memberID.
func (a *Account) writeContext(ctx context.Context, calID string) (calKR, signerKR *crypto.KeyRing, memberID string, err error) {
	calKR, err = a.calendarKeyRing(ctx, calID)
	if err != nil {
		return nil, nil, "", err
	}
	members, err := a.client.GetCalendarMembers(ctx, calID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("proton: fetching members for calendar %s: %w", calID, err)
	}
	memberID = a.resolveMemberID(members)

	var memberEmail string
	for _, m := range members {
		if m.ID == memberID {
			memberEmail = m.Email
			break
		}
	}
	signerKR = a.signerKeyRing(memberEmail)
	if signerKR == nil {
		return nil, nil, "", fmt.Errorf("proton: no address key available to sign for calendar %s", calID)
	}
	return calKR, signerKR, memberID, nil
}

// signerKeyRing picks the address keyring whose email matches the member
// (fallback: first unlocked address).
func (a *Account) signerKeyRing(email string) *crypto.KeyRing {
	if email != "" {
		for _, addr := range a.addresses {
			if strings.EqualFold(addr.Email, email) {
				if kr, ok := a.addrKRs[addr.ID]; ok {
					return kr
				}
			}
		}
	}
	for _, addr := range a.addresses {
		if kr, ok := a.addrKRs[addr.ID]; ok {
			return kr
		}
	}
	return nil
}

// ---- Sealing the 4 cards ----

// fragments carries the wrapped iCalendar fragments, ready to seal.
// attendees is the AttendeesEventContent card ("" = no attendees, M5a) —
// encrypted with the SAME session key as sharedEncrypted (no dedicated key
// packet: the SharedKeyPacket serves both).
type fragments struct {
	sharedSigned    string
	sharedEncrypted string
	calSigned       string
	calEncrypted    string
	attendees       string
}

// sealCards signs the cleartext cards and encrypts+signs the encrypted cards,
// assembling the event body of the sync PUT (create). The "shared" session key
// is generated ONCE and shared between the SharedEncrypted card and the
// attendees card (M5a) — same model as the web client.
func sealCards(f fragments, calKR, signerKR *crypto.KeyRing) (*eventBody, error) {
	sharedSignedSig, err := signDetached(f.sharedSigned, signerKR)
	if err != nil {
		return nil, fmt.Errorf("proton: signing shared card: %w", err)
	}
	calSignedSig, err := signDetached(f.calSigned, signerKR)
	if err != nil {
		return nil, fmt.Errorf("proton: signing calendar card: %w", err)
	}
	sharedSK, sharedKP, err := newSessionKey(calKR)
	if err != nil {
		return nil, fmt.Errorf("proton: shared session key: %w", err)
	}
	sharedData, sharedSig, err := encryptWithKeyAndSign(f.sharedEncrypted, sharedSK, signerKR)
	if err != nil {
		return nil, fmt.Errorf("proton: encrypting shared card: %w", err)
	}
	calSK, calKP, err := newSessionKey(calKR)
	if err != nil {
		return nil, fmt.Errorf("proton: calendar session key: %w", err)
	}
	calData, calSig, err := encryptWithKeyAndSign(f.calEncrypted, calSK, signerKR)
	if err != nil {
		return nil, fmt.Errorf("proton: encrypting calendar card: %w", err)
	}

	body := &eventBody{
		Permissions:       1,
		SharedKeyPacket:   sharedKP,
		CalendarKeyPacket: calKP,
		SharedEventContent: []eventPart{
			{Type: cardSigned, Data: f.sharedSigned, Signature: sharedSignedSig},
			{Type: cardEncryptedAndSigned, Data: sharedData, Signature: sharedSig},
		},
		CalendarEventContent: []eventPart{
			{Type: cardSigned, Data: f.calSigned, Signature: calSignedSig},
			{Type: cardEncryptedAndSigned, Data: calData, Signature: calSig},
		},
		AttendeesEventContent: []eventPart{},
		Attendees:             json.RawMessage("[]"),
		Notifications:         json.RawMessage("null"),
		Color:                 json.RawMessage("null"),
	}
	if f.attendees != "" {
		// Attendees card: SAME session key as SharedEventContent (the server
		// stores only one SharedKeyPacket); Type=3, signed the same way.
		attData, attSig, aerr := encryptWithKeyAndSign(f.attendees, sharedSK, signerKR)
		if aerr != nil {
			return nil, fmt.Errorf("proton: encrypting attendees card: %w", aerr)
		}
		body.AttendeesEventContent = []eventPart{
			{Type: cardEncryptedAndSigned, Data: attData, Signature: attSig},
		}
	}
	return body, nil
}

// signDetached produces an armored detached signature over the EXACT bytes of
// the plaintext (binary mode — no text canonicalization that would shift the
// covered bytes). The Data field sent must be that same plaintext verbatim.
func signDetached(plaintext string, signerKR *crypto.KeyRing) (string, error) {
	sig, err := signerKR.SignDetached(crypto.NewPlainMessage([]byte(plaintext)))
	if err != nil {
		return "", err
	}
	return sig.GetArmored()
}

// newSessionKey generates a fresh AES-256 session key and its key packet
// (PKESK encrypted to the calendar key, b64).
func newSessionKey(calKR *crypto.KeyRing) (*crypto.SessionKey, string, error) {
	sk, err := crypto.GenerateSessionKey() // AES-256 by default in gopenpgp v2
	if err != nil {
		return nil, "", err
	}
	keyPacket, err := calKR.EncryptSessionKey(sk)
	if err != nil {
		return nil, "", err
	}
	return sk, base64.StdEncoding.EncodeToString(keyPacket), nil
}

// encryptWithKeyAndSign encrypts the plaintext with a GIVEN session key
// (shareable between cards — M5a) and signs the plaintext (not the ciphertext)
// with the address key. Returns the data packet (SEIPD b64) and armored signature.
func encryptWithKeyAndSign(plaintext string, sk *crypto.SessionKey, signerKR *crypto.KeyRing) (dataPacketB64, armoredSig string, err error) {
	dataPacket, err := sk.Encrypt(crypto.NewPlainMessage([]byte(plaintext)))
	if err != nil {
		return "", "", err
	}
	armoredSig, err = signDetached(plaintext, signerKR)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(dataPacket), armoredSig, nil
}

// encryptAndSign encrypts the plaintext to the calendar key with a fresh
// AES-256 session key and signs the plaintext (not the ciphertext) with the
// address key. Returns the key packet (PKESK b64), data packet (SEIPD b64) and
// the armored signature.
func encryptAndSign(plaintext string, calKR, signerKR *crypto.KeyRing) (keyPacketB64, dataPacketB64, armoredSig string, err error) {
	sk, keyPacketB64, err := newSessionKey(calKR)
	if err != nil {
		return "", "", "", err
	}
	dataPacketB64, armoredSig, err = encryptWithKeyAndSign(plaintext, sk, signerKR)
	if err != nil {
		return "", "", "", err
	}
	return keyPacketB64, dataPacketB64, armoredSig, nil
}

// ---- Building the iCalendar fragments ----

// buildFragments builds the 4 fragments with a FIXED property ORDER (the order
// matters: the signed cards are covered byte for byte). The wrapper has no
// VERSION/PRODID and no trailing CRLF — neither do the Proton cards.
func buildFragments(uid string, now time.Time, in EventInput) fragments {
	stamp := icalFormatUTC(now)

	// Shared signed: time and recurrence structure. Fixed property order (same
	// order as the study reference): UID, DTSTAMP, DTSTART, DTEND,
	// [RECURRENCE-ID], [RRULE], EXDATEs, SEQUENCE.
	endTZ := in.EndTZID
	if endTZ == "" {
		endTZ = in.TZID // no end zone: same zone as the start
	}
	shared := []string{
		"UID:" + uid,
		"DTSTAMP:" + stamp,
		icalDTProp("DTSTART", in.Start, in.TZID, in.AllDay),
		icalDTProp("DTEND", in.End, endTZ, in.AllDay),
	}
	if in.RecurrenceID != nil {
		// Exception-row: the original occurrence, same form as DTSTART. The
		// server derives the row's RecurrenceID column from it.
		shared = append(shared, icalDTProp("RECURRENCE-ID", *in.RecurrenceID, in.TZID, in.AllDay))
	}
	if in.RRule != "" {
		shared = append(shared, "RRULE:"+in.RRule)
		// EXDATE only makes sense on a recurring event; same form as DTSTART.
		for _, ex := range in.ExDates {
			shared = append(shared, icalDTProp("EXDATE", ex, in.TZID, in.AllDay))
		}
	}
	if in.Organizer != "" {
		// Outbound invitation (M5a): ORGANIZER lives on the SharedSigned card,
		// AFTER EXDATE and BEFORE SEQUENCE — same position as the web client.
		// Never an X-PM-TOKEN on the organizer.
		shared = append(shared, organizerProp(in.OrganizerCN, in.Organizer))
	}
	shared = append(shared, "SEQUENCE:"+strconv.Itoa(in.Sequence))

	// Shared encrypted: creation + visible text fields.
	sharedEnc := []string{"UID:" + uid, "DTSTAMP:" + stamp, "CREATED:" + stamp}
	if in.Title != "" {
		sharedEnc = append(sharedEnc, "SUMMARY:"+icalEscapeText(in.Title))
	}
	if in.Description != "" {
		sharedEnc = append(sharedEnc, "DESCRIPTION:"+icalEscapeText(in.Description))
	}
	if in.Location != "" {
		sharedEnc = append(sharedEnc, "LOCATION:"+icalEscapeText(in.Location))
	}

	// Calendar signed: status / transparency, passthrough of the incoming ICS
	// (RFC 5545 defaults if absent).
	calSigned := []string{
		"UID:" + uid,
		"DTSTAMP:" + stamp,
		"STATUS:" + statusOrDefault(in.Status),
		"TRANSP:" + transpOrDefault(in.Transp),
	}

	// Calendar encrypted: comment (empty for a plain event).
	calEnc := []string{"UID:" + uid, "DTSTAMP:" + stamp, "COMMENT:"}

	return fragments{
		sharedSigned:    icalWrap(shared),
		sharedEncrypted: icalWrap(sharedEnc),
		calSigned:       icalWrap(calSigned),
		calEncrypted:    icalWrap(calEnc),
	}
}

// icalDTProp formats a date(-time) property in the three Proton forms: all-day
// VALUE=DATE (wall date of t, no zone conversion), UTC (Z form), or TZID (local
// wall time in the zone). An invalid IANA zone falls back to UTC.
func icalDTProp(name string, t time.Time, tzid string, allDay bool) string {
	if allDay {
		return fmt.Sprintf("%s;VALUE=DATE:%s", name, t.UTC().Format(icaltime.LayoutDate))
	}
	loc, ok := icaltime.LoadZone(tzid)
	if !ok {
		return name + ":" + icalFormatUTC(t)
	}
	return fmt.Sprintf("%s;TZID=%s:%s", name, tzid, t.In(loc).Format(icaltime.LayoutDateTime))
}

// icalFormatUTC renders an instant as an iCalendar UTC datetime: 20060102T150405Z.
func icalFormatUTC(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

// icalWrap folds each content line and assembles a VCALENDAR/VEVENT wrapper with
// CRLF separators and NO trailing CRLF (the Proton cards have none).
func icalWrap(lines []string) string {
	out := make([]string, 0, len(lines)+4)
	out = append(out, "BEGIN:VCALENDAR", "BEGIN:VEVENT")
	for _, l := range lines {
		out = append(out, icalFoldLine(l))
	}
	out = append(out, "END:VEVENT", "END:VCALENDAR")
	return strings.Join(out, "\r\n")
}

// icalEscapeText escapes a TEXT value per RFC 5545 §3.3.11 (\\ \; \, \n),
// preventing property injection from user text.
func icalEscapeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case ';':
			b.WriteString(`\;`)
		case ',':
			b.WriteString(`\,`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			// Bare CR ignored; a following LF is escaped above.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// icalMaxLineOctets is the RFC 5545 §3.1 limit of a content line (excluding CRLF).
const icalMaxLineOctets = 75

// icalFoldLine folds a content line per RFC 5545 §3.1: beyond 75 octets, breaks
// on CRLF+space, never in the middle of a rune.
func icalFoldLine(line string) string {
	if len(line) <= icalMaxLineOctets {
		return line
	}
	var b strings.Builder
	b.Grow(len(line) + 3*(len(line)/icalMaxLineOctets+1))
	budget := icalMaxLineOctets
	for len(line) > budget {
		cut := budget
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		if cut == 0 {
			_, size := utf8.DecodeRuneInString(line)
			cut = size
		}
		b.WriteString(line[:cut])
		b.WriteString("\r\n ")
		line = line[cut:]
		budget = icalMaxLineOctets - 1 // continuations start with a space
	}
	b.WriteString(line)
	return b.String()
}

// newUID generates an iCalendar UID for an event without an input UID
// (16 random bytes in hex). Third-party / Apple invites already carry their own UID.
func newUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure: unrecoverable
	}
	return hex.EncodeToString(b[:])
}

// ---- Wire of the /calendar/v1/{calID}/events/sync endpoint ----

// cardType is the type of a card (CALENDAR_CARD_TYPE on the web client).
type cardType int

const (
	cardClear              cardType = 0
	cardEncrypted          cardType = 1
	cardSigned             cardType = 2
	cardEncryptedAndSigned cardType = 3
)

// eventPart is an event content card on the wire.
type eventPart struct {
	Type      cardType `json:"Type"`
	Data      string   `json:"Data"`
	Signature string   `json:"Signature,omitempty"`
}

// eventBody is the Event object of a sync payload. Field presence is
// significant: the content arrays serialize to [] (never null);
// Attendees/Notifications/Color are []/null/null on a create (without attendees).
// IsOrganizer is emitted only on the CREATE of an invitation (M5a) — omitempty:
// absent on any other path, including the update.
type eventBody struct {
	Permissions           int             `json:"Permissions"`
	IsOrganizer           int             `json:"IsOrganizer,omitempty"`
	SharedKeyPacket       string          `json:"SharedKeyPacket,omitempty"`
	CalendarKeyPacket     string          `json:"CalendarKeyPacket,omitempty"`
	SharedEventContent    []eventPart     `json:"SharedEventContent"`
	CalendarEventContent  []eventPart     `json:"CalendarEventContent"`
	AttendeesEventContent []eventPart     `json:"AttendeesEventContent"`
	Attendees             json.RawMessage `json:"Attendees"`
	Notifications         json.RawMessage `json:"Notifications"`
	Color                 json.RawMessage `json:"Color"`
}

// syncEvent is an entry of the Events array: create (Overwrite + Event),
// update (ID + Event) or delete (ID only).
type syncEvent struct {
	ID        string     `json:"ID,omitempty"`
	Overwrite *int       `json:"Overwrite,omitempty"`
	Event     *eventBody `json:"Event,omitempty"`
}

// syncRequest is the PUT /calendar/v1/{calID}/events/sync payload. IsImport is
// present (0) only on creates.
type syncRequest struct {
	MemberID string      `json:"MemberID"`
	IsImport *int        `json:"IsImport,omitempty"`
	Events   []syncEvent `json:"Events"`
}

// syncResponse is the response of the sync endpoint.
type syncResponse struct {
	Code      int `json:"Code"`
	Responses []struct {
		Index    int `json:"Index"`
		Response struct {
			Code  int    `json:"Code"`
			Error string `json:"Error"`
			Event *struct {
				ID string `json:"ID"`
			} `json:"Event"`
		} `json:"Response"`
	} `json:"Responses"`
}

// firstCode returns the API code of the first entry of the response
// (0 if the response has no entries).
func (r *syncResponse) firstCode() int {
	if len(r.Responses) == 0 {
		return 0
	}
	return r.Responses[0].Response.Code
}

// err returns the response failure: error of the first entry, otherwise the
// top-level code; nil on success.
func (r *syncResponse) err() error {
	if len(r.Responses) == 0 {
		if r.Code == codeSuccess || r.Code == codeSuccessMulti {
			return nil
		}
		return fmt.Errorf("sync failed: code %d", r.Code)
	}
	resp := r.Responses[0].Response
	if resp.Code != codeSuccess {
		if resp.Error != "" {
			return fmt.Errorf("sync failed: code %d: %s", resp.Code, resp.Error)
		}
		return fmt.Errorf("sync failed: code %d", resp.Code)
	}
	return nil
}

// createdID returns the ID of the created event (first entry).
func (r *syncResponse) createdID() (string, error) {
	if err := r.err(); err != nil {
		return "", err
	}
	if len(r.Responses) == 0 || r.Responses[0].Response.Event == nil {
		return "", errors.New("sync succeeded but no event was echoed")
	}
	id := r.Responses[0].Response.Event.ID
	if id == "" {
		return "", errors.New("sync echoed an event without ID")
	}
	return id, nil
}

// putSync issues the PUT /calendar/v1/{calID}/events/sync (create, update by
// ID, delete by ID) via doAuthed.
func (a *Account) putSync(ctx context.Context, calID string, payload syncRequest) (*syncResponse, error) {
	var resp syncResponse
	if err := a.doAuthed(ctx, http.MethodPut, "/calendar/v1/"+calID+"/events/sync", payload, &resp); err != nil {
		return nil, fmt.Errorf("proton: PUT events/sync on calendar %s: %w", calID, err)
	}
	return &resp, nil
}

// doAuthed issues a request on go-proton-api's *resty.Client (base URL +
// x-pm-appversion + APIError parsing already wired), carrying the auth of the
// freshest session (uid + access token). On 401, forces a token refresh via an
// official read (which re-persists the session through AddAuthHandler) then
// retries once. Shared by the write path (putSync) and the update re-fetch
// (getEventRow).
func (a *Account) doAuthed(ctx context.Context, method, path string, body, result any) error {
	a.mu.Lock()
	rc := a.rc
	a.mu.Unlock()
	if rc == nil {
		return errors.New("proton: resty client not captured (no prior API call?)")
	}

	do := func() (int, error) {
		sess, err := LoadSession(a.dataDir)
		if err != nil {
			return 0, fmt.Errorf("proton: reloading session for write: %w", err)
		}
		req := rc.R().
			SetContext(ctx).
			SetHeader("x-pm-uid", sess.UID).
			SetAuthToken(sess.AccessToken)
		if body != nil {
			req.SetBody(body)
		}
		if result != nil {
			req.SetResult(result)
		}
		httpResp, err := req.Execute(method, path)
		status := 0
		if httpResp != nil {
			status = httpResp.StatusCode()
		}
		return status, err
	}

	status, err := do()
	if err != nil && status == 401 {
		if _, rerr := a.client.GetCalendars(ctx); rerr == nil {
			_, err = do()
		}
	}
	return err
}
