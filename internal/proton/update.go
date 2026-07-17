package proton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// This file implements the UPDATE path (M3) of the write path — the sequel to
// write.go (creation). Concepts verified against the proton-cal study reference
// (never copied, never vendored):
//
//   - same PUT /calendar/v1/{calID}/events/sync endpoint as creation, but the
//     Events array entry carries {ID, Event} (neither Overwrite nor IsImport);
//   - the update body carries NO key packet: the server keeps the original key
//     packets, so we must DECRYPT the existing session keys (calendar key) and
//     re-encrypt the cards with those SAME session keys — re-issuing fresh keys
//     without a key packet would make everything undecryptable;
//   - Notifications/Color/Attendees (the row's cleartext columns) must be
//     RE-EMITTED with their existing values, otherwise the sync wipes reminders
//     and RSVPs. Since M4, Notifications is MODELED (VALARM <-> reminders): the
//     original column is only replaced if the client changed the alarms
//     (notificationsPayload); Color and Attendees stay re-emitted verbatim.
//
// HARD anti-loss RULE: Apple only echoes back the properties WE served it. So
// we NEVER rebuild the cards from our model: we PATCH the decrypted iCalendar
// text property by property (the only modeled fields: DTSTART/DTEND/RRULE/
// EXDATE/SEQUENCE on the signed card, SUMMARY/DESCRIPTION/LOCATION on the
// encrypted card) — ORGANIZER, ATTENDEE, X-*, conferencing, COMMENT and any
// unknown property survive verbatim. An event whose card fails to decrypt is
// never re-sealed: ErrEventDegraded, which the backend maps to 403 (the client
// reverts cleanly).

// ErrEventDegraded refuses an update when the original event cannot be re-sealed
// without loss (at least one undecryptable card).
var ErrEventDegraded = errors.New("proton: event cannot be re-sealed without data loss (decrypt failed)")

// UpdateEvent modifies an EXISTING event: re-fetch the raw row, in-place patch
// of the decrypted cards, re-sealing with the original session keys, PUT sync
// addressed to the row ID.
func (a *Account) UpdateEvent(ctx context.Context, calID, eventID string, in EventInput) error {
	if in.Start.IsZero() || in.End.IsZero() {
		return errors.New("proton: UpdateEvent requires start and end times")
	}
	calKR, signerKR, memberID, err := a.writeContext(ctx, calID)
	if err != nil {
		return err
	}

	row, err := a.getEventRow(ctx, calID, eventID)
	if err != nil {
		return err
	}

	// Never start from a partially decrypted event (account.go rule).
	cur := decryptEvent(row.CalendarEvent, calKR)
	if cur.DecryptFailed {
		return fmt.Errorf("proton: updating event %s/%s: %w", calID, eventID, ErrEventDegraded)
	}

	// Exception guard (verified in the reference, event/smart.go): changing a
	// master's bounds or RRULE invalidates its exception rows (same-UID rows
	// with RecurrenceID != 0). Purging them would destroy edits made on the
	// Proton side; keeping them produces phantom occurrences. Honest refusal
	// (403) — EXCEPT when the caller reconciles the series itself from the same
	// payload (in.SeriesManaged, PUT routing folded in M4). Adding an EXDATE
	// alone does not touch the other occurrences: allowed.
	if row.RecurrenceID == 0 && !in.SeriesManaged {
		if signedPatch, _ := diffPatches(&cur, in); patchTouchesTimesOrRRule(signedPatch) {
			rows, lerr := a.listEventRowsByUID(ctx, calID, row.UID)
			if lerr != nil {
				return fmt.Errorf("proton: updating event %s/%s: enumerating series rows: %w", calID, eventID, lerr)
			}
			for i := range rows {
				if rows[i].ID != row.ID && rows[i].RecurrenceID != 0 {
					return fmt.Errorf("proton: updating event %s/%s: master has per-occurrence exception rows; structural changes would corrupt them: %w",
						calID, eventID, ErrEventDegraded)
				}
			}
		}
	}

	// Attendee diff (M5b): plan computed BEFORE any sealing — a
	// non-canonicalizable email or an unreadable card is a hard error, nothing
	// is written. plan nil (list unchanged) = card preserved verbatim.
	var plan *attendeePlan
	if in.AttendeesReplace {
		plan, err = a.planAttendeeUpdate(ctx, row, &cur, in, calKR)
		if err != nil {
			return fmt.Errorf("proton: updating event %s/%s: %w", calID, eventID, err)
		}
	}

	body, err := buildUpdateBody(row, &cur, in, calKR, signerKR, plan)
	if err != nil {
		return fmt.Errorf("proton: updating event %s/%s: %w", calID, eventID, err)
	}

	resp, err := a.putSync(ctx, calID, syncRequest{
		MemberID: memberID,
		Events:   []syncEvent{{ID: eventID, Event: body}},
	})
	if err != nil {
		return err
	}
	if err := resp.err(); err != nil {
		return fmt.Errorf("proton: updating event %s/%s: %w", calID, eventID, err)
	}
	return nil
}

// attendeeStatusRequest is the body of the dedicated endpoint that patches the
// PARTSTAT of ONE attendee (M6b, outbound RSVP): PUT /calendar/v1/{calID}/
// events/{eventID}/attendees/{attendeeID} — {Status, UpdateTime, Comment}
// (concept verified in WebClients api/calendars.ts::updateAttendeePartstat).
// UpdateTime is the Unix epoch of the response; Comment is not modeled (null).
type attendeeStatusRequest struct {
	Status     int             `json:"Status"`
	UpdateTime int64           `json:"UpdateTime"`
	Comment    json.RawMessage `json:"Comment"`
}

// UpdateAttendeeStatus patches the PARTSTAT of ONE attendee via the dedicated
// endpoint (M6b) — the account owner accepts/declines/tentatively-accepts a
// RECEIVED invitation. Touches ONLY that row: never the other attendees, never
// the organizer, never the encrypted cards of the event (the third party's,
// which we are not allowed to rewrite). Status: 0=NEEDS-ACTION, 1=TENTATIVE,
// 2=DECLINED, 3=ACCEPTED.
func (a *Account) UpdateAttendeeStatus(ctx context.Context, calID, eventID, attendeeID string, status int) error {
	if calID == "" || eventID == "" || attendeeID == "" {
		return errors.New("proton: UpdateAttendeeStatus requires calendar, event and attendee IDs")
	}
	body := attendeeStatusRequest{
		Status:     status,
		UpdateTime: time.Now().Unix(),
		Comment:    json.RawMessage("null"),
	}
	var resp struct{ Code int }
	// Proton IDs are path-safe (same convention as getEventRow/putSync).
	path := "/calendar/v1/" + calID + "/events/" + eventID + "/attendees/" + attendeeID
	if err := a.doAuthed(ctx, http.MethodPut, path, body, &resp); err != nil {
		if isProtonNotFound(err) {
			return fmt.Errorf("proton: attendee %s on %s/%s: %w", attendeeID, calID, eventID, ErrEventNotFound)
		}
		return fmt.Errorf("proton: updating attendee %s status on %s/%s: %w", attendeeID, calID, eventID, err)
	}
	if resp.Code != codeSuccess && resp.Code != codeSuccessMulti {
		return fmt.Errorf("proton: updating attendee %s status on %s/%s: code %d", attendeeID, calID, eventID, resp.Code)
	}
	return nil
}

// eventRow is the raw event row from the GET, extended with the columns that
// papi.CalendarEvent does not map. Notifications and Color are captured as RAW
// JSON; Color is re-emitted verbatim in the update body, Notifications goes
// through notificationsPayload — the tri-state is meaningful (null = inherit
// from the calendar, [] = none, array = custom reminders) and is only degraded
// if the client actually modified the alarms.
type eventRow struct {
	papi.CalendarEvent
	Notifications json.RawMessage `json:"Notifications"`
	Color         json.RawMessage `json:"Color"`
	// RecurrenceID != 0 identifies an exception row (modified occurrence of a
	// series, separate same-UID row); 0 = master or standalone event.
	RecurrenceID int64 `json:"RecurrenceID"`
	// IsOrganizer = 1 when the account is the organizer of the event (cleartext
	// column, not mapped by go-proton-api) — re-emitted on the update of an
	// invited event so as not to degrade the column (M5b).
	IsOrganizer int `json:"IsOrganizer"`
}

// getEventRow re-fetches the raw row of an event via the captured resty.Client
// (same transport as putSync; go-proton-api does not map the side columns
// needed for the update).
func (a *Account) getEventRow(ctx context.Context, calID, eventID string) (*eventRow, error) {
	var res struct{ Event eventRow }
	if err := a.doAuthed(ctx, http.MethodGet, "/calendar/v1/"+calID+"/events/"+eventID, nil, &res); err != nil {
		if isProtonNotFound(err) {
			return nil, fmt.Errorf("proton: event %s/%s: %w", calID, eventID, ErrEventNotFound)
		}
		return nil, fmt.Errorf("proton: fetching event %s/%s for update: %w", calID, eventID, err)
	}
	if res.Event.ID == "" {
		return nil, fmt.Errorf("proton: event %s/%s: empty row in update fetch", calID, eventID)
	}
	return &res.Event, nil
}

// attendeePlan is the result of planAttendeeUpdate: what the update body must
// write when the attendee list has actually changed (M5b).
type attendeePlan struct {
	fragment     string          // desired AttendeesEventContent card ("" = no more attendees, card removed)
	rows         json.RawMessage // cleartext Attendees array (Status of the kept ones preserved by token)
	setOrganizer string          // ORGANIZER to write on the SharedSigned card (";CN=…:mailto:…"), "" = leave untouched
	delOrganizer bool            // ORGANIZER to remove (no attendee left)
	isOrganizer  int             // IsOrganizer of the body (1 as long as attendees remain)
}

// planAttendeeUpdate computes the attendee diff of an update (M5b): the tokens
// of the desired set (in.Attendees, COMPLETE state) are derived as at creation
// (SHA1(UID+canonical)) and matched against the existing card. Identical list ->
// nil (the card survives verbatim, no re-sealing). Otherwise: card rebuilt
// (kept ones verbatim, removed ones purged, added ones as fresh lines),
// cleartext array recomputed with the RSVP Status of the kept ones preserved,
// and ORGANIZER touch-up when the event gains its first attendees (property set)
// or loses the last one (removed).
func (a *Account) planAttendeeUpdate(ctx context.Context, row *eventRow, cur *Event, in EventInput, calKR *crypto.KeyRing) (*attendeePlan, error) {
	// Existing state: card tokens (identities) + Status from the cleartext array.
	existing := make(map[string]bool, len(cur.Attendees))
	for _, at := range cur.Attendees {
		existing[at.Token] = true
	}
	statusByToken := make(map[string]int, len(row.Attendees))
	for _, r := range row.Attendees {
		statusByToken[strings.ToLower(r.Token)] = int(r.Status)
	}

	// Desired set: canonicalization (basis of the token, as at creation).
	var canon map[string]string
	if len(in.Attendees) > 0 {
		emails := make([]string, len(in.Attendees))
		for i := range in.Attendees {
			emails[i] = in.Attendees[i].Email
		}
		var err error
		if canon, err = a.canonicalEmails(ctx, emails); err != nil {
			return nil, err
		}
	}
	keep := make(map[string]bool, len(in.Attendees))
	var added []AttendeeInput
	var addedTokens []string
	rows := make([]attendeeRow, 0, len(in.Attendees))
	changed := false
	for _, at := range in.Attendees {
		tok := attendeeToken(row.UID, canon[at.Email])
		status := 0
		if existing[tok] {
			keep[tok] = true
			status = statusByToken[tok] // live RSVP preserved
		} else {
			added = append(added, at)
			addedTokens = append(addedTokens, tok)
			changed = true
		}
		rows = append(rows, attendeeRow{Token: tok, Status: status, Comment: json.RawMessage("null")})
	}
	for tok := range existing {
		if !keep[tok] {
			changed = true // attendee removed
		}
	}
	if !changed {
		return nil, nil // identical list: nothing to rewrite
	}

	// Original card decrypted — the lines of the kept ones survive verbatim.
	oldCard := ""
	if len(row.AttendeesEvents) > 0 {
		if len(row.AttendeesEvents) > 1 {
			// Outside the known model (web client = a single card): blind
			// re-sealing would lose identities — honest refusal.
			return nil, fmt.Errorf("event has %d attendees cards, expected 1: %w", len(row.AttendeesEvents), ErrEventDegraded)
		}
		plain, err := cardPlaintext(row.AttendeesEvents[0], row.SharedKeyPacket, calKR)
		if err != nil {
			return nil, fmt.Errorf("decrypting attendees card for diff (%v): %w", err, ErrEventDegraded)
		}
		oldCard = plain
	}

	p := &attendeePlan{
		fragment: rebuildAttendeesFragment(oldCard, row.UID, keep, added, addedTokens),
	}
	rowsJSON, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("encoding attendee rows: %w", err)
	}
	if len(rows) == 0 {
		rowsJSON = json.RawMessage("[]")
	}
	p.rows = rowsJSON
	if len(in.Attendees) > 0 {
		p.isOrganizer = 1
		if cur.Organizer == "" && in.Organizer != "" {
			// First attendees of an event that was bare until now: ORGANIZER set
			// on the SharedSigned card (never any X-PM-TOKEN on it).
			p.setOrganizer = strings.TrimPrefix(organizerProp(in.OrganizerCN, in.Organizer), "ORGANIZER")
		}
	} else if cur.Organizer != "" {
		// Last attendee removed: the event becomes bare again.
		p.delOrganizer = true
	}
	return p, nil
}

// buildUpdateBody re-seals the event by patching the decrypted cards in place:
// only the modeled AND actually-modified properties move, everything else is
// kept verbatim. Reuses the event's session keys; the body carries no key
// packet. A non-nil plan (M5b) rewrites the attendees card / the cleartext
// array / ORGANIZER and bumps SEQUENCE.
func buildUpdateBody(row *eventRow, cur *Event, in EventInput, calKR, signerKR *crypto.KeyRing, plan *attendeePlan) (*eventBody, error) {
	// ORIGINAL session keys. Some events (created by the web client) have no
	// encrypted calendar card, hence no CalendarKeyPacket.
	var sharedSK, calSK *crypto.SessionKey
	var err error
	if row.SharedKeyPacket != "" {
		sharedSK, err = sessionKeyFromPacket(row.SharedKeyPacket, calKR)
		if err != nil {
			// Unrecoverable session key = re-seal impossible without loss ->
			// honest refusal (403), not a server error.
			return nil, fmt.Errorf("extracting shared session key (%v): %w", err, ErrEventDegraded)
		}
	}
	if row.CalendarKeyPacket != "" {
		calSK, err = sessionKeyFromPacket(row.CalendarKeyPacket, calKR)
		if err != nil {
			return nil, fmt.Errorf("extracting calendar session key (%v): %w", err, ErrEventDegraded)
		}
	}

	signedPatch, encPatch := diffPatches(cur, in)
	calPatch := diffCalendarPatch(cur, in)
	if plan != nil {
		// Attendee diff = structural change of the invitation: SEQUENCE bumped
		// even if the bounds did not move (RFC 5546 — the REQUEST/CANCEL emitted
		// afterwards must exceed the SEQUENCE already known to the attendees).
		// Never two bumps: diffPatches may have already set it.
		if _, ok := signedPatch.set["SEQUENCE"]; !ok {
			signedPatch.set["SEQUENCE"] = ":" + strconv.Itoa(cur.Sequence+1)
		}
		if plan.setOrganizer != "" {
			signedPatch.set["ORGANIZER"] = plan.setOrganizer
		}
		if plan.delOrganizer {
			signedPatch.del["ORGANIZER"] = true
		}
	}

	sharedParts, err := resealParts(row.SharedEvents, row.SharedKeyPacket, sharedSK, calKR, signerKR, signedPatch, encPatch)
	if err != nil {
		return nil, fmt.Errorf("resealing shared card: %w", err)
	}
	calParts, err := resealParts(row.CalendarEvents, row.CalendarKeyPacket, calSK, calKR, signerKR, calPatch, cardPatch{})
	if err != nil {
		return nil, fmt.Errorf("resealing calendar card: %w", err)
	}
	// STATUS/TRANSP changed but NO cleartext/signed calendar card to patch
	// (events created by some clients): synthesize one — a pure signed card, no
	// session key needed.
	if !calPatch.empty() && !hasClearOrSignedPart(row.CalendarEvents) {
		frag := icalWrap([]string{
			"UID:" + row.UID,
			"DTSTAMP:" + icalFormatUTC(time.Now().UTC()),
			"STATUS:" + statusOrDefault(in.Status),
			"TRANSP:" + transpOrDefault(in.Transp),
		})
		sig, serr := signDetached(frag, signerKR)
		if serr != nil {
			return nil, fmt.Errorf("signing synthesized calendar card: %w", serr)
		}
		calParts = append(calParts, eventPart{Type: cardSigned, Data: frag, Signature: sig})
	}
	// Attendees card: encrypted with the SHARED session key. Without a plan,
	// never patched (identities outside the model), kept verbatim re-signed;
	// with a plan (M5b), the REBUILT card is sealed in its place (or removed
	// when no attendee remains).
	var attParts []eventPart
	if plan != nil {
		attParts = []eventPart{}
		if plan.fragment != "" {
			if sharedSK == nil {
				return nil, fmt.Errorf("attendees card without a shared session key: %w", ErrEventDegraded)
			}
			data, sig, aerr := encryptWithKeyAndSign(plan.fragment, sharedSK, signerKR)
			if aerr != nil {
				return nil, fmt.Errorf("sealing rebuilt attendees card: %w", aerr)
			}
			attParts = []eventPart{{Type: cardEncryptedAndSigned, Data: data, Signature: sig}}
		}
	} else {
		attParts, err = resealParts(row.AttendeesEvents, row.SharedKeyPacket, sharedSK, calKR, signerKR, cardPatch{}, cardPatch{})
		if err != nil {
			return nil, fmt.Errorf("resealing attendees card: %w", err)
		}
		if attParts == nil {
			attParts = []eventPart{}
		}
	}

	attendees := json.RawMessage(nil)
	isOrganizer := 0
	if plan != nil {
		attendees = plan.rows
		isOrganizer = plan.isOrganizer
	} else {
		if attendees, err = marshalAttendeeRows(row.Attendees); err != nil {
			return nil, fmt.Errorf("encoding attendees: %w", err)
		}
		if len(row.Attendees) > 0 {
			// Invited event updated without touching the list: the row's
			// cleartext IsOrganizer column is re-emitted as is (never degraded
			// by a cosmetic update). Bare events keep the historical body (field
			// absent, omitempty).
			isOrganizer = row.IsOrganizer
		}
	}

	return &eventBody{
		Permissions:           1,
		IsOrganizer:           isOrganizer,
		SharedEventContent:    sharedParts,
		CalendarEventContent:  calParts,
		AttendeesEventContent: attParts,
		Attendees:             attendees,
		Notifications:         notificationsPayload(row.Notifications, in.Notifications),
		Color:                 rawOrNull(row.Color),
	}, nil
}

// hasClearOrSignedPart spots a cleartext/signed card (patchable in-place) in a
// list of cards.
func hasClearOrSignedPart(parts []papi.CalendarEventPart) bool {
	for _, part := range parts {
		if part.Type&papi.CalendarEventTypeEncrypted == 0 {
			return true
		}
	}
	return false
}

// diffCalendarPatch computes the touch-up of the signed CalendarEvents card
// (STATUS / TRANSP). The comparison is done with defaults applied: a card
// without STATUS equals CONFIRMED — the property is only rewritten if the
// EFFECTIVE value changes (no SEQUENCE bump: non-structural change).
func diffCalendarPatch(cur *Event, in EventInput) cardPatch {
	p := cardPatch{set: map[string]string{}, del: map[string]bool{}}
	if want := statusOrDefault(in.Status); want != statusOrDefault(cur.Status) {
		p.set["STATUS"] = ":" + want
	}
	if want := transpOrDefault(in.Transp); want != transpOrDefault(cur.Transp) {
		p.set["TRANSP"] = ":" + want
	}
	return p
}

// patchTouchesTimesOrRRule recognizes a HEAVY structural change (bounds or
// recurrence rule) — the one that invalidates the exception rows. EXDATE alone
// (del+add without DTSTART/RRULE) is not part of it.
func patchTouchesTimesOrRRule(p cardPatch) bool {
	_, dtstart := p.set["DTSTART"]
	_, dtend := p.set["DTEND"]
	_, rrule := p.set["RRULE"]
	return dtstart || dtend || rrule || p.del["RRULE"]
}

// eventRowsPage is a page of GET /calendar/v1/{calID}/events (More = 1 if a
// page follows).
type eventRowsPage struct {
	Events []eventRow
	More   int
}

// listEventRowsByUID returns ALL rows of a UID (master + exceptions, server
// filter, paginated on the More cursor) — a multi-row series must be seen in
// full to route an update or delete without orphans.
func (a *Account) listEventRowsByUID(ctx context.Context, calID, uid string) ([]eventRow, error) {
	var all []eventRow
	for page := 0; ; page++ {
		path := "/calendar/v1/" + calID + "/events?UID=" + url.QueryEscape(uid) +
			"&Page=" + strconv.Itoa(page) + "&PageSize=" + strconv.Itoa(eventsPageSize)
		var res eventRowsPage
		if err := a.doAuthed(ctx, http.MethodGet, path, nil, &res); err != nil {
			return nil, fmt.Errorf("proton: listing rows by UID on calendar %s: %w", calID, err)
		}
		all = append(all, res.Events...)
		if res.More != 1 {
			return all, nil
		}
	}
}

// sessionKeyFromPacket decrypts a key packet (PKESK b64) with the calendar key
// to recover the event's original session key.
func sessionKeyFromPacket(keyPacketB64 string, calKR *crypto.KeyRing) (*crypto.SessionKey, error) {
	kp, err := base64.StdEncoding.DecodeString(keyPacketB64)
	if err != nil {
		return nil, err
	}
	return calKR.DecryptSessionKey(kp)
}

// resealParts re-signs the cleartext/signed cards and re-decrypts + patches +
// re-encrypts the encrypted cards (with the ORIGINAL session key), applying
// signedPatch/encPatch respectively. Card order preserved; a card of an unknown
// type passes verbatim.
func resealParts(parts []papi.CalendarEventPart, keyPacketB64 string, sk *crypto.SessionKey, calKR, signerKR *crypto.KeyRing, signedPatch, encPatch cardPatch) ([]eventPart, error) {
	out := make([]eventPart, 0, len(parts))
	for _, part := range parts {
		switch {
		case part.Type&papi.CalendarEventTypeEncrypted == 0:
			// Cleartext or signed: patch then re-signature (a cleartext card
			// becomes signed — the update is now of our own hand).
			plain := patchCard(part.Data, signedPatch)
			sig, err := signDetached(plain, signerKR)
			if err != nil {
				return nil, fmt.Errorf("re-signing card: %w", err)
			}
			out = append(out, eventPart{Type: cardSigned, Data: plain, Signature: sig})
		default:
			// Encrypted: without a recoverable session key, re-sealing without
			// loss is impossible — honest refusal rather than a destroyed card.
			if sk == nil {
				return nil, fmt.Errorf("encrypted card without a recoverable session key: %w", ErrEventDegraded)
			}
			plain, err := cardPlaintext(part, keyPacketB64, calKR)
			if err != nil {
				return nil, fmt.Errorf("decrypting card for reseal (%v): %w", err, ErrEventDegraded)
			}
			patched := patchCard(plain, encPatch)
			dataPacket, err := sk.Encrypt(crypto.NewPlainMessage([]byte(patched)))
			if err != nil {
				return nil, fmt.Errorf("re-encrypting card: %w", err)
			}
			sig, err := signDetached(patched, signerKR)
			if err != nil {
				return nil, fmt.Errorf("signing re-encrypted card: %w", err)
			}
			out = append(out, eventPart{
				Type:      cardEncryptedAndSigned,
				Data:      base64.StdEncoding.EncodeToString(dataPacket),
				Signature: sig,
			})
		}
	}
	return out, nil
}

// ---- Touch-up computation ----

// cardPatch describes property-by-property touch-ups of a decrypted card — any
// line not listed survives verbatim (THE anti-loss guarantee).
type cardPatch struct {
	// set replaces (in place) or inserts a single-valued property: key = NAME in
	// uppercase, value = rest of the line (":value" or ";PARAM=..:value").
	set map[string]string
	// del removes all lines of a property. Applied before set/add.
	del map[string]bool
	// add adds complete logical lines (e.g. multiple EXDATEs), inserted before
	// END:VEVENT; exact duplicates are ignored.
	add []string
}

func (p cardPatch) empty() bool {
	return len(p.set) == 0 && len(p.del) == 0 && len(p.add) == 0
}

// diffPatches computes the MINIMAL touch-ups bringing the current event toward
// the input: an unchanged field does not move (its original form — TZID,
// folding — stays intact). SEQUENCE is incremented on any structural
// modification (RFC 5546).
//
// FORM ANTI-REGRESSION GUARD (2026-07-16): a client may send back the "Z" form
// (in.TZID empty) for an event that LIVES in TZID inside Proton — this is
// exactly what Apple did when we served bare UTC, and writing that bare Z into
// the card freezes the wall-clock time across DST transitions (the
// recurring-master corruption case). Rules:
//   - unchanged instant -> no rewrite, the in-place patch already preserves the
//     original form;
//   - changed instant with in.TZID empty -> the ORIGINAL zone (cur.TZ / cur.EndTZ)
//     is reused for the written form — never a bare Z reintroduced;
//   - an explicit client TZID always stays master.
//
// EXDATE follows the same zone as the written DTSTART (RFC 5545 §3.8.5.1).
func diffPatches(cur *Event, in EventInput) (signed, enc cardPatch) {
	signed = cardPatch{set: map[string]string{}, del: map[string]bool{}}
	enc = cardPatch{set: map[string]string{}, del: map[string]bool{}}

	// FORM zones of the written dates — the instant itself does not depend on them.
	startTZ := writeTZ(in.TZID, cur.TZ)
	endTZ := in.EndTZID
	if endTZ == "" {
		endTZ = writeTZ(in.TZID, cur.EndTZ)
	}
	if endTZ == "" {
		endTZ = startTZ
	}

	structural := false

	// Bounds: rewritten only if the instant or the all-day form changes.
	if !in.Start.Equal(cur.Start) || !in.End.Equal(cur.End) || in.AllDay != cur.AllDay {
		structural = true
		signed.set["DTSTART"] = strings.TrimPrefix(icalDTProp("DTSTART", in.Start, startTZ, in.AllDay), "DTSTART")
		signed.set["DTEND"] = strings.TrimPrefix(icalDTProp("DTEND", in.End, endTZ, in.AllDay), "DTEND")
	}

	// Recurrence: removing the RRULE = removing the orphan EXDATEs.
	exdatesHandled := false
	if in.RRule != cur.RRule {
		structural = true
		if in.RRule == "" {
			signed.del["RRULE"] = true
			signed.del["EXDATE"] = true
			exdatesHandled = true
		} else {
			signed.set["RRULE"] = ":" + in.RRule
		}
	}

	// EXDATE: the input is the COMPLETE desired state (Apple sends back the whole
	// list) — replacement of the entire set when it differs, by instant.
	if !exdatesHandled && in.RRule != "" && !sameInstants(in.ExDates, cur.ExDates) {
		structural = true
		signed.del["EXDATE"] = true
		for _, ex := range in.ExDates {
			signed.add = append(signed.add, icalDTProp("EXDATE", ex, startTZ, in.AllDay))
		}
	}

	if structural {
		signed.set["SEQUENCE"] = ":" + strconv.Itoa(cur.Sequence+1)
	}

	diffText(&enc, "SUMMARY", cur.Title, in.Title)
	diffText(&enc, "DESCRIPTION", cur.Description, in.Description)
	diffText(&enc, "LOCATION", cur.Location, in.Location)
	return signed, enc
}

// writeTZ picks the FORM zone of a written date: the client's if provided,
// otherwise the ORIGINAL zone of the Proton event ("" or UTC -> Z form). This is
// the "zone" half of the diffPatches anti-regression guard.
func writeTZ(inTZ, curTZ string) string {
	if inTZ != "" {
		return inTZ
	}
	if curTZ != "" && curTZ != "UTC" {
		return curTZ
	}
	return ""
}

// diffText records the edit of a TEXT property: identical = no-op, empty =
// deletion, otherwise escaped replacement.
func diffText(p *cardPatch, name, cur, want string) {
	if want == cur {
		return
	}
	if want == "" {
		p.del[name] = true
		return
	}
	p.set[name] = ":" + icalEscapeText(want)
}

// sameInstants compares two sets of instants independently of order.
func sameInstants(a, b []time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]time.Time, len(a))
	bs := make([]time.Time, len(b))
	copy(as, a)
	copy(bs, b)
	sort.Slice(as, func(i, j int) bool { return as[i].Before(as[j]) })
	sort.Slice(bs, func(i, j int) bool { return bs[i].Before(bs[j]) })
	for i := range as {
		if !as[i].Equal(bs[i]) {
			return false
		}
	}
	return true
}

// patchCard applies a cardPatch to the unfolded text of a card and re-renders
// the wrapper (CRLF, folded lines, no trailing CRLF — same form as
// buildFragments). Only the top-level properties of the VEVENT are touched:
// nested components (VALARM…) and siblings (VTIMEZONE…) pass verbatim, in place.
// An empty patch returns the card unchanged byte for byte.
func patchCard(card string, patch cardPatch) string {
	if patch.empty() {
		return card
	}
	lines := unfoldLines(card)

	out := make([]string, 0, len(lines)+len(patch.set)+len(patch.add))
	seen := make(map[string]bool, len(patch.set))
	inVEvent := false
	nested := 0

	// insertNew adds the set properties never encountered (stable order) then
	// the add lines (without exact duplicate), just before END:VEVENT.
	insertNew := func(out []string) []string {
		names := make([]string, 0, len(patch.set))
		for n := range patch.set {
			if !seen[n] && !patch.del[n] {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, n+patch.set[n])
		}
		for _, l := range patch.add {
			dup := false
			for _, e := range out {
				if e == l {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, l)
			}
		}
		return out
	}

	for _, line := range lines {
		name, _, value, ok := splitContentLineParams(line)
		if ok && name == "BEGIN" {
			comp := strings.ToUpper(strings.TrimSpace(value))
			if inVEvent {
				nested++
			} else if comp == "VEVENT" {
				inVEvent = true
				nested = 0
			}
			out = append(out, line)
			continue
		}
		if ok && name == "END" {
			if inVEvent {
				if nested > 0 {
					nested--
				} else {
					out = insertNew(out)
					inVEvent = false
				}
			}
			out = append(out, line)
			continue
		}
		if !ok || !inVEvent || nested > 0 {
			out = append(out, line)
			continue
		}
		if patch.del[name] {
			continue
		}
		if repl, has := patch.set[name]; has {
			if !seen[name] {
				out = append(out, name+repl)
				seen[name] = true
			}
			continue
		}
		seen[name] = true
		out = append(out, line)
	}

	folded := make([]string, 0, len(out))
	for _, l := range out {
		folded = append(folded, icalFoldLine(l))
	}
	return strings.Join(folded, "\r\n")
}

// ---- Re-emitted cleartext columns ----

// attendeeRow is an entry of the cleartext Attendees array of an update body:
// opaque token + live RSVP status. Comment is not modeled (null).
type attendeeRow struct {
	Token   string          `json:"Token"`
	Status  int             `json:"Status"`
	Comment json.RawMessage `json:"Comment"`
}

// marshalAttendeeRows re-emits the existing cleartext attendee lines so that an
// update does not destroy the RSVPs; no attendee = empty array.
func marshalAttendeeRows(rows []papi.CalendarAttendee) (json.RawMessage, error) {
	if len(rows) == 0 {
		return json.RawMessage("[]"), nil
	}
	out := make([]attendeeRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, attendeeRow{Token: r.Token, Status: int(r.Status), Comment: json.RawMessage("null")})
	}
	return json.Marshal(out)
}

// rawOrNull returns the captured raw JSON, or null if it was absent from the
// response (absence = inherit, same semantics as null on the API side).
func rawOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}
