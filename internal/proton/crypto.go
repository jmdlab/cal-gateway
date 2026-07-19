package proton

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// This file implements the READ half of the Proton Calendar crypto model,
// on the official gopenpgp + go-proton-api primitives.
//
// Model (concept studied in proton-cal and the web client's code):
//
//	address key (unlocked at login via the salted key passphrase)
//	  └─ decrypts the calendar's "member passphrase" (armored PGP message)
//	       └─ unlocks the calendar's private keys (calendar keyring)
//	            └─ decrypts the event's session key (PKESK key packet, b64)
//	                 └─ decrypts each encrypted card (SEIPD data packet, b64)
//
// An event carries its iCalendar fragments as "cards": SharedEvents
// (DTSTART/DTEND/SUMMARY… signed and/or encrypted, key packet = SharedKeyPacket),
// CalendarEvents (STATUS/COMMENT on the calendar side, key packet = CalendarKeyPacket),
// AttendeesEvents and PersonalEvents (not consumed in M1: no invitees nor
// notifications in the read-only mirror).
//
// LENIENT read, like the Proton clients: no signature verification
// (other members' cards are not verifiable with our keys) and an unreadable
// card does not invalidate the event — it sets Event.DecryptFailed.
//
// TODO M2 (write half): "4 cards" encryption — per-event session key
// (reused on update: the server keeps the original key packet),
// EncryptSessionKey to the calendar key, detached address-key signatures.

// calendarKeyRing returns the unlocked calendar keyring, with cache.
// Chain: members -> our memberID, passphrase -> decrypted by an
// address key, keys -> unlocked with the passphrase.
func (a *Account) calendarKeyRing(ctx context.Context, calendarID string) (*crypto.KeyRing, error) {
	a.mu.Lock()
	kr, ok := a.calKRs[calendarID]
	a.mu.Unlock()
	if ok {
		return kr, nil
	}

	members, err := a.client.GetCalendarMembers(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("proton: fetching members for calendar %s: %w", calendarID, err)
	}
	memberID := a.resolveMemberID(members)

	pass, err := a.client.GetCalendarPassphrase(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("proton: fetching passphrase for calendar %s: %w", calendarID, err)
	}
	passphrase, err := a.decryptPassphrase(calendarID, memberID, pass)
	if err != nil {
		return nil, err
	}

	keys, err := a.client.GetCalendarKeys(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("proton: fetching keys for calendar %s: %w", calendarID, err)
	}
	// Official primitive: CalendarKeys.Unlock skips the keys that do not
	// open and assembles the keyring.
	kr, err = keys.Unlock(passphrase)
	if err != nil {
		return nil, fmt.Errorf("proton: unlocking keys for calendar %s: %w", calendarID, err)
	}
	if kr.CountDecryptionEntities() == 0 {
		return nil, fmt.Errorf("proton: no calendar key could be unlocked for calendar %s", calendarID)
	}

	a.mu.Lock()
	a.calKRs[calendarID] = kr
	a.mu.Unlock()
	return kr, nil
}

// resolveMemberID finds OUR member entry by case-insensitive email
// matching (a shared calendar also lists the other members), with a
// fallback to the first member.
func (a *Account) resolveMemberID(members []papi.CalendarMember) string {
	ours := make(map[string]bool, len(a.addresses))
	for _, addr := range a.addresses {
		ours[strings.ToLower(addr.Email)] = true
	}
	for _, m := range members {
		if ours[strings.ToLower(m.Email)] {
			return m.ID
		}
	}
	if len(members) > 0 {
		return members[0].ID
	}
	return ""
}

// decryptPassphrase decrypts the member-passphrase entry of our member
// (otherwise the first one) by trying each address keyring in API order —
// any of our addresses can be the recipient.
//
// Deliberately lenient: the detached signature is NOT verified (the
// official CalendarPassphrase.Decrypt helper requires it, which breaks on
// passphrases signed by another member's key) — same tolerant-read choice
// as the other third-party clients.
func (a *Account) decryptPassphrase(calendarID, memberID string, pass papi.CalendarPassphrase) ([]byte, error) {
	var entry *papi.MemberPassphrase
	for i := range pass.MemberPassphrases {
		if pass.MemberPassphrases[i].MemberID == memberID {
			entry = &pass.MemberPassphrases[i]
			break
		}
	}
	if entry == nil && len(pass.MemberPassphrases) > 0 {
		entry = &pass.MemberPassphrases[0]
	}
	if entry == nil {
		return nil, fmt.Errorf("proton: no member passphrase for calendar %s", calendarID)
	}

	msg, err := crypto.NewPGPMessageFromArmored(entry.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("proton: parsing passphrase for calendar %s: %w", calendarID, err)
	}
	for _, addr := range a.addresses {
		kr, ok := a.addrKRs[addr.ID]
		if !ok {
			continue
		}
		// verifyKey nil + verifyTime 0: decryption without verification.
		plain, err := kr.Decrypt(msg, nil, 0)
		if err != nil {
			continue
		}
		return plain.GetBinary(), nil
	}
	return nil, fmt.Errorf("proton: no address key could decrypt the passphrase for calendar %s", calendarID)
}

// decryptEvent turns an API row into a decrypted Event. Never an error:
// the row's cleartext fields (UID, bounds, timezone, all-day) are always
// served, unreadable cards set DecryptFailed.
func (a *Account) decryptEvent(raw papi.CalendarEvent, addrKeyPacket string, calKR *crypto.KeyRing) Event {
	ev := Event{
		ID:         raw.ID,
		UID:        raw.UID,
		CalendarID: raw.CalendarID,
		Start:      time.Unix(raw.StartTime, 0).UTC(),
		End:        time.Unix(raw.EndTime, 0).UTC(),
		TZ:         raw.StartTimezone,
		EndTZ:      raw.EndTimezone,
		AllDay:     bool(raw.FullDay),
		LastEdit:   time.Unix(raw.LastEditTime, 0).UTC(),
	}
	// Shared cards (SUMMARY/DESCRIPTION/LOCATION/RRULE/ORGANIZER…) then
	// calendar cards (STATUS/TRANSP), then the attendees card (M5a) —
	// encrypted with the SAME session key as the shared cards, so the
	// key packet is SharedKeyPacket.
	// Prefer AddressKeyPacket over SharedKeyPacket for the shared+attendees cards
	// (mirrors WebClients deserialize.readSessionKeys): a Proton-to-Proton invite
	// wraps the shared session key to our address key, not the calendar key.
	sharedKP := raw.SharedKeyPacket
	if addrKeyPacket != "" {
		sharedKP = addrKeyPacket
	}
	a.mergeCards(&ev, raw.SharedEvents, sharedKP, calKR)
	a.mergeCards(&ev, raw.CalendarEvents, raw.CalendarKeyPacket, calKR)
	a.mergeCards(&ev, raw.AttendeesEvents, sharedKP, calKR)
	// RSVP status: CLEARTEXT column of the row (Attendees array), joined
	// to the decrypted identities by Token (0=NEEDS-ACTION, 1=TENTATIVE,
	// 2=DECLINED, 3=ACCEPTED). A token without a cleartext entry stays 0.
	if len(ev.Attendees) > 0 && len(raw.Attendees) > 0 {
		type attMeta struct {
			status int
			id     string // ID of the attendee row (PARTSTAT endpoint M6b)
		}
		byToken := make(map[string]attMeta, len(raw.Attendees))
		for _, r := range raw.Attendees {
			byToken[strings.ToLower(r.Token)] = attMeta{status: int(r.Status), id: r.ID}
		}
		for i := range ev.Attendees {
			if m, ok := byToken[ev.Attendees[i].Token]; ok {
				ev.Attendees[i].Status = m.status
				ev.Attendees[i].ID = m.id
			}
		}
	}
	return ev
}

// mergeCards decrypts/parses a list of cards and merges their properties
// into the event. keyPacketB64 is the key packet shared by these cards.
func (a *Account) mergeCards(ev *Event, parts []papi.CalendarEventPart, keyPacketB64 string, calKR *crypto.KeyRing) {
	for _, part := range parts {
		data, err := a.cardPlaintext(part, keyPacketB64, calKR)
		if err != nil {
			ev.DecryptFailed = true
			continue
		}
		if data == "" {
			continue
		}
		frag, err := parseFragment(data)
		if err != nil {
			ev.DecryptFailed = true
			continue
		}
		if frag.summary != nil {
			ev.Title = *frag.summary
		}
		if frag.description != nil {
			ev.Description = *frag.description
		}
		if frag.location != nil {
			ev.Location = *frag.location
		}
		if frag.rrule != "" {
			ev.RRule = frag.rrule
		}
		if len(frag.exdates) > 0 {
			ev.ExDates = appendExDates(ev.ExDates, frag.exdates)
		}
		if frag.sequence != nil {
			ev.Sequence = *frag.sequence
		}
		if frag.status != nil {
			ev.Status = *frag.status
		}
		if frag.transp != nil {
			ev.Transp = *frag.transp
		}
		if frag.organizer != nil {
			ev.Organizer = *frag.organizer
		}
		if len(frag.attendees) > 0 {
			ev.Attendees = appendAttendees(ev.Attendees, frag.attendees)
		}
	}
}

// appendAttendees merges invitees by deduplicating on email (case-
// insensitive) — multiple cards should not repeat the property, but
// the read stays lenient.
func appendAttendees(dst, src []Attendee) []Attendee {
	for _, at := range src {
		dup := false
		for _, d := range dst {
			if strings.EqualFold(d.Email, at.Email) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, at)
		}
	}
	return dst
}

// appendExDates merges EXDATE instants by deduplicating on instant
// (multiple cards may repeat the property).
func appendExDates(dst, src []time.Time) []time.Time {
	for _, t := range src {
		dup := false
		for _, d := range dst {
			if d.Equal(t) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, t)
		}
	}
	return dst
}

// cardPlaintext returns the plaintext of a card: verbatim for the
// clear/signed types, decrypted for the encrypted types.
//
// Note: go-proton-api provides CalendarEventPart.Decode, but its
// value receiver loses the decrypted data and it requires signature
// verification; so we decrypt ourselves with gopenpgp.
func (a *Account) cardPlaintext(part papi.CalendarEventPart, keyPacketB64 string, calKR *crypto.KeyRing) (string, error) {
	if part.Type&papi.CalendarEventTypeEncrypted == 0 {
		// Clear or signed: the data is already the iCalendar fragment.
		return part.Data, nil
	}

	dataPacket, err := base64.StdEncoding.DecodeString(part.Data)
	if err != nil {
		// Without a key packet, the data is a complete armored PGP message.
		if keyPacketB64 == "" {
			msg, perr := crypto.NewPGPMessageFromArmored(part.Data)
			if perr != nil {
				return "", fmt.Errorf("proton: parsing armored card: %w", perr)
			}
			return a.decryptCardMessage(msg, calKR)
		}
		return "", fmt.Errorf("proton: decoding data packet: %w", err)
	}

	var msg *crypto.PGPMessage
	if keyPacketB64 == "" {
		msg = crypto.NewPGPMessage(dataPacket)
	} else {
		keyPacket, err := base64.StdEncoding.DecodeString(keyPacketB64)
		if err != nil {
			return "", fmt.Errorf("proton: decoding key packet: %w", err)
		}
		// key packet (PKESK, session key encrypted to the calendar OR address
		// key) + data packet (SEIPD) = complete PGP message.
		msg = crypto.NewPGPSplitMessage(keyPacket, dataPacket).GetPGPMessage()
	}
	return a.decryptCardMessage(msg, calKR)
}

// decryptCardMessage decrypts an event-card PGP message trying the calendar
// keyring first, then EACH address keyring (same lenient, verify-free, try-all
// approach as decryptPassphrase). The fallback is what unlocks a Proton-to-Proton
// invited event whose shared session key is wrapped to an address key rather
// than the calendar key — without it the SUMMARY card fails and the event is
// served untitled.
func (a *Account) decryptCardMessage(msg *crypto.PGPMessage, calKR *crypto.KeyRing) (string, error) {
	if calKR != nil {
		if plain, err := calKR.Decrypt(msg, nil, 0); err == nil {
			// GetBinary and not GetString: the CRLF->LF normalization would corrupt
			// the iCalendar fragment (line endings are part of the format).
			return string(plain.GetBinary()), nil
		}
	}
	for _, addr := range a.addresses {
		kr, ok := a.addrKRs[addr.ID]
		if !ok {
			continue
		}
		if plain, err := kr.Decrypt(msg, nil, 0); err == nil {
			return string(plain.GetBinary()), nil
		}
	}
	if calKR == nil {
		return "", errors.New("proton: no key ring could decrypt the card")
	}
	return "", errors.New("proton: decrypting event card: no calendar or address key matched")
}
