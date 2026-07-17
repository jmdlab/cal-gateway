package proton

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// This test exercises the COMPLETE read-decryption chain, offline,
// with keys generated on the fly:
//
//	address key -> member passphrase -> calendar key -> session key -> card
//
// The fixture is built in the encryption direction (like the Proton
// clients on write) and the Account must recover the plaintext.

const (
	testAddrID  = "addr1"
	testMember  = "member1"
	testCalID   = "cal1"
	testEventID = "event1"
	testEmail   = "user@example.test"
)

type fixture struct {
	client  *fakeClient
	account *Account
}

// newFixture builds a complete encrypted calendar + the Account to read it.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	// 1. Address key (unlocked, as after proton.Unlock at boot).
	addrKey, err := crypto.GenerateKey("user", testEmail, "x25519", 0)
	if err != nil {
		t.Fatalf("generating address key: %v", err)
	}
	addrKR, err := crypto.NewKeyRing(addrKey)
	if err != nil {
		t.Fatalf("address keyring: %v", err)
	}

	// 2. Calendar key, locked by a random passphrase.
	passphrase := []byte("frobnicate-the-calendar-passphrase")
	calKey, err := crypto.GenerateKey("calendar", "calendar@proton.local", "x25519", 0)
	if err != nil {
		t.Fatalf("generating calendar key: %v", err)
	}
	lockedCalKey, err := calKey.Lock(passphrase)
	if err != nil {
		t.Fatalf("locking calendar key: %v", err)
	}
	lockedArmored, err := lockedCalKey.Armor()
	if err != nil {
		t.Fatalf("armoring calendar key: %v", err)
	}

	// 3. Member passphrase: the calendar's passphrase encrypted to the
	//    address key (armored PGP message).
	encPass, err := addrKR.Encrypt(crypto.NewPlainMessage(passphrase), nil)
	if err != nil {
		t.Fatalf("encrypting passphrase: %v", err)
	}
	armoredPass, err := encPass.GetArmored()
	if err != nil {
		t.Fatalf("armoring passphrase: %v", err)
	}

	// 4. Event cards: session key encrypted to the calendar key
	//    (key packet) + fragments encrypted with the session key (data packets).
	calKR, err := crypto.NewKeyRing(calKey)
	if err != nil {
		t.Fatalf("calendar keyring: %v", err)
	}
	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatalf("session key: %v", err)
	}
	keyPacket, err := calKR.EncryptSessionKey(sk)
	if err != nil {
		t.Fatalf("key packet: %v", err)
	}

	encryptedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-1@proton.me\r\n" +
		"SUMMARY:Team lunch\\, The Counter\r\n" +
		"LOCATION:9 Market Square\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	dataPacket, err := sk.Encrypt(crypto.NewPlainMessage([]byte(encryptedCard)))
	if err != nil {
		t.Fatalf("data packet: %v", err)
	}

	// Signed (unencrypted) card carrying the RRULE, like the shared-signed ones.
	signedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-1@proton.me\r\n" +
		"RRULE:FREQ=WEEKLY;COUNT=10\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	event := papi.CalendarEvent{
		ID:              testEventID,
		UID:             "uid-1@proton.me",
		CalendarID:      testCalID,
		StartTime:       time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC).Unix(),
		EndTime:         time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC).Unix(),
		StartTimezone:   "Europe/Paris",
		FullDay:         false,
		LastEditTime:    1750000000,
		SharedKeyPacket: base64.StdEncoding.EncodeToString(keyPacket),
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: signedCard},
			{
				Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned,
				Data: base64.StdEncoding.EncodeToString(dataPacket),
			},
		},
	}

	client := &fakeClient{
		calendars: []papi.Calendar{{
			ID:    testCalID,
			Name:  "Personal",
			Color: "#663399",
			Flags: papi.CalendarFlagActive,
		}},
		members: []papi.CalendarMember{{ID: testMember, Email: testEmail, CalendarID: testCalID}},
		passphrase: papi.CalendarPassphrase{
			MemberPassphrases: []papi.MemberPassphrase{{MemberID: testMember, Passphrase: armoredPass}},
		},
		keys:   papi.CalendarKeys{{ID: "key1", CalendarID: testCalID, PrivateKey: lockedArmored}},
		events: []papi.CalendarEvent{event},
	}

	addresses := []papi.Address{{ID: testAddrID, Email: testEmail}}
	account := NewAccount(client, addresses, map[string]*crypto.KeyRing{testAddrID: addrKR})
	return &fixture{client: client, account: account}
}

// fakeClient simulates the go-proton-api subset consumed by Account.
type fakeClient struct {
	calendars  []papi.Calendar
	members    []papi.CalendarMember
	passphrase papi.CalendarPassphrase
	keys       papi.CalendarKeys
	events     []papi.CalendarEvent

	eventQueries int // instrumentation: number of GetCalendarEvents calls
}

func (f *fakeClient) GetCalendars(ctx context.Context) ([]papi.Calendar, error) {
	return f.calendars, nil
}

func (f *fakeClient) GetCalendarKeys(ctx context.Context, calendarID string) (papi.CalendarKeys, error) {
	return f.keys, nil
}

func (f *fakeClient) GetCalendarMembers(ctx context.Context, calendarID string) ([]papi.CalendarMember, error) {
	return f.members, nil
}

func (f *fakeClient) GetCalendarPassphrase(ctx context.Context, calendarID string) (papi.CalendarPassphrase, error) {
	return f.passphrase, nil
}

func (f *fakeClient) GetCalendarEvents(ctx context.Context, calendarID string, page, pageSize int, filter url.Values) ([]papi.CalendarEvent, error) {
	f.eventQueries++
	// The real server partitions by Type; the fake returns everything on
	// Type 0 page 0 and nothing elsewhere — the deduplication absorbs the rest.
	if filter.Get("Type") == "0" && page == 0 {
		return f.events, nil
	}
	return nil, nil
}

func (f *fakeClient) GetCalendarEvent(ctx context.Context, calendarID, eventID string) (papi.CalendarEvent, error) {
	for _, ev := range f.events {
		if ev.ID == eventID {
			return ev, nil
		}
	}
	// Same shape as the real server for a deleted event: APIError
	// Code 2501 / status 422 ("The event does not exist").
	return papi.CalendarEvent{}, fmt.Errorf("fetching event: %w",
		&papi.APIError{Status: 422, Code: 2501, Message: "The event does not exist"})
}

func TestListCalendars(t *testing.T) {
	fx := newFixture(t)
	cals, err := fx.account.ListCalendars(context.Background())
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	if len(cals) != 1 || cals[0].ID != testCalID || cals[0].Name != "Personal" {
		t.Fatalf("calendars = %+v", cals)
	}
}

func TestListEventsDecryptsFullChain(t *testing.T) {
	fx := newFixture(t)
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	events, err := fx.account.ListEvents(context.Background(), testCalID, start, end)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]

	if ev.DecryptFailed {
		t.Fatal("DecryptFailed set; the crypto chain must succeed end-to-end")
	}
	if ev.Title != "Team lunch, The Counter" {
		t.Errorf("Title = %q (escaped SUMMARY decrypted incorrectly?)", ev.Title)
	}
	if ev.Location != "9 Market Square" {
		t.Errorf("Location = %q", ev.Location)
	}
	if ev.RRule != "FREQ=WEEKLY;COUNT=10" {
		t.Errorf("RRule = %q (signed card not merged?)", ev.RRule)
	}
	if ev.UID != "uid-1@proton.me" || ev.ID != testEventID {
		t.Errorf("identity: uid=%q id=%q", ev.UID, ev.ID)
	}
	if want := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC); !ev.Start.Equal(want) {
		t.Errorf("Start = %v, want %v", ev.Start, want)
	}
	if ev.TZ != "Europe/Paris" || ev.AllDay {
		t.Errorf("tz/allday: %q %v", ev.TZ, ev.AllDay)
	}
}

func TestGetEventUsesCachedCalendarKeyring(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	if _, err := fx.account.GetEvent(ctx, testCalID, testEventID); err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	// Second call: the calendar keyring must come from the cache (no
	// re-bootstrap) — we verify it indirectly by clearing the key fixtures.
	fx.client.keys = nil
	fx.client.passphrase = papi.CalendarPassphrase{}
	ev, err := fx.account.GetEvent(ctx, testCalID, testEventID)
	if err != nil {
		t.Fatalf("GetEvent (cached): %v", err)
	}
	if ev.Title == "" || ev.DecryptFailed {
		t.Fatalf("cached keyring failed to decrypt: %+v", ev)
	}
}

func TestDecryptEventLenientOnBadCard(t *testing.T) {
	fx := newFixture(t)
	// Corrupt the encrypted card: the event must survive (cleartext fields
	// + signed card) with DecryptFailed set.
	fx.client.events[0].SharedEvents[1].Data = base64.StdEncoding.EncodeToString([]byte("garbage"))

	ev, err := fx.account.GetEvent(context.Background(), testCalID, testEventID)
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if !ev.DecryptFailed {
		t.Error("DecryptFailed not set on corrupted card")
	}
	if ev.UID != "uid-1@proton.me" {
		t.Errorf("clear fields lost: %+v", ev)
	}
	if ev.RRule != "FREQ=WEEKLY;COUNT=10" {
		t.Errorf("signed card lost: rrule=%q", ev.RRule)
	}
}
