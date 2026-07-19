package proton

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// newTestKeyRing generates an ephemeral unlocked PGP keyring for the sealing
// tests (no network, no Proton session).
func newTestKeyRing(t *testing.T, email string) *crypto.KeyRing {
	t.Helper()
	key, err := crypto.GenerateKey("Test", email, "x25519", 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	return kr
}

func TestBuildFragmentsFormat(t *testing.T) {
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	start := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	end := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	f := buildFragments("uid-1", now, EventInput{
		UID: "uid-1", Title: "TEST; a, b\nc", Start: start, End: end,
	})

	// Wrapper without trailing CRLF, CRLF separators, no VERSION/PRODID.
	if !strings.HasPrefix(f.sharedSigned, "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n") {
		t.Fatalf("sharedSigned bad prefix:\n%q", f.sharedSigned)
	}
	if strings.HasSuffix(f.sharedSigned, "\r\n") {
		t.Fatalf("sharedSigned has trailing CRLF")
	}
	if !strings.Contains(f.sharedSigned, "\r\nDTSTART:20260717T150000Z\r\n") {
		t.Errorf("sharedSigned DTSTART form:\n%q", f.sharedSigned)
	}
	if !strings.Contains(f.sharedSigned, "\r\nSEQUENCE:0\r\n") {
		t.Errorf("sharedSigned missing SEQUENCE")
	}
	// TEXT escaping in the encrypted card.
	if !strings.Contains(f.sharedEncrypted, `SUMMARY:TEST\; a\, b\nc`) {
		t.Errorf("SUMMARY not escaped:\n%q", f.sharedEncrypted)
	}
	// Calendar card: RFC defaults when the input carries nothing.
	for _, want := range []string{"STATUS:CONFIRMED", "TRANSP:OPAQUE"} {
		if !strings.Contains(f.calSigned, want) {
			t.Errorf("calSigned missing default %q:\n%q", want, f.calSigned)
		}
	}
}

// TestBuildFragmentsStatusTransp: passthrough of STATUS/TRANSP from the incoming
// ICS to the signed CalendarEvents card (end of the hardcoded CONFIRMED/OPAQUE).
func TestBuildFragmentsStatusTransp(t *testing.T) {
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	start := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	f := buildFragments("uid-st", now, EventInput{
		UID: "uid-st", Start: start, End: start.Add(time.Hour),
		Status: "TENTATIVE", Transp: "TRANSPARENT",
	})
	for _, want := range []string{"STATUS:TENTATIVE", "TRANSP:TRANSPARENT"} {
		if !strings.Contains(f.calSigned, want) {
			t.Errorf("calSigned missing %q:\n%q", want, f.calSigned)
		}
	}
}

func TestDTPropForms(t *testing.T) {
	utc := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	if got := icalDTProp("DTSTART", utc, "", false); got != "DTSTART:20260717T150000Z" {
		t.Errorf("UTC form = %q", got)
	}
	if got := icalDTProp("DTSTART", utc, "UTC", false); got != "DTSTART:20260717T150000Z" {
		t.Errorf("UTC(named) form = %q", got)
	}
	if got := icalDTProp("DTSTART", utc, "", true); got != "DTSTART;VALUE=DATE:20260717" {
		t.Errorf("all-day form = %q", got)
	}
	// TZID: the local wall time is re-rendered in the zone.
	got := icalDTProp("DTSTART", utc, "Europe/Paris", false)
	if got != "DTSTART;TZID=Europe/Paris:20260717T170000" {
		t.Errorf("TZID form = %q (want 17:00 Paris for 15:00Z summer)", got)
	}
}

// TestSealRoundTrip is the critical test: seal then re-decrypt with the READ
// path, and verify that the detached signature covers the EXACT bytes of the
// Data sent (the byte-stable pitfall). Simulates address key != calendar key.
func TestSealRoundTrip(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	f := buildFragments("uid-42", now, EventInput{
		UID: "uid-42", Title: "Third-party booking", Location: "Salon",
		Start: time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC),
	})
	body, err := sealCards(f, calKR, signerKR)
	if err != nil {
		t.Fatalf("sealCards: %v", err)
	}

	// 1) Verify the detached signature of the signed cards over the Data bytes.
	for _, part := range []eventPart{body.SharedEventContent[0], body.CalendarEventContent[0]} {
		if part.Type != cardSigned {
			t.Fatalf("expected signed card, got type %d", part.Type)
		}
		sig, err := crypto.NewPGPSignatureFromArmored(part.Signature)
		if err != nil {
			t.Fatalf("parse sig: %v", err)
		}
		if err := signerKR.VerifyDetached(crypto.NewPlainMessage([]byte(part.Data)), sig, crypto.GetUnixTime()); err != nil {
			t.Errorf("detached signature does not cover Data bytes: %v", err)
		}
	}

	// 2) Decrypt the shared encrypted card via the READ path and confirm the fields.
	sharedEnc := body.SharedEventContent[1]
	if sharedEnc.Type != cardEncryptedAndSigned {
		t.Fatalf("expected encrypted card, got type %d", sharedEnc.Type)
	}
	part := papi.CalendarEventPart{Type: papi.CalendarEventType(sharedEnc.Type), Data: sharedEnc.Data}
	plain, err := (&Account{}).cardPlaintext(part, body.SharedKeyPacket, calKR)
	if err != nil {
		t.Fatalf("cardPlaintext: %v", err)
	}
	frag, err := parseFragment(plain)
	if err != nil {
		t.Fatalf("parseFragment: %v", err)
	}
	if frag.summary == nil || *frag.summary != "Third-party booking" {
		t.Errorf("SUMMARY round-trip = %v", frag.summary)
	}
	if frag.location == nil || *frag.location != "Salon" {
		t.Errorf("LOCATION round-trip = %v", frag.location)
	}

	// 3) The key packet must decode (PKESK b64) and open the session key.
	kp, err := base64.StdEncoding.DecodeString(body.SharedKeyPacket)
	if err != nil {
		t.Fatalf("decode key packet: %v", err)
	}
	if _, err := calKR.DecryptSessionKey(kp); err != nil {
		t.Errorf("calendar key cannot open session key: %v", err)
	}
}
