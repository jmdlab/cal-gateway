package invite

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

var testICS = []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\n" +
	"BEGIN:VEVENT\r\nUID:uid-mime\r\nDTSTAMP:20260901T080000Z\r\n" +
	"DTSTART:20260915T120000Z\r\nDTEND:20260915T130000Z\r\nSUMMARY:Lunch\r\n" +
	"END:VEVENT\r\nEND:VCALENDAR\r\n")

func testMessage() Message {
	return Message{
		FromName: "Alice Example",
		From:     "alice@example.com",
		To:       "bob@example.com",
		Subject:  "Invitation: Lunch",
		Text:     "When: Tuesday 15 September 2026, 14:00 to 15:00 (Europe/Paris)\n",
		ICS:      testICS,
	}
}

// TestWriteEMLStructure verifies the EXACT MIME shape required by the
// Gmail / Outlook / Proton Mail trio:
//
//	multipart/mixed
//	├─ multipart/alternative [ text/plain ; text/calendar; method=REQUEST ]
//	└─ NAMED attachment invite.ics (same content)
func TestWriteEMLStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEML(testMessage(), &buf); err != nil {
		t.Fatalf("WriteEML: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("unreadable message: %v", err)
	}
	if got := msg.Header.Get("From"); !strings.Contains(got, "alice@example.com") {
		t.Errorf("From = %q (the address MUST be the ORGANIZER)", got)
	}
	if got := msg.Header.Get("To"); !strings.Contains(got, "bob@example.com") {
		t.Errorf("To = %q", got)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("root Content-Type = %q (%v), want multipart/mixed", mediaType, err)
	}

	var sawAlternative, sawPlain, sawCalendarInline, sawAttachment bool
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		pType, pParams, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("part Content-Type: %v", err)
		}
		switch {
		case pType == "multipart/alternative":
			sawAlternative = true
			inner := multipart.NewReader(part, pParams["boundary"])
			for {
				ip, ierr := inner.NextPart()
				if ierr == io.EOF {
					break
				}
				if ierr != nil {
					t.Fatalf("inner NextPart: %v", ierr)
				}
				iType, iParams, _ := mime.ParseMediaType(ip.Header.Get("Content-Type"))
				switch iType {
				case "text/plain":
					sawPlain = true
				case "text/calendar":
					sawCalendarInline = true
					if got := iParams["method"]; !strings.EqualFold(got, "REQUEST") {
						t.Errorf("inline text/calendar method = %q, want REQUEST", got)
					}
					if got := iParams["charset"]; !strings.EqualFold(got, "UTF-8") {
						t.Errorf("inline text/calendar charset = %q, want UTF-8", got)
					}
				}
			}
		case strings.HasPrefix(pType, "text/calendar"):
			// The attachment: the filename is THE Proton Mail widget criterion.
			sawAttachment = true
			_, dParams, derr := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			if derr != nil || dParams["filename"] != "invite.ics" {
				t.Errorf("attachment filename = %q (%v), want invite.ics", dParams["filename"], derr)
			}
			if enc := part.Header.Get("Content-Transfer-Encoding"); !strings.EqualFold(enc, "base64") {
				t.Errorf("attachment encoding = %q, want base64", enc)
			}
		}
	}
	if !sawAlternative || !sawPlain || !sawCalendarInline || !sawAttachment {
		t.Fatalf("incomplete MIME structure: alternative=%v plain=%v calendarInline=%v attachment=%v\n%s",
			sawAlternative, sawPlain, sawCalendarInline, sawAttachment, buf.String())
	}
}

// TestBuildValidation: From/To are mandatory (never a half-formed email).
func TestBuildValidation(t *testing.T) {
	m := testMessage()
	m.From = ""
	if _, err := build(m); err == nil {
		t.Error("build without From must fail")
	}
	m = testMessage()
	m.To = "not-an-email"
	if _, err := build(m); err == nil {
		t.Error("build with invalid To must fail")
	}
}
