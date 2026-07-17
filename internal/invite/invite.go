// Package invite builds and sends iMIP emails (RFC 6047 / 5546) through the
// local Proton Bridge SMTP — M5a: METHOD:REQUEST on creation; M5b: update
// REQUEST (SEQUENCE+1) and METHOD:CANCEL (invitee removal, deletion).
//
// Transport: the Bridge SMTP listens in CLEAR on loopback (127.0.0.1:1025,
// stunnel only wrapping the external 465 exposure) — hence TLSPolicy NoTLS and
// SMTPAuthPlainNoEnc (SMTPAuthPlain refuses an unencrypted channel). The
// password is the BRIDGE password, never the Proton password.
//
// Message shape (interop verified with Gmail / Outlook / Proton Mail):
//
//	multipart/mixed
//	├─ multipart/alternative
//	│  ├─ text/plain                                  (human-readable body)
//	│  └─ text/calendar; method=REQUEST; charset=UTF-8 (inline — Gmail)
//	└─ invite.ics (same content, base64)              (NAMED attachment —
//	   the Proton Mail widget matches on the filename extension)
//
// From MUST be exactly the ORGANIZER, otherwise Gmail/Outlook hide the RSVP
// buttons. One email per invitee.
package invite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wneessen/go-mail"
)

// Supported iMIP methods (RFC 5546). Any other Message.Method value falls back
// to REQUEST — never a free-form value in a MIME header. REPLY (M6b) is an
// invitee's answer to a received invitation (outgoing RSVP).
const (
	MethodRequest = "REQUEST"
	MethodCancel  = "CANCEL"
	MethodReply   = "REPLY"
)

// calendarContentType returns the Content-Type of the iCalendar part (inline
// AND attachment): the method= parameter is required for clients to treat the
// message as an invitation (REQUEST) or a cancellation (CANCEL) — it MUST match
// the METHOD of the embedded VCALENDAR.
func calendarContentType(method string) mail.ContentType {
	return mail.ContentType("text/calendar; method=" + method + "; charset=UTF-8")
}

// normalizeMethod clamps the method to supported values (default REQUEST) — the
// value goes into a MIME header, it is never free-form text.
func normalizeMethod(m string) string {
	switch {
	case strings.EqualFold(m, MethodCancel):
		return MethodCancel
	case strings.EqualFold(m, MethodReply):
		return MethodReply
	default:
		return MethodRequest
	}
}

// attachmentName is the name of the .ics attachment — the extension is the
// Proton Mail widget's detection criterion.
const attachmentName = "invite.ics"

// Config is the Bridge SMTP configuration ([invite] section of the TOML).
type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Username string // the bridge account address (e.g. the organizer)
	Password string // the BRIDGE password — never the Proton password
	FromName string // display name of the sender ("" = CN/address of the ORGANIZER)
}

// Message is an iMIP email to send: one recipient per message (the caller loops
// over the invitees).
type Message struct {
	FromName string // display name; the From address is ALWAYS the ORGANIZER
	From     string // exactly the ORGANIZER address (Gmail/Outlook RSVP)
	To       string
	Subject  string
	Text     string // human-readable body (when/where)
	ICS      []byte // VCALENDAR carrying the SAME METHOD as Method
	Method   string // iMIP METHOD: MethodRequest ("" = default) or MethodCancel
}

// stripHeaderCtrl removes every control character (CR/LF included) from a value
// destined for a MIME header — header-injection defense.
func stripHeaderCtrl(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// build assembles the MIME message (see package doc for the shape).
func build(m Message) (*mail.Msg, error) {
	if m.From == "" || m.To == "" {
		return nil, errors.New("invite: From and To are required")
	}
	// SECURITY (audit 2026-07-16, P1-b): the Subject derives from the SUMMARY of
	// a client ICS (untrusted); a CR/LF there would inject forged SMTP headers
	// (mass Bcc…) into a mail sent by the account. go-mail does not strip control
	// characters from headers → we do it here, for the Subject and sender name.
	msg := mail.NewMsg()
	if err := msg.FromFormat(stripHeaderCtrl(m.FromName), m.From); err != nil {
		return nil, fmt.Errorf("invite: From %q: %w", m.From, err)
	}
	if err := msg.To(m.To); err != nil {
		return nil, fmt.Errorf("invite: To %q: %w", m.To, err)
	}
	msg.Subject(stripHeaderCtrl(m.Subject))
	ct := calendarContentType(normalizeMethod(m.Method))
	// Meaningful order: body + alternative = multipart/alternative, the
	// attachment tips the whole thing into multipart/mixed (go-mail).
	msg.SetBodyString(mail.TypeTextPlain, m.Text)
	msg.AddAlternativeString(ct, string(m.ICS))
	if err := msg.AttachReader(attachmentName, bytes.NewReader(m.ICS),
		mail.WithFileContentType(ct)); err != nil {
		return nil, fmt.Errorf("invite: attaching %s: %w", attachmentName, err)
	}
	return msg, nil
}

// WriteEML renders the message as raw RFC 5322 (.eml) WITHOUT sending it — the
// dry-run test path (CALGW_LIVE without CALGW_LIVE_SEND) and diagnostics.
func WriteEML(m Message, w io.Writer) error {
	msg, err := build(m)
	if err != nil {
		return err
	}
	if _, err := msg.WriteTo(w); err != nil {
		return fmt.Errorf("invite: writing eml: %w", err)
	}
	return nil
}

// Sender sends invitations through the Bridge SMTP. It builds one connection
// per call (volume: a few invitations per event creation).
type Sender struct {
	cfg Config
}

// NewSender builds the Sender from the [invite] config (assumed Enabled).
func NewSender(cfg Config) *Sender {
	return &Sender{cfg: cfg}
}

// Send builds and sends ONE invitation. Any error (build, dial, auth, recipient
// rejection) propagates to the caller — which logs per recipient without
// failing the PUT (the Proton event already exists, the calendar state is true).
func (s *Sender) Send(ctx context.Context, m Message) error {
	msg, err := build(m)
	if err != nil {
		return err
	}
	client, err := mail.NewClient(s.cfg.Host,
		mail.WithPort(s.cfg.Port),
		// Cleartext loopback: NoTLS + PLAIN-NOENC (see package doc).
		mail.WithTLSPolicy(mail.NoTLS),
		mail.WithSMTPAuth(mail.SMTPAuthPlainNoEnc),
		mail.WithUsername(s.cfg.Username),
		mail.WithPassword(s.cfg.Password),
	)
	if err != nil {
		return fmt.Errorf("invite: smtp client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("invite: sending to %s: %w", m.To, err)
	}
	return nil
}
