// Package proton encapsulates access to the Proton account (session, calendars, events).
//
// Product rule: we rely on the OFFICIAL Proton libraries
// (go-proton-api for the API, gopenpgp for PGP) as primitives —
// the orchestration code is OURS. proton-cal serves only as a
// reading reference to understand the format (never copied, never vendored).
package proton

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/go-resty/resty/v2"
	"golang.org/x/sync/errgroup"
)

// appVersion is the x-pm-appversion header. "Other" is the generic value
// accepted by the Proton API for third-party clients (concept verified in the
// proton-cal study reference).
const appVersion = "Other"

// Calendar is a Proton calendar, cleartext fields (the calendar name is
// not encrypted on the v1 API).
type Calendar struct {
	ID          string
	Name        string
	Description string
	Color       string
}

// Event is a DECRYPTED event, ready to be serialized as a VEVENT.
type Event struct {
	ID         string // Proton row ID (stable, used as the CalDAV resource name)
	UID        string // iCalendar UID
	CalendarID string

	Title       string
	Description string
	Location    string

	Start time.Time // UTC
	End   time.Time // UTC
	// TZ is the IANA zone of DTSTART (StartTimezone column): the presentation
	// FORM served as TZID on the CalDAV side — the instant itself stays UTC.
	TZ string
	// EndTZ is the IANA zone of DTEND (EndTimezone column), "" = same as TZ.
	// Field added later: zero-value backward-compatible with the JSON store.
	EndTZ  string
	AllDay bool

	RRule string // verbatim RRULE value ("" = non-recurring)

	// ExDates are the deleted occurrences of the recurring master (EXDATE),
	// as UTC instants (a full day = UTC midnight of the date). Parsed from
	// the decrypted cards and served in the VEVENT — otherwise Apple
	// displays occurrences that Proton has deleted.
	ExDates []time.Time

	// Sequence is the SEQUENCE from the SharedSigned card; the update path
	// (M3) increments it on every structural modification (RFC 5546).
	Sequence int

	// RecurrenceID is the row's RecurrenceID API column (UTC epoch of the
	// ORIGINAL occurrence): != 0 identifies an exception-row — the edit of
	// ONE occurrence of a series, a separate Proton row carrying the SAME UID
	// as the master. 0 = master or simple event. It is the key to CalDAV
	// folding (1 UID = 1 resource = master + exceptions, M4): the backend
	// serializes this value as RECURRENCE-ID on the child VEVENT.
	RecurrenceID int64

	// Status / Transp come from the signed CalendarEvents card ("" = absent;
	// the RFC 5545 defaults CONFIRMED/OPAQUE then apply on the client side).
	Status string
	Transp string

	// Notifications are the reminders from the cleartext API column of the same
	// name (M4). nil covers null (inherit the calendar's default reminders) AND
	// [] (none): in both cases, nothing to serve as VALARM — the exact
	// tri-state is preserved only by the update path (raw JSON of eventRow).
	Notifications []Notification

	// Organizer is the email address of the ORGANIZER (SharedSigned card),
	// "" = no invitation. Attendees are the decrypted invitees from the
	// AttendeesEvents card, Status joined from the row's cleartext array by
	// Token (M5a). Zero-values backward-compatible with the JSON store.
	Organizer string
	Attendees []Attendee

	LastEdit time.Time // serves as ETag/ModTime on the CalDAV side

	// DecryptFailed indicates that at least one card could not be decrypted
	// or parsed. Lenient read: the event is still served with the available
	// fields, but a future write path (M2) must NEVER start from a
	// partially decrypted event.
	DecryptFailed bool
}

// apiClient is the subset of *proton.Client (go-proton-api) that we
// consume. An interface to allow unit tests without network.
type apiClient interface {
	GetCalendars(ctx context.Context) ([]papi.Calendar, error)
	GetCalendarKeys(ctx context.Context, calendarID string) (papi.CalendarKeys, error)
	GetCalendarMembers(ctx context.Context, calendarID string) ([]papi.CalendarMember, error)
	GetCalendarPassphrase(ctx context.Context, calendarID string) (papi.CalendarPassphrase, error)
	GetCalendarEvents(ctx context.Context, calendarID string, page, pageSize int, filter url.Values) ([]papi.CalendarEvent, error)
	GetCalendarEvent(ctx context.Context, calendarID, eventID string) (papi.CalendarEvent, error)
}

// Account encapsulates an authenticated Proton session: the API client and the
// unlocked address keyrings, plus a cache of calendar keyrings.
type Account struct {
	client    apiClient
	addresses []papi.Address             // API order, used to resolve our member
	addrKRs   map[string]*crypto.KeyRing // addressID -> unlocked keyring

	// calMeta captures the member-level metadata from GET /calendar/v1
	// (see calendarMetaCache); nil in tests → top-level fallback.
	calMeta *calendarMetaCache

	mu     sync.Mutex
	calKRs map[string]*crypto.KeyRing // calendarID -> unlocked calendar keyring

	// dataDir is the root of session.json; the write path (M2) reloads the
	// freshest session (tokens refreshed by AddAuthHandler) before a PUT.
	dataDir string
	// rc is the *resty.Client CONFIGURED by go-proton-api (base URL,
	// x-pm-appversion header, APIError error parsing), captured on the first call
	// via a pre-request hook. go-proton-api does not expose /events/sync for
	// writing: we issue the PUT on this same client (see write.go), reusing all of
	// its transport configuration rather than a hand-rolled net/http.
	rc *resty.Client
}

// calendarMemberMeta is the useful subset of a Members[] entry from
// GET /calendar/v1.
type calendarMemberMeta struct {
	Email       string
	Name        string
	Description string
	Color       string
	Flags       papi.CalendarFlag
}

// calendarMetaCache: the MODERN shape of GET /calendar/v1 (verified live on
// the account) no longer carries Name/Description/Color/Flags at the calendar
// level but on each Members[] entry — fields that go-proton-api's papi.Calendar
// struct does not map (they stay zero there). We therefore capture the RAW
// response via the official Client.AddPostRequestHook hook and parse it
// ourselves; papi remains the transport/auth primitive.
type calendarMetaCache struct {
	mu   sync.Mutex
	byID map[string][]calendarMemberMeta
}

// capture parses the raw body of a GET /calendar/v1 response. Unexpected
// response = no-op (we keep the top-level fallback).
func (c *calendarMetaCache) capture(body []byte) {
	var raw struct {
		Calendars []struct {
			ID      string
			Members []calendarMemberMeta
		}
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	byID := make(map[string][]calendarMemberMeta, len(raw.Calendars))
	for _, rc := range raw.Calendars {
		byID[rc.ID] = rc.Members
	}
	c.mu.Lock()
	c.byID = byID
	c.mu.Unlock()
}

// members returns the known member entries of a calendar (nil-safe).
func (c *calendarMetaCache) members(calID string) []calendarMemberMeta {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byID[calID]
}

// NewAccount builds an Account from a client and already-unlocked address
// keyrings (see RestoreAccount for the persisted-session path).
func NewAccount(client apiClient, addresses []papi.Address, addrKRs map[string]*crypto.KeyRing) *Account {
	return &Account{
		client:    client,
		addresses: addresses,
		addrKRs:   addrKRs,
		calKRs:    make(map[string]*crypto.KeyRing),
	}
}

// RestoreAccount reloads the session persisted by `cal-gateway login`
// (session.json in dataDir) and rebuilds the Account:
// tokens -> API client, saltedKeyPass -> user key -> address keyrings.
//
// The unlock chain (user key then address keys with the salted
// passphrase) is provided by the official proton.Unlock primitive.
func RestoreAccount(ctx context.Context, dataDir string) (*Account, error) {
	sess, err := LoadSession(dataDir)
	if err != nil {
		return nil, err
	}

	m := papi.New(papi.WithAppVersion(appVersion))
	client := m.NewClient(sess.UID, sess.AccessToken, sess.RefreshToken)

	// Capture the member-level metadata from /calendar/v1 (see
	// calendarMetaCache): official hook, synchronous within the request.
	calMeta := &calendarMetaCache{}
	client.AddPostRequestHook(func(_ *resty.Client, resp *resty.Response) error {
		req := resp.Request
		if req != nil && req.Method == http.MethodGet &&
			strings.HasSuffix(strings.TrimSuffix(req.URL, "/"), "/calendar/v1") {
			calMeta.capture(resp.Body())
		}
		return nil
	})

	// The API may refresh the tokens mid-flight: re-persist so that the
	// session survives the refresh (otherwise the next startup fails).
	client.AddAuthHandler(func(auth papi.Auth) {
		sess.UID = auth.UID
		sess.AccessToken = auth.AccessToken
		sess.RefreshToken = auth.RefreshToken
		// The current session stays valid in memory, but a persistence
		// failure is the ONLY signal before a session loss at the next
		// restart (manual TOTP re-login) — never silent.
		if err := SaveSession(dataDir, sess); err != nil {
			log.Printf("proton: ERROR persisting session after token refresh: %v — the next startup will start from a stale session (re-login likely)", err)
		}
	})

	user, err := client.GetUser(ctx)
	if err != nil {
		return nil, wrapSessionErr("fetching user", err)
	}
	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		return nil, wrapSessionErr("fetching addresses", err)
	}

	userKR, addrKRs, err := papi.Unlock(user, addrs, sess.SaltedKeyPass, nil)
	if err != nil {
		// Deterministic on the persisted passphrase: this is never a network
		// blip, the session needs to be re-created.
		return nil, fmt.Errorf("proton: unlocking keys: %v: %w", err, ErrSessionInvalid)
	}
	// The user key is only needed to unlock the address keys.
	userKR.ClearPrivateParams()

	acct := NewAccount(client, addrs, addrKRs)
	acct.calMeta = calMeta
	acct.dataDir = dataDir

	// Capture go-proton-api's *resty.Client on the first call of THIS client
	// (the hook is filtered by clientID). The write path (write.go) re-issues the
	// PUT /events/sync on it, reusing base URL + headers + error parsing.
	client.AddPreRequestHook(func(rc *resty.Client, _ *resty.Request) error {
		acct.mu.Lock()
		if acct.rc == nil {
			acct.rc = rc
		}
		acct.mu.Unlock()
		return nil
	})
	return acct, nil
}

// wrapSessionErr wraps a restore error: if the API rejected the session
// (refresh token revoked — code 10013 — or 401 after go-proton-api's automatic
// refresh attempt), the ErrSessionInvalid sentinel is attached so that main
// exits with the dedicated code (78) instead of crash-looping.
// A network failure (papi.NetError) or a 5xx stays an ordinary error:
// the systemd Restart will retry.
func wrapSessionErr(op string, err error) error {
	var apiErr *papi.APIError
	if errors.As(err, &apiErr) &&
		(apiErr.Code == papi.AuthRefreshTokenInvalid || apiErr.Status == http.StatusUnauthorized) {
		return fmt.Errorf("proton: %s: %v: %w", op, err, ErrSessionInvalid)
	}
	return fmt.Errorf("proton: %s: %w", op, err)
}

// Addresses returns the account's email addresses (login + aliases/custom
// domains), for the outgoing-invitation heuristic of the PUT guard.
func (a *Account) Addresses() []string {
	out := make([]string, 0, len(a.addresses))
	for _, addr := range a.addresses {
		if addr.Email != "" {
			out = append(out, addr.Email)
		}
	}
	return out
}

// ListCalendars returns the account's active calendars.
func (a *Account) ListCalendars(ctx context.Context) ([]Calendar, error) {
	raw, err := a.client.GetCalendars(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: listing calendars: %w", err)
	}
	out := make([]Calendar, 0, len(raw))
	for _, c := range raw {
		// Metadata: member-level first (modern shape, via calMeta),
		// top-level as fallback (legacy shape / test fakes).
		name, desc, color, flags := c.Name, c.Description, c.Color, c.Flags
		if m := a.pickMember(c.ID); m != nil {
			if m.Name != "" {
				name = m.Name
			}
			if m.Description != "" {
				desc = m.Description
			}
			if m.Color != "" {
				color = m.Color
			}
			flags = m.Flags
		}
		// We only serve usable calendars: not in key reset, not in loss of
		// access, not in incomplete setup.
		if flags&papi.CalendarFlagActive == 0 {
			continue
		}
		out = append(out, Calendar{
			ID:          c.ID,
			Name:        name,
			Description: desc,
			Color:       color,
		})
	}
	return out, nil
}

// pickMember returns OUR account's member entry for a calendar (email
// matching one of our addresses), otherwise the first one, otherwise nil.
func (a *Account) pickMember(calID string) *calendarMemberMeta {
	ms := a.calMeta.members(calID)
	if len(ms) == 0 {
		return nil
	}
	for i := range ms {
		for _, addr := range a.addresses {
			if strings.EqualFold(ms[i].Email, addr.Email) {
				return &ms[i]
			}
		}
	}
	return &ms[0]
}

// Constants for the windowed /calendar/v1/{id}/events query.
// Concept (verified in the proton-cal study reference, docs/api.md):
// the server only honors Start/End with a Type parameter, and partitions
// the rows into 4 buckets — you must query all 4 to see everything.
const (
	// Timed events starting within the window.
	queryTypePartDayInside = 0
	// Timed events starting before the window but overlapping it
	// (or recurring within it).
	queryTypePartDayBefore = 1
	// Full days starting within the window.
	queryTypeFullDayInside = 2
	// Earlier full days overlapping the window (recurring masters).
	queryTypeFullDayBefore = 3

	// Maximum window accepted by the server: 93 days
	// (beyond that: code 2000 "Time window is too big").
	maxWindowSeconds = 93 * 86400

	// The server buckets on timezone-local boundaries: a one-day margin on
	// each side avoids missing the full days at the edges.
	windowPadSeconds = 86400

	eventsPageSize = 100

	// listEventsConcurrency bounds the parallelism of the slice queries
	// (window × Type) of a full snapshot: ~6 slices × 4 Types = 24 sequential
	// requests/calendar = the bulk of the ~17.7 s of a historical cycle.
	// Since delta polling, the full only runs at boot + every 6 h
	// (safety full-resync); parallelizing it keeps this path short (~÷5 of
	// wall-clock) without hammering Proton (5 requests in flight max, resty concurrent-safe).
	listEventsConcurrency = 5
)

var queryTypes = [...]int{
	queryTypePartDayInside,
	queryTypePartDayBefore,
	queryTypeFullDayInside,
	queryTypeFullDayBefore,
}

// ListEvents returns the DECRYPTED events of the calendar overlapping
// [start, end). The window is split into slices of 93 days max, each
// slice queried for the 4 Types, paginated, then deduplicated by ID
// (recurring masters come back as-is — RRULE expansion is the
// job of the CalDAV client in M1).
func (a *Account) ListEvents(ctx context.Context, calendarID string, start, end time.Time) ([]Event, error) {
	if !end.After(start) {
		return nil, nil
	}
	calKR, err := a.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return nil, err
	}

	qStart := start.Unix() - windowPadSeconds
	if qStart < 0 {
		qStart = 0
	}
	qEnd := end.Unix() + windowPadSeconds

	// List of slices (window × Type) to query, in nominal order
	// (contiguous slices, each with its 4 Types) — this order drives the
	// deterministic deduplication below.
	type chunkQuery struct {
		s, e int64
		typ  int
	}
	var tasks []chunkQuery
	for s := qStart; s < qEnd; s += maxWindowSeconds {
		e := min(s+maxWindowSeconds, qEnd)
		for _, typ := range queryTypes {
			tasks = append(tasks, chunkQuery{s: s, e: e, typ: typ})
		}
	}

	// Parallelized requests, bounded concurrency: each task writes ITS slot
	// (no mutable sharing), error = first error, context cancelled to
	// cut the remaining tasks. Decryption itself stays sequential further
	// down (CPU, keyring already in hand).
	results := make([][]eventRow, len(tasks))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(listEventsConcurrency)
	for i, tk := range tasks {
		i, tk := i, tk
		g.Go(func() error {
			chunk, err := a.queryEvents(gctx, calendarID, tk.s, tk.e, tk.typ)
			if err != nil {
				return err
			}
			results[i] = chunk
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Merge + deduplication by ID in task order (deterministic,
	// independent of the goroutine completion order).
	seen := make(map[string]struct{})
	var rows []eventRow
	for _, chunk := range results {
		for _, ev := range chunk {
			if _, dup := seen[ev.ID]; dup {
				continue
			}
			seen[ev.ID] = struct{}{}
			rows = append(rows, ev)
		}
	}

	out := make([]Event, 0, len(rows))
	for _, raw := range rows {
		ev := a.decryptEvent(raw.CalendarEvent, raw.AddressKeyPacket, calKR)
		ev.Notifications = parseNotifications(raw.Notifications)
		ev.RecurrenceID = raw.RecurrenceID
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

// ListEventsByUID returns ALL the decrypted rows of a UID (master +
// exception-rows), sorted master first then by ascending RecurrenceID.
// It is the primitive of CalDAV folding (1 UID = 1 resource) AND of the
// write routing of a multi-VEVENT PUT — in this second role it is
// AUTHORITATIVE (server filter, never a cache): routing on a stale
// state would create duplicate exception-rows.
func (a *Account) ListEventsByUID(ctx context.Context, calendarID, uid string) ([]Event, error) {
	calKR, err := a.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	rows, err := a.listEventRowsByUID(ctx, calendarID, uid)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, raw := range rows {
		ev := a.decryptEvent(raw.CalendarEvent, raw.AddressKeyPacket, calKR)
		ev.Notifications = parseNotifications(raw.Notifications)
		ev.RecurrenceID = raw.RecurrenceID
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].RecurrenceID == 0) != (out[j].RecurrenceID == 0) {
			return out[i].RecurrenceID == 0 // master first
		}
		if out[i].RecurrenceID != out[j].RecurrenceID {
			return out[i].RecurrenceID < out[j].RecurrenceID
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// AuthoritativeEventsByUID is the explicit alias of ListEventsByUID for the
// caldav.Source interface contract: on the real Account both reads
// are already authoritative; only the cache wrapper (internal/sync)
// distinguishes them (folding served from the store, write routing delegated here).
func (a *Account) AuthoritativeEventsByUID(ctx context.Context, calendarID, uid string) ([]Event, error) {
	return a.ListEventsByUID(ctx, calendarID, uid)
}

// queryEvents paginates a slice (window, Type) into RAW rows (eventRow):
// the resty transport captures the columns that go-proton-api does not map
// (Notifications, RecurrenceID). Falls back to the official client when the resty
// is not captured (offline tests) — same rows, without the extra columns.
// Same posture as FindEventByUID.
func (a *Account) queryEvents(ctx context.Context, calendarID string, start, end int64, typ int) ([]eventRow, error) {
	if rows, err := a.queryEventRowsRaw(ctx, calendarID, start, end, typ); err == nil {
		return rows, nil
	}

	var all []eventRow
	for page := 0; ; page++ {
		filter := url.Values{}
		filter.Set("Start", strconv.FormatInt(start, 10))
		filter.Set("End", strconv.FormatInt(end, 10))
		filter.Set("Type", strconv.Itoa(typ))
		// The API partitions full days on LOCAL boundaries: the
		// Timezone param is mandatory (400 "The Timezone is required",
		// Code=2000, otherwise). Start/End are UTC epochs, so we query in UTC.
		filter.Set("Timezone", "UTC")

		chunk, err := a.client.GetCalendarEvents(ctx, calendarID, page, eventsPageSize, filter)
		if err != nil {
			return nil, fmt.Errorf("proton: listing events for calendar %s: %w", calendarID, err)
		}
		for _, ev := range chunk {
			all = append(all, eventRow{CalendarEvent: ev})
		}
		if len(chunk) < eventsPageSize {
			return all, nil
		}
	}
}

// queryEventRowsRaw is the raw variant of queryEvents on the captured resty
// (see doAuthed): paginates on the More cursor, with the "incomplete page"
// safeguard if More is missing from the response.
func (a *Account) queryEventRowsRaw(ctx context.Context, calendarID string, start, end int64, typ int) ([]eventRow, error) {
	var all []eventRow
	for page := 0; ; page++ {
		path := "/calendar/v1/" + calendarID + "/events" +
			"?Start=" + strconv.FormatInt(start, 10) +
			"&End=" + strconv.FormatInt(end, 10) +
			"&Type=" + strconv.Itoa(typ) +
			"&Timezone=UTC" + // same requirement as queryEvents
			"&Page=" + strconv.Itoa(page) +
			"&PageSize=" + strconv.Itoa(eventsPageSize)
		var res eventRowsPage
		if err := a.doAuthed(ctx, http.MethodGet, path, nil, &res); err != nil {
			return nil, fmt.Errorf("proton: listing raw events for calendar %s: %w", calendarID, err)
		}
		all = append(all, res.Events...)
		// Empty page = end whatever More says (never an infinite loop).
		if len(res.Events) == 0 || (res.More != 1 && len(res.Events) < eventsPageSize) {
			return all, nil
		}
	}
}

// GetEvent fetches and decrypts a specific event. The raw transport
// (getEventRow) is attempted first to capture the Notifications column;
// falls back to the official client (offline tests), without the reminders.
func (a *Account) GetEvent(ctx context.Context, calendarID, eventID string) (*Event, error) {
	calKR, err := a.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	if row, rerr := a.getEventRow(ctx, calendarID, eventID); rerr == nil {
		ev := a.decryptEvent(row.CalendarEvent, row.AddressKeyPacket, calKR)
		ev.Notifications = parseNotifications(row.Notifications)
		ev.RecurrenceID = row.RecurrenceID
		return &ev, nil
	} else if errors.Is(rerr, ErrEventNotFound) {
		return nil, rerr
	}
	raw, err := a.client.GetCalendarEvent(ctx, calendarID, eventID)
	if err != nil {
		if isProtonNotFound(err) {
			// Event deleted on the Proton side: CLEAN disappearance (the backend
			// maps it to 404), not a server error — a 500 in the multistatus
			// makes dataaccessd loop on the phantom href ("Error 2").
			return nil, fmt.Errorf("proton: event %s/%s: %w", calendarID, eventID, ErrEventNotFound)
		}
		return nil, fmt.Errorf("proton: fetching event %s/%s: %w", calendarID, eventID, err)
	}
	ev := a.decryptEvent(raw, "", calKR)
	return &ev, nil
}

// ErrEventNotFound signals an event that does not exist (or no longer exists)
// on the Proton side. The CalDAV backend translates it into 404 — never 500.
var ErrEventNotFound = errors.New("proton: event does not exist")

// codeEventNotFound is the Proton API code "The event does not exist"
// (returned with an HTTP 422 status on GET/DELETE of a deleted row).
const codeEventNotFound = 2501

// codeInvalidID is the Proton API code "Invalid ID attribute" (status 400):
// a CalDAV href whose segment is not a well-formed Proton ID cannot
// correspond to any resource — same clean disappearance as a 2501.
const codeInvalidID = 2061

// isProtonNotFound recognizes, in an API error (papi.APIError,
// possibly wrapped), the "this resource does not exist" cases to translate
// into CalDAV 404.
func isProtonNotFound(err error) bool {
	var apiErr *papi.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return int(apiErr.Code) == codeEventNotFound || int(apiErr.Code) == codeInvalidID
}
