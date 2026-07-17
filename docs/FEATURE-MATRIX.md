# FEATURE-MATRIX — iCalendar (Apple Calendar) ↔ Proton Calendar

cal-gateway's gatekeeping spec. Produced by a swarm of 4 research agents
(2026-07-16): RRULE matrix, recurring-operation semantics, property matrix,
gatekeeping architecture. Primary sources: `ProtonMail/WebClients` code
(validation lives 100% client-side), `cheeseandcereal/proton-cal` docs + live
tests, Apple `ccs-caldavtester` payloads, RFC 5545/4791.

**Founding principle:** the Proton server validates **nothing** (RRULE and most
properties are just text inside the encrypted/signed cards). An "accepted" PUT
(201) can therefore break display or editing in the owner's Proton app. Gatekeeping
is **entirely** the gateway's responsibility, and a refusal must always be an
honest error code (403) — never a 2xx no-op (a proven cause of the `dataaccessd`
"Error 2" loop, 2026-07-16).

## Policy legend

- **pass** — forwarded as-is, natively supported by Proton.
- **strip** — silently removed on write (cosmetic; same posture as Proton's
  official ICS import).
- **refuse** — PUT rejected with 403 + a `DAV:error` body (project namespace
  `https://cal-gateway.example/ns`, element `unsupported-property name="…"`).
  `dataaccessd` keeps the local edit and retries in the background without
  corrupting its cache — safe.
- **emulate** — the gateway translates to equivalent Proton primitives.
- **fix** — not gatekeeping: a gap in our implementation to fix.

## 1. Recurrence (RRULE)

Source of truth: `WebClients packages/shared/lib/calendar/recurrence/rrule.ts
::getIsRruleSupported`. Verdict: Proton covers nearly everything the Apple UI can
emit.

| Pattern | Apple UI | Proton | Policy |
|---|---|---|---|
| FREQ=DAILY/WEEKLY/MONTHLY/YEARLY + INTERVAL | yes | yes (max 999/4999/-/99) | pass |
| WEEKLY;BYDAY multiple (MO,WE,FR) | yes | yes | pass |
| MONTHLY fixed day (single BYMONTHDAY) | yes | yes | pass |
| MONTHLY;BYDAY+BYSETPOS ∈ {-1,1,2,3,4} ("2nd Tuesday") | yes | yes | pass |
| BYSETPOS=5 / -2/-3/-4, multiple BYMONTHDAY | no (UI) | no | refuse (defensive) |
| COUNT ("after N times") | yes | **max 49** | refuse if >49 |
| UNTIL ("on [date]") | yes | **max 2037-12-31** | refuse if beyond |
| EXDATE (occurrence deletion) | yes | yes (dedicated field) | pass (M3) |
| FREQ=SECONDLY/MINUTELY/HOURLY, BYHOUR/BYWEEKNO… | never | no | refuse |

## 2. Operations on recurring events

Structural trap: CalDAV = 1 href = 1 UID = 1 .ics that may contain N VEVENTs
(master + `RECURRENCE-ID` overrides). Proton = 1 row per master + 1 separate row
per exception (`RecurrenceID`), same UID. The href↔rows mapping is the gateway's
job. Apple always sends the COMPLETE STATE, never a delta.

**FOLDING (M4, done — the root fix for the recurring-master corruption case /
"Error 2"):** on read, 1 UID = ONE resource `{rowID-master}.ics` — a master
VEVENT (RRULE/EXDATE) + one VEVENT per exception-row with `RECURRENCE-ID`, NEVER
EXDATE/RRULE on the children (Radicale trap #1635). Group ETag: a hash of
(ID, LastEdit) of EVERY row (the max alone would miss a deletion). The href of a
row folded under its anchor returns 404; an orphan exception (no master) is still
served as a standalone resource. Folding happens at the BACKEND level (resource
construction); the store stays row-for-row faithful to Proton.

| Operation | Apple emits | Proton | Complexity | Status |
|---|---|---|---|---|
| 1. Delete 1 occurrence | PUT master + EXDATE (full list) | master's Exdates[] (+ purge of the same-day exception-row: absent from the PUT → DeleteEvent, cf. op. 4) | trivial | **M3** (+M4 purge) |
| 2. Delete "this and following" | PUT master, truncated RRULE (UNTIL/COUNT) | UpdateEvent master; post-cut exception-rows Apple drops from the payload are purged by op. 4 reconciliation | medium | **M4 done** (via reconciliation) |
| 3. Delete the series | DELETE href | batch-delete master **+ all same-UID rows in ONE sync call** (otherwise phantom orphan exceptions) | trivial | **M3 done, verified live M4** (+ group purge on the cache side) |
| 4. Edit 1 occurrence | PUT 1 .ics with 2 VEVENTs: master + RECURRENCE-ID child (no RANGE) | folded routing: child with no row → CreateEvent an exception-row (master UID, RecurrenceID, SEQUENCE ≥ master else code 2001); child with a row → UpdateEvent; row absent from the PUT → DeleteEvent | medium | **M4 done, verified live** (ref payload: ccs-caldavtester recurrenceput/5-6.txt) |
| 5. Edit "this and following" | PUT with RECURRENCE-ID child;**RANGE=THISANDFUTURE** | **no Proton equivalent** (`SINGLE_EDIT_UNSUPPORTED`). Emulation = split: truncated master UNTIL + NEW Proton series; the gateway must re-synthesize the RANGE on GET (1 Apple UID ↔ 2 Proton series) | high, risk of loss | M5, dedicated design BEFORE code; until then **refuse** (403) |
| 6. Edit the whole series | PUT modified master | UpdateEvent; exceptions follow the PAYLOAD (see decision below) | medium | **M4 done** |

Op. 6 decision (purge-vs-403 on a significant update, M4): neither a
proton-cal-style heuristic purge (`Significant()`) nor a 403 — **mirror the
payload.** Apple sends the complete desired state: exception-rows present in the
PUT are kept/updated, those Apple dropped are deleted. Apple decides which edits
survive a structural change — never a purge guessed by the gateway, never a
silent loss. The M3 guard (403 on a structural update of a master with
exceptions) now applies only to ISOLATED updates (`EventInput.SeriesManaged ==
false`).

**Recurring + attendees (M5b/C-3, 2026-07-16):** an INVITED WHOLE SERIES is
supported — create and update of the master pass, the invitation ICS carries the
RRULE + EXDATE (same form as DTSTART) + VTIMEZONE. Editing ONE OCCURRENCE of an
invited series (a RECURRENCE-ID child in the PUT, or an existing exception-row on
the Proton side) stays **403 `ATTENDEE-RECURRING`**: the per-occurrence
REQUEST/CANCEL (RECURRENCE-ID in the iMIP) is not emitted. The M6b OUTGOING RSVP
(§3) likewise covers only the MASTER: a PUT changing the owner's PARTSTAT is
routed to a REPLY only if the resource carries neither a RECURRENCE-ID child nor
an exception-row (per-occurrence REPLY is still to do).

**Scheduling announcement, RFC 6638 (M5c, 2026-07-16):** macOS only enables the
"Add invitees" UI for a NETWORK CalDAV account if the server ANNOUNCES scheduling
— `calendar-user-address-set` alone is not enough. The gateway now announces
(`internal/server/scheduling.go`): the `calendar-auto-schedule` token in the DAV
header of every OPTIONS (implicit scheduling ONLY — never `calendar-schedule`,
which would post invitations to the outbox instead of the PUT);
`schedule-inbox-URL`/`schedule-outbox-URL` + `calendar-user-type INDIVIDUAL` on
the principal; collections `/{user}/inbox/` (schedule-inbox always EMPTY, never
404) and `/{user}/outbox/` (POST VFREEBUSY iTIP → `schedule-response` with
`2.0;Success` + a VFREEBUSY with no busy range per attendee = everyone free,
never a 5xx). TOTAL interception before go-webdav (depth 2 = same depth as the
home set, otherwise routed as the home set). Sending invitations is unchanged:
PUT with ORGANIZER+ATTENDEE → iMIP (M5a/M5b).

Related bug fixed (M4): on a CREATE PUT, the client names the resource
(`{uid}.ics`) and the 201 returns a Location to `{rowID}.ics` (server rename,
legal). Seen in httpdebug: `dataaccessd` re-GETs the original name before
integrating the Location → this was a bare 404 (non-ID segment → code 2061). Fix:
a `client-name → rowID` alias persisted in the store (write-through), resolved by
GET/DELETE, purged when the target disappears.

**Timezones — DST root fix (2026-07-16):** times are served in the event's
ORIGINAL IANA zone (`DTSTART;TZID=…` in local wall-clock time + a generated
VTIMEZONE block — canonical tzurl table + probed Jan/Jul fallback,
`caldav/vtimezone.go`), falling back to "Z" if the zone is empty/UTC/unknown.
RECURRENCE-ID and EXDATE carry the SAME zone as the master's DTSTART (RFC 5545
§3.8.4.4 / §3.8.5.1); `RRULE;UNTIL=` stays UTC verbatim (§3.3.10); all-day
unchanged. Served as bare Z, a recurring event was re-expanded by Apple at a
FIXED UTC time all year → no match with the DST-correct RECURRENCE-ID/EXDATE
(Proton epochs) → "Error 2" + deleted occurrences still visible; worse, Apple
sent back the Z that the write path rewrote INTO Proton (self-corruption of the
recurring master). Write side: a form guard (`proton.writeTZ` in `diffPatches`) —
unchanged instant = original form kept intact (in-place patch); changed instant
with an empty client TZID = original zone reused, never a bare Z reintroduced; an
explicit client TZID stays authoritative. Internal instants (store,
`Event.Start/End/ExDates`) stay UTC — only the PRESENTATION changes. ETag:
`etagSchemaVersion` (v2) folded into ALL computations (group and single row) —
the bump forces paired clients to re-download in full (self-healing of the
`dataaccessd` caches).

**EXDATE anti-history-overwrite guard (2026-07-16):** Apple only sends back the
EXDATEs it DISPLAYS — its resync horizon purges past cancellations from a series
PUT (46 values lost on the corrupted recurring master). Policy
(`caldav.mergePastExDates`): on a series PUT, the written set =
(existing EXDATEs STRICTLY in the past — before today UTC — ALWAYS kept) ∪
(the client's list, authoritative for today/future). A past occurrence never
"restores" itself from the Apple UI: no loss of functionality, and the
cancellation history survives.

## 3. Non-recurrence properties

Four-card model (what lives where — constrains what we can write):

| Location | Fields | Crypto |
|---|---|---|
| SharedEvents signed | uid, dtstamp, dtstart, dtend, recurrence-id, rrule, exdate, organizer, sequence | clear + signed |
| SharedEvents encrypted | summary, description, location, created (+ surviving unknown props) | AES + signed |
| CalendarEvents signed | status, transp, exdate | clear + signed |
| CalendarEvents encrypted | comment | AES + signed |
| AttendeesEvents encrypted | attendee (emails) | AES + signed |
| API field `Notifications` | alerts ({Type EMAIL/DEVICE, Trigger}) | **clear** |
| API field `Color`, `Attendees[]` (SHA1 tokens + Status) | | **clear** |

| Feature | Proton | Policy |
|---|---|---|
| VALARM / alerts | API field `Notifications` (relative, before-start, max 10; DISPLAY/AUDIO→DEVICE) — absent from the pinned go-proton-api struct, currently lost both ways | **fix M4** (dedicated encode/decode, outside the cards) |
| ATTENDEE / ORGANIZER / RSVP | full model on the Proton side; iMIP sending does NOT live in /events/sync — the gateway sends it ITSELF via the SMTP bridge (config `[invite]`, `internal/invite`) | **incoming** (e.g. booking-site invites) → strip, unchanged. **Outgoing, M5a done (verified live 2026-07-16)**: CREATE with attendees = AttendeesEventContent card (session key SHARED with SharedEvents, token SHA1(UID+canonical)), ORGANIZER on the sharedSigned card, `Attendees[]`+`IsOrganizer:1`, THEN a REQUEST email (multipart/mixed: alternative[plain+text/calendar;method=…] + invite.ics attachment; From = ORGANIZER) — sync first, a send failure ≠ a PUT failure (201, ERROR log per attendee). Read: ATTENDEE served with PARTSTAT derived from the clear Status (0/1/2/3 → NEEDS-ACTION/TENTATIVE/DECLINED/ACCEPTED), never an X-PM-TOKEN. **M5b done (verified live 2026-07-16, full cycle on a `<test-calendar>`)**: UPDATE of an invited event allowed — **significant** diff (DTSTART/DTEND/all-day/RRULE/EXDATE/LOCATION) → "updated" REQUEST to KEPT attendees; **cosmetic** diff (SUMMARY/DESCRIPTION/alarms/STATUS) → update WITHOUT re-notification (Google/Outlook posture); attendee **ADDED** → REQUEST to the new one only (attendees card REBUILT: kept lines VERBATIM — PARTSTAT/params survive —, RSVP Status preserved by token, sealed with the shared session key); attendee **REMOVED** → CANCEL to the removed one only (STATUS:CANCELLED, ICS listing only the cancelled); removal of the last attendee → ORGANIZER removed from the card, the event becomes bare again. **SEQUENCE**: bump on a structural change (bounds/RRULE/EXDATE — diffPatches) OR an attendee diff, NEVER twice; LOCATION alone re-notifies without a bump (RFC 5546 doesn't require it, a fresher DTSTAMP suffices); the iMIP carries the post-update SEQUENCE (backend/proton mirror). **DELETE → CANCEL to each attendee** (best-effort after the delete succeeds; third-party organizer / `[invite]` absent / isolated exception-row → WARN without blocking). The 20-attendee cap is also applied to an UPDATE's set. **OUTGOING RSVP — M6b done (2026-07-17)**: the owner replies to a RECEIVED invitation (event with a third-party ORGANIZER). A PUT that changes ONLY the PARTSTAT of THEIR OWN line (an account address) — accept (`ACCEPTED`), decline (`DECLINED`), tentative (`TENTATIVE`) — is no longer refused: the backend (`detectOwnRSVP`) compares the PUT against the authoritative Proton state (`AuthoritativeEventsByUID`), and if the ONLY delta is the owner's PARTSTAT (bounds/RRULE/EXDATE/title/location/STATUS/attendee set ALL identical, `sameEventShape`+`sameAttendeeSet`), it (1) PATCHes THEIR line's `Status` via the dedicated endpoint `PUT /calendar/v1/{calID}/events/{eventID}/attendees/{attendeeID}` (body `{Status, UpdateTime, Comment}`, `Status` 0/1/2/3, attendeeID re-read from the clear array joined by Token) — WITHOUT touching the other attendees, the organizer, or the third party's encrypted cards — then (2) emits an iMIP **METHOD:REPLY** (`ReplyICS`: UID + third-party ORGANIZER + a SINGLE ATTENDEE line = the owner with their new PARTSTAT + SEQUENCE, never an X-PM-TOKEN, From = the owner, To = the organizer). Same security discipline: `stripCtrl` on every card/email field, shared send quota (`inviteRateLimiter`/`maxInvitesPerDay`), organizer masked in the logs. PATCH first (authoritative), REPLY after (best-effort, a send failure does not fail the PUT). **Still 403**: an occurrence of an invited series (`ATTENDEE-RECURRING`, per-RECURRENCE-ID REPLY not emitted), ANY OTHER change than a pure PARTSTAT on a third-party event (`ATTENDEE-FOREIGN` — would rewrite the organizer's event), `[invite]` absent. **INCOMING RSVP — M6a "accepted" badge: NOT free, watcher NOT built (design reserved).** Determined by the source (WebClients `mailIntegration/invite.ts`): updating `Attendees[].Status` on receipt of a REPLY iMIP is **client-side** — it's the Proton Mail webmail that parses the email and calls `updateAttendeePartstat`, NEVER the server alone. Since the owner lives in Apple Calendar (not the Proton webmail), the badge would not surface on its own. Definitive live proof still required (protocol: create an invited event `CALGW_LIVE_SEND=1`, reply from the invitee's client, re-probe `Attendees[].Status` ≤60s — probe `TestLivePartstatProbe`). Watcher design (to enable ONLY behind `[invite] watch_replies=false` by default, once proven): a lightweight IMAP on the owner's bridge (`127.0.0.1:1143`, **FETCH/EXAMINE STRICTLY read-only — never STORE/DELETE/flag**, absolute bridge read-only rule), detects `METHOD:REPLY`, correlates by UID+email+SEQUENCE, PATCHes `Status` via the same dedicated endpoint as M6b. Reserved wiring: `WatchReplies`+IMAP creds flag in `config.Invite`, `main.go` logs a WARN if enabled (no-op). The RSVP decision lives in the BACKEND (`PutCalendarObject`), no longer in the putguard |
| LOCATION text | yes (255c truncated) | pass |
| GEO / X-APPLE-STRUCTURED-LOCATION | zero support | strip |
| URL, ALTREP, CATEGORIES, ATTACH, X-APPLE-* | not consumed | strip |
| STATUS / TRANSP | carried by the signed CalendarEvents card. ⚠️ Live discovery (M4): the server VALIDATES the STATUS enum — CONFIRMED/CANCELLED accepted, **TENTATIVE rejected** (code 2000) | **done M4**: passthrough {CONFIRMED, CANCELLED}, TENTATIVE stripped → default |
| CLASS (private) | no model | strip + document (the "private" marker is lost) |
| Per-event COLOR | plan-gated, imposed palette; Apple doesn't emit it | n/a |
| All-day, multi-day, no DTEND | native / computed defaults | pass |
| DURATION instead of DTEND | converted on ingestion by Proton | **fix** (not parsed by icalToEventInput) |
| Floating time (no TZ, no Z) | refused by Proton (`UNEXPECTED_FLOATING_TIME`); we currently reinterpret as UTC silently | **refuse** (align with Proton, no silent distortion) |
| Custom VTIMEZONE / non-IANA TZID | never stored / rejected | strip the block, pass the IANA TZID |
| VTODO / VJOURNAL / VFREEBUSY | no model | **refuse** + announce VEVENT-only in supported-calendar-component-set |

## 4. Gatekeeping architecture (decisions)

1. **No "rich-truth" shadow store** (considered, then rejected): double truth
   between the Proton app and Apple Calendar, unmergeable drift on the first
   Proton-side edit, silent loss if the local store dies. The SQLite store (M4)
   stays a mirror uid↔protonEventID↔etag + the 1-Apple-UID↔N-Proton-rows mapping
   (cases 4/5).
2. **Refusal = HTTP middleware** (interceptProppatch pattern): go-webdav doesn't
   allow a structured DAV:error body from the Backend (internal type). An
   `interceptPutPrecondition` inspects the incoming VEVENT and returns 403 +
   in-house XML before delegating. **M5a amendment**: only STATELESS refusals
   (VTODO/VJOURNAL/VFREEBUSY) stay in the middleware; the ATTENDEE policy
   (create+invitation vs `ATTENDEE-UPDATE` vs incoming strip) needs to know the
   Proton state → it lives in the backend, as a 403 text (same form as the other
   backend refusals: THISANDFUTURE, floating…).
3. **Bounded emulation only**: 1:1 exception-row (op. 4), series split (op. 5).
   Never an RRULE→N events materialization.
4. **Update = patch-in-place**: start from the original decrypted iCal and apply
   only the modeled deltas (the sync body replaces everything; proton-cal fixed
   silent losses on this twice).

## Security — encryption at rest (audit 2026-07-17)

`session.json` (a complete Proton session grant: tokens + `salted_key_pass`) and
`store.json` (the owner's **decrypted** calendar) are **sealed at rest**
AES-256-GCM via `internal/atrest` — a local key `.atrest.key` (32 B, 0600,
generated on first boot), one key for both files, loaded once per process.
Container `magic("CGAR") ‖ version ‖ nonce(12) ‖ ct`. **Chosen option A** (local
key file) over TPM/systemd-creds: the realistic vector is a file/backup leak, not
full root access. Non-destructive cleartext→sealed migration on first boot
(session re-sealed in place, never discarded; store re-sealed on first persist).
The store's conditional-persist guard hashes the **cleartext** (the nonce changes
on each seal). Full threat model + what is NOT covered: see
[`../SECURITY.md`](../SECURITY.md).

## M4 priorities (after M3)

1. Op. 4 (edit 1 occurrence — the most frequent action): multi-VEVENT parsing +
   exception-rows.
2. Full op. 6 (purge exceptions on a significant change) + op. 2.
3. VALARM↔Notifications, STATUS/TRANSP passthrough, DURATION, floating refusal.
4. supported-calendar-component-set VEVENT-only + interceptPutPrecondition.
5. Op. 5 (THISANDFUTURE) last, design the split first.
6. Live check: the same-UID batch-delete of the M2 series-delete (orphan risk).

## Research caveats

- Proton validation = client code only; "if pushed anyway" behaviors are not
  live-tested against the API. Verify before widening the pass-list.
- ATTENDEE via /events/sync: write VERIFIED LIVE (M5a, 2026-07-16) — the server
  sends NO mail itself; it is indeed the gateway that emits the REQUEST iMIP via
  the SMTP bridge. The invitation-specific server error codes remain unknown: any
  sync rejection is surfaced generically and blocks the email send.
- Two web pages fetched during the research contained prompt-injection attempts
  (fake system-reminders) — ignored, flagged.
