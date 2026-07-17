package proton

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	srp "github.com/ProtonMail/go-srp"
)

// Login flow (our implementation on top of the official go-proton-api
// primitives; the order of calls verified in the reference study
// proton-cal pkg/auth):
//
//	NewClientWithLogin (SRP) → Auth2FA (TOTP) → GetSalts (with the
//	unlock-scope dance if code 9101) → SaltForKey → papi.Unlock verification →
//	SaveSession (tokens + saltedKeyPass, NEVER the password).
//
// Designed for supervised headless use: secrets arrive via callbacks (env or
// stdin, decided by the caller), nothing is logged here.

// ErrCaptchaRequired signals that the API requires a human verification
// (code 9001). The headless flow cannot satisfy it: the caller must exit
// cleanly and request a login via an official client first.
var ErrCaptchaRequired = errors.New("proton: human verification (CAPTCHA) required")

// codeInsufficientScope is the Proton "insufficient scope" code (verified
// live in the reference study proton-cal): GET /core/v4/keys/salts may
// require the "locked" scope, which a freshly logged-in session does not have.
const codeInsufficientScope = 9101

// LoginPrompts supplies the secrets requested during the flow. Each callback
// is only invoked if needed (TwoFACode if TOTP is active, MailboxPassword if
// the account is in two-password mode).
type LoginPrompts struct {
	TwoFACode       func() (string, error)
	MailboxPassword func() ([]byte, error)
}

// Login runs the full flow and persists the session in dataDir.
// password is the Proton LOGIN password; in two-password mode the mailbox
// password (key) is requested via prompts.MailboxPassword.
func Login(ctx context.Context, dataDir, username string, password []byte, prompts LoginPrompts) error {
	m := papi.New(papi.WithAppVersion(appVersion))
	defer m.Close()

	client, auth, err := m.NewClientWithLogin(ctx, username, password)
	if err != nil {
		var apiErr *papi.APIError
		if errors.As(err, &apiErr) && apiErr.IsHVError() {
			return fmt.Errorf("%w: %v", ErrCaptchaRequired, err)
		}
		return fmt.Errorf("proton: login (SRP): %w", err)
	}
	defer client.Close()

	// Tokens can be refreshed during the flow: track the latest value to
	// persist a valid session.
	sess := Session{UID: auth.UID, AccessToken: auth.AccessToken, RefreshToken: auth.RefreshToken}
	client.AddAuthHandler(func(a papi.Auth) {
		sess.UID, sess.AccessToken, sess.RefreshToken = a.UID, a.AccessToken, a.RefreshToken
	})

	// 2FA. Enabled is a bitmask (HasTOTP=1, HasFIDO2=2). We only support TOTP;
	// FIDO2-only is a dead end for a headless daemon.
	switch {
	case auth.TwoFA.Enabled&papi.HasTOTP != 0:
		code, err := prompts.TwoFACode()
		if err != nil {
			return fmt.Errorf("proton: reading 2FA code: %w", err)
		}
		if err := client.Auth2FA(ctx, papi.Auth2FAReq{TwoFactorCode: strings.TrimSpace(code)}); err != nil {
			return fmt.Errorf("proton: 2FA verification failed: %w", err)
		}
	case auth.TwoFA.Enabled&papi.HasFIDO2 != 0:
		return errors.New("proton: account requires FIDO2-only 2FA (unsupported); enable TOTP at account.proton.me and retry")
	}

	// Key-unlock password: login password in single-password mode, mailbox
	// password otherwise.
	keyPassword := password
	if auth.PasswordMode == papi.TwoPasswordMode {
		keyPassword, err = prompts.MailboxPassword()
		if err != nil {
			return fmt.Errorf("proton: reading mailbox password: %w", err)
		}
		if len(keyPassword) == 0 {
			return errors.New("proton: empty mailbox password")
		}
	}

	salts, err := fetchSalts(ctx, client, m, &sess, username, password)
	if err != nil {
		return err
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		return fmt.Errorf("proton: fetching user: %w", err)
	}
	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		return fmt.Errorf("proton: fetching addresses: %w", err)
	}

	keyID, err := primaryUserKeyID(user)
	if err != nil {
		return err
	}
	saltedKeyPass, err := salts.SaltForKey(keyPassword, keyID)
	if err != nil {
		return fmt.Errorf("proton: deriving salted key passphrase: %w", err)
	}
	// NB: SaltForKey can return (nil, nil) on an internal bcrypt error.
	if len(saltedKeyPass) == 0 {
		return errors.New("proton: deriving salted key passphrase: empty result")
	}

	// Verify BEFORE persisting that the passphrase actually unlocks the keys
	// (wrong mailbox password = failure here, not on the first serve).
	userKR, addrKRs, err := papi.Unlock(user, addrs, saltedKeyPass, nil)
	if err != nil {
		return fmt.Errorf("proton: verifying key unlock (wrong mailbox password?): %w", err)
	}
	if len(addrKRs) == 0 {
		return errors.New("proton: no address keys unlocked; calendar decryption would fail")
	}
	userKR.ClearPrivateParams()
	for _, kr := range addrKRs {
		kr.ClearPrivateParams()
	}

	sess.SaltedKeyPass = saltedKeyPass
	if err := SaveSession(dataDir, sess); err != nil {
		return err
	}
	return nil
}

// fetchSalts fetches the key salts; if the token lacks the "locked" scope
// (code 9101), it regains it via an SRP proof on PUT /core/v4/users/unlock,
// retries once, then releases the scope (best effort).
func fetchSalts(ctx context.Context, client *papi.Client, m *papi.Manager, sess *Session, username string, password []byte) (papi.Salts, error) {
	salts, err := client.GetSalts(ctx)
	if err == nil {
		return salts, nil
	}
	if !isInsufficientScope(err) {
		return nil, fmt.Errorf("proton: fetching key salts: %w", err)
	}

	if err := unlockScope(ctx, m, sess, username, password); err != nil {
		return nil, fmt.Errorf("proton: unlocking session scope: %w", err)
	}
	// Release the elevated scope as soon as the salts are read (best effort).
	defer func() { _ = rawPut(ctx, sess, "/core/v4/users/lock", struct{}{}, nil) }()

	salts, err = client.GetSalts(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: fetching key salts (after unlock): %w", err)
	}
	return salts, nil
}

// isInsufficientScope detects code 9101 STRICTLY by Proton code: a bare 403
// may be a genuine permission problem and must not trigger the SRP dance.
func isInsufficientScope(err error) bool {
	var apiErr *papi.APIError
	return errors.As(err, &apiErr) && int(apiErr.Code) == codeInsufficientScope
}

// unlockScope regains the "locked" scope: SRP proof of the LOGIN password on
// PUT /core/v4/users/unlock. go-proton-api does not implement this endpoint —
// raw HTTP call with the current session's tokens, server proof verified
// (anti-MITM).
func unlockScope(ctx context.Context, m *papi.Manager, sess *Session, username string, password []byte) error {
	info, err := m.AuthInfo(ctx, papi.AuthInfoReq{Username: username})
	if err != nil {
		return fmt.Errorf("fetching auth info: %w", err)
	}

	srpAuth, err := srp.NewAuth(info.Version, username, password, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("preparing SRP auth: %w", err)
	}
	proofs, err := srpAuth.GenerateProofs(2048)
	if err != nil {
		return fmt.Errorf("generating SRP proofs: %w", err)
	}

	var out struct {
		Code        int
		ServerProof string
	}
	if err := rawPut(ctx, sess, "/core/v4/users/unlock", map[string]any{
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}, &out); err != nil {
		return fmt.Errorf("PUT /core/v4/users/unlock: %w", err)
	}

	serverProof, err := base64.StdEncoding.DecodeString(out.ServerProof)
	if err != nil {
		return fmt.Errorf("decoding server proof: %w", err)
	}
	if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		return errors.New("server proof mismatch on unlock: possible MITM or server misbehaviour")
	}
	return nil
}

// rawPut makes an authenticated JSON PUT directly against the Proton API (same
// headers as go-proton-api: x-pm-uid + Bearer + x-pm-appversion), for the
// endpoints the library does not expose.
func rawPut(ctx context.Context, sess *Session, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, papi.DefaultHostURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("x-pm-uid", sess.UID)
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	req.Header.Set("x-pm-appversion", appVersion)
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Set("Content-Type", "application/json")

	httpc := &http.Client{Timeout: 30 * time.Second}
	res, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var envelope struct {
			Code    int
			Message string `json:"Error"`
		}
		_ = json.Unmarshal(raw, &envelope)
		return fmt.Errorf("status=%d code=%d: %s", res.StatusCode, envelope.Code, envelope.Message)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decoding %s response: %w", path, err)
		}
	}
	return nil
}

// primaryUserKeyID returns the ID of the user key marked primary, otherwise
// the first one.
func primaryUserKeyID(user papi.User) (string, error) {
	if len(user.Keys) == 0 {
		return "", errors.New("proton: user has no keys")
	}
	for _, key := range user.Keys {
		if key.Primary {
			return key.ID, nil
		}
	}
	return user.Keys[0].ID, nil
}
