module github.com/jmdlab/cal-gateway

go 1.26.5

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/ProtonMail/go-proton-api v0.4.1-0.20260608154204-c913195ec724
	github.com/ProtonMail/go-srp v0.0.7
	github.com/ProtonMail/gopenpgp/v2 v2.10.0-proton
	github.com/emersion/go-ical v0.0.0-20240127095438-fc1c9d8fb2b6
	github.com/emersion/go-webdav v0.7.0
	github.com/go-resty/resty/v2 v2.17.2
	github.com/wneessen/go-mail v0.8.1
	golang.org/x/sync v0.22.0
	golang.org/x/term v0.45.0
)

require (
	github.com/ProtonMail/bcrypt v0.0.0-20211005172633-e235017c1baf // indirect
	github.com/ProtonMail/gluon v0.17.1-0.20260225115619-c0f05c033a4a // indirect
	github.com/ProtonMail/go-crypto v1.4.1-proton // indirect
	github.com/ProtonMail/go-mime v0.0.0-20230322103455-7d82a3887f2f // indirect
	github.com/PuerkitoBio/goquery v1.12.0 // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/bradenaw/juniper v0.15.3 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cronokirby/saferith v0.33.0 // indirect
	github.com/emersion/go-message v0.16.0 // indirect
	github.com/emersion/go-textwrapper v0.0.0-20200911093747-65d896831594 // indirect
	github.com/emersion/go-vcard v0.0.0-20230815062825-8fda7d206ec9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/teambition/rrule-go v1.8.2 // indirect
	gitlab.com/c0b/go-ordered-json v0.0.0-20201030195603-febf46534d5a // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/go-resty/resty/v2 => github.com/ProtonMail/resty/v2 v2.0.0-20250929142426-e3dc6308c80b
