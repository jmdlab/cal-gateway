// PROPPATCH: go-webdav does not implement it and answers 501, which breaks
// dataaccessd's sync sequence (macOS/iOS sends PROPPATCH calendar-color /
// calendar-order on every collection before writing). So we intercept
// PROPPATCH here and answer a 207 multistatus that ACCEPTS (propstat 200) each
// requested property. A polite refusal (403) was tried first: dataaccessd
// RETRIES it in a loop (2×/cycle observed in capture) and shows "Calendar
// update failed (Error 2)" — calendar-color/order are cosmetic display
// preferences, and accepting them without persisting is the posture that
// coexists with Apple (the client never re-reads the value in a mandatory
// PROPFIND; if it re-pushes, we re-accept).
//
// If one day we truly want to persist color/name, this becomes a real handler
// backed by the store — for now the gateway is a mirror, and presentation
// metadata stays Proton's property.
package server

import (
	"encoding/xml"
	"io"
	"net/http"
)

// proppatchMaxBody bounds the accepted body: a real propertyupdate is a few
// hundred bytes, 1 MiB is already very generous.
const proppatchMaxBody = 1 << 20

// propertyupdate is the bare minimum to extract property names from a
// PROPPATCH (DAV:propertyupdate > set|remove > prop > *).
type propertyupdate struct {
	Set    []propContainer `xml:"set"`
	Remove []propContainer `xml:"remove"`
}

type propContainer struct {
	Prop rawProps `xml:"prop"`
}

type rawProps struct {
	Names []xml.Name `xml:",any"`
}

func (p *rawProps) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			p.Names = append(p.Names, t.Name)
			if err := d.Skip(); err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// interceptProppatch answers PROPPATCH in place of the go-webdav handler
// (which would return 501); any other verb falls through to the next handler.
func interceptProppatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PROPPATCH" {
			next.ServeHTTP(w, r)
			return
		}

		var names []xml.Name
		body, err := io.ReadAll(io.LimitReader(r.Body, proppatchMaxBody))
		if err == nil {
			var pu propertyupdate
			if xml.Unmarshal(body, &pu) == nil {
				for _, c := range append(pu.Set, pu.Remove...) {
					names = append(names, c.Prop.Names...)
				}
			}
		}

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		writeProppatchRefusal(w, r.URL.Path, names)
	})
}

// writeProppatchRefusal emits the multistatus: each requested property in a
// propstat 200 OK (accepted, not persisted). Empty/unreadable body → a single
// propstat 200 with no named prop.
func writeProppatchRefusal(w io.Writer, href string, names []xml.Name) {
	enc := xml.NewEncoder(w)
	io.WriteString(w, xml.Header)

	// Generic prop>name encoding with arbitrary namespaces is awkward via
	// structs; we write the tokens by hand.
	start := xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "multistatus"}}
	enc.EncodeToken(start)

	respStart := xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "response"}}
	enc.EncodeToken(respStart)
	enc.EncodeElement(href, xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "href"}})

	psStart := xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "propstat"}}
	enc.EncodeToken(psStart)
	propStart := xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "prop"}}
	enc.EncodeToken(propStart)
	for _, n := range names {
		el := xml.StartElement{Name: n}
		enc.EncodeToken(el)
		enc.EncodeToken(el.End())
	}
	enc.EncodeToken(propStart.End())
	enc.EncodeElement("HTTP/1.1 200 OK", xml.StartElement{Name: xml.Name{Space: "DAV:", Local: "status"}})
	enc.EncodeToken(psStart.End())

	enc.EncodeToken(respStart.End())
	enc.EncodeToken(start.End())
	enc.Flush()
}
