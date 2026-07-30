package caldav

import (
	"testing"
	"time"

	"github.com/jmdlab/cal-gateway/internal/proton"
)

// isOccurrenceDeletionOnly is the gate that lets "delete this occurrence" through
// on an invited series. It guards a real boundary: anything wider would let a PUT
// silently rewrite an event organised by a third party. These cases pin the
// narrowness — only EXDATE additions may pass.
func TestIsOccurrenceDeletionOnly(t *testing.T) {
	base := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ex1 := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	ex2 := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)

	row := proton.Event{
		Start: base, End: base.Add(time.Hour),
		RRule: "FREQ=WEEKLY", Title: "Thomas", Description: "d", Location: "l",
		ExDates: []time.Time{ex1},
	}
	// The stored event, unchanged, as a PUT.
	same := func() proton.EventInput {
		return proton.EventInput{
			Start: row.Start, End: row.End, AllDay: row.AllDay,
			RRule: row.RRule, Title: row.Title, Description: row.Description,
			Location: row.Location, ExDates: []time.Time{ex1},
		}
	}
	// The stored event plus one more excluded occurrence = the deletion.
	deletion := func() proton.EventInput {
		in := same()
		in.ExDates = []time.Time{ex1, ex2}
		return in
	}

	t.Run("suppression pure passe", func(t *testing.T) {
		if !isOccurrenceDeletionOnly(deletion(), row) {
			t.Fatal("une EXDATE ajoutée, rien d'autre modifié : doit passer")
		}
	})

	// Every case below must be REFUSED: they are edits wearing a deletion's coat.
	for _, tc := range []struct {
		name  string
		muter func(*proton.EventInput)
	}{
		{"titre modifié", func(in *proton.EventInput) { in.Title = "Autre" }},
		{"description modifiée", func(in *proton.EventInput) { in.Description = "x" }},
		{"lieu modifié", func(in *proton.EventInput) { in.Location = "ailleurs" }},
		{"début déplacé", func(in *proton.EventInput) { in.Start = base.Add(30 * time.Minute) }},
		{"fin déplacée", func(in *proton.EventInput) { in.End = base.Add(2 * time.Hour) }},
		{"bascule journée entière", func(in *proton.EventInput) { in.AllDay = !in.AllDay }},
		{"RRULE tronquée (this-and-following)", func(in *proton.EventInput) { in.RRule = "FREQ=WEEKLY;UNTIL=20261001T000000Z" }},
		{"statut annulé", func(in *proton.EventInput) { in.Status = "CANCELLED" }},
		{"transparence changée", func(in *proton.EventInput) { in.Transp = "TRANSPARENT" }},
	} {
		t.Run("refusé : "+tc.name, func(t *testing.T) {
			in := deletion()
			tc.muter(&in)
			if isOccurrenceDeletionOnly(in, row) {
				t.Fatalf("%s accompagné d'une EXDATE : doit être refusé", tc.name)
			}
		})
	}

	t.Run("refusé : aucune EXDATE ajoutée", func(t *testing.T) {
		if isOccurrenceDeletionOnly(same(), row) {
			t.Fatal("EXDATE identiques : ce n'est pas une suppression")
		}
	})

	t.Run("refusé : EXDATE retirée (dé-suppression)", func(t *testing.T) {
		in := same()
		in.ExDates = nil
		if isOccurrenceDeletionOnly(in, row) {
			t.Fatal("moins d'EXDATE : opération différente, doit être refusé")
		}
	})

	t.Run("refusé : une EXDATE stockée écrasée", func(t *testing.T) {
		in := same()
		in.ExDates = []time.Time{ex2, ex2.Add(24 * time.Hour)} // ex1 perdue
		if isOccurrenceDeletionOnly(in, row) {
			t.Fatal("une exclusion stockée disparaît : doit être refusé")
		}
	})

	t.Run("refusé : événement non récurrent", func(t *testing.T) {
		nr := row
		nr.RRule = ""
		in := deletion()
		in.RRule = ""
		if isOccurrenceDeletionOnly(in, nr) {
			t.Fatal("sans RRULE il n'y a pas d'occurrence à supprimer")
		}
	})
}
