package pipeline

import (
	"log"
	"sync/atomic"
	"time"

	"gpewebdefender/internal/detect"
	"gpewebdefender/internal/event"
	"gpewebdefender/internal/geo"
	"gpewebdefender/internal/hub"
	"gpewebdefender/internal/parse"
	"gpewebdefender/internal/store"
)

// Pipeline parses a raw line, stores it, runs detection, stores+broadcasts alerts.
type Pipeline struct {
	Store   *store.Store
	Engine  *detect.Engine
	Hub     *hub.Hub
	Geo     *geo.Resolver
	Seen    atomic.Int64
	Fired   atomic.Int64
	Dropped atomic.Int64
}

func (p *Pipeline) IngestLine(line, source string) {
	ev, ok := parse.Parse(line, source)
	if !ok {
		p.Dropped.Add(1)
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.ID == "" {
		ev.ID = store.ID()
	}
	if ev.Kind == "" {
		ev.Kind = event.KindWeb
	}
	p.Seen.Add(1)
	if err := p.Store.InsertEvent(ev); err != nil {
		log.Printf("store event: %v", err)
	}
	for _, al := range p.Engine.Evaluate(ev) {
		al.ID = store.ID()
		if al.Time.IsZero() {
			al.Time = ev.Time
		}
		p.enrich(&al)
		p.Fired.Add(1)
		if err := p.Store.InsertAlert(&al); err != nil {
			log.Printf("store alert: %v", err)
			continue
		}
		if p.Hub != nil {
			p.Hub.Publish(al)
		}
	}
}

func (p *Pipeline) IngestEvent(ev event.Event) {
	if ev.Decoded == "" {
		ev.Decoded = parse.DecodeForMatch(ev.Path, ev.Query)
	}
	raw, _ := evToLine(ev)
	if raw != "" {
		p.IngestLine(raw, ev.Source)
		return
	}
	// Already structured — skip re-parse.
	if ev.ID == "" {
		ev.ID = store.ID()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Kind == "" {
		ev.Kind = event.KindWeb
	}
	if ev.Kind == event.KindAppLogin {
		if ev.Method == "" {
			ev.Method = "LOGIN"
		}
		if ev.Outcome == "" {
			if ev.Status == 401 || ev.Status == 403 {
				ev.Outcome = event.OutcomeFail
			} else if ev.Status >= 200 && ev.Status < 400 {
				ev.Outcome = event.OutcomeOK
			}
		}
	}
	p.Seen.Add(1)
	_ = p.Store.InsertEvent(ev)
	for _, al := range p.Engine.Evaluate(ev) {
		al.ID = store.ID()
		p.enrich(&al)
		p.Fired.Add(1)
		_ = p.Store.InsertAlert(&al)
		if p.Hub != nil {
			p.Hub.Publish(al)
		}
	}
}

func (p *Pipeline) enrich(al *event.Alert) {
	if p.Geo == nil {
		return
	}
	loc := p.Geo.Lookup(al.SrcIP)
	if !loc.Ok {
		return
	}
	al.Country = loc.Country
	al.CountryName = loc.Name
	al.Lat = loc.Lat
	al.Lon = loc.Lon
	al.HasGeo = true
}

func evToLine(ev event.Event) (string, bool) {
	if ev.Raw != "" {
		return ev.Raw, true
	}
	return "", false
}
