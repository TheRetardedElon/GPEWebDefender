// Package intel trickles optional third-party IP checks. Off unless ABUSEIPDB_KEY is set.
// One request at a time, ~90s apart, cached. Never scrapes HTML lookup pages.
package intel

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"gpewebdefender/internal/event"
	"gpewebdefender/internal/store"
)

const (
	providerAbuse = "abuseipdb"
	minGap        = 90 * time.Second
	maxJitter     = 20 * time.Second
)

// Enabled is true when a provider key is present.
func Enabled() bool {
	return strings.TrimSpace(os.Getenv("ABUSEIPDB_KEY")) != ""
}

// Run pulls one queued IP at a time. Safe to start even with no key (it just waits / no-ops).
func Run(ctx context.Context, st *store.Store) {
	if !Enabled() {
		log.Print("intel trickle off — no ABUSEIPDB_KEY; local weight + browser links only")
		return
	}
	log.Print("intel trickle on — AbuseIPDB, ~90s between checks, cache first")
	client := &http.Client{Timeout: 12 * time.Second}
	fails := 0
	pauseUntil := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(minGap + time.Duration(rand.Int63n(int64(maxJitter)))):
		}
		if time.Now().Before(pauseUntil) {
			continue
		}
		ip, ok := st.NextIntelJob()
		if !ok {
			continue
		}
		code, score, note, raw, err := checkAbuse(client, ip)
		st.LogIntelFetch(ip, providerAbuse, code)
		if err != nil || code == 429 || code >= 500 {
			fails++
			if fails >= 3 {
				pauseUntil = time.Now().Add(30 * time.Minute)
				fails = 0
				log.Print("intel trickle paused 30m after provider errors")
			}
			st.EnqueueIntel(ip, 4, "retry")
			continue
		}
		fails = 0
		if code != 200 {
			continue
		}
		ttl := 48 * time.Hour
		if score >= 75 {
			ttl = 2 * time.Hour
		} else if score >= 25 {
			ttl = 8 * time.Hour
		}
		st.SaveIntelCache(ip, providerAbuse, score, note, raw, ttl)
	}
}

// MaybeQueue is called after an alert. Only hot things go on the slow queue.
func MaybeQueue(st *store.Store, al event.Alert) {
	if st == nil || !Enabled() {
		return
	}
	if al.SrcIP == "" {
		return
	}
	prio := 0
	reason := ""
	switch {
	case al.Category == "canary" || al.Severity == "critical":
		prio, reason = 1, al.Category
	case al.Severity == "high":
		prio, reason = 2, al.Severity
	default:
		return
	}
	st.EnqueueIntel(al.SrcIP, prio, reason)
}

type abuseResp struct {
	Data struct {
		Score   int    `json:"abuseConfidenceScore"`
		Reports int    `json:"totalReports"`
		ISP     string `json:"isp"`
		Usage   string `json:"usageType"`
		Tor     bool   `json:"isTor"`
	} `json:"data"`
}

func checkAbuse(client *http.Client, ip string) (code, score int, note, raw string, err error) {
	key := strings.TrimSpace(os.Getenv("ABUSEIPDB_KEY"))
	req, err := http.NewRequest(http.MethodGet, "https://api.abuseipdb.com/api/v2/check?ipAddress="+ip+"&maxAgeInDays=90", nil)
	if err != nil {
		return 0, 0, "", "", err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gwd-intel-trickle/0.9")
	res, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	code = res.StatusCode
	raw = string(body)
	if code != 200 {
		return code, 0, "", raw, nil
	}
	var parsed abuseResp
	if json.Unmarshal(body, &parsed) != nil {
		return code, 0, "", raw, nil
	}
	note = strings.TrimSpace(parsed.Data.Usage + " " + parsed.Data.ISP)
	if parsed.Data.Tor {
		note = strings.TrimSpace(note + " tor")
	}
	if parsed.Data.Reports > 0 {
		note = strings.TrimSpace(note + " reports=" + itoa(parsed.Data.Reports))
	}
	return code, parsed.Data.Score, note, raw, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
