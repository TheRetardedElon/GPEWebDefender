package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"gpewebdefender/internal/block"
	"gpewebdefender/internal/hoststat"
	"gpewebdefender/internal/store"
)

func pairCmd(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	url := fs.String("url", "", "manager URL (https://monitor.example:8787)")
	name := fs.String("name", hostname(), "stable host name shown in the UI")
	code := fs.String("code", "", "one-time pair code from Settings")
	phrase := fs.String("phrase", "", "enrollment phrase (omit to type it)")
	cred := fs.String("cred", defaultCredPath(), "where to write the host key")
	backend := fs.String("block", "", "fail2ban, ufw, windows, or off (empty = detect)")
	jail := fs.String("jail", "gpesiem", "fail2ban jail name")
	_ = fs.Parse(args)
	if *url == "" || *code == "" {
		log.Fatal("pair requires --url and --code")
	}
	if !store.ValidAgentName(*name) {
		log.Fatal("name must be 2–40 letters, numbers, . _ -")
	}
	ph := strings.TrimSpace(*phrase)
	if ph == "" {
		ph = strings.TrimSpace(os.Getenv("GWD_PAIR_PHRASE"))
	}
	if ph == "" {
		fmt.Fprint(os.Stderr, "Enrollment phrase: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		ph = strings.TrimSpace(line)
	}
	if ph == "" {
		log.Fatal("enrollment phrase is required")
	}
	blk := block.NormalizeBackend(*backend)
	if blk == "" {
		blk = block.DetectBackend()
	}

	body, _ := json.Marshal(map[string]string{
		"name": *name, "code": *code, "phrase": ph,
		"os": runtime.GOOS, "hostname": hostname(), "version": version,
	})
	endpoint := strings.TrimRight(*url, "/") + "/api/agent/pair"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		log.Fatal(err)
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if res.StatusCode >= 300 {
		log.Fatalf("pair failed: %s %s", res.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		OK          bool   `json:"ok"`
		ID          string `json:"id"`
		Secret      string `json:"secret"`
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"name"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Secret == "" {
		log.Fatalf("bad pair response: %s", raw)
	}
	c := agentCred{
		ID: out.ID, Secret: out.Secret, Name: out.Name, URL: strings.TrimRight(*url, "/"),
		Block: blk, Jail: *jail, Status: out.Status,
	}
	if err := saveCred(*cred, c); err != nil {
		log.Fatalf("write %s: %v", *cred, err)
	}
	fmt.Printf("paired as %s\n", c.Name)
	fmt.Printf("  fingerprint %s\n", out.Fingerprint)
	fmt.Printf("  key file    %s (mode 0600)\n", *cred)
	fmt.Printf("  block       %s\n", blk)
	fmt.Println("in the dashboard: Settings → Hosts → Approve this host. Until then it cannot take block orders.")
	waitEnroll(c, *cred)
}

func waitEnroll(c agentCred, credPath string) {
	fmt.Println("waiting for an admin to Approve… (Ctrl+C to stop; you can start the agent anytime)")
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, c.URL+"/api/agent/enroll", nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+c.Secret)
		res, err := client.Do(req)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		var st struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(res.Body).Decode(&st)
		res.Body.Close()
		if st.Status == store.AgentActive {
			c.Status = st.Status
			_ = saveCred(credPath, c)
			fmt.Println("approved. this host can take block orders.")
			return
		}
		if st.Status == store.AgentRejected || st.Status == store.AgentRevoked {
			fmt.Println("this pair was rejected. mint a new code and try again.")
			return
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("still pending. start the agent; it will pick up Approve later.")
}

func applyAgentCommand(c agentCred, credPath string, cmd map[string]any) (string, string) {
	action, _ := cmd["action"].(string)
	ip, _ := cmd["ip"].(string)
	switch action {
	case "ban":
		var until time.Time
		if v, ok := cmd["until"].(string); ok && v != "" && v != "0001-01-01T00:00:00Z" {
			until, _ = time.Parse(time.RFC3339, v)
		}
		res := block.Ban(c.Block, c.Jail, ip, until)
		if res.OK {
			rememberBan(credPath, ip, until)
			return store.CmdDone, res.Detail
		}
		return store.CmdFailed, res.Detail
	case "unban":
		res := block.Unban(c.Block, c.Jail, ip)
		if res.OK {
			forgetBan(credPath, ip)
			return store.CmdDone, res.Detail
		}
		return store.CmdFailed, res.Detail
	case "list":
		return store.CmdDone, "ok"
	case "stats":
		snap := hoststat.Collect(version)
		body, _ := json.Marshal(snap)
		req, err := http.NewRequest(http.MethodPost, c.URL+"/api/agent/stats", bytes.NewReader(body))
		if err != nil {
			return store.CmdFailed, err.Error()
		}
		req.Header.Set("Authorization", "Bearer "+c.Secret)
		req.Header.Set("Content-Type", "application/json")
		res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			return store.CmdFailed, err.Error()
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode >= 300 {
			return store.CmdFailed, res.Status
		}
		return store.CmdDone, "ok"
	default:
		return store.CmdFailed, "unknown action"
	}
}

func expireLocalBans(c agentCred, credPath string) {
	f := loadLocalBans(credPath)
	now := time.Now().UnixMilli()
	changed := false
	for ip, until := range f.Bans {
		if until > 0 && until <= now {
			res := block.Unban(c.Block, c.Jail, ip)
			if res.OK || strings.Contains(strings.ToLower(res.Detail), "not found") {
				delete(f.Bans, ip)
				changed = true
			}
		}
	}
	if changed {
		saveLocalBans(credPath, f)
	}
}

func pollCommands(ctx context.Context, c *agentCred, credPath string) {
	if c == nil || c.Secret == "" || c.URL == "" {
		return
	}
	client := &http.Client{Timeout: 15 * time.Second}
	hello := func() {
		body, _ := json.Marshal(map[string]string{
			"os": runtime.GOOS, "hostname": hostname(), "version": version,
			"block": c.Block, "jail": c.Jail,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/agent/hello", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+c.Secret)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return
		}
		var out struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if out.Status != "" && out.Status != c.Status {
			c.Status = out.Status
			_ = saveCred(credPath, *c)
			if out.Status == store.AgentActive {
				log.Printf("host %s approved — block orders enabled", c.Name)
			}
		}
	}
	hello()
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			expireLocalBans(*c, credPath)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/api/agent/commands", nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+c.Secret)
			res, err := client.Do(req)
			if err != nil {
				continue
			}
			var out struct {
				Commands []map[string]any `json:"commands"`
			}
			_ = json.NewDecoder(res.Body).Decode(&out)
			res.Body.Close()
			if res.StatusCode == http.StatusForbidden {
				continue
			}
			for _, cmd := range out.Commands {
				id, _ := cmd["id"].(string)
				st, detail := applyAgentCommand(*c, credPath, cmd)
				if id == "" {
					continue
				}
				body, _ := json.Marshal(map[string]string{"status": st, "result": detail})
				r2, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/agent/commands/"+id+"/result", bytes.NewReader(body))
				if err != nil {
					continue
				}
				r2.Header.Set("Authorization", "Bearer "+c.Secret)
				r2.Header.Set("Content-Type", "application/json")
				res2, err := client.Do(r2)
				if err == nil {
					io.Copy(io.Discard, res2.Body)
					res2.Body.Close()
				}
				act, _ := cmd["action"].(string)
				if st == store.CmdDone {
					if act == "stats" {
						log.Printf("stats posted")
					} else {
						log.Printf("block %s %s: %s", act, cmd["ip"], detail)
					}
				} else {
					log.Printf("command %s failed: %s", act, detail)
				}
			}
		}
	}
}
