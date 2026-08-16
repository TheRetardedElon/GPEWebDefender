package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type agentCred struct {
	ID      string `json:"id"`
	Secret  string `json:"secret"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Block   string `json:"block,omitempty"`
	Jail    string `json:"jail,omitempty"`
	Status  string `json:"status,omitempty"`
}

type localBanFile struct {
	Bans map[string]int64 `json:"bans"`
}

func defaultCredPath() string {
	if v := os.Getenv("GWD_AGENT_FILE"); v != "" {
		return v
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat("/etc/gpewebdefender"); err == nil && st.IsDir() {
			return "/etc/gpewebdefender/agent.json"
		}
	}
	return "agent.json"
}

func loadCred(path string) (agentCred, error) {
	var c agentCred
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func saveCred(path string, c agentCred) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && !os.IsExist(err) {
		// dir may be "." 
		if filepath.Dir(path) != "." {
			return err
		}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func banStatePath(credPath string) string {
	return strings.TrimSuffix(credPath, filepath.Ext(credPath)) + ".bans.json"
}

func loadLocalBans(credPath string) localBanFile {
	var f localBanFile
	b, err := os.ReadFile(banStatePath(credPath))
	if err != nil {
		f.Bans = map[string]int64{}
		return f
	}
	if json.Unmarshal(b, &f) != nil || f.Bans == nil {
		f.Bans = map[string]int64{}
	}
	return f
}

func saveLocalBans(credPath string, f localBanFile) {
	if f.Bans == nil {
		f.Bans = map[string]int64{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(banStatePath(credPath), append(b, '\n'), 0o600)
}

func rememberBan(credPath, ip string, until time.Time) {
	f := loadLocalBans(credPath)
	if until.IsZero() {
		f.Bans[ip] = 0
	} else {
		f.Bans[ip] = until.UnixMilli()
	}
	saveLocalBans(credPath, f)
}

func forgetBan(credPath, ip string) {
	f := loadLocalBans(credPath)
	delete(f.Bans, ip)
	saveLocalBans(credPath, f)
}
