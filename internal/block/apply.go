package block

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	BackendOff      = "off"
	BackendFail2ban = "fail2ban"
	BackendUFW      = "ufw"
	BackendWindows  = "windows"
)

// Run is swapped in tests.
var Run = func(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var LookPath = exec.LookPath

func NormalizeBackend(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case BackendFail2ban, "f2b":
		return BackendFail2ban
	case BackendUFW:
		return BackendUFW
	case BackendWindows, "netsh", "advfirewall":
		return BackendWindows
	case BackendOff, "none", "no", "":
		return BackendOff
	default:
		return ""
	}
}

func DetectBackend() string {
	if runtime.GOOS == "windows" {
		if _, err := LookPath("netsh"); err == nil {
			return BackendWindows
		}
		return BackendOff
	}
	if _, err := LookPath("fail2ban-client"); err == nil {
		return BackendFail2ban
	}
	if _, err := LookPath("ufw"); err == nil {
		return BackendUFW
	}
	return BackendOff
}

type ApplyResult struct {
	Backend string
	OK      bool
	Detail  string
}

func Ban(backend, jail, ip string, until time.Time) ApplyResult {
	backend = NormalizeBackend(backend)
	if backend == BackendOff {
		return ApplyResult{Backend: backend, Detail: "block is off on this host"}
	}
	switch backend {
	case BackendFail2ban:
		return banFail2ban(jail, ip)
	case BackendUFW:
		return banUFW(ip)
	case BackendWindows:
		return banWindows(ip)
	default:
		return ApplyResult{Backend: backend, Detail: "unknown backend"}
	}
}

func Unban(backend, jail, ip string) ApplyResult {
	backend = NormalizeBackend(backend)
	if backend == BackendOff {
		return ApplyResult{Backend: backend, Detail: "block is off on this host"}
	}
	switch backend {
	case BackendFail2ban:
		return unbanFail2ban(jail, ip)
	case BackendUFW:
		return unbanUFW(ip)
	case BackendWindows:
		return unbanWindows(ip)
	default:
		return ApplyResult{Backend: backend, Detail: "unknown backend"}
	}
}

func jailName(jail string) string {
	j := strings.TrimSpace(jail)
	if j == "" {
		return "gpesiem"
	}
	return j
}

func banFail2ban(jail, ip string) ApplyResult {
	j := jailName(jail)
	if _, err := LookPath("fail2ban-client"); err != nil {
		return ApplyResult{Backend: BackendFail2ban, Detail: "fail2ban-client not on PATH"}
	}
	if err := ensureFail2banJail(j); err != nil {
		return ApplyResult{Backend: BackendFail2ban, Detail: err.Error()}
	}
	out, err := Run("fail2ban-client", "set", j, "banip", ip)
	if err != nil {
		return ApplyResult{Backend: BackendFail2ban, Detail: firstLine(out, err)}
	}
	return ApplyResult{Backend: BackendFail2ban, OK: true, Detail: firstLine(out, nil)}
}

func unbanFail2ban(jail, ip string) ApplyResult {
	j := jailName(jail)
	out, err := Run("fail2ban-client", "set", j, "unbanip", ip)
	if err != nil {
		return ApplyResult{Backend: BackendFail2ban, Detail: firstLine(out, err)}
	}
	return ApplyResult{Backend: BackendFail2ban, OK: true, Detail: firstLine(out, nil)}
}

func ensureFail2banJail(jail string) error {
	if _, err := Run("fail2ban-client", "status", jail); err == nil {
		return nil
	}
	if err := writeFail2banJail(jail); err != nil {
		return fmt.Errorf("jail %s missing and could not install it: %w", jail, err)
	}
	_, _ = Run("fail2ban-client", "reload", jail)
	_, _ = Run("systemctl", "reload", "fail2ban")
	if _, err := Run("fail2ban-client", "status", jail); err != nil {
		return fmt.Errorf("jail %s still missing after install — add deploy/fail2ban-gpesiem.jail by hand", jail)
	}
	return nil
}

func writeFail2banJail(jail string) error {
	filter := `[Definition]
failregex =
ignoreregex =
`
	unit := fmt.Sprintf(`[gpesiem]
# Dedicated jail. The agent bans via fail2ban-client, not log matches.
enabled  = true
filter   = gpesiem
banaction = ufw
bantime  = 7d
findtime = 1d
maxretry = 999999
backend  = systemd
`)
	if jail != "gpesiem" {
		unit = strings.Replace(unit, "[gpesiem]", "["+jail+"]", 1)
		unit = strings.Replace(unit, "filter   = gpesiem", "filter   = "+jail, 1)
	}
	if err := os.WriteFile("/etc/fail2ban/filter.d/"+jail+".conf", []byte(filter), 0o644); err != nil {
		return err
	}
	return os.WriteFile("/etc/fail2ban/jail.d/"+jail+".local", []byte(unit), 0o644)
}

func banUFW(ip string) ApplyResult {
	if _, err := LookPath("ufw"); err != nil {
		return ApplyResult{Backend: BackendUFW, Detail: "ufw not on PATH"}
	}
	out, err := Run("ufw", "insert", "1", "deny", "from", ip, "comment", "gpesiem")
	if err != nil {
		out2, err2 := Run("ufw", "deny", "from", ip, "comment", "gpesiem")
		if err2 != nil {
			return ApplyResult{Backend: BackendUFW, Detail: firstLine(out+" "+out2, err2)}
		}
		out = out2
	}
	return ApplyResult{Backend: BackendUFW, OK: true, Detail: firstLine(out, nil)}
}

func unbanUFW(ip string) ApplyResult {
	out, err := Run("ufw", "delete", "deny", "from", ip)
	if err != nil {
		return ApplyResult{Backend: BackendUFW, Detail: firstLine(out, err)}
	}
	return ApplyResult{Backend: BackendUFW, OK: true, Detail: firstLine(out, nil)}
}

func ruleName(ip string) string {
	return "gwd-" + strings.ReplaceAll(ip, ":", "-")
}

func banWindows(ip string) ApplyResult {
	if runtime.GOOS != "windows" {
		return ApplyResult{Backend: BackendWindows, Detail: "windows backend only on Windows"}
	}
	name := ruleName(ip)
	_, _ = Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	out, err := Run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=in", "action=block", "remoteip="+ip, "enable=yes")
	if err != nil {
		return ApplyResult{Backend: BackendWindows, Detail: firstLine(out, err)}
	}
	return ApplyResult{Backend: BackendWindows, OK: true, Detail: firstLine(out, nil)}
}

func unbanWindows(ip string) ApplyResult {
	if runtime.GOOS != "windows" {
		return ApplyResult{Backend: BackendWindows, Detail: "windows backend only on Windows"}
	}
	out, err := Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName(ip))
	if err != nil {
		return ApplyResult{Backend: BackendWindows, Detail: firstLine(out, err)}
	}
	return ApplyResult{Backend: BackendWindows, OK: true, Detail: firstLine(out, nil)}
}

func firstLine(out string, err error) string {
	s := strings.TrimSpace(out)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" && err != nil {
		return err.Error()
	}
	if err != nil && s != "" {
		return s
	}
	return s
}
