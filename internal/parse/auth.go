package parse

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

// syslog / auth.log:
//   Aug 15 01:40:03 box sshd[11]: Failed password for root from 1.2.3.4 port 22 ssh2
//   2026-08-15T01:40:03.1+00:00 box sshd[11]: Accepted publickey for deploy from 1.2.3.4 port 22 ssh2
var syslogHead = regexp.MustCompile(`^(?:(\d{4}-\d{2}-\d{2}T\S+)|([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$`)

var (
	reFailPass = regexp.MustCompile(`(?i)Failed password for (invalid user )?(\S+) from (\S+)(?: port (\d+))?`)
	reInvalid  = regexp.MustCompile(`(?i)Invalid user (\S+) from (\S+)`)
	reAccepted = regexp.MustCompile(`(?i)Accepted (?:password|publickey|keyboard-interactive|passkey) for (\S+) from (\S+)`)
	reMaxAuth  = regexp.MustCompile(`(?i)(?:maximum authentication attempts exceeded|Too many authentication failures) for (\S+)(?: from (\S+))?`)
	rePAM      = regexp.MustCompile(`(?i)pam_unix\([^)]+\):\s+authentication failure`)
	rePAMUser  = regexp.MustCompile(`(?i)\buser=(\S+)`)
	rePAMHost  = regexp.MustCompile(`(?i)\brhost=(\S+)`)
	reSudo     = regexp.MustCompile(`(?i)^(\S+) : .*USER=(\S+)\s*;\s*COMMAND=(.+)$`)
	reLoginFail = regexp.MustCompile(`(?i)FAILED LOGIN.*FOR ['"]?(\S+?)['"]?(?:,|$)`)
)

// parseAuth recognizes sshd / sudo / login / pam failures. Everything else is ignored
// on purpose — this is not a general syslog SIEM.
func parseAuth(line, source string) (event.Event, bool) {
	m := syslogHead.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	ts := parseSyslogTime(m[1], m[2])
	host := m[3]
	proc := strings.ToLower(m[4])
	if i := strings.IndexByte(proc, '/'); i >= 0 {
		proc = proc[i+1:]
	}
	msg := m[6]

	ev := event.Event{
		Time:   ts,
		Host:   host,
		Source: source,
		Raw:    line,
		Kind:   event.KindHostAuth,
	}

	switch {
	case strings.Contains(proc, "sshd") || strings.Contains(strings.ToLower(msg), "sshd"):
		if !fillSSH(&ev, msg) {
			return event.Event{}, false
		}
	case strings.Contains(proc, "sudo"):
		if !fillSudo(&ev, msg) {
			return event.Event{}, false
		}
	case strings.Contains(proc, "login") || strings.Contains(proc, "gdm") || strings.Contains(proc, "lightdm"):
		if !fillLogin(&ev, msg) {
			return event.Event{}, false
		}
	case strings.Contains(strings.ToLower(msg), "authentication failure"):
		if !fillPAM(&ev, proc, msg) {
			return event.Event{}, false
		}
	default:
		return event.Event{}, false
	}
	if ev.Decoded == "" {
		ev.Decoded = ev.URL
	}
	return ev, true
}

func fillSSH(ev *event.Event, msg string) bool {
	ev.Method = "SSH"
	ev.Path = "sshd"
	if m := reFailPass.FindStringSubmatch(msg); m != nil {
		ev.Outcome = event.OutcomeFail
		ev.Status = 401
		ev.User = m[2]
		ev.SrcIP = stripHostPort(m[3])
		if strings.TrimSpace(m[1]) != "" {
			ev.URL = "invalid user " + ev.User + " from " + ev.SrcIP
			ev.Query = "invalid"
		} else {
			ev.URL = "failed password for " + ev.User + " from " + ev.SrcIP
		}
		return ev.SrcIP != ""
	}
	if m := reInvalid.FindStringSubmatch(msg); m != nil {
		ev.Outcome = event.OutcomeFail
		ev.Status = 401
		ev.User = m[1]
		ev.SrcIP = stripHostPort(m[2])
		ev.URL = "invalid user " + ev.User + " from " + ev.SrcIP
		ev.Query = "invalid"
		return ev.SrcIP != ""
	}
	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		ev.Outcome = event.OutcomeOK
		ev.Status = 200
		ev.User = m[1]
		ev.SrcIP = stripHostPort(m[2])
		ev.URL = "accepted for " + ev.User + " from " + ev.SrcIP
		return ev.SrcIP != ""
	}
	if m := reMaxAuth.FindStringSubmatch(msg); m != nil {
		ev.Outcome = event.OutcomeFail
		ev.Status = 401
		ev.User = m[1]
		if len(m) > 2 {
			ev.SrcIP = stripHostPort(m[2])
		}
		ev.URL = "max auth failures for " + ev.User
		return true
	}
	return false
}

func fillSudo(ev *event.Event, msg string) bool {
	m := reSudo.FindStringSubmatch(msg)
	if m == nil {
		low := strings.ToLower(msg)
		if strings.Contains(low, "authentication failure") || strings.Contains(low, "incorrect password") {
			ev.Method = "SUDO"
			ev.Path = "sudo"
			ev.Outcome = event.OutcomeFail
			ev.Status = 401
			ev.URL = msg
			if u := rePAMUser.FindStringSubmatch(msg); u != nil {
				ev.User = u[1]
			}
			return true
		}
		return false
	}
	ev.Method = "SUDO"
	ev.Path = "sudo"
	ev.User = m[1]
	ev.Outcome = event.OutcomeOK
	ev.Status = 200
	ev.URL = "sudo " + strings.TrimSpace(m[3]) + " as " + m[2]
	return true
}

func fillLogin(ev *event.Event, msg string) bool {
	if m := reLoginFail.FindStringSubmatch(msg); m != nil {
		ev.Method = "LOGIN"
		ev.Path = "login"
		ev.Outcome = event.OutcomeFail
		ev.Status = 401
		ev.User = strings.Trim(m[1], `'" `)
		ev.URL = "failed console login for " + ev.User
		return true
	}
	return fillPAM(ev, "login", msg)
}

func fillPAM(ev *event.Event, proc, msg string) bool {
	if !rePAM.MatchString(msg) && !strings.Contains(strings.ToLower(msg), "authentication failure") {
		return false
	}
	ev.Method = strings.ToUpper(proc)
	if ev.Method == "" {
		ev.Method = "AUTH"
	}
	ev.Path = proc
	ev.Outcome = event.OutcomeFail
	ev.Status = 401
	if u := rePAMUser.FindStringSubmatch(msg); u != nil {
		ev.User = u[1]
	}
	if h := rePAMHost.FindStringSubmatch(msg); h != nil {
		ev.SrcIP = stripHostPort(h[1])
	}
	ev.URL = "authentication failure"
	if ev.User != "" {
		ev.URL += " for " + ev.User
	}
	return true
}

func parseSyslogTime(iso, classic string) time.Time {
	if iso != "" {
		if ts, ok := parseAnyTime(iso); ok {
			return ts
		}
	}
	if classic != "" {
		now := time.Now()
		// "Aug 15 01:40:03" — no year, no zone. Assume local year, UTC clock as written.
		s := strings.Join(strings.Fields(classic), " ")
		for _, year := range []int{now.Year(), now.Year() - 1} {
			if ts, err := time.Parse("2006 Jan 2 15:04:05", strconv.Itoa(year)+" "+s); err == nil {
				ts = ts.UTC()
				if ts.After(now.Add(24 * time.Hour)) {
					continue
				}
				return ts
			}
		}
	}
	return time.Now().UTC()
}
