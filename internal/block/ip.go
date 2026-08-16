package block

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// AllowedDurations is what the portal may send. "until" means stay until an admin unbans.
var AllowedDurations = map[string]time.Duration{
	"15m":  15 * time.Minute,
	"1h":   time.Hour,
	"24h":  24 * time.Hour,
	"7d":   7 * 24 * time.Hour,
	"168h": 7 * 24 * time.Hour,
	"until": 0,
}

func ParseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("pick 15m, 1h, 24h, 7d, or until")
	}
	if d, ok := AllowedDurations[s]; ok {
		return d, nil
	}
	return 0, fmt.Errorf("duration must be 15m, 1h, 24h, 7d, or until")
}

// CheckBanIP rejects anything that is not a public unicast address.
// Private, loopback, link-local, CGNAT, and multicast must never reach a firewall.
func CheckBanIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("missing IP")
	}
	if strings.ContainsAny(s, " \t\r\n,/;|") {
		return "", fmt.Errorf("one IP only")
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("not an IP address")
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() ||
		ip.IsInterfaceLocalMulticast() {
		return "", fmt.Errorf("refusing non-public IP")
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return "", fmt.Errorf("refusing non-public IP")
		}
		// 100.64.0.0/10 shared address space (CGNAT)
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return "", fmt.Errorf("refusing shared CGNAT address")
		}
		// 198.18.0.0/15 benchmarking
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return "", fmt.Errorf("refusing reserved address")
		}
		return v4.String(), nil
	}
	return ip.String(), nil
}
