//go:build linux || darwin || freebsd

package hoststat

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func platformFill(s *Snapshot) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
			s.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 1 {
			if u, err := strconv.ParseFloat(f[0], 64); err == nil {
				s.UptimeSec = int64(u)
			}
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		var total, avail, swapTotal, swapFree uint64
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				total = kibField(line) * 1024
			case strings.HasPrefix(line, "MemAvailable:"):
				avail = kibField(line) * 1024
			case strings.HasPrefix(line, "SwapTotal:"):
				swapTotal = kibField(line) * 1024
			case strings.HasPrefix(line, "SwapFree:"):
				swapFree = kibField(line) * 1024
			}
		}
		f.Close()
		s.MemTotal = total
		s.MemAvail = avail
		if total > avail {
			s.MemUsed = total - avail
		}
		if total > 0 {
			s.MemPct = int((s.MemUsed * 100) / total)
		}
		s.SwapTotal = swapTotal
		if swapTotal > swapFree {
			s.SwapUsed = swapTotal - swapFree
		}
		if swapTotal > 0 {
			s.SwapPct = int((s.SwapUsed * 100) / swapTotal)
		}
	}
	seen := map[uint64]bool{}
	for _, p := range []string{"/", "/var", "/home"} {
		if d, id, ok := diskOf(p); ok && !seen[id] {
			seen[id] = true
			s.Disks = append(s.Disks, d)
		}
	}
}

func kibField(line string) uint64 {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(f[1], 10, 64)
	return n
}

func diskOf(path string) (Disk, uint64, bool) {
	if _, err := os.Stat(path); err != nil {
		return Disk{}, 0, false
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, 0, false
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	free := uint64(st.Bavail) * bsize
	if total == 0 {
		return Disk{}, 0, false
	}
	used := total - free
	return Disk{Path: path, Total: total, Used: used, Free: free, Pct: int((used * 100) / total)}, st.Blocks, true
}
