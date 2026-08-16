// Package hoststat takes a one-shot snapshot of this machine.
// Nothing is sampled until someone asks.
package hoststat

import (
	"os"
	"runtime"
	"time"
)

type Disk struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
	Pct   int    `json:"pct"`
}

type Snapshot struct {
	Time      time.Time `json:"time"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Version   string    `json:"version,omitempty"`
	CPUCount  int       `json:"cpu_count"`
	Load1     float64   `json:"load1,omitempty"`
	Load5     float64   `json:"load5,omitempty"`
	Load15    float64   `json:"load15,omitempty"`
	MemTotal  uint64    `json:"mem_total"`
	MemAvail  uint64    `json:"mem_avail"`
	MemUsed   uint64    `json:"mem_used"`
	MemPct    int       `json:"mem_pct"`
	SwapTotal uint64    `json:"swap_total,omitempty"`
	SwapUsed  uint64    `json:"swap_used,omitempty"`
	SwapPct   int       `json:"swap_pct,omitempty"`
	UptimeSec int64     `json:"uptime_sec,omitempty"`
	Disks     []Disk    `json:"disks,omitempty"`
}

func Collect(version string) Snapshot {
	s := Snapshot{
		Time:     time.Now().UTC(),
		Hostname: hostName(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  version,
		CPUCount: runtime.NumCPU(),
		Disks:    []Disk{},
	}
	platformFill(&s)
	return s
}

func hostName() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
