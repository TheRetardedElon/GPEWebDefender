package hoststat

import (
	"runtime"
	"testing"
)

func TestCollectBasics(t *testing.T) {
	s := Collect("test-ver")
	if s.OS != runtime.GOOS {
		t.Fatalf("os: %s", s.OS)
	}
	if s.Arch != runtime.GOARCH {
		t.Fatalf("arch: %s", s.Arch)
	}
	if s.CPUCount < 1 {
		t.Fatalf("cpu: %d", s.CPUCount)
	}
	if s.Version != "test-ver" {
		t.Fatalf("version: %s", s.Version)
	}
	if s.Hostname == "" {
		t.Fatal("empty hostname")
	}
	if s.Time.IsZero() {
		t.Fatal("zero time")
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if s.MemTotal == 0 {
			t.Fatalf("expected memory on %s", runtime.GOOS)
		}
	}
}
