package store

import (
	"path/filepath"
	"testing"
	"time"

	"gpewebdefender/internal/hoststat"
)

func TestSaveSnapshotAndHostStatus(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "st.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		snap := hoststat.Snapshot{
			Time: now.Add(time.Duration(i) * time.Minute), Hostname: "box",
			OS: "linux", Arch: "amd64", CPUCount: 2, MemPct: 40 + i, Load1: 0.2,
			Disks: []hoststat.Disk{{Path: "/", Pct: 50 + i}},
		}
		if err := st.SaveSnapshot("local", snap); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.HostStatus()
	if err != nil || len(list) != 1 {
		t.Fatalf("hosts: %+v %v", list, err)
	}
	h := list[0]
	if h.ID != "local" || h.Name != "manager" || h.Snapshot == nil || h.Snapshot.MemPct != 42 {
		t.Fatalf("manager: %+v", h)
	}
	if len(h.History) != 3 || h.History[0].MemPct != 40 || h.History[2].DiskPct != 52 {
		t.Fatalf("history: %+v", h.History)
	}

	_ = st.SetPairPhrase("correct-horse-phrase")
	code, _, _ := st.MintPairCode("ops")
	a, _, err := st.PairAgent("web-1", "correct-horse-phrase", code, "linux", "web1", "0.9.25", "198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueCommand(a.ID, "stats", "", "", "ops"); err == nil {
		t.Fatal("stats before approve should fail")
	}
	_ = st.ApproveAgent(a.ID, "ops")
	cmd, err := st.EnqueueCommand(a.ID, "stats", "", "", "ops")
	if err != nil || cmd.Action != "stats" {
		t.Fatalf("enqueue stats: %+v %v", cmd, err)
	}
	if err := st.SaveSnapshot(a.ID, hoststat.Snapshot{Time: now, Hostname: "web1", MemPct: 11}); err != nil {
		t.Fatal(err)
	}
	list, err = st.HostStatus()
	if err != nil || len(list) != 2 {
		t.Fatalf("after pair: %d %v", len(list), err)
	}
	if list[1].Name != "web-1" || list[1].Snapshot == nil || list[1].Snapshot.MemPct != 11 {
		t.Fatalf("agent: %+v", list[1])
	}
}
