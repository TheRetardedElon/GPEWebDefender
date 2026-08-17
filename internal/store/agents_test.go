package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPairApproveAndBanRails(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetPairPhrase("correct-horse-phrase"); err != nil {
		t.Fatal(err)
	}
	if !st.PairPhraseSet() || !st.CheckPairPhrase("correct-horse-phrase") {
		t.Fatal("phrase")
	}
	if st.CheckPairPhrase("wrong-phrase-here") {
		t.Fatal("wrong phrase accepted")
	}
	code, _, err := st.MintPairCode("ops")
	if err != nil {
		t.Fatal(err)
	}
	a, secret, err := st.PairAgent("web-1", "correct-horse-phrase", code, "linux", "box", "0.9.19", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != AgentPending || secret == "" {
		t.Fatalf("%+v", a)
	}
	got, err := st.AgentBySecret(secret)
	if err != nil || got.ID != a.ID {
		t.Fatalf("secret: %+v %v", got, err)
	}
	if _, err := st.EnqueueCommand(a.ID, "ban", "198.51.100.12", "1h", "ops"); err == nil {
		t.Fatal("ban before approve")
	}
	if err := st.ApproveAgent(a.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueCommand(a.ID, "ban", "10.0.0.8", "1h", "ops"); err == nil {
		t.Fatal("private IP")
	}
	if _, err := st.EnqueueCommand(a.ID, "ban", "203.0.113.9", "1h", "ops"); err == nil {
		t.Fatal("self IP")
	}
	cmd, err := st.EnqueueCommand(a.ID, "ban", "198.51.100.12", "1h", "ops")
	if err != nil || cmd.Action != "ban" {
		t.Fatalf("ban: %+v %v", cmd, err)
	}
	taken, err := st.TakeCommands(a.ID)
	if err != nil || len(taken) != 1 || taken[0].IP != "198.51.100.12" {
		t.Fatalf("take: %+v %v", taken, err)
	}
	if err := st.CommandResult(taken[0].ID, a.ID, CmdDone, "banned"); err != nil {
		t.Fatal(err)
	}
	// used code cannot pair again
	if _, _, err := st.PairAgent("web-2", "correct-horse-phrase", code, "linux", "box2", "", "198.51.100.1"); err == nil {
		t.Fatal("reused code")
	}
}

func TestBlockListRemembersWhy(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "bl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetPairPhrase("correct-horse-phrase")
	code, _, _ := st.MintPairCode("ops")
	a, _, err := st.PairAgent("edge", "correct-horse-phrase", code, "", "", "", "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.ApproveAgent(a.ID, "ops")
	_, err = st.EnqueueCommandWhy(a.ID, "ban", "198.51.100.88", "1h", "ops", BanWhy{
		Title: "SSH failed login as root", Category: "hostauth", AlertNum: 20265, Scope: "this",
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := st.BlockList()
	if err != nil || rep.Active != 1 || len(rep.Rows) != 1 {
		t.Fatalf("list: %+v %v", rep, err)
	}
	if rep.Rows[0].Title != "SSH failed login as root" || rep.Rows[0].AlertNum != 20265 || rep.Rows[0].Host != "edge" {
		t.Fatalf("why: %+v", rep.Rows[0])
	}
}

func TestBlockListDoesNotDeadlock(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetPairPhrase("correct-horse-phrase")
	code, _, _ := st.MintPairCode("ops")
	a, _, err := st.PairAgent("edge", "correct-horse-phrase", code, "", "", "", "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.ApproveAgent(a.ID, "ops")
	if _, err := st.EnqueueCommandWhy(a.ID, "ban", "198.51.100.88", "1h", "ops", BanWhy{
		Title: "SSH failed login as root", Category: "hostauth", AlertNum: 1, Scope: "this",
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := st.BlockList(); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("BlockList deadlocked on nested SQLite query")
	}
}

func TestCommandExpires(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetPairPhrase("correct-horse-phrase")
	code, _, _ := st.MintPairCode("ops")
	a, _, err := st.PairAgent("edge", "correct-horse-phrase", code, "", "", "", "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.ApproveAgent(a.ID, "ops")
	cmd, err := st.EnqueueCommand(a.ID, "ban", "198.51.100.99", "15m", "ops")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.db.Exec(`UPDATE agent_commands SET expires_ms = ? WHERE id = ?`, time.Now().Add(-time.Minute).UnixMilli(), cmd.ID)
	taken, err := st.TakeCommands(a.ID)
	if err != nil || len(taken) != 0 {
		t.Fatalf("expired still returned: %+v %v", taken, err)
	}
}
