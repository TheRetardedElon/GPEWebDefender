package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestUsersAndSessions(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if st.UserCount() != 0 {
		t.Fatal("expected empty")
	}
	admin, err := st.CreateUser("Op-One", "first-admin-pass", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if admin.Username != "op-one" || admin.Role != "admin" {
		t.Fatalf("admin: %+v", admin)
	}
	if _, err := st.CreateUser("op-one", "another-long-pw", "viewer"); err == nil {
		t.Fatal("duplicate username")
	}
	view, err := st.CreateUser("reader", "viewer-long-pw", "viewer")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := st.NewSession(admin.ID, "1.2.3.4", time.Hour)
	if err != nil || raw == "" {
		t.Fatal(err)
	}
	got, err := st.SessionUser(raw)
	if err != nil || got.ID != admin.ID {
		t.Fatalf("session: %+v %v", got, err)
	}
	if _, err := st.SessionUser("nope"); err == nil {
		t.Fatal("bogus session")
	}

	if err := st.DeleteUser(admin.ID); err == nil {
		t.Fatal("deleted last remaining admin while viewer exists? wait — viewer is not admin, admin is last")
	}
	if err := st.SetUserDisabled(admin.ID, true); err == nil {
		t.Fatal("disabled last admin")
	}
	if err := st.DeleteUser(view.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(admin.ID); err == nil {
		t.Fatal("deleted last admin")
	}

	st.RecordFail("op-one", "9.9.9.9")
	for i := 0; i < 7; i++ {
		st.RecordFail("op-one", "9.9.9.9")
	}
	if !st.LockedOut("op-one", "9.9.9.9") {
		t.Fatal("expected lockout")
	}
	if st.LockedOut("op-one", "1.1.1.1") {
		t.Fatal("lockout should be per ip")
	}
	st.ClearFails("op-one", "9.9.9.9")
	if st.LockedOut("op-one", "9.9.9.9") {
		t.Fatal("cleared lockout")
	}
}

func TestPasswordChangeRevokes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.CreateUser("ops", "original-pass-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := st.NewSession(u.ID, "10.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword(u.ID, "rotated-pass-22"); err != nil {
		t.Fatal(err)
	}
	st.RevokeUserSessions(u.ID)
	if _, err := st.SessionUser(raw); err == nil {
		t.Fatal("old session still valid")
	}
}
