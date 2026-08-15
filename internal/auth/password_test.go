package auth

import "testing"

func TestHashAndCheck(t *testing.T) {
	h, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct-horse-battery") {
		t.Fatal("good password rejected")
	}
	if CheckPassword(h, "wrong-password-xx") {
		t.Fatal("bad password accepted")
	}
	if CheckPassword("not-a-hash", "correct-horse-battery") {
		t.Fatal("garbage hash accepted")
	}
}

func TestValidPassword(t *testing.T) {
	if err := ValidPassword("short", "op"); err == nil {
		t.Fatal("short password allowed")
	}
	if err := ValidPassword("operatoradmin", "operatoradmin"); err == nil {
		t.Fatal("username-as-password allowed")
	}
	if err := ValidPassword("passwordpassword", "op"); err == nil {
		t.Fatal("common password allowed")
	}
	if err := ValidPassword("a-reasonable-pass-99", "op"); err != nil {
		t.Fatal(err)
	}
}

func TestValidUsername(t *testing.T) {
	if ValidUsername("ab") || ValidUsername("Bad Name") || !ValidUsername("op_1") {
		t.Fatal("username rules")
	}
}

func TestTokensEqual(t *testing.T) {
	if !TokensEqual("secret", "secret") || TokensEqual("secret", "other") {
		t.Fatal("token compare")
	}
}
