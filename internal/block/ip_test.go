package block

import "testing"

func TestCheckBanIP(t *testing.T) {
	if _, err := CheckBanIP("1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"127.0.0.1", "10.0.0.8", "192.168.1.1", "172.16.0.1",
		"::1", "fc00::1", "169.254.1.1", "100.64.1.2",
		"0.0.0.0", "224.0.0.1", "not-an-ip", "1.2.3.4 5.6.7.8",
	} {
		if _, err := CheckBanIP(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	if _, err := ParseDuration("1h"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDuration("until"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDuration("9h"); err == nil {
		t.Fatal("9h should fail")
	}
}
