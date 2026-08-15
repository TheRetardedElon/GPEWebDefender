package geo

import "testing"

func TestPinLookup(t *testing.T) {
	r := New()
	loc := r.Lookup("185.220.101.47")
	if !loc.Ok || loc.Country != "DE" {
		t.Fatalf("pin: %+v", loc)
	}
}

func TestPrivateSilent(t *testing.T) {
	r := New()
	if r.Lookup("10.0.4.22").Ok {
		t.Fatal("private should not plot")
	}
	if r.Lookup("127.0.0.1").Ok {
		t.Fatal("loopback should not plot")
	}
}

func TestHomeISO(t *testing.T) {
	loc, err := ParseHome("DE")
	if err != nil || loc.Country != "DE" || !loc.Ok {
		t.Fatalf("%+v %v", loc, err)
	}
	loc, err = ParseHome("51.5,-0.12")
	if err != nil || loc.Lat != 51.5 || loc.Lon != -0.12 {
		t.Fatalf("%+v %v", loc, err)
	}
}

func TestParseHomes(t *testing.T) {
	m, err := ParseHomes("edge=41.88,-87.63;proxy=DE")
	if err != nil {
		t.Fatal(err)
	}
	if m["edge"].Lat != 41.88 || m["edge"].Lon != -87.63 || m["edge"].Name != "edge" {
		t.Fatalf("edge: %+v", m["edge"])
	}
	if m["proxy"].Country != "DE" || m["proxy"].Name != "proxy" {
		t.Fatalf("proxy: %+v", m["proxy"])
	}
	r := New()
	if err := r.SetHomes("edge=40.7,-74.0"); err != nil {
		t.Fatal(err)
	}
	if r.HomeFor("edge").Lat != 40.7 {
		t.Fatalf("HomeFor edge: %+v", r.HomeFor("edge"))
	}
	if r.HomeFor("missing").Country != "US" {
		t.Fatalf("fallback: %+v", r.HomeFor("missing"))
	}
}

func TestCentroidCoverage(t *testing.T) {
	if _, ok := Centroid("US"); !ok {
		t.Fatal("US")
	}
	if _, ok := Centroid("CN"); !ok {
		t.Fatal("CN")
	}
}
