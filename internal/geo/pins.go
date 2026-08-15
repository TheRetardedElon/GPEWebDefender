package geo

// defaultPins maps invented demo IPs to ISO countries so `gpewebdefender demo`
// can draw arcs with no GeoIP file. serve/live never enable this table.
func defaultPins() map[string]string {
	return map[string]string{
		// demo attackers
		"185.220.101.47":  "DE",
		"45.155.205.88":   "NL",
		"193.35.18.91":    "RU",
		"91.219.236.177":  "UA",
		"167.94.138.44":   "US",
		"45.83.12.9":      "RO",
		"103.107.196.10":  "SG",
		"41.76.108.22":    "ZA",
		"200.89.75.14":    "BR",
		"36.99.140.8":     "CN",
		"122.162.55.9":    "IN",
		"78.128.112.3":    "BG",
		"5.188.206.44":    "RU",
		"51.15.123.10":    "FR",
		"13.107.42.14":    "US",
		"8.219.76.55":     "SG",
		"20.118.40.7":     "US",
		"34.96.80.12":     "US",
		"102.129.165.3":   "ZA",
		"177.54.148.22":   "BR",
		"61.19.44.90":     "TH",
		"118.70.12.8":     "VN",
		"91.132.144.6":    "IR",
		"185.156.73.54":   "TR",
		"45.142.212.61":   "NL",
		"194.26.29.18":    "PL",
		"79.124.8.21":     "BG",
		"31.220.0.45":     "DE",
		"89.248.165.9":    "NL",
		"141.98.10.62":    "LT",
		"193.142.59.17":   "NL",
	}
}
