package store

import (
	"time"

	"gpewebdefender/internal/event"
)

func (s *Store) Settings() (event.Settings, error) {
	rows, err := s.db.Query(`SELECT k, v FROM settings`)
	if err != nil {
		return event.Settings{}, err
	}
	defer rows.Close()
	kv := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return event.Settings{}, err
		}
		kv[k] = v
	}
	return event.Settings{
		SiteName: kv["site_name"],
		Home:     kv["home"],
		Homes:    kv["homes"],
		Retain:   kv["retain"],
		Timezone: kv["timezone"],
	}, rows.Err()
}

func (s *Store) PutSettings(in event.Settings) error {
	pairs := [][2]string{
		{"site_name", in.SiteName},
		{"home", in.Home},
		{"homes", in.Homes},
		{"retain", in.Retain},
		{"timezone", in.Timezone},
	}
	for _, p := range pairs {
		if _, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES(?,?)
			ON CONFLICT(k) DO UPDATE SET v = excluded.v`, p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Retain() time.Duration {
	st, err := s.Settings()
	if err != nil || st.Retain == "" {
		return 168 * time.Hour
	}
	d, err := time.ParseDuration(st.Retain)
	if err != nil || d <= 0 {
		return 168 * time.Hour
	}
	return d
}
