package store

import (
	"encoding/json"
	"time"

	"gpewebdefender/internal/hoststat"
)

const localAgentID = "local"

type HostSample struct {
	Time    time.Time `json:"time"`
	MemPct  int       `json:"mem_pct"`
	DiskPct int       `json:"disk_pct"`
	Load1   float64   `json:"load1"`
}

type HostStatus struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Paired    bool              `json:"paired"`
	Status    string            `json:"status,omitempty"`
	LastSeen  time.Time         `json:"last_seen,omitempty"`
	Checked   time.Time         `json:"checked,omitempty"`
	Snapshot  *hoststat.Snapshot `json:"snapshot,omitempty"`
	History   []HostSample      `json:"history,omitempty"`
}

func (s *Store) initStatus() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS agent_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  ts_ms INTEGER NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ast_agent ON agent_stats(agent_id, ts_ms);
`)
	return err
}

func (s *Store) SaveSnapshot(agentID string, snap hoststat.Snapshot) error {
	if agentID == "" {
		agentID = localAgentID
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	ts := snap.Time.UnixMilli()
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	if _, err := s.db.Exec(`INSERT INTO agent_stats(agent_id, ts_ms, payload) VALUES(?,?,?)`, agentID, ts, string(b)); err != nil {
		return err
	}
	_, _ = s.db.Exec(`DELETE FROM agent_stats WHERE agent_id = ? AND id NOT IN (
		SELECT id FROM agent_stats WHERE agent_id = ? ORDER BY ts_ms DESC LIMIT 40)`, agentID, agentID)
	return nil
}

func (s *Store) lastSnapshot(agentID string) (*hoststat.Snapshot, time.Time, []HostSample) {
	rows, err := s.db.Query(`SELECT ts_ms, payload FROM agent_stats WHERE agent_id = ? ORDER BY ts_ms DESC LIMIT 24`, agentID)
	if err != nil {
		return nil, time.Time{}, nil
	}
	defer rows.Close()
	var hist []HostSample
	var first *hoststat.Snapshot
	var firstTS time.Time
	for rows.Next() {
		var ts int64
		var raw string
		if rows.Scan(&ts, &raw) != nil {
			continue
		}
		var snap hoststat.Snapshot
		if json.Unmarshal([]byte(raw), &snap) != nil {
			continue
		}
		disk := 0
		if len(snap.Disks) > 0 {
			disk = snap.Disks[0].Pct
		}
		hist = append(hist, HostSample{Time: time.UnixMilli(ts).UTC(), MemPct: snap.MemPct, DiskPct: disk, Load1: snap.Load1})
		if first == nil {
			cp := snap
			first = &cp
			firstTS = time.UnixMilli(ts).UTC()
		}
	}
	// history is newest-first; reverse for charts
	for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
		hist[i], hist[j] = hist[j], hist[i]
	}
	return first, firstTS, hist
}

func (s *Store) HostStatus() ([]HostStatus, error) {
	agents, err := s.ListAgents()
	if err != nil {
		return nil, err
	}
	out := []HostStatus{}
	snap, checked, hist := s.lastSnapshot(localAgentID)
	out = append(out, HostStatus{
		ID: localAgentID, Name: "manager", Paired: true, Status: "local",
		Checked: checked, Snapshot: snap, History: hist,
	})
	for _, a := range agents {
		if a.Status == AgentRejected || a.Status == AgentRevoked {
			continue
		}
		st := HostStatus{ID: a.ID, Name: a.Name, Paired: a.Status == AgentActive, Status: a.Status, LastSeen: a.LastSeen}
		if a.Status == AgentActive {
			st.Snapshot, st.Checked, st.History = s.lastSnapshot(a.ID)
		}
		out = append(out, st)
	}
	return out, nil
}
