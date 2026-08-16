package server

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"

	"gpewebdefender/internal/block"
	"gpewebdefender/internal/hoststat"
	"gpewebdefender/internal/store"
)

func (s *Server) registerAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/agent/pair", s.agentPair)
	mux.HandleFunc("GET /api/agent/enroll", s.agentEnroll)
	mux.HandleFunc("POST /api/agent/hello", s.agentHello)
	mux.HandleFunc("GET /api/agent/commands", s.agentCommands)
	mux.HandleFunc("POST /api/agent/commands/{id}/result", s.agentCommandResult)

	mux.HandleFunc("GET /api/pair-status", s.pairStatus)
	mux.HandleFunc("POST /api/pair-phrase", s.setPairPhrase)
	mux.HandleFunc("POST /api/pair-codes", s.mintPairCode)
	mux.HandleFunc("GET /api/agents", s.listAgents)
	mux.HandleFunc("POST /api/agents/{id}/approve", s.approveAgent)
	mux.HandleFunc("POST /api/agents/{id}/reject", s.rejectAgent)
	mux.HandleFunc("POST /api/agents/{id}/revoke", s.revokeAgent)
	mux.HandleFunc("POST /api/agents/{id}/ban", s.banAgent)
	mux.HandleFunc("POST /api/agents/{id}/unban", s.unbanAgent)
	mux.HandleFunc("GET /api/agents/{id}/bans", s.listAgentBans)
	mux.HandleFunc("POST /api/agents/ban-all", s.banAllAgents)
	mux.HandleFunc("GET /api/agent-audit", s.agentAudit)
	mux.HandleFunc("GET /api/reports/blocks", s.reportBlocks)
	mux.HandleFunc("GET /api/status", s.hostStatus)
	mux.HandleFunc("POST /api/status/check", s.checkSelf)
	mux.HandleFunc("POST /api/agents/{id}/check", s.checkAgent)
	mux.HandleFunc("POST /api/agents/check-all", s.checkAllAgents)
	mux.HandleFunc("POST /api/agent/stats", s.agentStats)
}

func (s *Server) reportBlocks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.reqUser(r); !ok && s.Store.UserCount() > 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rep, err := s.Store.BlockList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}

func (s *Server) agentPair(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.Store.LockedOut("pair", ip) {
		http.Error(w, "too many attempts — wait 15 minutes", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Name     string `json:"name"`
		Code     string `json:"code"`
		Phrase   string `json:"phrase"`
		OS       string `json:"os"`
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	a, secret, err := s.Store.PairAgent(in.Name, in.Phrase, in.Code, in.OS, in.Hostname, in.Version, ip)
	if err != nil {
		s.Store.RecordFail("pair", ip)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.Store.ClearFails("pair", ip)
	writeJSON(w, map[string]any{
		"ok": true, "id": a.ID, "name": a.Name, "status": a.Status,
		"secret": secret, "fingerprint": a.Fingerprint,
	})
}

func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	a, ok := s.reqAgent(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fresh, err := s.Store.AgentByID(a.ID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"id": fresh.ID, "name": fresh.Name, "status": fresh.Status,
		"fingerprint": fresh.Fingerprint,
	})
}

func (s *Server) agentHello(w http.ResponseWriter, r *http.Request) {
	a, ok := s.reqAgent(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var in struct {
		OS       string `json:"os"`
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
		Block    string `json:"block"`
		Jail     string `json:"jail"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
	if in.OS == "" {
		in.OS = runtime.GOOS
	}
	s.Store.TouchAgent(a.ID, clientIP(r), in.OS, in.Hostname, in.Version, in.Block, in.Jail)
	writeJSON(w, map[string]any{"ok": true, "status": a.Status, "name": a.Name})
}

func (s *Server) agentCommands(w http.ResponseWriter, r *http.Request) {
	a, ok := s.reqAgent(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if a.Status != store.AgentActive {
		http.Error(w, "agent not approved", http.StatusForbidden)
		return
	}
	s.Store.TouchAgent(a.ID, clientIP(r), "", "", "", "", "")
	cmds, err := s.Store.TakeCommands(a.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"commands": cmds})
}

func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request) {
	a, ok := s.reqAgent(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var in struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.Store.CommandResult(r.PathValue("id"), a.ID, in.Status, in.Result); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) pairStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.reqUser(r); !ok && s.Store.UserCount() > 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"phrase_set": s.Store.PairPhraseSet()})
}

func (s *Server) setPairPhrase(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var in struct {
		Phrase string `json:"phrase"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.Store.SetPairPhrase(in.Phrase); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "phrase_set": true})
}

func (s *Server) mintPairCode(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	code, exp, err := s.Store.MintPairCode(u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"code": code, "expires": exp.UTC(), "ttl": "15m"})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.reqUser(r); !ok && s.Store.UserCount() > 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	list, err := s.Store.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (s *Server) approveAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := s.Store.ApproveAgent(r.PathValue("id"), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) rejectAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := s.Store.RejectAgent(r.PathValue("id"), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := s.Store.RevokeAgent(r.PathValue("id"), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) banBody(w http.ResponseWriter, r *http.Request) (ip, duration string, why store.BanWhy, ok bool) {
	var in struct {
		IP       string `json:"ip"`
		Duration string `json:"duration"`
		Title    string `json:"title"`
		Category string `json:"category"`
		Num      int64  `json:"num"`
		Scope    string `json:"scope"`
	}
	if !readJSON(w, r, &in) {
		return "", "", why, false
	}
	clean, err := block.CheckBanIP(in.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", "", why, false
	}
	if in.Duration == "" {
		in.Duration = "1h"
	}
	if _, err := block.ParseDuration(in.Duration); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", "", why, false
	}
	if clean == clientIP(r) {
		http.Error(w, "refusing to ban your current session IP", http.StatusBadRequest)
		return "", "", why, false
	}
	why = store.BanWhy{Title: in.Title, Category: in.Category, AlertNum: in.Num, Scope: in.Scope}
	return clean, in.Duration, why, true
}

func (s *Server) banAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	ip, dur, why, ok := s.banBody(w, r)
	if !ok {
		return
	}
	if why.Scope == "" {
		why.Scope = "this"
	}
	cmd, err := s.Store.EnqueueCommandWhy(r.PathValue("id"), "ban", ip, dur, u.Username, why)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "command": cmd})
}

func (s *Server) unbanAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	cmd, err := s.Store.EnqueueCommand(r.PathValue("id"), "unban", in.IP, "", u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "command": cmd})
}

func (s *Server) listAgentBans(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.reqUser(r); !ok && s.Store.UserCount() > 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	list, err := s.Store.AgentBans(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (s *Server) banAllAgents(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	ip, dur, why, ok := s.banBody(w, r)
	if !ok {
		return
	}
	why.Scope = "all"
	n, err := s.Store.EnqueueBanAllWhy(ip, dur, u.Username, why)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "hosts": n, "ip": ip, "duration": dur})
}

func (s *Server) hostStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.reqUser(r); !ok && s.Store.UserCount() > 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	list, err := s.Store.HostStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"hosts": list})
}

func (s *Server) checkSelf(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	snap := hoststat.Collect(s.Version)
	if err := s.Store.SaveSnapshot("local", snap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "snapshot": snap})
}

func (s *Server) checkAgent(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "local" {
		s.checkSelf(w, r)
		return
	}
	cmd, err := s.Store.EnqueueCommand(id, "stats", "", "", u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "command": cmd})
}

func (s *Server) checkAllAgents(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := s.Store.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n := 0
	for _, a := range list {
		if a.Status != store.AgentActive {
			continue
		}
		if _, err := s.Store.EnqueueCommand(a.ID, "stats", "", "", u.Username); err == nil {
			n++
		}
	}
	snap := hoststat.Collect(s.Version)
	_ = s.Store.SaveSnapshot("local", snap)
	writeJSON(w, map[string]any{"ok": true, "queued": n, "manager": snap})
}

func (s *Server) agentStats(w http.ResponseWriter, r *http.Request) {
	ag, ok := s.reqAgent(r)
	if !ok || ag.Status != store.AgentActive {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var snap hoststat.Snapshot
	if !readJSON(w, r, &snap) {
		return
	}
	if err := s.Store.SaveSnapshot(ag.ID, snap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Store.TouchAgent(ag.ID, clientIP(r), "", "", "", "", "")
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) agentAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	list, err := s.Store.AgentAudit(40)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}
