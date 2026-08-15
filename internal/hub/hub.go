package hub

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"gpewebdefender/internal/event"
)

// Hub fans alerts out to browser SSE clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func New() *Hub {
	return &Hub{clients: map[chan []byte]struct{}{}}
}

func (h *Hub) Publish(al event.Alert) {
	b, err := json.Marshal(al)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- b:
		default:
		}
	}
}

func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()

	_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
	fl.Flush()

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
			fl.Flush()
		case b := <-ch:
			_, _ = w.Write([]byte("event: alert\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			fl.Flush()
		}
	}
}
