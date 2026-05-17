package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Hub manages WebSocket clients and broadcasts events to them.
type Hub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
	send    chan WSMessage
}

type wsClient struct {
	hub  *Hub
	send chan []byte
	done chan struct{}
}

func NewHub() *Hub {
	return &Hub{
		clients: map[*wsClient]struct{}{},
		send:    make(chan WSMessage, 256),
	}
}

func (h *Hub) Run() {
	for msg := range h.send {
		b, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		h.mu.RLock()
		for c := range h.clients {
			select {
			case c.send <- b:
			default:
				// slow client: drop the message
			}
		}
		h.mu.RUnlock()
	}
}

// Broadcast enqueues a message to all connected clients (non-blocking).
func (h *Hub) Broadcast(msgType string, data any) {
	select {
	case h.send <- WSMessage{Type: msgType, Data: data}:
	default:
	}
}

func (h *Hub) register(c *wsClient) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) unregister(c *wsClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// ─── HTTP upgrade ────────────────────────────────────────────────────────────

// Lightweight WebSocket implementation (no external deps).
// Supports text frames only — sufficient for JSON event streaming.

func (h *Handlers) WebSocket(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	if s == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgradeWS(w, r)
	if err != nil {
		slog.Error("ws upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	client := &wsClient{hub: h.hub, send: make(chan []byte, 64), done: make(chan struct{})}
	h.hub.register(client)
	defer h.hub.unregister(client)

	// Send a welcome ping
	client.send <- []byte(`{"type":"connected"}`)

	// Write pump
	go func() {
		defer close(client.done)
		for {
			select {
			case msg, ok := <-client.send:
				if !ok {
					return
				}
				if err := wsWriteText(conn, msg); err != nil {
					return
				}
			case <-time.After(30 * time.Second):
				if err := wsWritePing(conn); err != nil {
					return
				}
			}
		}
	}()

	// Read pump — just drain pong frames to keep connection alive
	wsReadLoop(conn)
	close(client.send)
	<-client.done
}
