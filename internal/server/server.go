// Package server wires the emulator: the ARM surface, the family feed, the
// /_emulator control surface (clock + faults), and health.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/calvinchengx/arm-emulator/internal/arm"
	"github.com/calvinchengx/arm-emulator/internal/auth"
	"github.com/calvinchengx/arm-emulator/internal/clock"
	"github.com/calvinchengx/arm-emulator/internal/config"
	"github.com/calvinchengx/arm-emulator/internal/store"
)

// Server owns the emulator's components.
type Server struct {
	Cfg   *config.Config
	Store *store.Store
	Clock *clock.Clock
	ARM   *arm.Service
	mux   *http.ServeMux
}

// New wires the emulator. jwksClient overrides the JWKS-fetching HTTP client
// when non-nil (in-process tests against entra-emulator's test listener).
func New(cfg *config.Config, jwksClient *http.Client) (*Server, error) {
	ck := clock.New()
	st, err := store.Open(cfg.DataDir, ck)
	if err != nil {
		return nil, err
	}
	v := auth.NewMulti(cfg.IssuerJWKS(), cfg.EntraTLSInsecure, ck.Now, jwksClient)
	a := arm.New(cfg, st, v)

	s := &Server{Cfg: cfg, Store: st, Clock: ck, ARM: a, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "now": ck.Now()})
	})
	s.mux.HandleFunc("GET /_family/authorization", a.ServeFeed)
	s.registerControl()
	s.mux.Handle("/", a)
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Close releases resources.
func (s *Server) Close() error { return s.Store.Close() }

func (s *Server) registerControl() {
	s.mux.HandleFunc("GET /_emulator/clock", func(w http.ResponseWriter, r *http.Request) {
		offset, frozen, now := s.Clock.State()
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
	})
	s.mux.HandleFunc("POST /_emulator/clock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Offset  *int64 `json:"offset"`
			Advance *int64 `json:"advance"`
			Freeze  *bool  `json:"freeze"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.Offset != nil {
			s.Clock.SetOffset(*body.Offset)
		}
		if body.Freeze != nil {
			if *body.Freeze {
				s.Clock.Freeze()
			} else {
				s.Clock.Unfreeze()
			}
		}
		if body.Advance != nil {
			s.Clock.Advance(*body.Advance)
		}
		offset, frozen, now := s.Clock.State()
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
	})
	s.mux.HandleFunc("POST /_emulator/faults", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ThrottleNextRequests *int `json:"throttleNextRequests"`
			RejectNextRequests   *int `json:"rejectNextRequests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		throttle, reject := -1, -1
		if body.ThrottleNextRequests != nil {
			throttle = *body.ThrottleNextRequests
		}
		if body.RejectNextRequests != nil {
			reject = *body.RejectNextRequests
		}
		s.ARM.SetFaults(throttle, reject)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
