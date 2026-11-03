package main

import (
	"encoding/json"
	"net/http"
)

// These handlers contain no OAuth code: requireScope has already checked
// the token by the time they run.

// handleListNotes implements GET /notes (needs notes:read).
func (s *server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.notes)
}

// handleAddNote implements POST /notes (needs notes:write).
// Body: {"text": "..."}
func (s *server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `body must be {"text": "..."}`})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes = append(s.notes, body.Text)
	writeJSON(w, http.StatusCreated, s.notes)
}
