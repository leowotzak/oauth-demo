package main

import (
	"encoding/json"
	"net/http"
)

// These handlers contain no OAuth code: requireScope has already checked the
// token and worked out whose notes the request is for.

// notesResponse shows whose notes these are, which makes the per-user
// separation easy to see in curl output.
type notesResponse struct {
	Owner string   `json:"owner"`
	Notes []string `json:"notes"`
}

// handleListNotes implements GET /notes (needs notes:read): the token
// owner's notes only.
func (s *server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	owner := ownerFrom(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, notesResponse{owner, s.notesOf(owner)})
}

// handleAddNote implements POST /notes (needs notes:write), adding to the
// token owner's notes. Body: {"text": "..."}
func (s *server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `body must be {"text": "..."}`})
		return
	}

	owner := ownerFrom(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes[owner] = append(s.notes[owner], body.Text)
	writeJSON(w, http.StatusCreated, notesResponse{owner, s.notesOf(owner)})
}

// notesOf returns an owner's notes, as an empty list rather than null when
// they have none. The caller holds s.mu.
func (s *server) notesOf(owner string) []string {
	if s.notes[owner] == nil {
		return []string{}
	}
	return s.notes[owner]
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
