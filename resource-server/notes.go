package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// These handlers contain no OAuth code: requireScope has already checked the
// token and worked out whose notes the request is for.

// notesKey is the Redis list holding one owner's notes.
func notesKey(owner string) string { return "notes:" + owner }

// notesResponse shows whose notes these are, which makes the per-user
// separation easy to see in curl output.
type notesResponse struct {
	Owner string   `json:"owner"`
	Notes []string `json:"notes"`
}

// handleListNotes implements GET /notes (needs notes:read): the token
// owner's notes only.
func (s *server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	s.writeNotes(w, r, http.StatusOK)
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
	// RPUSH appends atomically, so concurrent requests never lose a note.
	if err := s.rdb.RPush(r.Context(), notesKey(ownerFrom(r)), body.Text).Err(); err != nil {
		log.Printf("adding note: %v", err)
		http.Error(w, "cannot save the note right now", http.StatusServiceUnavailable)
		return
	}
	s.writeNotes(w, r, http.StatusCreated)
}

// writeNotes responds with the token owner's notes: an empty list, not null,
// when they have none.
func (s *server) writeNotes(w http.ResponseWriter, r *http.Request, status int) {
	owner := ownerFrom(r)
	notes, err := s.rdb.LRange(r.Context(), notesKey(owner), 0, -1).Result()
	if err != nil {
		log.Printf("reading notes: %v", err)
		http.Error(w, "cannot read notes right now", http.StatusServiceUnavailable)
		return
	}
	if notes == nil {
		notes = []string{}
	}
	writeJSON(w, status, notesResponse{owner, notes})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
