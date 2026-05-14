package example

import "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"

type CreateNoteRequest struct {
	Title string `json:"title" binding:"required"`
	Body  string `json:"body"`
}

type UpdateNoteRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type NoteResponse struct {
	UUID  string `json:"uuid"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

func toNoteResponse(n *note.Note) NoteResponse {
	return NoteResponse{
		UUID:  n.UUID.String(),
		Title: n.Title,
		Body:  n.Body,
	}
}
