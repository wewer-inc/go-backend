package generate

import "github.com/google/uuid"

// UUID generates a new UUIDv4 string using google UUID.
func UUID() string {
	return uuid.NewString()
}
