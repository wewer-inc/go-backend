package heartbeat

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestBeatsAtOnceWithFieldsAndStopsCleanly(t *testing.T) {
	var buf safeBuffer
	b := New(zerolog.New(&buf), time.Hour).WithFields(func(e *zerolog.Event) { e.Int("open", 3) })
	b.Start()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), Message) {
		if time.Now().After(deadline) {
			t.Fatal("no immediate beat")
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.Stop()
	b.Stop()

	if !strings.Contains(buf.String(), `"open":3`) {
		t.Fatalf("fields missing: %s", buf.String())
	}
}

func TestStopWithoutStartIsSafe(t *testing.T) {
	New(zerolog.Nop(), time.Hour).Stop()
}
