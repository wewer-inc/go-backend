package reqid

import (
	"context"
	"testing"
)

func TestFromContextReadsTheAttachedID(t *testing.T) {
	if got := FromContext(NewContext(context.Background(), "abc")); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestNewContextIgnoresAnEmptyID(t *testing.T) {
	ctx := context.Background()
	if NewContext(ctx, "") != ctx {
		t.Fatal("an empty id must return the same context")
	}
	if got := FromContext(ctx); got != "" {
		t.Fatalf("got %q", got)
	}
}
