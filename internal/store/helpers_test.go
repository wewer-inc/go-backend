package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
)

func TestLikePatternsEscapeMetacharacters(t *testing.T) {
	cases := map[string][2]string{
		"plain":  {`%plain%`, `plain%`},
		"50%":    {`%50\%%`, `50\%%`},
		"a_b":    {`%a\_b%`, `a\_b%`},
		`trail\`: {`%trail\\%`, `trail\\%`},
		`mix\%_`: {`%mix\\\%\_%`, `mix\\\%\_%`},
	}
	for in, want := range cases {
		if got := store.LikeContains(in); got != want[0] {
			t.Errorf("LikeContains(%q) = %q, want %q", in, got, want[0])
		}
		if got := store.LikePrefix(in); got != want[1] {
			t.Errorf("LikePrefix(%q) = %q, want %q", in, got, want[1])
		}
	}
}

func TestLikeEscapeMatchesLiterally(t *testing.T) {
	db := newTestDB(t)
	for _, name := range []string{"100% wool", "100 wool"} {
		if err := db.Create(&TestUserEntity{Email: name, Name: name}).Error; err != nil {
			t.Fatal(err)
		}
	}
	var got []TestUserEntity
	if err := db.Where("name LIKE ? "+store.LikeEscape, store.LikeContains("100%")).Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "100% wool" {
		t.Fatalf("got %+v", got)
	}
}

func TestValidSearchTextRefusesNULAndBadUTF8(t *testing.T) {
	if !store.ValidSearchText("héllo") {
		t.Error("valid text refused")
	}
	if store.ValidSearchText("a\x00b") {
		t.Error("NUL accepted")
	}
	if store.ValidSearchText("a\xffb") {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestExpectError(t *testing.T) {
	target := errors.New("dup")
	other := errors.New("other")
	second := errors.New("second")
	ctx := store.ExpectError(context.Background(), func(err error) bool { return errors.Is(err, target) })

	if !store.IsExpectedError(ctx, target) {
		t.Error("marked error not expected")
	}
	if store.IsExpectedError(ctx, other) {
		t.Error("unmarked error treated as expected")
	}
	if store.IsExpectedError(ctx, nil) {
		t.Error("nil treated as expected")
	}

	both := store.ExpectError(ctx, func(err error) bool { return errors.Is(err, second) })
	if !store.IsExpectedError(both, target) || !store.IsExpectedError(both, second) {
		t.Error("marks must compose")
	}
	if store.ExpectError(ctx, nil) != ctx {
		t.Error("a nil match must return the same context")
	}
}
