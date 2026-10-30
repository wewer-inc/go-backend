package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/google/uuid"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type TestUserEntity struct {
	gorm.Model
	UUID         uuid.UUID `gorm:"type:text"`
	Email        string    `gorm:"uniqueIndex"`
	PasswordHash string
	Name         string
	PlatformRole string
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite in-memory db: %v", err)
	}

	if err := db.AutoMigrate(
		&TestUserEntity{},
	); err != nil {
		t.Fatalf("failed to automigrate: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxIdleTime(time.Minute)

	return db
}

func TestUserRepo_CreateAndGetAndDelete(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	userRepo := repo.NewGormRepo[TestUserEntity](db)

	u := &TestUserEntity{
		UUID:         uuid.New(),
		Email:        "test@example.com",
		PasswordHash: "vnjwuirnfeuirhguih349h",
		Name:         "Test User",
		PlatformRole: "user",
	}

	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	gotByID, err := userRepo.GetByID(ctx, u.ID)

	if err != nil {
		t.Fatalf("failed to get user by ID: %v", err)
	}
	if gotByID.Email != u.Email {
		t.Errorf("got email %q, want %q", gotByID.Email, u.Email)
	}

	gotByUUID, err := userRepo.GetByUUID(ctx, u.UUID)
	if err != nil {
		t.Fatalf("failed to get user by UUID: %v", err)
	}
	if gotByUUID.Email != u.Email {
		t.Errorf("got email %q, want %q", gotByUUID.Email, u.Email)
	}

	if err := userRepo.HardDelete(ctx, u.ID); err != nil {
		t.Fatalf("failed to hard delete user: %v", err)
	}

	_, err = userRepo.GetByID(ctx, u.ID)
	if err == nil {
		t.Fatalf("expected error when getting hard-deleted user, got nil")
	}
}

func TestUserRepo_List_WithPaginationAndSort(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	userRepo := repo.NewGormRepo[TestUserEntity](db)

	for i := 1; i <= 30; i++ {
		u := TestUserEntity{
			UUID:         uuid.New(),
			Email:        fmt.Sprintf("user%02d@example.com", i),
			PasswordHash: "skvjnfvnskn",
			Name:         fmt.Sprintf("User %02d", i),
			PlatformRole: "user",
		}

		if err := userRepo.Create(ctx, &u); err != nil {
			t.Fatalf("seed creation failed for %d: %v", i, err)
		}
	}

	// Page 2, size 10, sorted by Email ASC
	opts := store.QueryOpts{
		Page:     2,
		PageSize: 10,
		Sort: []store.SortField{
			{
				Field: "email",
				Desc:  false,
			},
		},
	}

	users, pageInfo, err := userRepo.List(ctx, opts)

	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(users) != 10 {
		t.Errorf("got %d users, want 10", len(users))
	}

	if pageInfo.PageSize != 10 || pageInfo.Page != 2 {
		t.Errorf("got pageInfo %+v, want PageSize=10, CurrentPage=2", pageInfo)
	}

	if pageInfo.Total != 30 {
		t.Errorf("got total %d, want 30", pageInfo.Total)
	}

	if !pageInfo.HasNext {
		t.Errorf("expected HasNext to be true")
	}

	// Spot check first record on page 2
	if users[0].Email != "user11@example.com" {
		t.Errorf("got first user email %q, want user11@example.com", users[0].Email)
	}
}

func TestUserRepo_UpdateAndSoftDelete(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	userRepo := repo.NewGormRepo[TestUserEntity](db)

	u := &TestUserEntity{
		UUID:         uuid.New(),
		Email:        "test@example.com",
		PasswordHash: "initialhash",
		Name:         "Initial Name",
		PlatformRole: "user",
	}

	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	u.Name = "Updated Name"
	if err := userRepo.Update(ctx, u); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	updated, err := userRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to get user after update: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("got name %q, want %q", updated.Name, "Updated Name")
	}

	if err := userRepo.SoftDelete(ctx, u.ID); err != nil {
		t.Fatalf("failed to soft delete user: %v", err)
	}

	_, err = userRepo.GetByID(ctx, u.ID)
	if err == nil {
		t.Fatalf("expected error when getting soft-deleted user, got nil")
	}

	// But row should still exist in DB
	var raw TestUserEntity
	if err := db.Unscoped().First(&raw, u.ID).Error; err != nil {
		t.Fatalf("expected row to exist Unscoped, got error: %v", err)
	}

	if !raw.DeletedAt.Valid {
		t.Fatalf("Expected DeletedAt to be set for soft-deleted row")
	}
}

func TestUserRepo_Upsert_OnEmail(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	userRepo := repo.NewGormRepo[TestUserEntity](db)

	u := &TestUserEntity{
		UUID:         uuid.New(),
		Email:        "test@example.com",
		PasswordHash: "initialhash",
		Name:         "Initial Name",
		PlatformRole: "user",
	}

	if err := userRepo.Upsert(ctx, u, []string{"email"}); err != nil {
		t.Fatalf("failed to upsert user: %v", err)
	}

	firstID := u.ID

	u.Name = "Updated Name"
	if err := userRepo.Upsert(ctx, u, []string{"email"}); err != nil {
		t.Fatalf("failed to upsert user second time: %v", err)
	}

	got, err := userRepo.GetByID(ctx, firstID)
	if err != nil {
		t.Fatalf("failed to get user after upsert: %v", err)
	}

	if got.ID != firstID {
		t.Errorf("expected same ID %d after upsert, got %d", firstID, got.ID)
	}

	if got.Name != "Updated Name" {
		t.Errorf("got name %q, want %q", got.Name, "Updated Name")
	}
}

func TestUserRepo_RollbackAndCommit(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// 1) Rollback scenario
	err := store.WithTx(ctx, db, func(ctx context.Context, tx *gorm.DB) error {
		r := repo.NewGormRepo[TestUserEntity](tx)
		u := &TestUserEntity{
			UUID:         uuid.New(),
			Email:        "tx-rollback@example.com",
			Name:         "Tx User",
			PasswordHash: "samplehash",
			PlatformRole: "user",
		}
		if err := r.Create(ctx, u); err != nil {
			return err
		}

		// Force rollback
		return fmt.Errorf("forcing rollback")
	})
	if err == nil {
		t.Fatalf("expected error from transaction to force rollback, got nil")
	}

	var count int64
	if err := db.Model(&TestUserEntity{}).Where("email = ?", "tx-rollback@example.com").Count(&count).Error; err != nil {
		t.Fatalf("failed to count users: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 users after rollback, got %d", count)
	}

	// 2) Commit scenario
	err = store.WithTx(ctx, db, func(ctx context.Context, tx *gorm.DB) error {
		r := repo.NewGormRepo[TestUserEntity](tx)
		u := &TestUserEntity{
			UUID:         uuid.New(),
			Email:        "tx-commit@example.com",
			Name:         "Tx Commit User",
			PasswordHash: "samplehash",
			PlatformRole: "user",
		}
		return r.Create(ctx, u)
	})
	if err != nil {
		t.Fatalf("unexpected error from transaction commit: %v", err)
	}

	if err := db.Model(&TestUserEntity{}).Where("email = ?", "tx-commit@example.com").Count(&count).Error; err != nil {
		t.Fatalf("failed to count users: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 user after commit, got %d", count)
	}
}

func TestUpdateColumnsGuarded(t *testing.T) {
	ctx := context.Background()
	r := repo.NewGormRepo[TestUserEntity](newTestDB(t))
	a := &TestUserEntity{Email: "a@example.com", Name: "a", PlatformRole: "pending"}
	b := &TestUserEntity{Email: "b@example.com", Name: "", PlatformRole: "pending"}
	for _, u := range []*TestUserEntity{a, b} {
		if err := r.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	pending := map[string]any{"platform_role": "pending"}

	ok, err := r.UpdateColumnsGuarded(ctx, a.ID, pending, nil, map[string]any{"platform_role": "active"})
	if err != nil || !ok {
		t.Fatalf("first transition: ok=%v err=%v", ok, err)
	}
	ok, err = r.UpdateColumnsGuarded(ctx, a.ID, pending, nil, map[string]any{"platform_role": "lost-the-race"})
	if err != nil || ok {
		t.Fatalf("second transition must lose: ok=%v err=%v", ok, err)
	}
	got, _ := r.GetByID(ctx, a.ID)
	if got.PlatformRole != "active" {
		t.Fatalf("role = %q", got.PlatformRole)
	}

	// A nil guard value is IS NULL, never raw SQL.
	ok, err = r.UpdateColumnsGuarded(ctx, a.ID, map[string]any{"deleted_at": nil}, nil, map[string]any{"name": "still-live"})
	if err != nil || !ok {
		t.Fatalf("IS NULL guard: ok=%v err=%v", ok, err)
	}

	// A raw OR condition must stay scoped to this id: b also has an empty name.
	where := []store.Clause{{Expr: "name IS NULL OR name = ?", Args: []any{""}}}
	ok, err = r.UpdateColumnsGuarded(ctx, a.ID, nil, where, map[string]any{"platform_role": "x"})
	if err != nil || ok {
		t.Fatalf("raw guard should not match a: ok=%v err=%v", ok, err)
	}
	got, _ = r.GetByID(ctx, b.ID)
	if got.PlatformRole != "pending" {
		t.Fatal("a raw OR guard leaked to another row")
	}

	// Injected keys are refused whichever value they carry, nil included.
	for _, val := range []any{"x", nil} {
		_, err := r.UpdateColumnsGuarded(ctx, a.ID, map[string]any{"1=1) OR (1=1": val}, nil, map[string]any{"name": "pwned"})
		if err == nil {
			t.Fatalf("injected guard column with value %v was accepted", val)
		}
	}
	got, _ = r.GetByID(ctx, b.ID)
	if got.Name == "pwned" {
		t.Fatal("injection reached another row")
	}
}

func TestListTotalIsRightWithAndWithoutTheCountQuery(t *testing.T) {
	ctx := context.Background()
	r := repo.NewGormRepo[TestUserEntity](newTestDB(t))
	for i := range 5 {
		if err := r.Create(ctx, &TestUserEntity{Email: fmt.Sprintf("u%d@example.com", i)}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		page, size int
		rows       int
		total      int64
		next       bool
	}{
		{1, 10, 5, 5, false}, // room to spare: derived
		{1, 5, 5, 5, false},  // exactly full: counted
		{1, 2, 2, 5, true},   // full with more after it
		{3, 2, 1, 5, false},  // short last page: derived
		{9, 2, 0, 5, false},  // past the end: counted, not offset+0
	}
	for _, tc := range cases {
		rows, info, err := r.List(ctx, store.QueryOpts{Page: tc.page, PageSize: tc.size})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != tc.rows || info.Total != tc.total || info.HasNext != tc.next {
			t.Errorf("page %d size %d: rows=%d total=%d next=%v", tc.page, tc.size, len(rows), info.Total, info.HasNext)
		}
	}
}

func TestUnscopedFindsSoftDeletedRows(t *testing.T) {
	ctx := context.Background()
	r := repo.NewGormRepo[TestUserEntity](newTestDB(t))
	u := &TestUserEntity{Email: "gone@example.com"}
	if err := r.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := r.SoftDelete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	opts := store.QueryOpts{Filters: map[string]any{"email": u.Email}}
	if n, _ := r.Count(ctx, opts); n != 0 {
		t.Fatalf("default scope count = %d", n)
	}
	opts.Unscoped = true
	if n, _ := r.Count(ctx, opts); n != 1 {
		t.Fatalf("unscoped count = %d", n)
	}
}
