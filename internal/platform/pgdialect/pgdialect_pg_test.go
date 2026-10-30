//go:build integration

package pgdialect

import (
	"os"
	"testing"

	"gorm.io/gorm"
)

func TestExecModeSurvivesASchemaChangeAndKeepsBytesIntact(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := gorm.Open(Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // reuse one connection, the one that would hold a stale shape
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.Exec(`DROP TABLE IF EXISTS pgd_probe; CREATE TABLE pgd_probe (id int, j jsonb, t text, b bytea)`).Error; err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"a":1}`)
	bin := Bytea{0x00, 0x5c, 0xff}
	if err := db.Exec(`INSERT INTO pgd_probe (id, j, t, b) VALUES (1, ?, ?, ?)`, raw, raw, bin).Error; err != nil {
		t.Fatalf("[]byte into jsonb and text, Bytea into bytea: %v", err)
	}

	var rows []map[string]any
	if err := db.Raw(`SELECT * FROM pgd_probe`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`ALTER TABLE pgd_probe ADD COLUMN extra int`).Error; err != nil {
		t.Fatal(err)
	}
	// The default pgx mode fails here with "cached plan must not change result type".
	rows = nil
	if err := db.Raw(`SELECT * FROM pgd_probe`).Scan(&rows).Error; err != nil {
		t.Fatalf("select after adding a column: %v", err)
	}
	if _, ok := rows[0]["extra"]; !ok {
		t.Fatalf("new column missing: %v", rows[0])
	}
	if got := rows[0]["t"]; got != string(raw) {
		t.Fatalf("[]byte reached a text column as %v", got)
	}

	var stored []byte
	if err := db.Raw(`SELECT b FROM pgd_probe`).Row().Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(bin) {
		t.Fatalf("bytea round trip = %x", stored)
	}
}
