package pgdialect

import (
	"database/sql"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestConfigForcesExecModeOverTheDSN(t *testing.T) {
	cfg, err := Config("postgres://u:p@localhost:5432/d?default_query_exec_mode=cache_statement")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultQueryExecMode != ExecMode {
		t.Fatalf("mode = %v", cfg.DefaultQueryExecMode)
	}
}

func TestOpenBuildsAPoolWithoutConnecting(t *testing.T) {
	d, ok := Open("postgres://u:p@localhost:1/d").(*postgres.Dialector)
	if !ok {
		t.Fatal("a valid DSN must give the postgres dialector")
	}
	pool, ok := d.Conn.(*sql.DB)
	if !ok {
		t.Fatalf("conn = %T", d.Conn)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBadDSNSurfacesFromOpenWithoutThePassword(t *testing.T) {
	_, err := gorm.Open(Open("postgres://u:hunter2@localhost:notaport/d"), &gorm.Config{})
	if err == nil {
		t.Fatal("a bad DSN must fail gorm.Open")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("password leaked: %v", err)
	}
}
