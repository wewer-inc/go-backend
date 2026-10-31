// Package pgdialect gives GORM its Postgres connections, configured the way all of this
// application's pools have to be.
//
// The setting that justifies a separate package is QueryExecModeExec. Left on its default,
// pgx prepares a statement the first time a connection sees it and remembers the columns
// it returns. Adding a column changes the answer for `SELECT *`, so after such a migration
// each older connection reports "cached plan must not change result type" once per
// remembered statement, and users see a run of 500s during the deploy. The longer
// connections live, the longer that run lasts.
//
// How the modes compare:
//   - QueryExecModeExec keeps no state on the connection, leaving nothing for a schema
//     change to invalidate, and each statement costs a single round trip every time.
//   - QueryExecModeSimpleProtocol avoids the error too, but it inlines parameter values
//     into the statement, where Postgres statement logging would record personal data.
//     Exec mode leaves $n placeholders in what the server sees.
//   - QueryExecModeCacheDescribe still remembers the columns. QueryExecModeDescribeExec
//     does not, but needs two round trips per statement.
//
// What Exec mode gives up is plan reuse and binary results: Postgres plans each execution
// and answers in text. Neither is significant next to the network round trip.
//
// One trap follows from it. Exec mode encodes an argument as the default Postgres type of
// its Go type, and for []byte pgx defaults to bytea, which sends hex such as `\x7b22...`.
// A json column refuses that, and a text column keeps the hex as though it were the value.
// Each connection therefore maps []byte to text. A real bytea column is written through the
// Bytea type, because a plain []byte would arrive as text and any backslash in it would be
// read as an escape.
//
// Staying a leaf package lets platform/db, the test support and any entity with a Bytea
// field import it.
package pgdialect

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ExecMode is the pgx query mode applied to all connections. The package comment explains
// the choice.
const ExecMode = pgx.QueryExecModeExec

// Bytea marks a value bound for a bytea column, and such a column must be written through
// it rather than as []byte. Assignment to and from []byte is implicit, so code reading the
// value needs no cast. It must not implement driver.Valuer, since database/sql would then
// hand pgx a plain []byte and the type that pgx dispatches on would be gone.
type Bytea []byte

// Config returns the pgx connection settings for dsn with ExecMode forced. A
// default_query_exec_mode in the DSN loses, because the mode decides whether a deploy
// breaks running queries and no environment should be able to opt out of that.
func Config(dsn string) (*pgx.ConnConfig, error) {
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		// Safe to wrap and log: pgconn strips the password out of a parse failure.
		return nil, fmt.Errorf("pgdialect: parse dsn: %w", err)
	}
	parsed.DefaultQueryExecMode = ExecMode
	return parsed, nil
}

func afterConnect(_ context.Context, conn *pgx.Conn) error {
	types := conn.TypeMap()
	types.RegisterDefaultPgType([]byte(nil), "text")
	types.RegisterDefaultPgType(Bytea(nil), "bytea")
	return nil
}

// Open returns a GORM dialector backed by a database/sql pool that uses Config's settings.
// An invalid DSN is not reported here but by gorm.Open.
func Open(dsn string) gorm.Dialector {
	connConfig, err := Config(dsn)
	if err != nil {
		return rejectedDSN{cause: err}
	}
	pool := stdlib.OpenDB(*connConfig, stdlib.OptionAfterConnect(afterConnect))
	return postgres.New(postgres.Config{Conn: pool})
}

// rejectedDSN stands in for a real dialector so that Initialize can return the parse error.
type rejectedDSN struct {
	postgres.Dialector
	cause error
}

func (r rejectedDSN) Initialize(*gorm.DB) error { return r.cause }
