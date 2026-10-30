package db

// Nothing generates this file. The .gen.go suffix is deliberate, and renaming the file
// would damage the SQL log.
//
// GORM prefixes each log line with the file and line that issued the statement, which is
// what connects a slow or failed query to the code behind it. To find that place it walks
// up the stack, skipping GORM's own frames, test files and anything named *.gen.go.
// expectingLogger.Trace sits on every statement's path, so under an ordinary filename this
// file would be reported as the origin of every line. TestSQLLogNamesTheCallerNotTheWrapper
// fails if that happens.

import (
	"context"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// expectingLogger wraps the SQL log and discards the line for any statement error that
// store.ExpectError marked on its context. Everything else reaches the inner logger as is.
type expectingLogger struct{ glogger.Interface }

// Redaction depends on the method this assertion checks. GORM looks for ParamsFilter with a
// type assertion on the outermost logger, and the embedded interface does not declare it,
// so without an explicit method here the values would be back in every logged statement.
var _ gorm.ParamsFilter = expectingLogger{}

// LogMode rewraps the logger GORM derives for a new level, so that it keeps the filtering.
func (l expectingLogger) LogMode(level glogger.LogLevel) glogger.Interface {
	return expectingLogger{Interface: l.Interface.LogMode(level)}
}

// Trace forwards to the inner logger unless ctx marks err as expected.
func (l expectingLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if !store.IsExpectedError(ctx, err) {
		l.Interface.Trace(ctx, begin, fc, err)
	}
}

// ParamsFilter delegates to the inner logger if it filters, and otherwise returns the
// statement and its parameters as given.
func (l expectingLogger) ParamsFilter(ctx context.Context, sql string, params ...any) (string, []any) {
	if f, ok := l.Interface.(gorm.ParamsFilter); ok {
		return f.ParamsFilter(ctx, sql, params...)
	}
	return sql, params
}
