package store

import "context"

type expectedErrorKey struct{}

// ExpectError returns a context under which a failing statement stays out of the SQL log
// when match accepts its error. Only the log line is affected: the caller still receives
// the error as usual.
//
// Use it where an error is a normal result, as when a unique violation means the row was
// already there. GORM logs all failures the same way, so otherwise a routine conflict
// looks like a fault to whoever reads the log and trips any alert on "ERROR". Scope the
// mark to the single call that anticipates the error, and make match no broader than that
// result.
//
// Nesting adds to what is accepted: under two marks, an error either one accepts is quiet.
func ExpectError(ctx context.Context, match func(error) bool) context.Context {
	if match == nil {
		return ctx
	}
	accepts := match
	if outer := expectedBy(ctx); outer != nil {
		accepts = func(err error) bool { return outer(err) || match(err) }
	}
	return context.WithValue(ctx, expectedErrorKey{}, accepts)
}

// IsExpectedError reports whether a mark on ctx accepts err. It is always false for a nil err.
func IsExpectedError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if accepts := expectedBy(ctx); accepts != nil {
		return accepts(err)
	}
	return false
}

func expectedBy(ctx context.Context) func(error) bool {
	accepts, _ := ctx.Value(expectedErrorKey{}).(func(error) bool)
	return accepts
}
