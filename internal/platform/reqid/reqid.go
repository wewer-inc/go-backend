// Package reqid holds the request id on a context.Context, for code below the HTTP layer
// that wants to say which request it is serving.
//
// Handlers pass c.Request.Context() down and nothing else, so the context is the only
// route the id has to a service. RequestIDMiddleware writes it here so that a service can
// read it without importing the middleware package, which would make a lower layer depend
// on a higher one just to obtain a string.
package reqid

import "context"

type ctxKey struct{}

// NewContext attaches id to ctx. An empty id leaves ctx as it was, which makes an unset id
// and an empty one indistinguishable to FromContext.
func NewContext(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the id attached to ctx. Expect it to be empty in background work,
// since no request started that.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}
