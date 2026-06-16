package proxy

import "context"

// contextKey is an unexported type for context keys in this package,
// preventing collisions with keys from other packages.
type contextKey int

const (
	// originalPathKey is the context key for the preserved original request path.
	originalPathKey contextKey = iota
)

// withOriginalPath returns a new context that carries the given original path.
func withOriginalPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, originalPathKey, path)
}

// OriginalPathFromContext retrieves the original request path stored in ctx by
// withOriginalPath. Returns an empty string if no path has been stored.
func OriginalPathFromContext(ctx context.Context) string {
	v, _ := ctx.Value(originalPathKey).(string)
	return v
}
