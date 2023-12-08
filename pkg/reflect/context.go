package reflect

import (
	"context"
	"fmt"

	"darvaza.org/core"
	"darvaza.org/slog"
)

var (
	idCtxKey  = core.NewContextKey[string]("dns.reflect.id")
	logCtxKey = core.NewContextKey[func(string) (slog.LogLevel, bool)]("dns.reflect.enabled")
)

// WithID attaches a tracing ID to the request's context.
func WithID(ctx context.Context, machID uint16, msgID uint16) context.Context {
	// TODO: include 32 bit timestamp
	s := fmt.Sprintf("%04x-%04x", machID, msgID)
	return idCtxKey.WithValue(ctx, s)
}

// WithFormattedID attaches a tracing ID to the request's context.
func WithFormattedID(ctx context.Context, id string) context.Context {
	return idCtxKey.WithValue(ctx, id)
}

// GetID extracts the tracing ID from the request's context.
func GetID(ctx context.Context) (string, bool) {
	return idCtxKey.Get(ctx)
}

// WithEnabledFunc attaches a function to determine of a reflection layer is enabled
// or not.
func WithEnabledFunc(ctx context.Context, cond func(string) (slog.LogLevel, bool)) context.Context {
	if cond == nil {
		panic(core.ErrInvalid)
	}

	return logCtxKey.WithValue(ctx, cond)
}

// WithEnabled attaches an unconditional reflection layer state regardless the name
func WithEnabled(ctx context.Context, level slog.LogLevel, enabled bool) context.Context {
	cond := func(string) (slog.LogLevel, bool) {
		return level, enabled
	}

	return WithEnabledFunc(ctx, cond)
}

// GetEnabled tests if the context enables the specified reflection layer or not.
func GetEnabled(ctx context.Context, name string) (slog.LogLevel, bool) {
	if cond, ok := logCtxKey.Get(ctx); ok {
		return cond(name)
	}

	return slog.UndefinedLevel, false
}
