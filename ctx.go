package main

import "context"

func setContext(ctx context.Context, key, val any) context.Context {
	return context.WithValue(ctx, key, val)
}
