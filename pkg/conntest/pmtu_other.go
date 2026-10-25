//go:build !linux

package conntest

import "context"

// PathMTU is only measured on Linux.
func PathMTU(context.Context, Link) int { return 0 }
