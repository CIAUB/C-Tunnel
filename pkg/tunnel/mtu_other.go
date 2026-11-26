//go:build !linux

package tunnel

import "context"

func probeICMPPathMTU(context.Context, string, int) int { return 0 }
