//go:build !linux

package pck

// CleanupPckGuards is a no-op where PCK cannot install kernel rules.
func CleanupPckGuards(...string) {}
