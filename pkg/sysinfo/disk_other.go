//go:build !unix

package sysinfo

func diskUsage() (used, total uint64) { return 0, 0 }
