//go:build unix

package sysinfo

import "syscall"

func diskUsage() (used, total uint64) {
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		total = fs.Blocks * uint64(fs.Bsize)
		used = (fs.Blocks - fs.Bfree) * uint64(fs.Bsize)
	}
	return used, total
}
