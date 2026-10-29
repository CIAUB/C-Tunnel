// Package atomicfile replaces a file without exposing a partial write.
package atomicfile

import (
	"os"
	"runtime"
	"time"
)

// Replace renames src over dst. On Windows an open destination briefly rejects
// the replace with a sharing violation, so retry that window instead of
// failing a save. Non-Windows systems rename atomically in one call.
func Replace(src, dst string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(src, dst)
	}
	var err error
	for i := 0; i < 100; i++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}
