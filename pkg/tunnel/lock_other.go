//go:build !unix

package tunnel

// LockDir is unused where tunnels cannot run.
var LockDir = ""

func lockTunnel(string) (func(), error) { return func() {}, nil }
