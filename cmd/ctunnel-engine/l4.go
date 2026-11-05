package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ctunnel/pkg/atomicfile"
	"ctunnel/pkg/l4"
	"ctunnel/pkg/tunnel"
)

// runL4 serves a layer-4 reverse tunnel (pkg/l4). With no interface to count
// on, it publishes its byte counters where an interface keeps them, under
// tunnel.L4Dir/<dev>, so traffic totals and the panel read it the same way.
func runL4(cfg config) error {
	forwards, err := l4.ParseForwards(strings.Fields(cfg.forwards))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	st := &l4.Stats{}
	done := make(chan struct{})
	go publishL4(cfg, st, done)
	err = l4.Run(ctx, l4.Config{
		Role:      cfg.role,
		Transport: cfg.kind,
		Port:      cfg.port,
		RemoteIP:  cfg.remoteIP,
		Token:     cfg.secret,
		Forwards:  forwards,
		SNI:       cfg.sni,
		Logf:      log.Printf,
	}, st)
	close(done)
	writeL4Counters(cfg, st, l4Key)
	return err
}

// l4Key changes with every engine start, as an ifindex does when an
// interface is recreated, so a restart starts its counters afresh.
var l4Key = func() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "l4-" + hex.EncodeToString(b)
}()

func publishL4(cfg config, st *l4.Stats, done <-chan struct{}) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		writeL4Counters(cfg, st, l4Key)
		select {
		case <-done:
			return
		case <-t.C:
		}
	}
}

// writeL4Counters writes ifindex, links and statistics/{rx,tx}_bytes. rx is
// what this server received through the tunnel: Kharej→Iran on Iran.
func writeL4Counters(cfg config, st *l4.Stats, key string) {
	dir := filepath.Join(tunnel.L4Dir, cfg.dev)
	if err := os.MkdirAll(filepath.Join(dir, "statistics"), 0o755); err != nil {
		return
	}
	rx, tx := st.Up.Load(), st.Down.Load()
	if cfg.role == "kharej" {
		rx, tx = tx, rx
	}
	for name, v := range map[string]string{
		"ifindex":             key,
		"links":               strconv.FormatInt(st.Links.Load(), 10),
		"statistics/rx_bytes": strconv.FormatInt(rx, 10),
		"statistics/tx_bytes": strconv.FormatInt(tx, 10),
	} {
		writeFileAtomic(filepath.Join(dir, name), v+"\n")
	}
}

func writeFileAtomic(path, text string) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return
	}
	if atomicfile.Replace(tmp, path) != nil {
		_ = os.Remove(tmp)
	}
}
