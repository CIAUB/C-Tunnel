package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/version"
)

const (
	BackupFormatV1  = "ctunnel-backup/1"
	BackupFormatV2  = "ctunnel-backup/2"
	MaxBackupBytes  = 4 << 20
	MaxBackupTunnel = 256
)

// TrafficEntry stores cumulative RX/TX bytes for a tunnel or archived ledger.
type TrafficEntry struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// BackupFile is the portable JSON archive exported and imported by the Web
// Panel, Telegram Bot, and CLI. Version 2 includes persistent per-tunnel and
// archived cumulative traffic totals; version 1 backups remain fully readable.
type BackupFile struct {
	Format   string                  `json:"format"`
	Version  string                  `json:"version"`
	Created  time.Time               `json:"created"`
	Tunnels  []catalog.TunnelConfig  `json:"tunnels"`
	Traffic  map[string]TrafficEntry `json:"traffic,omitempty"`
	Archived TrafficEntry            `json:"archived,omitempty"`
	Total    TrafficEntry            `json:"total,omitempty"`
}

// RestoreResult summarizes what RestoreBackup did.
type RestoreResult struct {
	Created        []string `json:"created"`
	Overwritten    []string `json:"overwritten,omitempty"`
	Skipped        []string `json:"skipped"`
	Failed         []string `json:"failed"`
	RestoredRx     uint64   `json:"restored_rx"`
	RestoredTx     uint64   `json:"restored_tx"`
	TotalCumRx     uint64   `json:"total_cum_rx"`
	TotalCumTx     uint64   `json:"total_cum_tx"`
	BackupVersion  string   `json:"backup_version,omitempty"`
	TrafficEntries int      `json:"traffic_entries"`
}

// CreateBackup checkpoints live tunnel traffic and encodes all tunnels plus
// their persistent cumulative traffic counters into a ctunnel-backup/2 JSON blob.
func CreateBackup(storeDir string) ([]byte, BackupFile, error) {
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return nil, BackupFile{}, err
	}
	now := time.Now().UTC()
	tunnels := st.Tunnels
	if tunnels == nil {
		tunnels = []catalog.TunnelConfig{}
	}
	traffic := make(map[string]TrafficEntry, len(tunnels))
	var sumRx, sumTx uint64
	for _, tc := range tunnels {
		_ = CheckpointTraffic(tc.Name)
		rx, tx := TrafficTotal(tc.Name)
		traffic[tc.Name] = TrafficEntry{RxBytes: rx, TxBytes: tx}
		sumRx += rx
		sumTx += tx
	}
	bf := BackupFile{
		Format:   BackupFormatV2,
		Version:  version.Version,
		Created:  now,
		Tunnels:  tunnels,
		Traffic:  traffic,
		Archived: TrafficEntry{RxBytes: st.ArchivedRx, TxBytes: st.ArchivedTx},
		Total:    TrafficEntry{RxBytes: sumRx + st.ArchivedRx, TxBytes: sumTx + st.ArchivedTx},
	}
	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return nil, BackupFile{}, err
	}
	data = append(data, '\n')
	return data, bf, nil
}

// ParseBackup decodes and validates a ctunnel-backup/1 or ctunnel-backup/2 file.
func ParseBackup(data []byte) (BackupFile, error) {
	if len(data) == 0 || len(data) > MaxBackupBytes {
		return BackupFile{}, errors.New("backup file is empty or exceeds size limit")
	}
	var bf BackupFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bf); err != nil {
		return BackupFile{}, errors.New("not a valid C-Tunnel backup file")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return BackupFile{}, errors.New("backup file contains trailing data")
	}
	if bf.Format != BackupFormatV1 && bf.Format != BackupFormatV2 {
		return BackupFile{}, fmt.Errorf("unsupported backup format %q", bf.Format)
	}
	if len(bf.Tunnels) > MaxBackupTunnel {
		return BackupFile{}, errors.New("the backup holds too many tunnels")
	}
	return bf, nil
}

// RestoreBackup imports tunnels and their persistent traffic usage from data.
// When overwrite is false, existing tunnels with the same name are left intact.
// When overwrite is true, existing same-name tunnels are updated and their
// traffic counters are restored from the backup as well.
func RestoreBackup(storeDir string, data []byte, overwrite bool) (RestoreResult, error) {
	bf, err := ParseBackup(data)
	if err != nil {
		return RestoreResult{}, err
	}
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return RestoreResult{}, err
	}
	res := RestoreResult{
		Created:       []string{},
		Overwritten:   []string{},
		Skipped:       []string{},
		Failed:        []string{},
		BackupVersion: bf.Version,
	}

	for _, tc := range bf.Tunnels {
		origName := tc.Name
		cleanName := SanitizeName(tc.Name)
		_, exists := st.Find(cleanName)
		if exists && !overwrite {
			res.Skipped = append(res.Skipped, origName)
			continue
		}
		if exists {
			if err := Save(st, &tc); err != nil {
				res.Failed = append(res.Failed, origName+": "+err.Error())
				continue
			}
			res.Overwritten = append(res.Overwritten, tc.Name)
		} else {
			if err := Create(st, &tc); err != nil {
				res.Failed = append(res.Failed, origName+": "+err.Error())
				continue
			}
			res.Created = append(res.Created, tc.Name)
		}
		// Restore persistent traffic counters before starting the tunnel so the
		// live counter starts adding on top of the restored historical total.
		if tr, ok := lookupBackupTraffic(bf.Traffic, origName, tc.Name); ok {
			if err := SeedTraffic(tc.Name, tr.RxBytes, tr.TxBytes); err == nil {
				res.RestoredRx += tr.RxBytes
				res.RestoredTx += tr.TxBytes
				res.TrafficEntries++
			}
		}
		// Respect QuotaStopped on restored tunnels so an already-exhausted
		// tunnel does not unexpectedly resume until the user acts.
		if tc.QuotaStopped {
			continue
		}
		if err := Apply(tc); err != nil {
			res.Failed = append(res.Failed, tc.Name+": saved, but starting failed: "+err.Error())
		}
	}

	// Preserve archived cumulative traffic (e.g. from previously removed tunnels)
	// so server-wide cumulative totals survive server migration intact.
	archivedChanged := false
	if bf.Archived.RxBytes > st.ArchivedRx {
		st.ArchivedRx = bf.Archived.RxBytes
		archivedChanged = true
	}
	if bf.Archived.TxBytes > st.ArchivedTx {
		st.ArchivedTx = bf.Archived.TxBytes
		archivedChanged = true
	}
	if archivedChanged {
		_ = st.Save()
	}

	res.TotalCumRx, res.TotalCumTx = TotalTrafficAll(st)
	return res, nil
}

func lookupBackupTraffic(m map[string]TrafficEntry, origName, cleanName string) (TrafficEntry, bool) {
	if len(m) == 0 {
		return TrafficEntry{}, false
	}
	if v, ok := m[cleanName]; ok {
		return v, true
	}
	if origName != cleanName {
		if v, ok := m[origName]; ok {
			return v, true
		}
	}
	return TrafficEntry{}, false
}
