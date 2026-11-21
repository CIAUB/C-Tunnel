package tunnel

import (
	"errors"
	"fmt"
	"math"

	"ctunnel/pkg/catalog"
)

// BytesPerGB is 1 GiB (1024^3 bytes), matching panel and bot traffic formatting.
const BytesPerGB = uint64(1024 * 1024 * 1024)

// QuotaInfo describes a tunnel's live traffic usage against its configured quota.
type QuotaInfo struct {
	QuotaGB        float64 `json:"quota_gb"`
	LimitBytes     uint64  `json:"limit_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	RemainingBytes uint64  `json:"remaining_bytes"`
	Percent        float64 `json:"percent"`
	Active         bool    `json:"active"`
	Exhausted      bool    `json:"exhausted"`
	Stopped        bool    `json:"stopped"`
	Overridden     bool    `json:"overridden"`
}

// QuotaLimitBytes converts quotaGB to bytes (0 when unlimited).
func QuotaLimitBytes(quotaGB float64) uint64 {
	if quotaGB <= 0 || math.IsNaN(quotaGB) || math.IsInf(quotaGB, 0) {
		return 0
	}
	v := quotaGB * float64(BytesPerGB)
	if v >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Round(v))
}

// QuotaStatus returns the current usage and quota state for tc.
func QuotaStatus(tc catalog.TunnelConfig) QuotaInfo {
	rx, tx := TrafficTotal(tc.Name)
	used := rx + tx
	limit := QuotaLimitBytes(tc.QuotaGB)
	q := QuotaInfo{
		QuotaGB:    tc.QuotaGB,
		LimitBytes: limit,
		UsedBytes:  used,
		Active:     limit > 0,
		Stopped:    tc.QuotaStopped,
		Overridden: tc.QuotaOverride,
	}
	if limit > 0 {
		if used >= limit {
			q.Exhausted = true
			q.RemainingBytes = 0
			q.Percent = 100
		} else {
			q.RemainingBytes = limit - used
			q.Percent = math.Round((float64(used)/float64(limit))*1000) / 10
		}
	}
	return q
}

// StartManual starts a tunnel explicitly on user command. If the tunnel has an
// exhausted quota (or was auto-stopped by quota), it enables QuotaOverride so
// the background agent will not automatically stop it again until reset or top-up.
func StartManual(st *catalog.Store, name string) (catalog.TunnelConfig, bool, error) {
	tc, ok := st.Find(name)
	if !ok {
		return catalog.TunnelConfig{}, false, fmt.Errorf("tunnel %q not found", name)
	}
	q := QuotaStatus(tc)
	overrode := false
	if q.Active && (q.Exhausted || tc.QuotaStopped) {
		tc.QuotaOverride = true
		tc.QuotaStopped = false
		overrode = true
		if err := st.Upsert(tc); err != nil {
			return tc, false, err
		}
	}
	if err := Apply(tc); err != nil {
		return tc, overrode, err
	}
	return tc, overrode, nil
}

// ResetQuotaUsage zeroes the tunnel's recorded traffic counter and clears any
// exhausted/override flags so normal quota enforcement resumes cleanly.
func ResetQuotaUsage(st *catalog.Store, name string) (catalog.TunnelConfig, error) {
	tc, ok := st.Find(name)
	if !ok {
		return catalog.TunnelConfig{}, fmt.Errorf("tunnel %q not found", name)
	}
	if err := ResetTraffic(tc.Name); err != nil {
		return tc, err
	}
	tc.QuotaStopped = false
	tc.QuotaOverride = false
	if err := st.Upsert(tc); err != nil {
		return tc, err
	}
	return tc, nil
}

// AddQuotaGB increases a tunnel's traffic quota by extraGB. If the tunnel was
// auto-stopped by quota and the new cap exceeds current usage, it clears
// QuotaStopped/QuotaOverride and restarts the tunnel automatically.
func AddQuotaGB(st *catalog.Store, name string, extraGB float64) (catalog.TunnelConfig, bool, error) {
	if math.IsNaN(extraGB) || math.IsInf(extraGB, 0) || extraGB <= 0 {
		return catalog.TunnelConfig{}, false, errors.New("extra quota must be greater than 0 GB")
	}
	tc, ok := st.Find(name)
	if !ok {
		return catalog.TunnelConfig{}, false, fmt.Errorf("tunnel %q not found", name)
	}
	wasStopped := tc.QuotaStopped
	tc.QuotaGB = math.Round((tc.QuotaGB+extraGB)*100) / 100
	q := QuotaStatus(tc)
	resumed := false
	if !q.Exhausted {
		tc.QuotaStopped = false
		tc.QuotaOverride = false
	}
	if err := st.Upsert(tc); err != nil {
		return tc, false, err
	}
	if wasStopped && !q.Exhausted {
		if err := Apply(tc); err != nil {
			return tc, false, err
		}
		resumed = true
	}
	return tc, resumed, nil
}

// EnforceQuota checks one tunnel against its configured traffic cap. When the
// cap is reached (and neither QuotaOverride nor QuotaStopped is set), it
// checkpoints traffic, records QuotaStopped=true, stops the tunnel, and reports
// tripped=true along with the final used and limit byte counts.
func EnforceQuota(st *catalog.Store, name string) (tripped bool, usedBytes, limitBytes uint64, err error) {
	tc, ok := st.Find(name)
	if !ok {
		return false, 0, 0, nil
	}
	if tc.QuotaGB <= 0 || tc.QuotaOverride || tc.QuotaStopped {
		return false, 0, 0, nil
	}
	_ = CheckpointTraffic(tc.Name)
	q := QuotaStatus(tc)
	if !q.Active || !q.Exhausted {
		return false, q.UsedBytes, q.LimitBytes, nil
	}
	tc.QuotaStopped = true
	if err := st.Upsert(tc); err != nil {
		return false, q.UsedBytes, q.LimitBytes, err
	}
	if err := Stop(tc); err != nil {
		return true, q.UsedBytes, q.LimitBytes, err
	}
	return true, q.UsedBytes, q.LimitBytes, nil
}
