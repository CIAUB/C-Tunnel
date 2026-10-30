package webpanel

import (
	"time"
)

const telemetrySamples = 60

type telemetrySeries struct {
	RXMbps    float64   `json:"rx_mbps"`
	TXMbps    float64   `json:"tx_mbps"`
	RXTotal   uint64    `json:"rx_total"`
	TXTotal   uint64    `json:"tx_total"`
	RXHistory []float64 `json:"rx_history"`
	TXHistory []float64 `json:"tx_history"`
}

type telemetryView struct {
	SampleSeconds float64                    `json:"sample_seconds"`
	Aggregate     telemetrySeries            `json:"aggregate"`
	Tunnels       map[string]telemetrySeries `json:"tunnels"`
}

type telemetryState struct {
	last      time.Time
	aggregate telemetrySeries
	tunnels   map[string]*telemetryTunnel
}

type telemetryTunnel struct {
	rx     uint64
	tx     uint64
	series telemetrySeries
}

func newSeries() telemetrySeries {
	return telemetrySeries{
		RXHistory: make([]float64, telemetrySamples),
		TXHistory: make([]float64, telemetrySamples),
	}
}

func newTelemetryState() *telemetryState {
	return &telemetryState{aggregate: newSeries(), tunnels: map[string]*telemetryTunnel{}}
}

func appendSample(history []float64, value float64) []float64 {
	if len(history) >= telemetrySamples {
		copy(history, history[len(history)-telemetrySamples+1:])
		history[telemetrySamples-1] = value
		return history
	}
	return append(history, value)
}

func (s *Server) observeTelemetry(views []tunnelView, now time.Time) telemetryView {
	s.telemetryMu.Lock()
	defer s.telemetryMu.Unlock()
	st := s.telemetry
	if st == nil {
		st = newTelemetryState()
		s.telemetry = st
	}
	dt := 0.0
	if !st.last.IsZero() {
		dt = now.Sub(st.last).Seconds()
		if dt < 0 {
			dt = 0
		}
	}
	st.last = now

	seen := make(map[string]bool, len(views))
	next := make(map[string]*telemetryTunnel, len(views))
	var aggRX, aggTX float64
	var totalRX, totalTX uint64
	for _, view := range views {
		seen[view.Name] = true
		t := st.tunnels[view.Name]
		if t == nil {
			t = &telemetryTunnel{rx: view.Status.RxBytes, tx: view.Status.TxBytes, series: newSeries()}
		}
		rx, tx := 0.0, 0.0
		if dt > 0 && view.Status.RxBytes >= t.rx && view.Status.TxBytes >= t.tx {
			rx = float64(view.Status.RxBytes-t.rx) * 8 / dt / 1e6
			tx = float64(view.Status.TxBytes-t.tx) * 8 / dt / 1e6
		}
		t.rx, t.tx = view.Status.RxBytes, view.Status.TxBytes
		t.series.RXMbps, t.series.TXMbps = rx, tx
		t.series.RXTotal, t.series.TXTotal = view.Status.RxBytes, view.Status.TxBytes
		t.series.RXHistory = appendSample(t.series.RXHistory, rx)
		t.series.TXHistory = appendSample(t.series.TXHistory, tx)
		aggRX += rx
		aggTX += tx
		totalRX += view.Status.RxBytes
		totalTX += view.Status.TxBytes
		next[view.Name] = t
	}
	for name := range st.tunnels {
		if !seen[name] {
			delete(st.tunnels, name)
		}
	}
	for name, t := range next {
		st.tunnels[name] = t
	}
	st.aggregate.RXMbps, st.aggregate.TXMbps = aggRX, aggTX
	st.aggregate.RXTotal, st.aggregate.TXTotal = totalRX, totalTX
	st.aggregate.RXHistory = appendSample(st.aggregate.RXHistory, aggRX)
	st.aggregate.TXHistory = appendSample(st.aggregate.TXHistory, aggTX)

	out := telemetryView{
		SampleSeconds: dt,
		Aggregate:     copyTelemetrySeries(st.aggregate),
		Tunnels:       make(map[string]telemetrySeries, len(next)),
	}
	for name, t := range next {
		out.Tunnels[name] = copyTelemetrySeries(t.series)
	}
	return out
}

func copyTelemetrySeries(s telemetrySeries) telemetrySeries {
	s.RXHistory = append([]float64(nil), s.RXHistory...)
	s.TXHistory = append([]float64(nil), s.TXHistory...)
	return s
}
