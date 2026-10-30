package webpanel

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
)

var runMethodTest = conntest.Run

type testDeployment struct {
	Owner    string
	Expires  time.Time
	Config   catalog.TunnelConfig
	Result   conntest.Result
	Created  bool
	Response map[string]any
}

type methodTestRequest struct {
	Link    string   `json:"link"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Role    string   `json:"role"`
	LocalIP string   `json:"local_ip"`
	Token   string   `json:"token"`
	Ports   []string `json:"ports"`
}

// chooseBest uses only successful measured rows, penalizing latency and jitter.
// A TCP baseline or a family-level suggestion is never turned into a GRE result.
func chooseBest(rows []conntest.Result) (conntest.Result, bool) {
	return chooseBestMode(rows, "")
}

func chooseBestMode(rows []conntest.Result, mode string) (conntest.Result, bool) {
	var best conntest.Result
	bestScore := -1.0
	for _, r := range rows {
		if mode != "" && r.Mode != mode {
			continue
		}
		if r.Status() != "ok" || r.Sent < conntest.Probes || r.Received != r.Sent || r.DownMbps <= 0 || r.UpMbps <= 0 {
			continue
		}
		base := strings.TrimPrefix(strings.TrimPrefix(r.Method, "frp+"), "rev+")
		m, ok := catalog.LookupMethod(base)
		if !ok || m.Name != base {
			continue
		}
		score := r.Total() / (1 + (r.RTTms+r.JitterMs)/20)
		if math.IsNaN(score) || math.IsInf(score, 0) || score <= 0 {
			continue
		}
		if score > bestScore || (score == bestScore && r.RTTms < best.RTTms) {
			best, bestScore = r, score
		}
	}
	return best, bestScore >= 0
}

func (s *Server) handleLinkTest(w http.ResponseWriter, r *http.Request) {
	var req methodTestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	// Capture the authenticated cookie before a long-running test: panel settings
	// may change the cookie namespace while measurement is in flight.
	cookie, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session changed; log in again"})
		return
	}
	select {
	case s.testSlot <- struct{}{}:
		defer func() { <-s.testSlot }()
	default:
		writeError(w, 429, errors.New("a connection test is already running"))
		return
	}
	if req.Link == "" {
		// Preserve the legacy baseline API, without claiming a protocol was measured.
		ip := net.ParseIP(strings.TrimSpace(req.Host))
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			writeError(w, 400, errors.New("enter a unicast IP address or a method-test link"))
			return
		}
		if req.Port < 1 || req.Port > 65535 {
			req.Port = speedtest.DefaultSpeedPort
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		res := speedtest.Run(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(req.Port)), 12)
		writeJSON(w, 200, map[string]any{"result": res, "text": speedtest.Format(res), "deployment_available": false})
		return
	}
	link, err := conntest.DecodeLink(req.Link)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if req.Role != "iran" && req.Role != "kharej" {
		writeError(w, 400, errors.New("select this server's deployment role"))
		return
	}
	if req.LocalIP != "" && net.ParseIP(req.LocalIP) == nil {
		writeError(w, 400, errors.New("invalid local IP"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	rows, err := runMethodTest(ctx, link, nil)
	if err != nil {
		writeError(w, 502, err)
		return
	}
	res := map[string]any{"rows": rows, "text": conntest.Verdict(link.Host, rows), "deployment_available": false}
	best, ok := chooseBest(rows)
	if ok {
		id, e := randomID()
		if e != nil {
			writeError(w, 500, e)
			return
		}
		tc := catalog.TunnelConfig{Role: req.Role, Method: strings.TrimPrefix(strings.TrimPrefix(best.Method, "frp+"), "rev+"), Reverse: best.Mode == "REVERSE", LocalIP: req.LocalIP, RemoteIP: link.Host, Token: req.Token, Ports: req.Ports}
		if tc.Role != "iran" {
			tc.Ports = nil
		}
		s.mu.Lock()
		for key, t := range s.tests {
			if time.Now().After(t.Expires) {
				delete(s.tests, key)
			}
		}
		if len(s.tests) >= 8 {
			s.mu.Unlock()
			writeError(w, 429, errors.New("too many pending deployments; retry after the test expiry"))
			return
		}
		s.tests[id] = &testDeployment{Owner: cookie.Value, Expires: time.Now().Add(10 * time.Minute), Config: tc, Result: best}
		s.mu.Unlock()
		res["test_id"], res["best"], res["deployment_available"] = id, best, true
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleDeployBest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TestID string `json:"test_id"`
		Token  string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	cookie, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session changed; log in again"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	test, ok := s.tests[req.TestID]
	if !ok || test.Owner != cookie.Value || time.Now().After(test.Expires) {
		writeError(w, 404, errors.New("test expired or unavailable; run the method test again"))
		return
	}
	if test.Created {
		writeJSON(w, 200, test.Response)
		return
	}

	tc := test.Config
	if strings.TrimSpace(req.Token) != "" {
		tc.Token = strings.TrimSpace(req.Token)
	}
	if tc.Role == "kharej" && strings.TrimSpace(tc.Token) == "" {
		writeError(w, 400, errors.New("enter the Iran tunnel secret before deploying on Kharej"))
		return
	}
	if strings.TrimSpace(tc.LocalIP) == "" {
		tc.LocalIP = detectHostIP()
	}
	st, err := s.store()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if err = tunnel.Create(st, &tc); err != nil {
		writeError(w, 400, err)
		return
	}
	// Mark saved before Apply: a client retry must never create a duplicate tunnel.
	test.Config, test.Created = tc, true
	test.Response = s.startTunnel(tc)
	writeJSON(w, 200, test.Response)
}
