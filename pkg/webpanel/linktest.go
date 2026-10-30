package webpanel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/speedtest"
)

const (
	testListenerTTL = 15 * time.Minute
	linkTestJobTTL  = 10 * time.Minute
	maxLinkTestJobs = 8
)

var runPathMTU = conntest.PathMTU

type testResponder struct {
	mu         sync.Mutex
	link       conntest.Link
	udpPort    int
	tcpPort    int
	rawOpen    []int
	rawError   string
	started    time.Time
	expires    time.Time
	rows       []conntest.Result
	reportRows []conntest.Result
	reportBest *conntest.Best
	reportText string
	cancel     context.CancelFunc
	stopTCP    func()
	timer      *time.Timer
}

type testServerView struct {
	Active     bool              `json:"active"`
	Link       string            `json:"link,omitempty"`
	Host       string            `json:"host,omitempty"`
	UDPPort    int               `json:"udp_port,omitempty"`
	TCPPort    int               `json:"tcp_port,omitempty"`
	RawOpen    []int             `json:"raw_open,omitempty"`
	RawError   string            `json:"raw_error,omitempty"`
	StartedAt  time.Time         `json:"started_at,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	Rows       []conntest.Result `json:"rows,omitempty"`
	ReportRows []conntest.Result `json:"report_rows,omitempty"`
	ReportBest *conntest.Best    `json:"report_best,omitempty"`
	ReportText string            `json:"report_text,omitempty"`
}

func (r *testResponder) view() testServerView {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := testServerView{
		Active:     true,
		Link:       conntest.EncodeLink(r.link),
		Host:       r.link.Host,
		UDPPort:    r.udpPort,
		TCPPort:    r.tcpPort,
		RawOpen:    append([]int(nil), r.rawOpen...),
		RawError:   r.rawError,
		StartedAt:  r.started,
		ExpiresAt:  r.expires,
		Rows:       append([]conntest.Result(nil), r.rows...),
		ReportRows: append([]conntest.Result(nil), r.reportRows...),
		ReportText: r.reportText,
	}
	if r.reportBest != nil {
		b := *r.reportBest
		v.ReportBest = &b
	}
	return v
}

func (s *Server) startTestResponder(host string) (*testResponder, error) {
	token := conntest.NewToken()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := conntest.Serve(ctx, 0, token)
	if err != nil {
		cancel()
		return nil, err
	}
	tcpAddr, stopTCP, err := speedtest.StartServer("0.0.0.0:0")
	if err != nil {
		cancel()
		return nil, err
	}
	_, udpPortText, err := net.SplitHostPort(r.UDPAddr)
	if err != nil {
		cancel()
		stopTCP()
		return nil, fmt.Errorf("test UDP address: %w", err)
	}
	_, tcpPortText, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		cancel()
		stopTCP()
		return nil, fmt.Errorf("test TCP address: %w", err)
	}
	udpPort, err := strconv.Atoi(udpPortText)
	if err != nil {
		cancel()
		stopTCP()
		return nil, errors.New("invalid test UDP port")
	}
	tcpPort, err := strconv.Atoi(tcpPortText)
	if err != nil {
		cancel()
		stopTCP()
		return nil, errors.New("invalid test TCP port")
	}
	now := time.Now()
	st := &testResponder{
		link:     conntest.Link{Host: host, UDPPort: udpPort, TCPPort: tcpPort, TokenHex: token},
		udpPort:  udpPort,
		tcpPort:  tcpPort,
		rawOpen:  append([]int(nil), r.RawOpen...),
		started:  now,
		expires:  now.Add(testListenerTTL),
		cancel:   cancel,
		stopTCP:  stopTCP,
		rawError: "",
	}
	if r.RawError != nil {
		st.rawError = r.RawError.Error()
	}
	r.SetCallbacks(
		func(rows []conntest.Result) {
			st.mu.Lock()
			st.rows = append([]conntest.Result(nil), rows...)
			st.mu.Unlock()
		},
		func(rep conntest.Report) {
			st.mu.Lock()
			st.reportRows = append([]conntest.Result(nil), rep.Rows...)
			best := rep.Best
			st.reportBest = &best
			st.reportText = conntest.Verdict(rep.Peer, rep.Rows) + "\n" + rep.Best.String()
			st.mu.Unlock()
		},
	)
	return st, nil
}

func validTestHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast)
}

func (s *Server) stopAllTests() {
	s.testMu.Lock()
	st := s.responder
	s.testMu.Unlock()
	if st != nil {
		s.stopTestResponder(st)
	}
	s.jobMu.Lock()
	for _, job := range s.jobs {
		if job.Status == "running" {
			job.Status = "stopped"
			job.Error = "session ended"
			if job.cancel != nil {
				job.cancel()
			}
		}
	}
	s.jobMu.Unlock()
}

func (s *Server) stopTestResponder(st *testResponder) {
	s.testMu.Lock()
	if s.responder != st {
		s.testMu.Unlock()
		return
	}
	s.responder = nil
	s.testMu.Unlock()
	if st.timer != nil {
		st.timer.Stop()
	}
	st.cancel()
	if st.stopTCP != nil {
		st.stopTCP()
	}
}

func (s *Server) handleTestServerStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = detectHostIP()
	}
	if !validTestHost(host) {
		writeError(w, http.StatusBadRequest, errors.New("enter a valid IPv4 address for the test link"))
		return
	}
	s.testMu.Lock()
	if s.responder != nil {
		view := s.responder.view()
		s.testMu.Unlock()
		writeJSON(w, http.StatusConflict, view)
		return
	}
	st, err := s.startTestResponder(host)
	if err != nil {
		s.testMu.Unlock()
		writeError(w, http.StatusConflict, err)
		return
	}
	s.responder = st
	st.timer = time.AfterFunc(testListenerTTL, func() { s.stopTestResponder(st) })
	s.testMu.Unlock()
	writeJSON(w, http.StatusOK, st.view())
}

func (s *Server) handleTestServerStatus(w http.ResponseWriter, r *http.Request) {
	s.testMu.Lock()
	st := s.responder
	if st == nil {
		s.testMu.Unlock()
		writeJSON(w, http.StatusOK, testServerView{Active: false})
		return
	}
	view := st.view()
	s.testMu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleTestServerStop(w http.ResponseWriter, r *http.Request) {
	s.testMu.Lock()
	st := s.responder
	s.testMu.Unlock()
	if st != nil {
		s.stopTestResponder(st)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type linkTestDeployment struct {
	TestID string          `json:"test_id"`
	Best   conntest.Result `json:"best"`
}

type linkTestJob struct {
	ID           string
	Owner        string
	Peer         string
	Status       string
	Rows         []conntest.Result
	Text         string
	Best         conntest.Result
	BestSettings conntest.Best
	Deployments  map[string]linkTestDeployment
	Error        string
	Expires      time.Time
	cancel       context.CancelFunc
}

func (s *Server) handleLinkTestStart(w http.ResponseWriter, r *http.Request) {
	var req methodTestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	link, err := conntest.DecodeLink(req.Link)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Role != "iran" && req.Role != "kharej" {
		writeError(w, http.StatusBadRequest, errors.New("select this server's deployment role"))
		return
	}
	if req.LocalIP != "" && net.ParseIP(req.LocalIP) == nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid local IP"))
		return
	}
	cookie, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session changed; log in again"})
		return
	}
	select {
	case s.testSlot <- struct{}{}:
	default:
		writeError(w, http.StatusTooManyRequests, errors.New("a connection test is already running"))
		return
	}
	id, err := randomID()
	if err != nil {
		<-s.testSlot
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	job := &linkTestJob{
		ID:          id,
		Owner:       cookie.Value,
		Peer:        link.Host,
		Status:      "running",
		Deployments: map[string]linkTestDeployment{},
		Expires:     time.Now().Add(linkTestJobTTL),
		cancel:      cancel,
	}
	s.jobMu.Lock()
	s.pruneJobsLocked(time.Now())
	if len(s.jobs) >= maxLinkTestJobs {
		s.jobMu.Unlock()
		cancel()
		<-s.testSlot
		writeError(w, http.StatusTooManyRequests, errors.New("too many stored test results; retry after they expire"))
		return
	}
	s.jobs[id] = job
	s.jobMu.Unlock()
	go s.runLinkTestJob(job, ctx, link, req)
	writeJSON(w, http.StatusAccepted, map[string]any{"test_id": id, "status": "running"})
}

func (s *Server) runLinkTestJob(job *linkTestJob, ctx context.Context, link conntest.Link, req methodTestRequest) {
	defer func() { <-s.testSlot }()
	defer job.cancel()
	rows, err := runMethodTest(ctx, link, func(progress []conntest.Result) {
		s.jobMu.Lock()
		if s.jobs[job.ID] == job && job.Status == "running" {
			job.Rows = append([]conntest.Result(nil), progress...)
		}
		s.jobMu.Unlock()
	})
	if err != nil {
		s.finishLinkTestJob(job, "error", err.Error(), nil, nil, conntest.Result{}, conntest.Best{})
		return
	}
	best, _ := chooseBest(rows)
	direct, okDirect := chooseBestMode(rows, "DIRECT")
	reverse, okReverse := chooseBestMode(rows, "REVERSE")
	localIP := strings.TrimSpace(req.LocalIP)
	if localIP == "" {
		localIP = detectHostIP()
	}
	deployments := map[string]linkTestDeployment{}
	var deploymentErr string
	add := func(mode string, result conntest.Result) {
		if localIP == "" {
			deploymentErr = "this server has no IPv4 address for deployment"
			return
		}
		tc := catalog.TunnelConfig{
			Role: req.Role, Method: strings.TrimPrefix(strings.TrimPrefix(result.Method, "frp+"), "rev+"),
			Reverse: result.Mode == "REVERSE", LocalIP: localIP, RemoteIP: link.Host,
			Token: req.Token, Ports: req.Ports,
		}
		if tc.Role != "iran" {
			tc.Ports = nil
		}
		id, err := s.addTestDeployment(job.Owner, tc, result)
		if err != nil {
			deploymentErr = err.Error()
			return
		}
		deployments[mode] = linkTestDeployment{TestID: id, Best: result}
	}
	if okDirect {
		add("direct", direct)
	}
	if okReverse {
		add("reverse", reverse)
	}
	pathMTU := runPathMTU(ctx, link)
	bestSettings := conntest.BestSettings(rows, pathMTU)
	conntest.SendReport(ctx, link, rows, bestSettings)
	s.finishLinkTestJob(job, "done", deploymentErr, deployments, rows, best, bestSettings)
}

func (s *Server) finishLinkTestJob(job *linkTestJob, status, message string, deployments map[string]linkTestDeployment, rows []conntest.Result, best conntest.Result, bestSettings conntest.Best) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.jobs[job.ID] != job || job.Status == "stopped" {
		return
	}
	job.Status = status
	job.Error = message
	if rows != nil {
		job.Rows = append([]conntest.Result(nil), rows...)
	}
	job.Best = best
	job.BestSettings = bestSettings
	if deployments != nil {
		job.Deployments = deployments
	}
	if status == "done" {
		job.Text = conntest.Verdict(job.Peer, job.Rows)
	}
}

func (s *Server) addTestDeployment(owner string, tc catalog.TunnelConfig, result conntest.Result) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, test := range s.tests {
		if now.After(test.Expires) {
			delete(s.tests, key)
		}
	}
	if len(s.tests) >= 8 {
		return "", errors.New("too many pending deployments; retry after the test expiry")
	}
	s.tests[id] = &testDeployment{Owner: owner, Expires: now.Add(10 * time.Minute), Config: tc, Result: result}
	return id, nil
}

func (s *Server) pruneJobsLocked(now time.Time) {
	for id, job := range s.jobs {
		if now.After(job.Expires) {
			if job.cancel != nil {
				job.cancel()
			}
			delete(s.jobs, id)
		}
	}
}

func (s *Server) handleLinkTestJob(w http.ResponseWriter, r *http.Request) {
	cookie, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session changed; log in again"})
		return
	}
	id := r.PathValue("id")
	now := time.Now()
	s.jobMu.Lock()
	s.pruneJobsLocked(now)
	job := s.jobs[id]
	if job == nil || job.Owner != cookie.Value {
		s.jobMu.Unlock()
		writeError(w, http.StatusNotFound, errors.New("test result expired or unavailable"))
		return
	}
	view := map[string]any{
		"test_id": job.ID, "status": job.Status,
		"rows": append([]conntest.Result(nil), job.Rows...),
		"best": job.Best, "best_settings": job.BestSettings, "text": job.Text, "error": job.Error,
		"deployments": job.Deployments, "expires_at": job.Expires,
	}
	s.jobMu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleLinkTestStop(w http.ResponseWriter, r *http.Request) {
	cookie, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session changed; log in again"})
		return
	}
	id := r.PathValue("id")
	s.jobMu.Lock()
	job := s.jobs[id]
	if job == nil || job.Owner != cookie.Value {
		s.jobMu.Unlock()
		writeError(w, http.StatusNotFound, errors.New("test result expired or unavailable"))
		return
	}
	if job.Status == "running" {
		job.Status = "stopped"
		job.Error = "stopped by the operator"
		if job.cancel != nil {
			job.cancel()
		}
	}
	s.jobMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
