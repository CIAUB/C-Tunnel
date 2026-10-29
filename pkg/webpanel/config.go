package webpanel

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"ctunnel/pkg/atomicfile"
)

// PanelConfig contains no certificate contents or private key material.
type PanelConfig struct {
	BasePath string `json:"base_path"`
	Domain   string `json:"domain"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

var panelPathRE = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9_-]{5,63}$`)
var domainLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func atomicJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".panel-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return atomicfile.Replace(f.Name(), path)
}

// LoadConfig initializes a persistent, unpredictable path once. Existing invalid
// configurations fail closed rather than silently exposing the root URL.
func LoadConfig(dir string) (PanelConfig, error) {
	var c PanelConfig
	if err := os.MkdirAll(dir, 0700); err != nil {
		return c, err
	}
	path := filepath.Join(dir, "panel.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		id, e := randomID()
		if e != nil {
			return c, e
		}
		c.BasePath = "/panel-" + id
		b, e = json.MarshalIndent(c, "", "  ")
		if e != nil {
			return c, e
		}
		// Link a fully written temporary file atomically; concurrent readers never
		// observe an empty configuration during first setup.
		f, e := os.CreateTemp(dir, ".panel-init-*.tmp")
		if e != nil {
			return c, e
		}
		defer os.Remove(f.Name())
		if _, e = f.Write(b); e != nil {
			f.Close()
			return c, e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return c, e
		}
		if e = f.Close(); e != nil {
			return c, e
		}
		if e = os.Link(f.Name(), path); os.IsExist(e) {
			return LoadConfig(dir)
		} else if e != nil {
			return c, e
		}

		return c, nil
	}
	if err != nil {
		return c, err
	}
	if len(b) > 8192 {
		return c, errors.New("panel configuration is too large")
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("invalid panel.json: %w", err)
	}
	if err = validatePanelConfig(c); err != nil {
		return c, err
	}
	return c, nil
}

func validatePanelConfig(c PanelConfig) error {
	if !panelPathRE.MatchString(c.BasePath) {
		return errors.New("panel path must start with / and contain 6–64 letters, digits, underscores or hyphens")
	}
	if c.Domain != "" {
		if len(c.Domain) > 253 || c.Domain != strings.ToLower(c.Domain) {
			return errors.New("invalid domain")
		}
		for _, label := range strings.Split(c.Domain, ".") {
			if !domainLabelRE.MatchString(label) {
				return errors.New("enter a hostname without scheme, port or path")
			}
		}
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("both certificate and private key are required")
	}
	if c.CertFile != "" {
		if !filepath.IsAbs(c.CertFile) || !filepath.IsAbs(c.KeyFile) {
			return errors.New("certificate paths must be absolute")
		}
		_, err := loadPanelCertificate(c)
		return err
	}
	return nil
}

func readPEM(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, errors.New("certificate files must be regular files smaller than 64 KiB")
	}
	b := make([]byte, info.Size())
	n, err := f.ReadAt(b, 0)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func loadPanelCertificate(c PanelConfig) (tls.Certificate, error) {
	certPEM, err := readPEM(c.CertFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read fullchain: %w", err)
	}
	keyPEM, err := readPEM(c.KeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return pair, errors.New("certificate and private key are invalid or do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return pair, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return pair, errors.New("certificate is expired or not yet valid")
	}
	if c.Domain != "" {
		if err = leaf.VerifyHostname(c.Domain); err != nil {
			return pair, errors.New("certificate does not cover the configured domain")
		}
	}
	if len(leaf.ExtKeyUsage) > 0 {
		allowed := false
		for _, u := range leaf.ExtKeyUsage {
			allowed = allowed || u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny
		}
		if !allowed {
			return pair, errors.New("certificate is not valid for a TLS server")
		}
	}
	pair.Leaf = leaf
	return pair, nil
}

func configURL(c PanelConfig, host, port string) string {
	if c.Domain != "" {
		host = c.Domain
	}
	scheme := "http"
	if c.CertFile != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + c.BasePath + "/"
}

func PanelURL(dir, host string, port int) (string, error) {
	c, err := LoadConfig(dir)
	if err != nil {
		return "", err
	}
	return configURL(c, host, fmt.Sprint(port)), nil
}

func (s *Server) config() PanelConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.panelConfig
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, s.config())
		return
	}
	var req struct {
		PanelConfig
		TLSMode string `json:"tls_mode"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	s.configMu.Lock()
	locked := true
	defer func() {
		if locked {
			s.configMu.Unlock()
		}
	}()
	previous := s.panelConfig
	c := req.PanelConfig
	var staging string
	if req.TLSMode == "http" {
		c.CertFile, c.KeyFile = "", ""
	} else if req.TLSMode != "https" {
		writeError(w, 400, errors.New("choose http or https"))
		return
	}
	if req.TLSMode == "https" && (req.CertPEM != "" || req.KeyPEM != "") {
		ip := net.ParseIP(clientIP(r))
		if r.TLS == nil && (ip == nil || !ip.IsLoopback()) {
			writeError(w, 400, errors.New("private-key uploads require HTTPS or a loopback connection; use server certificate paths over HTTP"))
			return
		}
		if req.CertPEM == "" || req.KeyPEM == "" {
			writeError(w, 400, errors.New("upload both fullchain.pem and privkey.pem"))
			return
		}
		certDir := filepath.Join(s.storeDir, "certificates")
		if err := os.MkdirAll(certDir, 0700); err != nil {
			writeError(w, 500, err)
			return
		}
		var err error
		staging, err = os.MkdirTemp(certDir, "pair-")
		if err != nil {
			writeError(w, 500, err)
			return
		}
		keep := false
		defer func() {
			if !keep {
				os.RemoveAll(staging)
			}
		}()
		c.CertFile, c.KeyFile = filepath.Join(staging, "fullchain.pem"), filepath.Join(staging, "privkey.pem")
		if err = os.WriteFile(c.CertFile, []byte(req.CertPEM), 0600); err != nil {
			writeError(w, 500, err)
			return
		}
		if err = os.WriteFile(c.KeyFile, []byte(req.KeyPEM), 0600); err != nil {
			writeError(w, 500, err)
			return
		}
		if err = validatePanelConfig(c); err != nil {
			writeError(w, 400, err)
			return
		}
		if err = atomicJSON(filepath.Join(s.storeDir, "panel.json"), c); err != nil {
			writeError(w, 500, err)
			return
		}
		keep = true
	} else {
		if req.TLSMode == "https" && c.CertFile == "" {
			writeError(w, 400, errors.New("HTTPS requires a valid certificate and private key"))
			return
		}
		if err := validatePanelConfig(c); err != nil {
			writeError(w, 400, err)
			return
		}
		if err := atomicJSON(filepath.Join(s.storeDir, "panel.json"), c); err != nil {
			writeError(w, 500, err)
			return
		}
	}
	s.panelConfig = c
	if c != previous {
		s.authGeneration.Add(1)
		http.SetCookie(w, &http.Cookie{Name: panelCookieName(r, previous.BasePath), Path: previous.BasePath + "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		_, port, _ = net.SplitHostPort(s.listenAddr)
		if port == "" {
			port = "80"
			if r.TLS != nil {
				port = "443"
			}
		}
	}
	s.configMu.Unlock()
	locked = false
	writeJSON(w, 200, map[string]any{"ok": true, "url": configURL(c, host, port), "config": c})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	select {
	case s.reload <- struct{}{}:
	default:
	}
}
