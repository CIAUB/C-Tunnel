package webpanel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new 20-byte (160-bit) base32-encoded TOTP secret.
func GenerateTOTPSecret() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(raw[:]), nil
}

// OTPAuthURI builds the standard otpauth://totp/ URI for authenticator apps.
func OTPAuthURI(secret, account string) string {
	if account == "" {
		account = "admin"
	}
	v := url.Values{}
	v.Set("secret", strings.ToUpper(strings.TrimSpace(secret)))
	v.Set("issuer", "C-Tunnel")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/C-Tunnel:%s?%s", url.PathEscape(account), v.Encode())
}

// VerifyTOTP validates a 6-digit RFC 6238 TOTP code against a base32 secret,
// allowing ±1 30-second step for clock skew.
func VerifyTOTP(secret, code string, now time.Time) bool {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if cleanSecret == "" {
		return false
	}
	key, err := totpBase32.DecodeString(strings.TrimRight(cleanSecret, "="))
	if err != nil || len(key) < 10 {
		return false
	}
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != 6 {
		return false
	}
	for _, ch := range cleanCode {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	step := now.Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		expect := totpCodeAt(key, uint64(step+delta))
		if subtle.ConstantTimeCompare([]byte(cleanCode), []byte(expect)) == 1 {
			return true
		}
	}
	return false
}

func totpCodeAt(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", binCode%1_000_000)
}

// parseAllowedIPs parses a comma- or newline-separated list of IPv4/IPv6 addresses or CIDRs.
func parseAllowedIPs(raw string) ([]*net.IPNet, string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return nil, "", nil
	}
	var nets []*net.IPNet
	var normalized []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			_, ipnet, err := net.ParseCIDR(p)
			if err != nil {
				return nil, "", fmt.Errorf("invalid CIDR in allowed IPs: %s", p)
			}
			nets = append(nets, ipnet)
			normalized = append(normalized, ipnet.String())
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, "", fmt.Errorf("invalid IP in allowed IPs: %s", p)
		}
		if v4 := ip.To4(); v4 != nil {
			nets = append(nets, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
			normalized = append(normalized, v4.String())
		} else {
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			normalized = append(normalized, ip.String())
		}
	}
	return nets, strings.Join(normalized, ", "), nil
}

// ipAllowed reports whether clientAddr is permitted by the configured AllowedIPs list.
// Loopback addresses are always allowed so local CLI/recovery access cannot be locked out.
func ipAllowed(allowedRaw, clientAddr string) bool {
	if strings.TrimSpace(allowedRaw) == "" {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientAddr))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	nets, _, err := parseAllowedIPs(allowedRaw)
	if err != nil || len(nets) == 0 {
		return true
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
