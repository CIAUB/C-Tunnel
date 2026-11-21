package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultInitDataMaxAge bounds how old Telegram WebApp initData may be.
	DefaultInitDataMaxAge = 10 * time.Minute
	maxInitDataLen        = 8192
	maxFutureSkewSec      = 120
)

var (
	ErrInvalidInitData = errors.New("invalid telegram initData")
	ErrExpiredInitData = errors.New("expired telegram initData")
	ErrNotAdmin        = errors.New("telegram user is not a configured admin")
)

// WebAppUser represents the authenticated Telegram user extracted from signed initData.
type WebAppUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// VerifyInitData cryptographically verifies Telegram Mini App initData using
// HMAC-SHA256 with secret_key = HMAC-SHA256("WebAppData", botToken), checks
// auth_date freshness against now/maxAge, and confirms user.id belongs to admins.
func VerifyInitData(initData, botToken string, admins []int64, now time.Time, maxAge time.Duration) (WebAppUser, error) {
	if botToken == "" || len(admins) == 0 {
		return WebAppUser{}, ErrNotAdmin
	}
	if len(initData) == 0 || len(initData) > maxInitDataLen {
		return WebAppUser{}, ErrInvalidInitData
	}
	vals, err := url.ParseQuery(initData)
	if err != nil {
		return WebAppUser{}, ErrInvalidInitData
	}
	for _, vs := range vals {
		if len(vs) != 1 {
			return WebAppUser{}, ErrInvalidInitData
		}
	}
	gotHash := strings.ToLower(strings.TrimSpace(vals.Get("hash")))
	if len(gotHash) != 64 {
		return WebAppUser{}, ErrInvalidInitData
	}
	if _, err := hex.DecodeString(gotHash); err != nil {
		return WebAppUser{}, ErrInvalidInitData
	}

	authDateStr := strings.TrimSpace(vals.Get("auth_date"))
	authDate, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil || authDate <= 0 {
		return WebAppUser{}, ErrInvalidInitData
	}
	if maxAge <= 0 {
		maxAge = DefaultInitDataMaxAge
	}
	age := now.Unix() - authDate
	if age > int64(maxAge.Seconds()) || age < -maxFutureSkewSec {
		return WebAppUser{}, ErrExpiredInitData
	}

	// Build Telegram data_check_string: sorted "key=value" lines excluding "hash".
	keys := make([]string, 0, len(vals))
	for k := range vals {
		if k == "hash" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+vals.Get(k))
	}
	dataCheck := strings.Join(lines, "\n")

	secretMAC := hmac.New(sha256.New, []byte("WebAppData"))
	secretMAC.Write([]byte(botToken))
	secretKey := secretMAC.Sum(nil)

	calcMAC := hmac.New(sha256.New, secretKey)
	calcMAC.Write([]byte(dataCheck))
	expectedHash := hex.EncodeToString(calcMAC.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(expectedHash)) != 1 {
		return WebAppUser{}, ErrInvalidInitData
	}

	userJSON := strings.TrimSpace(vals.Get("user"))
	if userJSON == "" {
		return WebAppUser{}, ErrInvalidInitData
	}
	var user WebAppUser
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil || user.ID <= 0 {
		return WebAppUser{}, ErrInvalidInitData
	}

	for _, id := range admins {
		if id == user.ID {
			return user, nil
		}
	}
	return WebAppUser{}, ErrNotAdmin
}
