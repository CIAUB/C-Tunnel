package sponsor

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
)

// MediaKind classifies a sponsor asset as "image" (including animated GIF) or "video".
const (
	KindImage = "image"
	KindVideo = "video"
)

var allowedMediaExts = map[string]bool{
	".png":  true,
	".jpg":  true,
	".jpeg": true,
	".webp": true,
	".gif":  true,
	".mp4":  true,
	".webm": true,
	".mov":  true,
}

// IsSponsorMediaName reports whether filename matches sponsor* or sponser*
// (case-insensitive) with a supported image, GIF, or video extension.
func IsSponsorMediaName(name string) bool {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	if base == "" || base == "." || base == "/" {
		return false
	}
	if !strings.HasPrefix(base, "sponsor") && !strings.HasPrefix(base, "sponser") {
		return false
	}
	return allowedMediaExts[strings.ToLower(filepath.Ext(base))]
}

// DetectMediaMIME inspects raw file magic bytes and returns a safe MIME type
// and kind ("image" or "video"). It rejects HTML, SVG, scripts, and unknown formats.
func DetectMediaMIME(b []byte) (mime, kind string, ok bool) {
	if len(b) < 12 {
		return "", "", false
	}
	// Static/animated images via standard signatures.
	switch http.DetectContentType(b) {
	case "image/png":
		return "image/png", KindImage, true
	case "image/jpeg":
		return "image/jpeg", KindImage, true
	case "image/gif":
		return "image/gif", KindImage, true
	case "image/webp":
		return "image/webp", KindImage, true
	}
	// WebM / Matroska EBML header (0x1A 0x45 0xDF 0xA3) containing "webm" DocType.
	if b[0] == 0x1a && b[1] == 0x45 && b[2] == 0xdf && b[3] == 0xa3 {
		head := b
		if len(head) > 64 {
			head = head[:64]
		}
		if bytes.Contains(bytes.ToLower(head), []byte("webm")) {
			return "video/webm", KindVideo, true
		}
	}
	// ISO Base Media File Format (MP4 / QuickTime MOV): [4B box size]["ftyp"][4B major brand].
	if string(b[4:8]) == "ftyp" {
		brand := string(b[8:12])
		if brand == "qt  " {
			return "video/quicktime", KindVideo, true
		}
		switch brand {
		case "isom", "iso2", "iso3", "iso4", "iso5", "iso6",
			"mp41", "mp42", "avc1", "M4V ", "M4VH", "M4VP",
			"dash", "MSNV", "mp71", "f4v ":
			return "video/mp4", KindVideo, true
		}
	}
	return "", "", false
}

// MediaKindForMIME maps a validated MIME type to KindImage or KindVideo.
func MediaKindForMIME(mime string) string {
	if strings.HasPrefix(strings.ToLower(mime), "video/") {
		return KindVideo
	}
	return KindImage
}
