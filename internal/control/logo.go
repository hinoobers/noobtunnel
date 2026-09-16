package control

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/noobtunnel/noobtunnel/internal/web"
)

// maxLogoBytes caps an uploaded brand image.
const maxLogoBytes = 2 << 20

// logoPath is where an uploaded logo lives. The extension keeps the content type
// obvious without storing one.
func (s *Server) logoPath() string {
	return filepath.Join(s.opts.StateDir, "logo.png")
}

// logoVersion changes whenever the logo does, so browsers reload it.
func (s *Server) logoVersion() string {
	info, err := os.Stat(s.logoPath())
	if err != nil {
		return "default"
	}
	return fmt.Sprintf("%d", info.ModTime().Unix())
}

// handleLogo serves the uploaded logo, falling back to the bundled one.
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	if raw, err := os.ReadFile(s.logoPath()); err == nil {
		w.Header().Set("Content-Type", detectImageType(raw))
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(raw)
		return
	}
	raw, err := web.DefaultLogo()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}

// detectImageType sniffs the few formats we accept.
func detectImageType(raw []byte) string {
	switch {
	case len(raw) > 8 && string(raw[1:4]) == "PNG":
		return "image/png"
	case len(raw) > 3 && string(raw[0:3]) == "\xff\xd8\xff":
		return "image/jpeg"
	case len(raw) > 12 && string(raw[0:4]) == "RIFF" && string(raw[8:12]) == "WEBP":
		return "image/webp"
	case len(raw) > 5 && string(raw[0:5]) == "<svg ":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// handleLogoUpload stores or clears the uploaded brand image.
func (s *Server) handleLogoUpload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		raw, err := readLimited(r, maxLogoBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		kind := detectImageType(raw)
		if kind == "application/octet-stream" {
			writeJSON(w, http.StatusBadRequest, errBody("upload a PNG, JPEG, WEBP or SVG image"))
			return
		}
		if err := os.WriteFile(s.logoPath(), raw, 0o644); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("branding", "logo updated")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.logoVersion(), "type": kind})
	case http.MethodDelete:
		if err := os.Remove(s.logoPath()); err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("branding", "logo reset to the default")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.logoVersion()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST or DELETE"))
	}
}

// readLimited reads a request body with a size cap.
func readLimited(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("the image is larger than %d MB", limit/(1<<20))
	}
	return raw, nil
}
