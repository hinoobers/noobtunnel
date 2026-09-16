package control

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/web"
)

// maxCSSBytes caps the custom stylesheet. The default sheet is well under 100 KB
// and a theme has no reason to be larger than half a megabyte.
const maxCSSBytes = 512 << 10

// customCSSPath is where an operator's stylesheet lives.
func (s *Server) customCSSPath() string {
	return filepath.Join(s.opts.StateDir, "custom.css")
}

// customCSSVersion changes whenever the sheet does, so browsers reload it
// without the operator having to hard refresh.
func (s *Server) customCSSVersion() string {
	info, err := os.Stat(s.customCSSPath())
	if err != nil {
		return "default"
	}
	return fmt.Sprintf("%d", info.ModTime().Unix())
}

// customCSS reads the stored stylesheet, reporting whether one exists.
func (s *Server) customCSS() ([]byte, bool) {
	raw, err := os.ReadFile(s.customCSSPath())
	if err != nil {
		return nil, false
	}
	return raw, true
}

// hasCustomCSS reports whether the operator has replaced the bundled sheet.
func (s *Server) hasCustomCSS() bool {
	_, ok := s.customCSS()
	return ok
}

// BrandName is what the UI calls this deployment. It falls back to the bundled
// name so an unconfigured control node never renders an empty header.
func (s *Server) BrandName() string {
	name := strings.TrimSpace(s.store.Settings().BrandName)
	if name == "" {
		return "noobtunnel"
	}
	return name
}

// handleCustomCSS serves the operator's stylesheet on a public URL, because the
// login screen wears the theme too. With no custom sheet it answers 204 and the
// browser keeps the bundled stylesheet it already loaded.
func (s *Server) handleCustomCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	raw, ok := s.customCSS()
	if !ok {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}

// handleBrandCSS is the authenticated editor API: it reads the current sheet
// (or the bundled one), replaces it, or falls back to the default.
func (s *Server) handleBrandCSS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, custom := s.customCSS()
		if !custom {
			var err error
			raw, err = web.StyleSheet()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"css":     string(raw),
			"custom":  custom,
			"version": s.customCSSVersion(),
		})
	case http.MethodPost:
		raw, err := readLimited(r, maxCSSBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if strings.TrimSpace(string(raw)) == "" {
			writeJSON(w, http.StatusBadRequest, errBody("the stylesheet is empty, use reset to restore the default"))
			return
		}
		if err := os.WriteFile(s.customCSSPath(), raw, 0o644); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("branding", "custom stylesheet updated")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.customCSSVersion(), "bytes": len(raw)})
	case http.MethodDelete:
		if err := os.Remove(s.customCSSPath()); err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("branding", "custom stylesheet reset to the default")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.customCSSVersion()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET, POST or DELETE"))
	}
}
