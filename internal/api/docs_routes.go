package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleDocDownload allows authenticated users to download documentation Markdown files
func (h *Handler) handleDocDownload(w http.ResponseWriter, r *http.Request) {
	requestedFile := r.URL.Query().Get("file")
	if requestedFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file parameter"})
		return
	}

	// Sanitize filename to prevent directory traversal
	cleanName := filepath.Base(filepath.Clean(requestedFile))
	if !strings.HasSuffix(strings.ToLower(cleanName), ".md") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only markdown (.md) documents can be downloaded"})
		return
	}

	// Potential candidate directories
	candidates := []string{
		filepath.Join("docs", cleanName),
		cleanName,
		filepath.Join("/opt/syslog-platform", "docs", cleanName),
		filepath.Join("/opt/syslog-platform", cleanName),
	}

	var foundPath string
	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			foundPath = cand
			break
		}
	}

	if foundPath == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("document %q not found", cleanName)})
		return
	}

	content, err := os.ReadFile(foundPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read document"})
		return
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", cleanName))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// handleDocView serves documentation Markdown files inline for browser viewing
func (h *Handler) handleDocView(w http.ResponseWriter, r *http.Request) {
	requestedFile := r.URL.Query().Get("file")
	if requestedFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file parameter"})
		return
	}

	cleanName := filepath.Base(filepath.Clean(requestedFile))
	if !strings.HasSuffix(strings.ToLower(cleanName), ".md") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only markdown (.md) documents can be viewed"})
		return
	}

	candidates := []string{
		filepath.Join("docs", cleanName),
		cleanName,
		filepath.Join("/opt/syslog-platform", "docs", cleanName),
		filepath.Join("/opt/syslog-platform", cleanName),
	}

	var foundPath string
	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			foundPath = cand
			break
		}
	}

	if foundPath == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("document %q not found", cleanName)})
		return
	}

	content, err := os.ReadFile(foundPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read document"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", cleanName))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
