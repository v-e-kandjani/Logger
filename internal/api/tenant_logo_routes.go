package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var validSlugRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleTenantLogo manages branding logo retrieval, upload, and deletion for any tenant (including root default)
func (h *Handler) handleTenantLogo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serveTenantLogo(w, r)
	case http.MethodPost:
		h.uploadTenantLogo(w, r)
	case http.MethodDelete:
		h.deleteTenantLogo(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// serveTenantLogo serves the tenant-specific logo or falls back to system LogSeal logo
func (h *Handler) serveTenantLogo(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	if slug == "" {
		if session, ok := h.getSession(r); ok && session != nil && session.TenantSlug != "" {
			slug = session.TenantSlug
		} else {
			slug = "default"
		}
	}

	if !validSlugRegex.MatchString(slug) {
		slug = "default"
	}

	// Potential extensions for custom branding
	exts := []string{".png", ".svg", ".jpg", ".jpeg", ".webp"}
	dirs := []string{
		filepath.Join("data", "branding", slug),
		filepath.Join("/opt/syslog-platform", "data", "branding", slug),
		filepath.Join("/var/lib/logseal", "tenants", slug, "branding"),
	}

	var foundPath string
	for _, dir := range dirs {
		for _, ext := range exts {
			candidate := filepath.Join(dir, "logo"+ext)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				foundPath = candidate
				break
			}
		}
		if foundPath != "" {
			break
		}
	}

	// If not found, fallback to system logo
	if foundPath == "" {
		fallbackCandidates := []string{
			filepath.Join("web", "static", "img", "logseal_logo.png"),
			filepath.Join("web", "static", "images", "logo.png"),
			filepath.Join("/opt/syslog-platform", "web", "static", "img", "logseal_logo.png"),
			filepath.Join("/opt/syslog-platform", "web", "static", "images", "logo.png"),
		}
		for _, fb := range fallbackCandidates {
			if info, err := os.Stat(fb); err == nil && !info.IsDir() {
				foundPath = fb
				break
			}
		}
	}

	if foundPath == "" {
		// As a last-ditch fallback, return a minimal 1x1 transparent PNG
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
			0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
			0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
			0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
		})
		return
	}

	// Determine mime type
	lower := strings.ToLower(foundPath)
	var contentType string
	switch {
	case strings.HasSuffix(lower, ".svg"):
		contentType = "image/svg+xml"
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		contentType = "image/jpeg"
	case strings.HasSuffix(lower, ".webp"):
		contentType = "image/webp"
	default:
		contentType = "image/png"
	}

	data, err := os.ReadFile(foundPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read logo"})
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=120")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// uploadTenantLogo accepts a multipart upload (PNG, JPG, SVG, WEBP, up to 5MB) and stores it
func (h *Handler) uploadTenantLogo(w http.ResponseWriter, r *http.Request) {
	session, ok := h.getSession(r)
	if !ok || session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Parse multipart form (max 5 MB)
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid multipart form (max 5MB)"})
		return
	}

	slug := strings.TrimSpace(r.FormValue("slug"))
	if slug == "" {
		slug = strings.TrimSpace(r.URL.Query().Get("slug"))
	}
	if slug == "" {
		slug = session.TenantSlug
	}
	if slug == "" {
		slug = "default"
	}

	if !validSlugRegex.MatchString(slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant slug format"})
		return
	}

	// Authorization check: Root operator can upload for anyone; tenant admin only for their tenant
	isRoot := session.IsRootOperator()
	isTenantAdmin := session.IsTenantAdmin && session.TenantSlug == slug
	if !isRoot && !isTenantAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions to update tenant logo"})
		return
	}

	file, header, err := r.FormFile("logo")
	if err != nil {
		file, header, err = r.FormFile("file")
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'logo' file in upload"})
		return
	}
	defer file.Close()

	if header.Size > 5*1024*1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "logo file size exceeds 5MB limit"})
		return
	}

	// Read first 512 bytes for content-type sniff
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	contentType := http.DetectContentType(buf[:n])
	_, _ = file.Seek(0, io.SeekStart)

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext == "" {
		if strings.Contains(contentType, "svg") {
			ext = ".svg"
		} else if strings.Contains(contentType, "jpeg") {
			ext = ".jpg"
		} else {
			ext = ".png"
		}
	}

	// Validate allowed image types
	validExts := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".svg": true, ".webp": true}
	if !validExts[ext] && !strings.HasPrefix(contentType, "image/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported file format; please upload PNG, JPG, SVG, or WebP"})
		return
	}

	// Normalize filename to logo.png or logo{ext}
	targetDirs := []string{
		filepath.Join("data", "branding", slug),
	}
	if info, err := os.Stat("/opt/syslog-platform"); err == nil && info.IsDir() {
		targetDirs = append(targetDirs, filepath.Join("/opt/syslog-platform", "data", "branding", slug))
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read uploaded file"})
		return
	}

	for _, dir := range targetDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}
		// Remove existing logos in directory
		for _, e := range []string{".png", ".svg", ".jpg", ".jpeg", ".webp"} {
			_ = os.Remove(filepath.Join(dir, "logo"+e))
		}
		destPath := filepath.Join(dir, "logo"+ext)
		if err := os.WriteFile(destPath, fileBytes, 0644); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to save logo: %v", err)})
			return
		}
	}

	// Persist logo_url in PostgreSQL
	logoURL := fmt.Sprintf("/api/v1/tenants/logo?slug=%s", slug)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := h.pgDB.UpdateTenantLogo(ctx, slug, logoURL); err != nil {
		// Log warning but don't fail if DB update encountered an issue
		fmt.Printf("WARN: failed to update tenant logo_url in DB: %v\n", err)
	}

	h.recordAudit(r, "TENANT_LOGO_UPDATE", "tenant/"+slug, "SUCCESS", map[string]interface{}{
		"slug":     slug,
		"filename": header.Filename,
		"size":     header.Size,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"slug":     slug,
		"logo_url": fmt.Sprintf("%s&t=%d", logoURL, time.Now().Unix()),
		"message":  "Tenant logo uploaded successfully",
	})
}

// deleteTenantLogo resets the tenant logo to the system default
func (h *Handler) deleteTenantLogo(w http.ResponseWriter, r *http.Request) {
	session, ok := h.getSession(r)
	if !ok || session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	if slug == "" {
		slug = session.TenantSlug
	}
	if slug == "" {
		slug = "default"
	}

	if !validSlugRegex.MatchString(slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant slug"})
		return
	}

	isRoot := session.IsRootOperator()
	isTenantAdmin := session.IsTenantAdmin && session.TenantSlug == slug
	if !isRoot && !isTenantAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions to reset tenant logo"})
		return
	}

	targetDirs := []string{
		filepath.Join("data", "branding", slug),
		filepath.Join("/opt/syslog-platform", "data", "branding", slug),
	}
	for _, dir := range targetDirs {
		for _, ext := range []string{".png", ".svg", ".jpg", ".jpeg", ".webp"} {
			_ = os.Remove(filepath.Join(dir, "logo"+ext))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_ = h.pgDB.UpdateTenantLogo(ctx, slug, "")

	h.recordAudit(r, "TENANT_LOGO_RESET", "tenant/"+slug, "SUCCESS", map[string]interface{}{
		"slug": slug,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"slug":    slug,
		"message": "Tenant logo reset to default",
	})
}
