package api

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/debug"
	"github.com/syslog-platform/logger/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// handleCreateSupportBundle generates a new diagnostic tar.gz bundle
func (h *Handler) handleCreateSupportBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req debug.BundleRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	req.RequestedBy = sess.Username
	if sess.TenantSlug != "" && sess.TenantSlug != "all" {
		req.TenantSlug = sess.TenantSlug
	} else if req.TenantSlug == "" {
		req.TenantSlug = "default"
	}

	// Determine portal BaseURL
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.HasSuffix(r.Host, ":8443") {
		scheme = "https"
	}
	req.BaseURL = fmt.Sprintf("%s://%s", scheme, r.Host)

	// Gather health metrics
	healthStats := h.gatherDiagnosticHealth(r)

	gen := debug.NewGenerator(h.pgDB, "")
	res, err := gen.Generate(r.Context(), req, healthStats)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate support bundle: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// handleListSupportBundles returns recent support packages
func (h *Handler) handleListSupportBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	tenantScope := sess.TenantSlug
	if sess.IsRootOperator() {
		// Root can view all or filter by query
		if q := r.URL.Query().Get("tenant"); q != "" && q != "all" {
			tenantScope = q
		} else {
			tenantScope = ""
		}
	}

	bundles, err := h.pgDB.ListSupportBundles(r.Context(), tenantScope, 50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// If not root superadmin, redact passcode
	if !sess.IsRootOperator() {
		for i := range bundles {
			bundles[i].AccessPasscode = "********"
			bundles[i].AccessToken = "********"
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"bundles": bundles,
		"count":   len(bundles),
	})
}

// handleSupportDownload manages the secure password-protected download gateway
func (h *Handler) handleSupportDownload(w http.ResponseWriter, r *http.Request) {
	bundleID := strings.TrimSpace(r.URL.Query().Get("id"))
	if bundleID == "" {
		bundleID = strings.TrimSpace(r.FormValue("id"))
	}
	if bundleID == "" {
		http.Error(w, "Bundle ID required", http.StatusBadRequest)
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	bundle, err := h.pgDB.GetSupportBundle(ctx, bundleID)
	if err != nil || bundle == nil {
		http.Error(w, "Support bundle not found or expired", http.StatusNotFound)
		return
	}

	// Verify file exists on disk
	fi, err := os.Stat(bundle.FilePath)
	if err != nil {
		http.Error(w, "Bundle archive file is no longer available on disk", http.StatusGone)
		return
	}

	// Check authentication & permissions
	authorized := false
	authErrorMsg := ""

	// Check 1: Already authenticated active Super Administrator session
	if sess, ok := h.getSession(r); ok && (sess.IsRootOperator() || sess.Role == "Super Administrator") {
		authorized = true
	}

	// Check 2: Passcode or Token supplied via query or form
	passcode := strings.TrimSpace(r.URL.Query().Get("passcode"))
	if passcode == "" {
		passcode = strings.TrimSpace(r.FormValue("passcode"))
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		token = strings.TrimSpace(r.FormValue("token"))
	}

	if passcode != "" && strings.EqualFold(passcode, bundle.AccessPasscode) {
		authorized = true
	}
	if token != "" && token == bundle.AccessToken {
		authorized = true
	}

	// Check 3: Submitted Root Superadmin login credentials in download form
	userParam := strings.TrimSpace(r.FormValue("username"))
	passParam := strings.TrimSpace(r.FormValue("password"))
	if userParam != "" && passParam != "" {
		u, uErr := h.pgDB.GetUserByUsername(ctx, userParam)
		if uErr == nil && u.IsEnabled && (u.Role == "Super Administrator" || u.Role == "Administrator") {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(passParam)) == nil {
				authorized = true
			} else {
				authErrorMsg = "Geçersiz yönetici parolası / Invalid administrator password"
			}
		} else {
			authErrorMsg = "Geçersiz kullanıcı adı / Invalid username"
		}
	} else if (r.Method == http.MethodPost || passcode != "") && !authorized && authErrorMsg == "" {
		authErrorMsg = "Hatalı güvenlik şifresi (Passcode) / Invalid access passcode"
	}

	// If authorized, stream the tar.gz file
	if authorized {
		_ = h.pgDB.IncrementBundleDownloadCount(ctx, bundle.ID)
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", bundle.Filename))
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		http.ServeFile(w, r, bundle.FilePath)
		return
	}

	// If not authorized, render the secure authentication gate page
	h.renderDownloadGatePage(w, r, bundle, authErrorMsg)
}

func (h *Handler) renderDownloadGatePage(w http.ResponseWriter, r *http.Request, b *models.SupportBundle, errorMsg string) {
	tmplStr := `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenli Destek Paketi İndirme | Valtrivo LogSeal</title>
    <link rel="icon" type="image/svg+xml" href="/static/images/logo.svg">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: #111827;
            --border: #1f293d;
            --primary: #38bdf8;
            --primary-hover: #0284c7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            max-width: 500px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.6);
        }
        .header {
            text-align: center;
            margin-bottom: 24px;
        }
        .logo {
            font-size: 2.4rem;
            margin-bottom: 8px;
        }
        .title {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 4px;
        }
        .subtitle {
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        .bundle-meta {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 20px;
            font-size: 0.85rem;
        }
        .meta-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 6px;
        }
        .meta-row:last-child { margin-bottom: 0; }
        .meta-lbl { color: var(--text-muted); }
        .meta-val { font-weight: 600; color: var(--primary); }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            font-size: 0.82rem;
            font-weight: 600;
            margin-bottom: 6px;
            color: var(--text-muted);
        }
        input {
            width: 100%;
            padding: 10px 14px;
            background: #0d1322;
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-main);
            font-size: 0.92rem;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus {
            border-color: var(--primary);
        }
        .divider {
            text-align: center;
            margin: 16px 0;
            position: relative;
        }
        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: var(--border);
        }
        .divider span {
            background: var(--bg-card);
            padding: 0 10px;
            font-size: 0.75rem;
            color: var(--text-muted);
            position: relative;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: var(--primary);
            color: #090d16;
            font-weight: 700;
            font-size: 0.95rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover {
            background: var(--primary-hover);
            color: #ffffff;
        }
        .alert-error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--danger);
            color: #fca5a5;
            padding: 10px;
            border-radius: 8px;
            font-size: 0.84rem;
            margin-bottom: 16px;
            text-align: center;
        }
        .footer {
            margin-top: 24px;
            text-align: center;
            font-size: 0.75rem;
            color: var(--text-muted);
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="logo">📦</div>
            <h1 class="title">Güvenli Destek Paketi İndirme</h1>
            <p class="subtitle">Secure Support Bundle Gateway</p>
        </div>

        {{if .Error}}
        <div class="alert-error">{{.Error}}</div>
        {{end}}

        <div class="bundle-meta">
            <div class="meta-row">
                <span class="meta-lbl">Paket Referansı:</span>
                <span class="meta-val">#{{.Bundle.ID}}</span>
            </div>
            <div class="meta-row">
                <span class="meta-lbl">Dosya Adı:</span>
                <span class="meta-val" style="font-family: monospace; font-size: 0.78rem;">{{.Bundle.Filename}}</span>
            </div>
            <div class="meta-row">
                <span class="meta-lbl">Boyut:</span>
                <span class="meta-val">{{printf "%.1f" .SizeKB}} KB</span>
            </div>
            <div class="meta-row">
                <span class="meta-lbl">Oluşturulma Tarihi:</span>
                <span class="meta-val">{{.CreatedStr}}</span>
            </div>
        </div>

        <form method="POST" action="/support/download">
            <input type="hidden" name="id" value="{{.Bundle.ID}}">

            <div class="form-group">
                <label for="passcode">Paket Güvenlik Şifresi (Passcode):</label>
                <input type="text" id="passcode" name="passcode" placeholder="Örn: SUP-XXXX-XXXX" autocomplete="off" autofocus>
                <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 4px;">Talebi oluşturan operatör veya e-posta ile iletilen 10 haneli şifre.</div>
            </div>

            <div class="divider">
                <span>VEYA / OR</span>
            </div>

            <div class="form-group">
                <label for="username">Süper Yönetici Kullanıcı Adı:</label>
                <input type="text" id="username" name="username" placeholder="admin" autocomplete="username">
            </div>

            <div class="form-group">
                <label for="password">Süper Yönetici Parolası:</label>
                <input type="password" id="password" name="password" placeholder="••••••••" autocomplete="current-password">
            </div>

            <button type="submit" class="btn">🔒 Doğrula ve İndir / Verify &amp; Download</button>
        </form>

        <div class="footer">
            Valtrivo LogSeal &bull; “Her kayıt, zamanıyla kanıt.”<br>
            Yetkisiz indirmeler şifreleme ve denetim kayıtları ile engellenmiştir.
        </div>
    </div>
</body>
</html>`

	tmpl, parseErr := template.New("download").Parse(tmplStr)
	if parseErr != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, map[string]any{
		"Bundle":     b,
		"SizeKB":     float64(b.FileSize) / 1024,
		"CreatedStr": b.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		"Error":      errorMsg,
	})
}

// gatherDiagnosticHealth collects realtime stats for bundling
func (h *Handler) gatherDiagnosticHealth(r *http.Request) map[string]any {
	ctx, cancel := contextWithTimeout(r, 4*time.Second)
	defer cancel()

	chStatus := "DOWN"
	if h.chClient != nil && h.chClient.IsHealthy() {
		chStatus = "UP"
	}

	pgStatus := "DOWN"
	if h.pgDB != nil && h.pgDB.Ping(ctx) == nil {
		pgStatus = "UP"
	}

	stats := map[string]any{
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"clickhouse":   chStatus,
		"postgres":     pgStatus,
		"status":       "HEALTHY",
		"version":      "v1.5.18",
		"udp_listener": "ACTIVE",
		"tcp_listener": "ACTIVE",
	}

	if h.pipeline != nil {
		stats["queue_depth"] = h.pipeline.QueueDepth()
		stats["packets_rx"] = h.pipeline.PacketsReceived.Load()
		stats["events_parsed"] = h.pipeline.EventsParsed.Load()
		stats["dropped_unauthorized"] = h.pipeline.DroppedUnauthorized.Load()
	}
	if h.chClient != nil {
		stats["events_inserted"] = h.chClient.TotalInserted.Load()
		stats["insert_errors"] = h.chClient.TotalFailed.Load()
	}

	return stats
}
