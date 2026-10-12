package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleDocDownload allows authenticated users to download documentation Markdown files directly
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

	foundPath := findDocPath(cleanName)
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

// handleDocView serves documentation Markdown files formatted with fonts, paragraphs, and tables
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

	foundPath := findDocPath(cleanName)
	if foundPath == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("document %q not found", cleanName)})
		return
	}

	content, err := os.ReadFile(foundPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read document"})
		return
	}

	// If ?raw=true or Accept header is text/markdown, serve raw text
	if r.URL.Query().Get("raw") == "true" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", cleanName))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
		return
	}

	// JSON encoded content for safe JS string literal insertion
	jsonContent, _ := json.Marshal(string(content))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s — Valtrivo LogSeal Kılavuzu</title>
    <link rel="icon" type="image/svg+xml" href="/static/images/favicon.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="/static/js/marked.min.js"></script>
    <style>
        :root {
            --bg-body: #080c14;
            --bg-card: #0f172a;
            --bg-surface: #1e293b;
            --bg-header: rgba(15, 23, 42, 0.85);
            --border-color: rgba(255, 255, 255, 0.1);
            --border-subtle: rgba(255, 255, 255, 0.06);
            --text-main: #f1f5f9;
            --text-body: #cbd5e1;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-hover: #0284c7;
            --primary-bg: rgba(56, 189, 248, 0.08);
            --accent: #6366f1;
            --font-main: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, Consolas, monospace;
        }

        body.light-theme {
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-surface: #f1f5f9;
            --bg-header: rgba(255, 255, 255, 0.9);
            --border-color: rgba(0, 0, 0, 0.1);
            --border-subtle: rgba(0, 0, 0, 0.06);
            --text-main: #0f172a;
            --text-body: #334155;
            --text-muted: #64748b;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --primary-bg: rgba(2, 132, 199, 0.08);
            --accent: #4f46e5;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-body);
            color: var(--text-body);
            font-family: var(--font-main);
            font-size: 15.5px;
            line-height: 1.75;
            -webkit-font-smoothing: antialiased;
            min-height: 100vh;
        }

        /* Top Sticky Navbar */
        .doc-navbar {
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            background: var(--bg-header);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .doc-nav-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
            color: var(--text-main);
        }
        .doc-nav-brand img {
            width: 30px;
            height: 30px;
            object-fit: contain;
        }
        .doc-nav-title {
            font-weight: 700;
            font-size: 15px;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .doc-badge {
            background: var(--primary-bg);
            color: var(--primary);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 6px;
            padding: 2px 8px;
            font-size: 12px;
            font-family: var(--font-mono);
            font-weight: 600;
        }
        .doc-nav-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            text-decoration: none;
            border: 1px solid transparent;
            font-family: var(--font-main);
        }
        .btn-primary {
            background: var(--primary);
            color: #04101e;
        }
        .btn-primary:hover {
            background: var(--primary-hover);
            color: #ffffff;
        }
        .btn-outline {
            background: transparent;
            border-color: var(--border-color);
            color: var(--text-body);
        }
        .btn-outline:hover {
            background: var(--bg-surface);
            color: var(--text-main);
            border-color: var(--primary);
        }

        /* Reader Layout */
        .doc-container {
            max-width: 980px;
            margin: 32px auto 64px auto;
            padding: 0 24px;
        }
        .doc-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 44px 52px;
            box-shadow: 0 20px 45px rgba(0, 0, 0, 0.35);
        }

        /* Markdown Typography & Formatting */
        .markdown-body {
            color: var(--text-body);
        }
        .markdown-body h1 {
            color: var(--primary);
            font-size: 2.2rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            margin: 0.2em 0 0.8em 0;
            padding-bottom: 0.4em;
            border-bottom: 2px solid rgba(56, 189, 248, 0.25);
            line-height: 1.25;
        }
        .markdown-body h2 {
            color: var(--text-main);
            font-size: 1.55rem;
            font-weight: 700;
            letter-spacing: -0.015em;
            margin: 1.8em 0 0.7em 0;
            padding-bottom: 0.3em;
            border-bottom: 1px solid var(--border-color);
            line-height: 1.35;
        }
        .markdown-body h3 {
            color: var(--primary);
            font-size: 1.25rem;
            font-weight: 600;
            margin: 1.4em 0 0.6em 0;
            line-height: 1.4;
        }
        .markdown-body h4, .markdown-body h5, .markdown-body h6 {
            color: var(--text-main);
            font-size: 1.05rem;
            font-weight: 600;
            margin: 1.2em 0 0.5em 0;
        }
        .markdown-body p {
            margin: 1.15em 0;
            line-height: 1.75;
            color: var(--text-body);
        }
        .markdown-body strong {
            color: var(--text-main);
            font-weight: 600;
        }
        .markdown-body em {
            color: #93c5fd;
        }
        .markdown-body a {
            color: var(--primary);
            text-decoration: underline;
            text-underline-offset: 3px;
        }
        .markdown-body a:hover {
            color: var(--primary-hover);
        }
        .markdown-body hr {
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 2.2em 0;
        }

        /* Lists */
        .markdown-body ul, .markdown-body ol {
            margin: 1.1em 0;
            padding-left: 1.8em;
        }
        .markdown-body li {
            margin: 0.45em 0;
            line-height: 1.7;
        }
        .markdown-body li > ul, .markdown-body li > ol {
            margin: 0.3em 0;
        }

        /* Blockquotes */
        .markdown-body blockquote {
            border-left: 4px solid var(--primary);
            background: var(--primary-bg);
            border-radius: 0 8px 8px 0;
            padding: 12px 20px;
            margin: 1.5em 0;
            color: #93c5fd;
            font-style: normal;
        }
        .markdown-body blockquote p {
            margin: 0.4em 0;
        }

        /* Tables — Pixel-Perfect Styling */
        .table-responsive {
            width: 100%%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            margin: 1.6em 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-card);
        }
        .markdown-body table {
            width: 100%%;
            border-collapse: collapse;
            font-size: 13.5px;
            min-width: 650px;
            display: table;
        }
        .markdown-body th {
            background: var(--bg-surface);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
            padding: 12px 16px;
            border-bottom: 2px solid rgba(56, 189, 248, 0.35);
            text-align: left;
            white-space: nowrap;
        }
        .markdown-body td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text-body);
            line-height: 1.5;
            vertical-align: middle;
        }
        .markdown-body tbody tr:nth-child(even) {
            background: rgba(255, 255, 255, 0.02);
        }
        .markdown-body tbody tr:hover {
            background: rgba(56, 189, 248, 0.06);
        }
        .markdown-body td strong {
            color: var(--text-main);
        }

        /* Code Blocks & Inline Code */
        .markdown-body code {
            font-family: var(--font-mono);
            font-size: 0.88em;
            background: rgba(255, 255, 255, 0.08);
            color: var(--primary);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid var(--border-subtle);
        }
        body.light-theme .markdown-body code {
            background: rgba(0, 0, 0, 0.06);
            border-color: rgba(0, 0, 0, 0.1);
        }
        .code-block-wrapper {
            position: relative;
            margin: 1.6em 0;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            background: #090d16;
        }
        .code-block-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #111827;
            padding: 6px 14px;
            font-size: 11px;
            font-family: var(--font-mono);
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-subtle);
        }
        .btn-copy-code {
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            transition: all 0.15s;
        }
        .btn-copy-code:hover {
            color: var(--primary);
            background: rgba(255, 255, 255, 0.05);
        }
        .markdown-body pre {
            margin: 0;
            padding: 16px;
            overflow-x: auto;
            background: transparent;
        }
        .markdown-body pre code {
            background: transparent;
            border: none;
            padding: 0;
            color: #38bdf8;
            font-size: 13px;
            line-height: 1.6;
            display: block;
        }

        /* Print Media Styles */
        @media print {
            body { background: #ffffff !important; color: #000000 !important; }
            .doc-navbar { display: none !important; }
            .doc-container { max-width: 100%% !important; margin: 0 !important; padding: 0 !important; }
            .doc-card { border: none !important; box-shadow: none !important; padding: 0 !important; }
            .markdown-body h1 { color: #0284c7 !important; border-bottom: 2px solid #0284c7 !important; }
            .markdown-body th { background: #f1f5f9 !important; color: #0f172a !important; border-bottom: 2px solid #0284c7 !important; }
            .markdown-body td { border-bottom: 1px solid #e2e8f0 !important; color: #0f172a !important; }
            .code-block-wrapper { border: 1px solid #cbd5e1 !important; background: #f8fafc !important; }
            .markdown-body pre code { color: #0f172a !important; }
        }

        @media (max-width: 768px) {
            .doc-card { padding: 24px 20px; border-radius: 8px; }
            .markdown-body h1 { font-size: 1.7rem; }
            .doc-navbar { padding: 10px 16px; flex-wrap: wrap; }
        }
    </style>
</head>
<body>
    <header class="doc-navbar">
        <a href="/" class="doc-nav-brand">
            <img src="/static/images/logo.svg" alt="Valtrivo LogSeal">
            <div class="doc-nav-title">
                <span>Valtrivo LogSeal</span>
                <span class="doc-badge">%s</span>
            </div>
        </a>
        <div class="doc-nav-actions">
            <button class="btn btn-outline" onclick="toggleTheme()" id="btn-theme" title="Koyu / Açık Tema Değiştir">
                <span>🌓 Tema</span>
            </button>
            <button class="btn btn-outline" onclick="window.print()" title="Belgeyi Yazdır veya PDF Kaydet">
                <span>🖨️ Yazdır</span>
            </button>
            <a href="/api/v1/docs/download?file=%s" class="btn btn-primary" title="Markdown (.md) Olarak İndir">
                <span>⬇️ İndir (.md)</span>
            </a>
            <button class="btn btn-outline" onclick="window.history.length > 1 ? window.history.back() : window.close()" title="Sayfayı Kapat">
                <span>✕ Kapat</span>
            </button>
        </div>
    </header>

    <main class="doc-container">
        <article class="doc-card">
            <div id="markdown-rendered" class="markdown-body">
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    Doküman yükleniyor...
                </div>
            </div>
        </article>
    </main>

    <script>
        const rawContent = %s;

        function toggleTheme() {
            document.body.classList.toggle('light-theme');
            const isLight = document.body.classList.contains('light-theme');
            localStorage.setItem('doc_theme', isLight ? 'light' : 'dark');
        }

        // Apply saved theme
        if (localStorage.getItem('doc_theme') === 'light') {
            document.body.classList.add('light-theme');
        }

        // Fallback lightweight parser if marked fails to load
        function renderFallbackMarkdown(md) {
            const container = document.getElementById('markdown-rendered');
            if (window.marked && typeof window.marked.parse === 'function') {
                container.innerHTML = window.marked.parse(md);
            } else {
                // Preformatted fallback
                container.innerHTML = '<pre style="white-space: pre-wrap; font-family: var(--font-mono);">' + 
                    md.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + 
                    '</pre>';
                return;
            }

            // Post-process: wrap tables in .table-responsive for perfect mobile & desktop scrolling
            container.querySelectorAll('table').forEach(table => {
                if (!table.parentElement.classList.contains('table-responsive')) {
                    const wrapper = document.createElement('div');
                    wrapper.className = 'table-responsive';
                    table.parentNode.insertBefore(wrapper, table);
                    wrapper.appendChild(table);
                }
            });

            // Post-process: wrap pre blocks in .code-block-wrapper with copy button
            container.querySelectorAll('pre').forEach(pre => {
                if (!pre.parentElement.classList.contains('code-block-wrapper')) {
                    const wrapper = document.createElement('div');
                    wrapper.className = 'code-block-wrapper';
                    
                    const header = document.createElement('div');
                    header.className = 'code-block-header';
                    const code = pre.querySelector('code');
                    let lang = 'CODE';
                    if (code && code.className) {
                        const m = code.className.match(/language-([a-zA-Z0-9_-]+)/);
                        if (m) lang = m[1].toUpperCase();
                    }
                    header.innerHTML = '<span>' + lang + '</span><button class="btn-copy-code" onclick="copyCode(this)">📋 Kopyala</button>';
                    
                    pre.parentNode.insertBefore(wrapper, pre);
                    wrapper.appendChild(header);
                    wrapper.appendChild(pre);
                }
            });
        }

        function copyCode(btn) {
            const pre = btn.closest('.code-block-wrapper').querySelector('pre');
            if (!pre) return;
            navigator.clipboard.writeText(pre.innerText).then(() => {
                btn.textContent = '✓ Kopyalandı!';
                setTimeout(() => { btn.textContent = '📋 Kopyala'; }, 2000);
            }).catch(() => {
                btn.textContent = 'Hata!';
            });
        }

        // Execute rendering
        document.addEventListener('DOMContentLoaded', () => {
            renderFallbackMarkdown(rawContent);
        });
    </script>
</body>
</html>`, cleanName, cleanName, cleanName, string(jsonContent))
}

// findDocPath searches candidate locations for the markdown document
func findDocPath(cleanName string) string {
	candidates := []string{
		filepath.Join("docs", cleanName),
		cleanName,
		filepath.Join("/opt/syslog-platform", "docs", cleanName),
		filepath.Join("/opt/syslog-platform", cleanName),
	}
	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand
		}
	}
	return ""
}
