package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.Header().Del("Content-Length")
	return w.writer.Write(b)
}

// gzipMiddleware provides transparent Gzip compression and browser caching headers
// for web assets (HTML, CSS, JS, SVG, Fonts), drastically speeding up initial page loads.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// High-performance caching headers for static assets
		if strings.HasPrefix(path, "/static/") {
			if strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
				strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".png") ||
				strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ttf") {
				w.Header().Set("Cache-Control", "public, max-age=86400, stale-while-revalidate=604800")
			}
		}

		// Check if client accepts gzip
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// WebSocket / SSE upgrade requests must not be gzipped
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")

		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		defer func() {
			_ = gz.Close()
			gzipWriterPool.Put(gz)
		}()

		gzw := &gzipResponseWriter{
			ResponseWriter: w,
			writer:         gz,
		}

		next.ServeHTTP(gzw, r)
	})
}
