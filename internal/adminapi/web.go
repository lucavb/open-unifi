package adminapi

import (
	_ "embed"
	"net/http"
)

// page serves the embedded single-file web console at "/".
//
// Single source of truth: static/index.html is the console — compiled into
// this package via go:embed (embed cannot reference parent directories,
// which is why the old ../web/static reference copy was deleted). There is
// no second copy to drift against; the compiler is the sync test: edit the
// file, rebuild, done.
//
//go:embed static/index.html
var indexHTML []byte

// cspConsole is the Content-Security-Policy for the single-file console.
// Honest limitation: the console needs inline <script> and <style> because
// it is one self-contained file, so 'unsafe-inline' is unavoidable there —
// esc() in the embedded script is the ACTUAL XSS fix; this CSP is
// defense-in-depth: even if some markup slipped past esc(), it cannot
// exfiltrate to other origins (connect/default-src), be framed
// (frame-ancestors 'none'), hijack hyperlinks (base-uri 'none') or load
// plugin content (object-src 'none').
const cspConsole = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self'; " +
	"img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", cspConsole)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHTML)
}
