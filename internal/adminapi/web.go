package adminapi

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

// dist is the build output of the web console: the Vite project in web/
// (a Vue 3 app, no runtime compiler) builds into static/dist via
// `make update-frontend`. The bundle is never committed — the CI web job
// hands it to the Go jobs as an artifact, the Docker image builds it in
// a node stage, and locally the Makefile builds it on demand (AGENTS.md).
//
//go:embed static/dist
var dist embed.FS

// cspConsole is the Content-Security-Policy for the web console. The built
// shell (dist/index.html) is markup only — its JavaScript arrives as
// same-origin /assets/*.js module scripts and its styles as /assets/*.css,
// so script-src and style-src are plain 'self' with no 'unsafe-inline' and
// no 'unsafe-eval' (the SFC template is precompiled at build time, so the
// runtime never evaluates code). The XSS fix lives in the app itself: every
// value from the API is rendered through Vue's {{ }} interpolation, which
// HTML-escapes automatically, and the console source (web/src) never uses
// v-html or innerHTML — the tripwire tests enforce both — so no device data
// is ever spliced into the DOM as markup. This CSP is defense-in-depth on
// top: even if some markup slipped past, it cannot exfiltrate to other
// origins (connect/default-src), be framed (frame-ancestors 'none'), hijack
// hyperlinks (base-uri 'none') or load plugin content (object-src 'none').
const cspConsole = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"connect-src 'self'; " +
	"img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

// page serves the built console shell (dist/index.html) at "/".
func page(w http.ResponseWriter, _ *http.Request) {
	data, err := dist.ReadFile("static/dist/index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "console build output missing")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", cspConsole)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// assets serves the built console bundles (dist/assets/*) by exact name.
// Vite's output filenames are content-hashed, so the year-long immutable
// cache is safe; anything unknown 404s (no directory listing).
func assets(w http.ResponseWriter, r *http.Request) {
	// path.Base pins the lookup to the flat assets/ namespace, so no
	// request can reach outside dist/assets/ via parent-directory segments.
	name := path.Base(r.URL.Path)
	ct, ok := assetsContentType(name)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such endpoint")
		return
	}
	data, err := dist.ReadFile("static/dist/assets/" + name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such endpoint")
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", cspConsole)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// assetsContentType maps the console's asset types; the build ships only
// hashed JS and CSS, so anything else is unknown and 404s.
func assetsContentType(name string) (string, bool) {
	i := strings.LastIndex(name, ".")
	switch strings.ToLower(name[i+1:]) {
	case "js":
		return "application/javascript", true
	case "css":
		return "text/css", true
	default:
		return "", false
	}
}
