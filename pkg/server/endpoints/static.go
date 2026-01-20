package endpoints

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
)

//go:embed static/css static/img
var staticFiles embed.FS

// RegisterStaticFiles registers static file serving for CSS, images, etc.
// Static files are embedded in the binary.
func RegisterStaticFiles(srv *server.Server) {
	// Create sub-filesystem rooted at "static"
	staticFS, _ := fs.Sub(staticFiles, "static")

	// Serve /css/* from embedded static/css/
	cssFS, _ := fs.Sub(staticFS, "css")
	srv.Router.PathPrefix("/css/").Handler(
		http.StripPrefix("/css/", http.FileServer(http.FS(cssFS))),
	)

	// Serve /img/* from embedded static/img/
	imgFS, _ := fs.Sub(staticFS, "img")
	srv.Router.PathPrefix("/img/").Handler(
		http.StripPrefix("/img/", http.FileServer(http.FS(imgFS))),
	)

	// Serve favicon.ico (return 404 if not present)
	srv.Router.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
}
