// genexamples genera los ejemplos de examples/ escaneando únicamente
// servidores locales con contenido de fixture (127.0.0.1, puertos fijos).
// Uso: go run ./tools/genexamples [directorio-de-salida]
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/maxirossi/mateprobe/collect"
	"github.com/maxirossi/mateprobe/detect"
	"github.com/maxirossi/mateprobe/export"
	"github.com/maxirossi/mateprobe/scan"
	"github.com/maxirossi/mateprobe/targets"
)

const wp = `<!doctype html><html><head><meta charset="utf-8"><title>Blog de ejemplo</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
<script src="/wp-content/themes/ejemplo/app.js"></script></head><body>fixture</body></html>`

const next = `<!doctype html><html><head><title>Tienda Next</title></head><body><div id="__next"></div>
<script src="/_next/static/chunks/main.js"></script><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>`

func serve(addr string, h http.HandlerFunc) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	go http.Serve(ln, h)
}

func main() {
	dir := "examples"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	serve("127.0.0.1:18081", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.12")
		w.Header().Add("Set-Cookie", "wordpress_test_cookie=WP%20Cookie%20check; path=/")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprint(w, wp)
	})
	serve("127.0.0.1:18082", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "8a1b2c3d4e5f6789-EZE")
		w.Header().Set("X-Powered-By", "Next.js")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, next)
	})
	serve("127.0.0.1:18083", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "página mínima sin señales")
	})
	serve("127.0.0.1:18084", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://otro-host.example.test:18083/", http.StatusFound)
	})
	// 127.0.0.1:18089 queda sin servicio a propósito (error de conexión).

	e, err := detect.New()
	if err != nil {
		panic(err)
	}
	in := []string{"http://127.0.0.1:18081/", "http://127.0.0.1:18082/", "http://127.0.0.1:18083/",
		"http://127.0.0.1:18084/", "http://127.0.0.1:18089/"}
	list, err := targets.Expand(in, targets.Options{})
	if err != nil {
		panic(err)
	}
	cfg := scan.Config{Version: "ejemplo", Concurrency: 1, MaxAddresses: 256,
		Collect: collect.Config{UserAgent: "mateprobe/ejemplo", Timeout: 5 * time.Second, MaxRedirects: 5,
			MaxBodyBytes: collect.DefaultMaxBody, Rate: 0}}
	rep := scan.Run(context.Background(), cfg, list, e)

	_ = os.MkdirAll(dir, 0o755)
	for name, format := range map[string]string{"resultado.json": "json", "resultado.csv": "csv", "reporte.html": "html", "resultado.txt": "table"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			panic(err)
		}
		if err := export.Write(f, format, rep); err != nil {
			panic(err)
		}
		f.Close()
	}
	fmt.Println("ejemplos escritos en", dir)
}
