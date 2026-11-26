package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/maxirossi/mateprobe/i18n"
)

// El backtick no cabe en un string raw: se escribe como ¬ y se reemplaza.
const bannerArt = `  ____              _____                _   _       _
 |  _ \  __ _ _   _|__  /___ _ __ ___   | | | |_   _| |__
 | | | |/ _¬ | | | | / // _ \ '__/ _ \  | |_| | | | | '_ \
 | |_| | (_| | |_| |/ /|  __/ | | (_) | |  _  | |_| | |_) |
 |____/ \__,_|\__, /____\___|_|  \___/  |_| |_|\__,_|_.__/
              |___/`

// printBanner dibuja el logo ASCII en w, solo si es una terminal (no ensucia pipes, archivos ni tests).
func printBanner(w io.Writer) {
	if !isTTY(w) {
		return
	}
	art := strings.ReplaceAll(bannerArt, "¬", "`")
	green, dim, reset := "\x1b[32m", "\x1b[2m", "\x1b[0m"
	if _, off := os.LookupEnv("NO_COLOR"); off {
		green, dim, reset = "", "", ""
	}
	fmt.Fprintf(w, "\n%s%s%s\n", green, art, reset)
	fmt.Fprintf(w, "%s  mateprobe %s · %s · dayzerohub.site%s\n\n", dim, version,
		i18n.Tr("escáner local de seguridad", "local security scanner"), reset)
}
