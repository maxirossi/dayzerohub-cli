package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/maxirossi/mateprobe/credentials"
	"github.com/maxirossi/mateprobe/dzh"
)

const loginUsage = `Uso:
  mateprobe login    autoriza este equipo con tu cuenta de DayZeroHub y guarda una API key personal
  mateprobe logout   borra la API key guardada en este equipo (revocala también en el panel)

La key se guarda en el directorio de configuración del usuario con permisos 0600 y la usa "mateprobe audit".
`

// Puntos de inyección para pruebas.
var (
	loginOpen  = openFile
	loginSleep = func(ctx context.Context, d time.Duration) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
)

func installationName() string {
	host, _ := os.Hostname()
	name := host
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username + "@" + host
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		name = "mateprobe"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

func runLogin(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprint(stderr, loginUsage)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cl := dzh.New(auditBaseURL, "")
	cl.UserAgent = "mateprobe/" + version
	d, err := cl.StartDevice(ctx, installationName())
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "Para autorizar este equipo abrí este link con tu sesión de DayZeroHub:\n\n  %s\n\nCódigo: %s (vence en %d min)\n\nEsperando la autorización ...\n",
		d.VerificationURL, d.UserCode, d.ExpiresIn/60)
	_ = loginOpen(d.VerificationURL)

	interval := time.Duration(d.Interval) * time.Second
	if interval < time.Second {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		if err := loginSleep(ctx, interval); err != nil {
			fmt.Fprintln(stderr, "Interrumpido.")
			return exitInterrupted
		}
		key, err := cl.PollDevice(ctx, d.DeviceCode)
		if errors.Is(err, dzh.ErrPending) {
			continue
		}
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		if err := credentials.Save(key); err != nil {
			fmt.Fprintf(stderr, "error: no se pudo guardar la key: %v\n", err)
			return exitUsage
		}
		p, _ := credentials.Path()
		fmt.Fprintf(stdout, "Listo: equipo autorizado. Key guardada en %s\n", p)
		return exitOK
	}
	fmt.Fprintln(stderr, "error: el código venció sin ser autorizado; ejecutá `mateprobe login` de nuevo")
	return exitUsage
}

func runLogout(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprint(stderr, loginUsage)
		return exitUsage
	}
	if err := credentials.Delete(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(stdout, "Key local borrada. Si querés invalidarla, revocala en el panel de DayZeroHub (API técnica).")
	return exitOK
}
