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
	"github.com/maxirossi/mateprobe/i18n"
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
		fmt.Fprint(stderr, loginUsageText())
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
	printBanner(stderr)
	fmt.Fprintf(stderr, i18n.Tr("Para autorizar este equipo abrí este link con tu sesión de DayZeroHub:\n\n  %s\n\nCódigo: %s (vence en %d min)\n\nEsperando la autorización ...\n", "To authorize this machine, open this link with your DayZeroHub session:\n\n  %s\n\nCode: %s (expires in %d min)\n\nWaiting for authorization ...\n"),
		d.VerificationURL, d.UserCode, d.ExpiresIn/60)
	_ = loginOpen(d.VerificationURL)

	interval := time.Duration(d.Interval) * time.Second
	if interval < time.Second {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		if err := loginSleep(ctx, interval); err != nil {
			fmt.Fprintln(stderr, i18n.Tr("Interrumpido.", "Interrupted."))
			return exitInterrupted
		}
		key, err := cl.PollDevice(ctx, d.DeviceCode)
		if errors.Is(err, dzh.ErrPending) {
			continue
		}
		if errors.Is(err, dzh.ErrExpired) {
			fmt.Fprintln(stderr, i18n.Tr("error: el código venció; ejecutá `mateprobe login` de nuevo", "error: the code expired; run `mateprobe login` again"))
			return exitUsage
		}
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		if err := credentials.Save(key); err != nil {
			fmt.Fprintf(stderr, i18n.Tr("error: no se pudo guardar la key: %v\n", "error: could not save the key: %v\n"), err)
			return exitUsage
		}
		p, _ := credentials.Path()
		fmt.Fprintf(stdout, i18n.Tr("Listo: equipo autorizado. Key guardada en %s\n", "Done: machine authorized. Key saved to %s\n"), p)
		return exitOK
	}
	fmt.Fprintln(stderr, i18n.Tr("error: el código venció sin ser autorizado; ejecutá `mateprobe login` de nuevo", "error: the code expired without being authorized; run `mateprobe login` again"))
	return exitUsage
}

func runLogout(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprint(stderr, loginUsageText())
		return exitUsage
	}
	if err := credentials.Delete(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(stdout, i18n.Tr("Key local borrada. Si querés invalidarla, revocala en el panel de DayZeroHub (API técnica).", "Local key deleted. To invalidate it, revoke it in the DayZeroHub panel (Technical API)."))
	return exitOK
}
