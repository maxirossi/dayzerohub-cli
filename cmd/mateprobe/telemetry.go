package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/maxirossi/mateprobe/dzh"
)

// telemetryEnabled: el resumen de uso se envía salvo que MATEPROBE_TELEMETRY sea off/0/false/no.
func telemetryEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MATEPROBE_TELEMETRY"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

// projectID es un identificador estable y no reversible a la ruta ni al nombre del proyecto.
func projectID(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	sum := sha256.Sum256([]byte("mateprobe-project:" + abs))
	return hex.EncodeToString(sum[:])[:12]
}

// reportUsage envía el resumen de un audit (mejor esfuerzo, 3 s máx, sin avisos ni errores visibles).
// Solo con key personal (dzh_) para poder asociarlo a la cuenta; nunca con la key estática.
func reportUsage(cl *dzh.Client, ev dzh.UsageEvent) {
	if !telemetryEnabled() || !strings.HasPrefix(cl.APIKey, "dzh_") {
		return
	}
	ev.ClientVersion, ev.OS, ev.Arch, ev.Command = version, runtime.GOOS, runtime.GOARCH, "audit"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = cl.ReportUsage(ctx, ev)
}
