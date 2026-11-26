// Package credentials guarda la API key personal que obtiene `mateprobe login`
// en el directorio de configuración del usuario (permisos 0600).
package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Path devuelve la ruta del archivo de credenciales.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mateprobe", "credentials"), nil
}

// Load devuelve la key guardada ("" si no hay).
func Load() (string, error) {
	p, err := Path()
	if err != nil {
		return "", nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Save escribe la key con permisos 0600.
func Save(key string) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(key+"\n"), 0o600)
}

// Delete borra la key guardada (no falla si no existe).
func Delete() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
