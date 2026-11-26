package discover

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxIndexSize = 256 << 20

// indexPath devuelve la ruta del índice de Git de gitRoot sin ejecutar git:
// .git/index, o X/index si .git es un archivo "gitdir: X" (worktrees).
func indexPath(gitRoot string) (string, error) {
	dotgit := filepath.Join(gitRoot, ".git")
	st, err := os.Lstat(dotgit)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return filepath.Join(dotgit, "index"), nil
	}
	b, err := os.ReadFile(dotgit)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	dir, ok := strings.CutPrefix(line, "gitdir:")
	if !ok {
		return "", errors.New(".git no tiene el formato «gitdir: ruta»")
	}
	dir = strings.TrimSpace(dir)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(gitRoot, dir)
	}
	return filepath.Join(dir, "index"), nil
}

// readIndex lee las rutas (relativas a la raíz git) de archivos tracked.
func readIndex(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxIndexSize {
		return nil, fmt.Errorf("índice demasiado grande (%d bytes, máximo %d)", st.Size(), maxIndexSize)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseIndex(b)
}

func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	v := uint64(c & 127)
	i := 1
	for c&128 != 0 {
		if i >= len(b) || i > 10 {
			return 0, 0
		}
		v++
		c = b[i]
		i++
		v = v<<7 + uint64(c&127)
	}
	return v, i
}

// parseIndex decodifica un índice de Git v2, v3 o v4 (ignora las extensiones
// y el checksum). Devuelve solo archivos regulares y symlinks.
func parseIndex(b []byte) ([]string, error) {
	if len(b) < 12 || string(b[:4]) != "DIRC" {
		return nil, errors.New("no es un índice de Git (falta la cabecera DIRC)")
	}
	ver := binary.BigEndian.Uint32(b[4:])
	count := binary.BigEndian.Uint32(b[8:])
	if ver < 2 || ver > 4 {
		return nil, fmt.Errorf("versión de índice %d no soportada", ver)
	}
	if uint64(count)*63 > uint64(len(b)) {
		return nil, errors.New("el número de entradas excede el tamaño del archivo")
	}
	var out []string
	off, prev := 12, ""
	for i := uint32(0); i < count; i++ {
		if off+62 > len(b) {
			return nil, errors.New("índice truncado")
		}
		mode := binary.BigEndian.Uint32(b[off+24:])
		flags := binary.BigEndian.Uint16(b[off+60:])
		start := off + 62
		if ver >= 3 && flags&0x4000 != 0 {
			start += 2
		}
		if start > len(b) {
			return nil, errors.New("índice truncado")
		}
		var path string
		if ver == 4 {
			strip, n := varint(b[start:])
			if n == 0 || strip > uint64(len(prev)) {
				return nil, errors.New("prefijo de ruta inválido (v4)")
			}
			p := start + n
			end := bytes.IndexByte(b[p:], 0)
			if end < 0 {
				return nil, errors.New("ruta sin terminador")
			}
			path = prev[:len(prev)-int(strip)] + string(b[p:p+end])
			off = p + end + 1
		} else {
			end := bytes.IndexByte(b[start:], 0)
			if end < 0 {
				return nil, errors.New("ruta sin terminador")
			}
			path = string(b[start : start+end])
			off += ((start - off + end + 1) + 7) &^ 7
		}
		prev = path
		if t := (mode >> 12) & 0xF; (t == 0x8 || t == 0xA) && path != "" && !strings.HasSuffix(path, "/") {
			out = append(out, path)
		}
	}
	return out, nil
}

// loadTracked carga el índice y lo convierte a rutas relativas a la raíz analizada.
func (w *walker) loadTracked(gitRoot string) {
	path, err := indexPath(gitRoot)
	if err == nil {
		var paths []string
		if paths, err = readIndex(path); err == nil {
			w.tracked, w.trackedDirs = map[string]bool{}, map[string]bool{}
			for _, p := range paths {
				if w.gitPref != "" {
					var ok bool
					if p, ok = strings.CutPrefix(p, w.gitPref+"/"); !ok {
						continue
					}
				}
				w.tracked[p] = true
				for d := p; ; {
					i := strings.LastIndexByte(d, '/')
					if i < 0 {
						break
					}
					d = d[:i]
					if w.trackedDirs[d] {
						break
					}
					w.trackedDirs[d] = true
				}
			}
			w.gitLines = append(w.gitLines, fmt.Sprintf("índice de Git: %d archivos tracked nunca se ignoran por .gitignore (--ignore-git-index lo desactiva)", len(w.tracked)))
			return
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return // repositorio sin índice: nada tracked
	}
	w.rep.Errors = append(w.rep.Errors, fmt.Sprintf("aviso: no se pudo leer el índice de Git (se continúa sin él): %v", err))
}
