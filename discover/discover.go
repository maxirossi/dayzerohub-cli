// Package discover recorre un directorio para el inventario de MateProbe
// respetando .gitignore, exclusiones por defecto, --exclude e --include.
// Los directorios excluidos se podan durante el recorrido: no se leen.
//
// # Precedencia
//
// Las reglas se evalúan en este orden y la última que coincide gana:
//
//  1. exclusiones por defecto (solo directorios; desactivables con NoDefaultExcludes);
//  2. .git/info/exclude y .gitignore, desde la raíz git hacia el directorio más
//     profundo (desactivables con NoGitignore);
//  3. Excludes (--exclude, sintaxis gitignore relativa a la raíz analizada);
//  4. Includes (--include): una entrada que coincide con un include se
//     re-incluye aunque la excluyan los defaults, un .gitignore o --exclude.
//
// Un include de directorio (x/) hace que se recorra x y su contenido, pero
// dentro de x siguen aplicando las demás reglas (p. ej. node_modules). Un
// include sin '/' (sin anclar) obliga a recorrer directorios excluidos (costoso):
// preferí patrones anclados. ".git" nunca se recorre. La raíz solicitada nunca
// se excluye (un .git que es archivo, como en un worktree, no la excluye).
//
// Sin Git (o sin .git en ningún ancestro) funciona igual leyendo los
// .gitignore que haya dentro de la raíz. Si la raíz está dentro de un repo, se
// cargan los .gitignore de los ancestros hasta la raíz git; aplican solo a
// descendientes de la raíz. No se lee el gitignore global.
//
// Symlinks: por defecto no se siguen. Con FollowSymlinks se siguen solo los que
// apuntan dentro de la raíz real y a rutas aún no visitadas (sin ciclos).
package discover

import (
	"context"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Options configura el recorrido.
type Options struct {
	NoDefaultExcludes, NoGitignore, FollowSymlinks bool
	NoTracked                                      bool     // no usar el índice de Git (--ignore-git-index)
	Excludes                                       []string // --exclude
	Includes                                       []string // --include
	MaxEntries                                     int      // 0 = 400000
	MaxDepth                                       int      // 0 = 12
}

// Entry es un archivo o directorio no excluido.
type Entry struct {
	Rel, Abs, Name string // Rel con '/', sin "./"
	IsDir          bool
}

// Omitted es un directorio podado.
type Omitted struct{ Path, Reason string }

// Report resume el recorrido.
type Report struct {
	Omitted        []Omitted
	Rules          []string
	Symlinks       int // symlinks no seguidos o descartados
	SymlinkSkipped []string
	Entries        int
	Truncated      bool
	DepthSkipped   int
	Errors         []string
}

var defaultDirNames = []string{".git", "node_modules", "target", "dist", "build", ".next", ".nuxt", ".output",
	"vendor", ".hg", ".svn", "__pycache__", ".cache", ".venv", "venv", "coverage", ".turbo", ".idea", ".vscode",
	".gradle", ".terraform", "bower_components", ".parcel-cache", ".svelte-kit"}

const worktreesPath = ".claude/worktrees"

var errStop = errors.New("stop")

type state struct{ inExcluded, covered, trackedOnly bool }

type walker struct {
	ctx                         context.Context
	opts                        Options
	absRoot, realRoot, gitPref  string
	defaults, excludes, include []rule
	rep                         Report
	fn                          func(Entry) error
	count, maxEntries, maxDepth int
	visited                     map[string]bool
	gitLines                    []string
	tracked, trackedDirs        map[string]bool
}

func userRules(pats []string, label string, keepNeg bool) []rule {
	var out []rule
	for _, p := range pats {
		p = strings.TrimSpace(filepath.ToSlash(p))
		p = strings.TrimPrefix(p, "./")
		if p == "" {
			continue
		}
		if p[0] == '#' {
			p = `\` + p
		}
		if r, ok := parseLine(p); ok && (keepNeg || !r.neg) {
			r.label = label
			out = append(out, r)
		}
	}
	return out
}

// Walk recorre root llamando fn por cada entrada no excluida (salvo la raíz).
func Walk(ctx context.Context, root string, opts Options, fn func(e Entry) error) (Report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Report{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Report{}, err
	}
	if st, err := os.Stat(real); err != nil || !st.IsDir() {
		return Report{}, fmt.Errorf(i18n.Tr("%s no es un directorio", "%s is not a directory"), root)
	}
	w := &walker{ctx: ctx, opts: opts, absRoot: abs, realRoot: real, fn: fn, visited: map[string]bool{real: true},
		maxEntries: opts.MaxEntries, maxDepth: opts.MaxDepth}
	if w.maxEntries <= 0 {
		w.maxEntries = 400000
	}
	if w.maxDepth <= 0 {
		w.maxDepth = 12
	}
	// Reglas por defecto.
	if !opts.NoDefaultExcludes {
		for _, n := range defaultDirNames {
			if n == ".git" {
				continue
			}
			r, _ := parseLine(n + "/")
			r.label = i18n.Tr("regla por defecto: ", "default rule: ") + n
			w.defaults = append(w.defaults, r)
		}
		r, _ := parseLine("**/" + worktreesPath + "/")
		r.label = i18n.Tr("regla por defecto: ", "default rule: ") + worktreesPath
		w.defaults = append(w.defaults, r)
		w.rep.Rules = append(w.rep.Rules, i18n.Tr("por defecto (directorios): ", "default (directories): ")+strings.Join(append(append([]string{}, defaultDirNames...), worktreesPath), ", "))
	} else {
		w.rep.Rules = append(w.rep.Rules, i18n.Tr("exclusiones por defecto desactivadas (--no-default-excludes); .git nunca se recorre", "default exclusions disabled (--no-default-excludes); .git is never walked"))
	}
	w.excludes = userRules(opts.Excludes, "--exclude", true)
	w.include = userRules(opts.Includes, "--include", false)

	// Raíz git y gitignore de ancestros.
	var git []rule
	gitRoot := w.findGitRoot()
	foundGit := gitRoot != ""
	if opts.NoGitignore {
		w.rep.Rules = append(w.rep.Rules, i18n.Tr(".gitignore desactivado (--no-gitignore)", ".gitignore disabled (--no-gitignore)"))
	} else {
		if gitRoot == "" {
			gitRoot = real
		}
		if rel, err := filepath.Rel(gitRoot, real); err == nil && rel != "." {
			w.gitPref = filepath.ToSlash(rel)
		}
		if st, err := os.Stat(filepath.Join(gitRoot, ".git")); err == nil && st.IsDir() {
			if b, err := os.ReadFile(filepath.Join(gitRoot, ".git", "info", "exclude")); err == nil {
				if rs := parseRules(b, "", ".git/info/exclude"); len(rs) > 0 {
					git = append(git, rs...)
					w.gitLines = append(w.gitLines, fmt.Sprintf(i18n.Tr(".git/info/exclude (%d reglas)", ".git/info/exclude (%d rules)"), len(rs)))
				}
			}
		}
		if foundGit && !opts.NoTracked {
			w.loadTracked(gitRoot)
		}
		if w.gitPref != "" {
			parts := strings.Split(w.gitPref, "/")
			dir, base := gitRoot, ""
			for i := 0; i < len(parts); i++ { // gitRoot y ancestros intermedios (la raíz se carga al entrar)
				git = append(git, w.loadFile(dir, base)...)
				dir = filepath.Join(dir, parts[i])
				base = strings.Join(parts[:i+1], "/")
			}
		}
	}
	err = w.walkDir(real, "", real, git, state{})
	if errors.Is(err, errStop) || errors.Is(err, fs.SkipAll) {
		err = nil
	}
	w.rep.Rules = append(w.rep.Rules, w.gitLines...)
	for _, r := range w.excludes {
		w.rep.Rules = append(w.rep.Rules, "--exclude: "+r.raw)
	}
	for _, r := range w.include {
		w.rep.Rules = append(w.rep.Rules, "--include: "+r.raw)
	}
	if opts.FollowSymlinks {
		w.rep.Rules = append(w.rep.Rules, i18n.Tr("symlinks: se siguen solo dentro de la raíz y sin ciclos", "symlinks: followed only inside the root and without cycles"))
	} else {
		w.rep.Rules = append(w.rep.Rules, i18n.Tr("symlinks: no se siguen", "symlinks: not followed"))
	}
	sort.SliceStable(w.rep.Omitted, func(i, j int) bool { return w.rep.Omitted[i].Path < w.rep.Omitted[j].Path })
	w.rep.Entries = w.count
	return w.rep, err
}

func (w *walker) findGitRoot() string {
	dir := w.realRoot
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		p := filepath.Dir(dir)
		if p == dir {
			return ""
		}
		dir = p
	}
}

// loadFile lee dir/.gitignore con base (relativa a la raíz git).
func (w *walker) loadFile(dir, base string) []rule {
	path := filepath.Join(dir, ".gitignore")
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		w.rep.Errors = append(w.rep.Errors, fmt.Sprintf("%s: %v", path, err))
		return nil
	}
	label := w.labelFor(base)
	rs := parseRules(b, base, label)
	if len(rs) > 0 {
		w.gitLines = append(w.gitLines, fmt.Sprintf(i18n.Tr(".gitignore: %s (%d reglas)", ".gitignore: %s (%d rules)"), label, len(rs)))
	}
	return rs
}

func (w *walker) labelFor(base string) string {
	switch {
	case w.gitPref == "":
		return joinRel(base, ".gitignore")
	case base == w.gitPref:
		return ".gitignore"
	case strings.HasPrefix(base, w.gitPref+"/"):
		return joinRel(base[len(w.gitPref)+1:], ".gitignore")
	}
	return i18n.Tr("(ancestro) ", "(ancestor) ") + joinRel(base, ".gitignore")
}

func joinRel(a, b string) string {
	if a == "" {
		return b
	}
	return a + "/" + b
}

func (w *walker) gitRel(rel string) string {
	switch {
	case w.gitPref == "":
		return rel
	case rel == "":
		return w.gitPref
	}
	return w.gitPref + "/" + rel
}

type verdict struct {
	excluded, direct bool
	trackedDir       bool // ignorado por .gitignore pero con archivos tracked: se recorre solo lo tracked
	reason           string
}

func (w *walker) decide(rel string, isDir bool, git []rule, st state) verdict {
	for i := range w.include {
		if w.include[i].matches(rel, isDir) {
			return verdict{direct: true}
		}
	}
	var hard verdict // defaults + --exclude (mandan sobre el índice de Git)
	for i := range w.defaults {
		if w.defaults[i].matches(rel, isDir) {
			hard = verdict{excluded: true, reason: w.defaults[i].label}
		}
	}
	v := hard
	trackedFile := !isDir && w.tracked[rel]
	if !st.trackedOnly && !trackedFile {
		g := w.gitRel(rel)
		for i := range git {
			if git[i].matches(g, isDir) {
				v = verdict{excluded: !git[i].neg}
				if v.excluded {
					v.reason = fmt.Sprintf(i18n.Tr("ignorado por .gitignore (%s: %s)", "ignored by .gitignore (%s: %s)"), git[i].label, git[i].raw)
				}
			}
		}
	}
	for i := range w.excludes {
		if w.excludes[i].matches(rel, isDir) {
			hard = verdict{excluded: !w.excludes[i].neg}
			if hard.excluded {
				hard.reason = "--exclude: " + w.excludes[i].raw
			}
			v = hard
		}
	}
	silent := st.inExcluded && !st.covered
	switch {
	case silent && !v.excluded:
		v = verdict{excluded: true}
	case st.trackedOnly && !v.excluded:
		if !(isDir && w.trackedDirs[rel]) && !trackedFile {
			v = verdict{excluded: true, reason: i18n.Tr("dentro de un directorio ignorado por .gitignore, sin archivos tracked", "inside a directory ignored by .gitignore, with no tracked files")}
		}
	case isDir && v.excluded && !hard.excluded && !silent && !st.trackedOnly && w.trackedDirs[rel]:
		v = verdict{trackedDir: true}
	}
	return v
}

// mayMatchBelow indica si algún include puede coincidir con algo dentro de dir.
func (w *walker) mayMatchBelow(dir string) bool {
	d := strings.Split(dir, "/")
	for i := range w.include {
		r := &w.include[i]
		if !r.anchored {
			return true
		}
		var lit []string
		for _, s := range r.segs {
			if s == "**" || strings.ContainsAny(s, `*?[\`) {
				break
			}
			lit = append(lit, s)
		}
		full := len(lit) == len(r.segs)
		if full && len(d) > len(lit) {
			continue
		}
		n := min(len(d), len(lit))
		ok := true
		for k := 0; k < n; k++ {
			if d[k] != lit[k] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (w *walker) skipSymlink(rel string) {
	w.rep.Symlinks++
	if len(w.rep.SymlinkSkipped) < 20 {
		w.rep.SymlinkSkipped = append(w.rep.SymlinkSkipped, rel)
	}
}

func within(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

func (w *walker) walkDir(readPath, rel, realDir string, git []rule, st state) error {
	if !w.opts.NoGitignore && !(st.inExcluded && !st.covered) {
		if rs := w.loadFile(readPath, w.gitRel(rel)); len(rs) > 0 {
			git = append(git[:len(git):len(git)], rs...)
		}
	}
	des, err := os.ReadDir(readPath)
	if err != nil {
		w.rep.Errors = append(w.rep.Errors, fmt.Sprintf(i18n.Tr("no se pudo leer %s: %v", "could not read %s: %v"), displayRel(rel), err))
		return nil
	}
	for _, de := range des {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		name := de.Name()
		if name == ".git" {
			continue
		}
		if w.count++; w.count > w.maxEntries {
			w.rep.Truncated = true
			return errStop
		}
		erel := joinRel(rel, name)
		eabs := filepath.Join(w.absRoot, filepath.FromSlash(erel))
		isDir := de.IsDir()
		real := filepath.Join(realDir, name)
		readFrom := filepath.Join(readPath, name)
		if de.Type()&fs.ModeSymlink != 0 {
			if !w.opts.FollowSymlinks {
				w.skipSymlink(erel)
				continue
			}
			tst, err := os.Stat(readFrom)
			if err != nil {
				w.skipSymlink(erel)
				continue
			}
			rp, err := filepath.EvalSymlinks(readFrom)
			if err != nil || !within(w.realRoot, rp) {
				w.skipSymlink(erel)
				continue
			}
			isDir = tst.IsDir()
			if isDir && w.visited[rp] {
				w.skipSymlink(erel)
				continue
			}
			real, readFrom = rp, rp
		}
		if isDir && w.opts.FollowSymlinks && de.Type()&fs.ModeSymlink == 0 && w.visited[real] {
			continue // ya visitado a través de un symlink
		}
		v := w.decide(erel, isDir, git, st)
		child := st
		if v.direct {
			child.covered, child.trackedOnly = true, false
		}
		if v.trackedDir {
			child.trackedOnly = true
		}
		if !isDir {
			if v.direct || !v.excluded {
				if err := w.fn(Entry{Rel: erel, Abs: eabs, Name: name}); err != nil {
					if errors.Is(err, fs.SkipDir) {
						return nil
					}
					return err
				}
			}
			continue
		}
		descend := true
		if v.excluded {
			silent := st.inExcluded && !st.covered
			descend = w.mayMatchBelow(erel)
			if !silent {
				reason := v.reason
				if descend {
					reason += i18n.Tr(" (re-incluido parcialmente por --include)", " (partially re-included by --include)")
				}
				w.rep.Omitted = append(w.rep.Omitted, Omitted{erel, reason})
			}
			child = state{inExcluded: true}
		} else {
			if w.maxDepth > 0 && strings.Count(erel, "/") >= w.maxDepth {
				w.rep.DepthSkipped++
				continue
			}
			if err := w.fn(Entry{Rel: erel, Abs: eabs, Name: name, IsDir: true}); err != nil {
				if errors.Is(err, fs.SkipDir) {
					continue
				}
				return err
			}
		}
		if !descend {
			continue
		}
		if v.excluded && strings.Count(erel, "/") >= w.maxDepth {
			w.rep.DepthSkipped++
			continue
		}
		w.visited[real] = true
		if err := w.walkDir(readFrom, erel, real, git, child); err != nil {
			return err
		}
	}
	return nil
}

func displayRel(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}
