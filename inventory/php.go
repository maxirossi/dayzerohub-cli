package inventory

import (
	"encoding/json"
	"github.com/maxirossi/mateprobe/i18n"
	"sort"
	"strings"
)

var phpFrameworks = map[string]string{
	"laravel/framework": "Laravel", "symfony/symfony": "Symfony", "symfony/framework-bundle": "Symfony",
	"symfony/http-kernel": "Symfony (HttpKernel)", "yiisoft/yii2": "Yii", "cakephp/cakephp": "CakePHP",
	"codeigniter4/framework": "CodeIgniter", "slim/slim": "Slim", "laminas/laminas-mvc": "Laminas",
	"livewire/livewire": "Livewire", "drupal/core": "Drupal", "roots/wordpress": "WordPress",
	"johnpbloch/wordpress": "WordPress", "magento/product-community-edition": "Magento",
}

type composerJSON struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func phpKind(name string) string {
	switch phpFrameworks[name] {
	case "":
		return KindLibrary
	case "WordPress", "Drupal", "Magento":
		return KindCMS
	}
	return KindFramework
}

func platformReq(name string) bool {
	return name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") ||
		name == "composer-plugin-api" || name == "composer-runtime-api" || name == "composer"
}

func (a *analyzer) processPHP(dir string, f map[string]bool, sp *Subproject) {
	var cj composerJSON
	haveJSON := false
	if f["composer.json"] {
		if b, ok := a.read(join(dir, "composer.json"), maxManifest); ok {
			if err := json.Unmarshal(b, &cj); err != nil {
				a.errorf(i18n.Tr("%s: JSON inválido: %v", "%s: invalid JSON: %v"), join(dir, "composer.json"), err)
			} else {
				haveJSON = true
			}
		}
	}
	if !haveJSON && !f["composer.lock"] {
		return
	}
	sp.addEco(EcoComposer)
	if sp.Name == "" && cj.Name != "" {
		sp.Name = cleanText(cj.Name, 100)
	}
	if haveJSON {
		sp.Files = append(sp.Files, join(dir, "composer.json"))
		php := Component{Name: "PHP", Ecosystem: EcoComposer, Kind: KindLanguage, State: StateUnknown, Relation: RelDirect,
			Evidence: join(dir, "composer.json"), Subproject: dir, Aliases: []string{"php"},
			Notes: []string{i18n.Tr("proyecto PHP; la versión del runtime no está declarada", "PHP project; the runtime version is not declared")}}
		if v := cj.Require["php"]; v != "" {
			php.Constraint, php.State = cleanText(v, 60), StateConstraint
			php.Notes = []string{i18n.Tr("declarado en require.php", "declared in require.php")}
		}
		a.add(php)
	}

	direct := map[string]string{}
	dev := map[string]bool{}
	for n, v := range cj.Require {
		if !platformReq(n) {
			direct[n] = v
		}
	}
	for n, v := range cj.RequireDev {
		if _, ok := direct[n]; !ok && !platformReq(n) {
			direct[n], dev[n] = v, true
		}
	}

	seen := map[string]bool{}
	lockFile := ""
	if f["composer.lock"] {
		lockFile = join(dir, "composer.lock")
		sp.Files = append(sp.Files, lockFile)
		if b, ok := a.read(lockFile, maxLockfile); ok {
			var lock composerLock
			if err := json.Unmarshal(b, &lock); err != nil {
				a.errorf(i18n.Tr("%s: JSON inválido: %v", "%s: invalid JSON: %v"), lockFile, err)
			} else {
				emit := func(pk composerPkg, isDev bool) {
					if pk.Name == "" {
						return
					}
					c := Component{Name: strings.ToLower(pk.Name), Ecosystem: EcoComposer, Kind: phpKind(strings.ToLower(pk.Name)),
						Version: pk.Version, State: StateExact, Relation: RelTransitive, Scope: scopeOf(isDev), Evidence: lockFile, Subproject: dir}
					if pk.Version == "" {
						c.State = StateUnknown
					}
					if rng, ok := direct[pk.Name]; ok {
						c.Relation, c.Constraint = RelDirect, cleanText(rng, 80)
						seen[pk.Name] = true
					}
					if disp, ok := phpFrameworks[c.Name]; ok {
						c.Aliases = append(c.Aliases, strings.ToLower(disp))
					}
					a.add(c)
				}
				for _, p := range lock.Packages {
					emit(p, false)
				}
				for _, p := range lock.PackagesDev {
					emit(p, true)
				}
			}
		}
	} else if haveJSON {
		a.res.Limitations = append(a.res.Limitations, join(dir, "composer.json")+i18n.Tr(": sin composer.lock; las versiones son restricciones declaradas, no versiones resueltas", ": no composer.lock; versions are declared constraints, not resolved versions"))
	}
	names := make([]string, 0, len(direct))
	for n := range direct {
		if !seen[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		rng := cleanText(direct[n], 80)
		c := Component{Name: strings.ToLower(n), Ecosystem: EcoComposer, Kind: phpKind(strings.ToLower(n)), Constraint: rng,
			State: StateConstraint, Relation: RelDirect, Scope: scopeOf(dev[n]), Evidence: join(dir, "composer.json"), Subproject: dir}
		if isExact(rng) {
			c.Version, c.State = strings.TrimPrefix(rng, "v"), StateExact
			c.Notes = append(c.Notes, i18n.Tr("versión fijada en composer.json", "version pinned in composer.json"))
		}
		if disp, ok := phpFrameworks[c.Name]; ok {
			c.Aliases = append(c.Aliases, strings.ToLower(disp))
		}
		a.add(c)
	}
}
