# Licencias y atribuciones de terceros

Dependencias incluidas en el binario (verificadas con `go version -m`), versiones fijadas en `go.mod`/`go.sum`:

| Módulo | Versión | Licencia | Uso |
|---|---|---|---|
| `github.com/projectdiscovery/wappalyzergo` | v0.3.11 | MIT (© 2021 ProjectDiscovery, Inc.) — ver abajo sobre las firmas | motor de detección y base de firmas embebida |
| `golang.org/x/net` | v0.62.0 | BSD-3-Clause (© The Go Authors) | tokenizador HTML, IDNA |
| `golang.org/x/text` | v0.43.0 | BSD-3-Clause (© The Go Authors) | dependencia de `x/net/idna` |
| `golang.org/x/time` | v0.16.0 | BSD-3-Clause (© The Go Authors) | rate limiter |

Además se enlaza la biblioteca estándar de Go (BSD-3-Clause).

Las dependencias solo de prueba/desarrollo de wappalyzergo (p. ej. `go-rod`, `testify`) **no** forman parte del binario.

## ⚠️ Pendiente de decisión: licencia de las firmas de tecnologías

- El **código** de `wappalyzergo` es MIT.
- Pero la **base de firmas** que embebe (`fingerprints_data.json`) se genera, según su propia herramienta `cmd/update-fingerprints`, a partir de:
  - `github.com/enthec/webappanalyzer` — licencia **GPL-3.0** (según la API de GitHub, consultada el 2026-11-25)
  - `github.com/HTTPArchive/wappalyzer` — licencia **GPL-3.0** (ídem)
- Distribuir un binario que embebe datos derivados de fuentes GPL-3.0 **puede imponer obligaciones GPL** (entrega del código fuente, licenciar el conjunto bajo GPL-3.0, avisos). Esto no está resuelto en este MVP y **no se eligió licencia para mateprobe**.
- Opciones a evaluar por el titular antes de publicar binarios:
  1. Licenciar mateprobe bajo GPL-3.0 y cumplir sus obligaciones.
  2. Uso estrictamente interno/local (sin distribuir el binario) mientras se decide.
  3. Reemplazar la base de firmas por una propia o de licencia permisiva, conservando las reglas propias de `detect/rules.go` (que son de este proyecto).
  4. Consultar a asesoría legal.

Las **reglas propias** (`detect/rules.go`) son código original de este proyecto y no incorporan firmas de terceros.

## Texto de la licencia MIT de wappalyzergo

```
MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

El texto completo de cada licencia se encuentra en el módulo correspondiente (`$GOPATH/pkg/mod/<módulo>@<versión>/LICENSE`).
