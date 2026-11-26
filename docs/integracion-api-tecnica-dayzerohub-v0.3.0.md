# Integración de la API técnica de DayZeroHub en `mateprobe audit` (v0.3.0)

- **Fecha:** 2026-11-25
- **Proyecto:** `/home/maxi/Escritorio/matelabs/projects/mateprobe`
- **Estado:** implementado y verificado; sin commitear
- **Decisiones de diseño:** ver [`adr1.md`](adr1.md) (subcomando `audit`) y [`adr2.md`](adr2.md) (API técnica y rangos locales)
- **Fuentes del cambio:** `/home/maxi/Escritorio/instrucciones-cliente-go-dayzerohub.md` y `/home/maxi/Escritorio/matelabs/projects/zerodaynotices/docs/mateprobe-api-integration.md`

## 1. Qué cambió

Las URLs y la autenticación del proyecto cambiaron: hay cuatro rutas bajo `https://dayzerohub.site` y **una sola `api_key`** (cabecera `X-API-Key`, nunca en la query).

| Método y ruta | Constante (`dzh/client.go`) | Método del cliente |
|---|---|---|
| `GET /api/v1/news?lang=es` | `newsPath` | `Fetch` |
| `GET /api/v1/security/catalog` | `securityCatalog` | `Catalog` |
| `GET /api/v1/security/advisories` | `securityAdvisory` | `Advisories` (una página por llamada, cursor opaco) |
| `POST /api/v1/security/packages/lookup` | `securityLookup` | `Lookup` |

- **Configuración:** la key sigue en `.env`/entorno como `api_key` (minúsculas). `config/config.go` no cambió. Las URLs son constantes del código, no variables de entorno.
- **Cliente:** un solo camino HTTP (`call`/`once`) para las cuatro rutas: timeout, límite de cuerpo, reintentos 429/5xx/red con backoff exponencial y jitter, respeto de `Retry-After` (máx. 30 s) y key quitada en redirecciones a otro origen. **Un 401 no se reintenta** y corta las consultas siguientes (los 401 repetidos pueden banear la IP); el informe sale parcial.
- **`Lookup`:** lotes de ≤100 componentes, `limit` 100 por componente, sigue `next_cursor` por componente (tope local de 20 páginas) y reintenta una vez solo los `status=error`. Si falla el transporte devuelve lo obtenido más el error.
- **Privacidad:** solo viaja `{ecosystem, name}` de paquetes `npm`, `Packagist` y `Go`. Nunca versiones, rutas ni contenido. Runtimes (Node.js, PHP, Go) y WordPress no se consultan en la API técnica. Hay una prueba que lo verifica.

## 2. Cómo se decide si una versión está afectada

La decisión es **local** (`version/` y `correlate/technical.go`); la API no evalúa versiones.

1. Componente identificado (ecosistema + nombre con evidencia en lockfile, `go.mod`, etc.).
2. Aviso asociado (`matched`): es una posibilidad, no un hallazgo.
3. Versión dentro del rango: se compara la versión **exacta** con `ranges`/`versions` según `version_scheme`, solo si `identity.status = verified` y `range_quality = usable`.
   - Comparadores: semver (npm, Go) y composer/WordPress. Otros esquemas (PyPI, Maven, RubyGems, NuGet) → «No determinado».
   - Semántica OSV: `introduced` inclusivo (`"0"` = desde el inicio), `fixed` exclusivo, `last_affected` inclusivo, `limit` exclusivo. Cada `introduced…cierre` es una rama independiente; sin cierre, el rango es abierto.
   - Sin rangos pero con `versions[]` (paquetes maliciosos `MAL-…`): se usa la lista explícita.
   - Varias filas (una por fuente): afectado si alguna lo indica; «fuera de rango» solo si todas son evaluables y no hay conflictos.
4. Explotabilidad: se muestra `known_exploited` / `not_listed_in_kev` / sin información; «sin información» nunca se presenta como «no explotado».

**Resultados posibles:** «Versión local dentro del rango afectado», «Versión local fuera del rango informado» y «No determinado».

**Siempre «No determinado» cuando:** la versión local es una restricción (`^5.0.0`) o desconocida; el rango es `GIT` o `insufficient`/`unknown`; la identidad está `pending`; el esquema no tiene comparador; las fuentes discrepan (`quality.conflicts`); o el módulo Go tiene `replace`.

**Go:** la versión de `go.mod` es «declarada» (mínima de MVS). Se evalúa con una salvedad explícita en el informe.

**Estados sin dato ≠ seguro:** `no_match`, `ecosystem_not_covered` y `error` se informan como «sin datos». Los avisos `withdrawn`/`rejected` no son hallazgos (se cuentan aparte).

## 3. Informe

HTML y Markdown tienen las mismas secciones. Novedades:

- **Avisos técnicos (API de seguridad):** agrupados en *dentro del rango*, *No determinado* y *fuera del rango*, con severidad y CVSS informados, explotación, identificadores (id DZH + alias), versiones corregidas candidatas, fuentes, motivos de cada decisión y enlace editorial.
- **Componentes sin datos utilizables:** ecosistema sin cobertura, ambiguos, inválidos, con error o sin consultar.
- **Consulta a DayZeroHub:** fecha del catálogo, ecosistemas cubiertos, identidades consultadas, con avisos, `no_match` (con la aclaración «no equivale a seguro»), retirados, pedidos HTTP y reintentos.
- **Feed editorial:** pasa a ser complementario (WordPress y textos). Si comparte CVE/GHSA con un hallazgo técnico del mismo componente, se muestra solo el técnico.
- **Estado:** «Consulta técnica completada/incompleta/no completada» junto al estado del feed. Si ambas fallan: «Consulta de vulnerabilidades no completada».

Códigos de salida de `audit`: `0` completo · `1` error de uso/configuración · `2` informe parcial (cualquier consulta incompleta o key rechazada) · `130` interrumpido con Ctrl+C.

## 4. Archivos nuevos o modificados

| Ruta | Contenido |
|---|---|
| `dzh/client.go` | Constantes de rutas, `call`/`once` genéricos, jitter, mensajes de error (401 «api_key inválida o ausente») |
| `dzh/security.go` | `Catalog`, `Advisories`, `Lookup` y tipos del contrato `dzh-security/1` |
| `version/version.go` | Comparadores semver y composer/WordPress |
| `correlate/technical.go` | `Evaluate`, `LookupComponents`, `Technical`, `DropCovered` |
| `auditreport/` | `SecurityInput`, vistas técnicas y secciones HTML/Markdown |
| `cmd/mateprobe/audit.go` | Orquestación: catálogo → lookup → feed → informe; corte ante 401 |
| `internal/fakedzh/` | Servidor falso de las cuatro URLs (datos inventados) |
| `testdata/security/db.json` | Fixtures `FIXTURE-*` (ramas, `last_affected`, rango `GIT`, conflicto, paginación por cursor, error con reintento, aviso retirado, lista `versions[]`) |
| `examples/audit-informe.{html,md}` | Informes de ejemplo regenerados |
| `README.md`, `docs/adr2.md` | Documentación |

## 5. Verificación

- `gofmt` sin diferencias; `go vet ./...` y `go test -race ./...` pasan en todos los paquetes.
- Pruebas nuevas: comparadores de versiones, ramas y tipos de evento, casos «No determinado», conflictos, Go declarado y `replace`, lotes de >100 componentes, cursor por componente, reintento solo de `error`, resultado parcial por fallo de transporte, 401 sin reintento ni filtrado de la key, privacidad del cuerpo del lookup y reportes HTML/Markdown.
- **Contra la API real** (con la key del servidor, sin guardarla en el repo ni en el binario):
  - Catálogo y lookup respondieron 200; sin key, 401.
  - Auditoría de `mateturnos`: 503 identidades consultadas, 1 con avisos (6 retirados, ignorados) y ningún hallazgo.
  - Proyecto temporal con `code-review-mcp-server` 0.0.1 (corregida en 1.5.3) y `codebase-utilites` 1.0.0 (paquete malicioso): ambos «dentro del rango afectado», con la versión corregida candidata.

## 6. Cómo ejecutarlo

```bash
cd /home/maxi/Escritorio/matelabs/projects/mateprobe
# .env con api_key=... (o la variable de entorno api_key)
./dist/mateprobe-0.3.0-linux-amd64 audit --path /home/maxi/Escritorio/matelabs/projects/mateturnos --open
```

Binario: `/home/maxi/Escritorio/matelabs/projects/mateprobe/dist/mateprobe-0.3.0-linux-amd64` (la 0.2.0 solo usa el feed editorial). Para recompilar: `make build-linux VERSION=0.3.0`. Para regenerar los ejemplos: `make examples`.

## 7. Pendientes y límites

- **WordPress** no tiene cobertura técnica: el catálogo no trae datos de plugins/temas/core; depende del feed editorial.
- **Ecosistemas sin comparador:** PyPI, Maven, RubyGems y NuGet quedan «No determinado». Los rangos `GIT` también.
- **Catálogo acotado:** hoy cubre 8 ecosistemas (~100 avisos npm). «Sin avisos» no equivale a «seguro».
- La fuente `osv` figura con `status: error` en el catálogo real (lado del servidor).
- `Advisories` está implementado pero el informe no lo usa; la sincronización incremental (`updated_since`, `redirects[]`) no se implementó.
- `pnpm-lock.yaml` y los imports del código fuente siguen sin soportarse.
- Nada está commiteado.
