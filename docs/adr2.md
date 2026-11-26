# ADR 2 — Consumir la API técnica de DayZeroHub (`dzh-security/1`) y decidir rangos localmente

- **Fecha:** 2026-11-25
- **Estado:** Aceptada (implementada, sin commitear)
- **Reemplaza parcialmente:** ADR 1, puntos 4 y 7 (el feed editorial pasa a ser complementario)

## Contexto

Cambiaron las URLs del proyecto y la autenticación: hay cuatro rutas bajo `https://dayzerohub.site/api/v1` (`news`, `security/catalog`, `security/advisories`, `security/packages/lookup`) con **una sola `api_key`** en `X-API-Key`. La API técnica trae identidades verificadas, rangos de versiones, procedencia y calidad, pero **no evalúa versiones**. Fuente: `/home/maxi/Escritorio/instrucciones-cliente-go-dayzerohub.md` y `zerodaynotices/docs/mateprobe-api-integration.md`.

## Decisiones

1. **Configuración:** la key sigue siendo `api_key` en `.env`/entorno (sin cambios en `config`). Las URLs son constantes en `dzh/client.go`, no variables de entorno.
2. **Un solo camino HTTP:** `Client.call/once` sirve a las cuatro rutas (reintentos 429/5xx/red con backoff y jitter, `Retry-After`, límite de cuerpo, key quitada en redirecciones a otro origen). **401 no se reintenta** y corta las consultas siguientes.
3. **Nuevos métodos:** `Catalog`, `Advisories` (una página por llamada, cursor opaco) y `Lookup` (lotes de 100, sigue `next_cursor` por componente con tope, reintenta solo `status=error`). Ignora campos desconocidos.
4. **Privacidad:** solo `{ecosystem, name}` viaja al lookup (npm, Packagist, Go). Nunca versiones, paths ni contenido. Runtimes y WordPress no se consultan.
5. **Decisión de rango local (`correlate/technical.go`, `version/`):** comparador semver y composer/WordPress; los demás esquemas → «No determinado». Se exige identidad `verified` y `range_quality=usable`; OSV: `introduced` inclusivo, `fixed` exclusivo, `last_affected` inclusivo, `limit` exclusivo; ramas independientes; rango sin cierre = abierto; `versions[]` explícita cuando no hay rangos. Si hay filas de varias fuentes: afectado si alguna lo indica; «fuera de rango» solo si todas son evaluables y no hay conflictos.
6. **Go:** la versión de `go.mod` es «declarada»; se evalúa con salvedad explícita, salvo módulos con `replace` (→ no determinado).
7. **Estados sin dato ≠ seguro:** `no_match`, `ecosystem_not_covered` y `error` se informan como «sin datos». `exploitation.unknown` nunca se muestra como «no explotado». Avisos `withdrawn/rejected` no son hallazgos.
8. **Feed editorial:** se mantiene como complemento (WordPress y textos); si comparte CVE/GHSA con un hallazgo técnico del mismo componente, se muestra solo el técnico.
9. **Pruebas:** servidor falso `internal/fakedzh` con datos inventados (`FIXTURE-*`) en `testdata/security/db.json`; sin red ni key real.

## Consecuencias

- Los informes ahora distinguen «dentro del rango», «fuera del rango» y «No determinado» para npm, Packagist y Go.
- WordPress no tiene cobertura técnica: sigue dependiendo del feed editorial.
- Cobertura del catálogo acotada a lo que declara `catalog` (hoy 8 ecosistemas, ~100 avisos npm).
- Verificado contra la API real con la key del servidor: catálogo, lookup y un proyecto de prueba con un paquete afectado.
