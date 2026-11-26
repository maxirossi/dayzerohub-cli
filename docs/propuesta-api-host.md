# Propuesta de contrato: avisos del host (SO, kernel, aplicaciones)

Para el backend de DayZeroHub. Contexto: `mateprobe audit --host` ya inventaría el equipo
(distro, kernel, navegadores). Los avisos existen en el sitio (`/es/advisories?q=linux`), pero
`POST /api/v1/security/packages/lookup` hoy solo acepta ecosistemas de paquetes (npm, Packagist, Go).

## Principio: la versión no viaja
El contrato `dzh-security/1` ya devuelve por aviso `affected[].ranges` (eventos
`introduced`/`fixed`/`last_affected`) y `version_scheme`. El cliente compara la versión local contra
esos rangos. Por eso **no hace falta enviar versiones**: seguimos mandando solo `ecosystem` + `name`,
y la lista de software instalado del usuario nunca sale del equipo.

## Cambios pedidos

1. **Ecosistemas nuevos** en lookup y en `GET /security/catalog` (`coverage.ecosystems`):
   - `os`: nombre = `ID` de os-release (`ubuntu`, `debian`, `alpine`, `rhel`, ...) y `linux-kernel`.
   - `application`: `chrome`, `chromium`, `firefox` (ampliable).
   Si un ecosistema no está en el catálogo, el CLI sigue informando `ecosystem_not_covered` («sin datos»).
2. **Esquemas de versión** (`version_scheme`) para comparar en el cliente, además de los actuales:
   `dpkg` (Debian/Ubuntu), `rpm`, `apk`, `semver`/numérico para kernel y navegadores.
   Si un rango no es comparable, marcar `range_quality` ≠ `exact` para que el CLI lo muestre como
   «a verificar» y no como seguro.
3. **Mapeo de identidad** de los avisos existentes (los que hoy aparecen como `linux`, `firefox`,
   `Google`, `Red Hat Enterprise Linux 10`) a esas identidades canónicas, con `identity.status`
   que distinga match exacto de heurístico (el CLI ya lo lee).
4. **Distro y release**: el kernel y los paquetes de una distro se corrigen por release
   (`ubuntu 24.04`). Se pide que `affected[]` pueda calificar con `distro_release` (opcional);
   el CLI lo cruza con `VERSION_ID` local sin enviarlo.

## Fuera de alcance por ahora
Paquetes individuales del sistema (`dpkg -l`, `rpm -qa`): son miles de identidades por equipo. Se
decide después, con el catálogo ya cubriendo los puntos 1–3.

## Lado CLI (cuando el catálogo declare los ecosistemas)
- Habilitar el envío de componentes `os` / `application` solo si `Catalog.Covers(eco)`.
- Comparación de versión local con los esquemas nuevos.
- Sección «Entorno del equipo» en el informe, separada de las dependencias del repo.

## Fuentes para alimentar el catálogo (verificadas el 2026-11-26)
Todas son públicas y responden hoy. Se proponen para que el **backend** las ingiera y las exponga con el
contrato `dzh-security/1` (el CLI no las consulta directo, para no enviar versiones a terceros).

| Qué cubre | Fuente | Formato | Notas |
|---|---|---|---|
| Distros (Ubuntu, Debian, Alpine, RHEL...) y sus paquetes | **OSV.dev** (`api.osv.dev`, volcado en GCS) | OSV JSON, rangos por distro | Probado: `Ubuntu:24.04:LTS` y `Debian:12` devuelven avisos. Es el que mejor encaja con `ranges`/`events` y `distro_release`. Se consulta por paquete **fuente** (`linux`, `chromium`), no por el binario. |
| Kernel de Linux | **NVD** (CPE `o:linux:linux_kernel`, 19.8k CVE) + **kernel.org CNA** | NVD API 2.0 | Rangos por CPE. Para el kernel de distro (`6.8.0-45-generic`) conviene OSV/Ubuntu, que mapea a la versión del paquete. |
| Chrome / Chromium | **NVD** (CPE `a:google:chrome`, 4.2k CVE) | NVD API 2.0 | Los CVE traen «prior to X.Y.Z» → rango `fixed`. Complementar con el CNA `chrome-cve-admin@google.com`. |
| Firefox | **NVD** (CPE `a:mozilla:firefox`, 3.4k CVE) + **Mozilla MFSA** (`mozilla/foundation-security-advisories` en GitHub, YAML) | NVD / YAML | OSV no devuelve Firefox para Debian (el paquete se llama `firefox-esr`): mapear nombre. |
| Explotación activa | **CISA KEV** (`known_exploited_vulnerabilities.json`) | JSON | Alimenta `exploitation.status`. |
| Prioridad opcional | **EPSS** (FIRST.org) | CSV/API | Probabilidad de explotación; no es obligatorio. |

Mapeo de identidades sugerido: `os/ubuntu` ↔ OSV `Ubuntu:<VERSION_ID>`, `os/debian` ↔ `Debian:<VERSION_ID>`,
`os/linux-kernel` ↔ paquete fuente `linux` + NVD, `application/chrome` ↔ CPE `google:chrome` (+ `chromium` en OSV),
`application/firefox` ↔ CPE `mozilla:firefox` (+ `firefox-esr` en OSV).

Salvedades a resolver en el backend:
- El kernel que reporta `uname -r` (`6.8.0-45-generic`) no es la versión del paquete (`6.8.0-45.45`): el CLI
  debería además leer la versión del paquete (`dpkg-query -W linux-image-$(uname -r)`), pendiente de agregar.
- OSV de Ubuntu lista CVE antiguos de `linux`: hay que usar el estado por release (`fixed`/`needed`/`not-affected`) y no
  marcar como afectado lo que ya está corregido en el paquete instalado.
- NVD tiene límite de peticiones sin clave: ingerir en lote y cachear, no consultar por cada auditoría.
