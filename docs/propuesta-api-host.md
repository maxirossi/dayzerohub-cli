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
