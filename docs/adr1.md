# ADR 1 — Subcomando `audit`: inventario local cruzado con DayZeroHub

- **Fecha:** 2026-11-25
- **Estado:** Aceptada (MVP implementado, sin commitear)
- **Proyecto:** `/home/maxi/Escritorio/matelabs/projects/mateprobe`

## Contexto

`mateprobe` solo escaneaba sitios web (`scan`). Se necesita analizar un proyecto local, identificar sus tecnologías y dependencias, consultar el feed de DayZeroHub y generar un informe, sin ejecutar ni instalar nada del proyecto analizado.

## Decisiones

1. **Subcomando `audit`** junto a `scan`, con la librería `flag` de la biblioteca estándar (la que ya usa el repo). Opciones: `--path`, `--env-file`, `--format`, `--output`, `--open`.
2. **Paquetes separados:** `config`, `inventory`, `dzh` (cliente HTTP), `correlate`, `auditreport`, más `cmd/mateprobe/audit.go`. La correlación no depende del cliente HTTP, para poder incorporar después una API técnica con rangos estructurados.
3. **Configuración:** nombres en minúsculas (`api_key`, `report_format`). `api_key`: entorno → `.env` → pregunta sin eco (`golang.org/x/term`). Formato: `--format` > entorno > `.env` > pregunta. El `.env` se parsea como texto, sin expansión ni shell. Nunca se carga el `.env` del proyecto analizado. Sin terminal interactiva y con datos faltantes, el comando falla con un mensaje claro.
4. **API (contrato verificado):** `GET https://dayzerohub.site/api/v1/news?lang=es&page=N`, cabecera `X-API-Key`. Respuesta `{items, page, page_size, max_pages}`; `page ≤ 5`, `page_size ≤ 20` (422 si se excede) → ventana de 100 avisos. Hoy responde 200 incluso con clave inválida. Es un feed de noticias, no una base completa de vulnerabilidades.
5. **Cliente:** `net/http` con timeout, cancelación con Ctrl+C, límite de respuesta, reintentos acotados en 429/5xx/red respetando `Retry-After` (máx. 30 s), y sin reenviar `X-API-Key` a otro origen en redirecciones. Un fallo a mitad produce resultado parcial.
6. **Detección (solo lectura de manifiestos y lockfiles):** npm (`package.json`, `package-lock.json` v1/v2/v3, `yarn.lock`), Composer, Go (`go.mod`/`go.work`, versiones declaradas, `replace`; `go.sum` no se usa), WordPress (`version.php` y encabezados de plugins, sin ejecutar PHP). Se omiten `node_modules`, `vendor`, builds y caches; no se siguen symlinks. Se distingue versión resuelta, restricción y desconocida.
7. **Correlación sin confirmar vulnerabilidades:** dos niveles — «Coincidencia de componente; afectación por versión sin verificar» y «Posible coincidencia textual; requiere revisión». Identificador exacto o alias acotado primero; texto libre solo como evidencia secundaria y solo si el aviso no atribuye el problema a otro producto. No se interpretan rangos del título (`< 3.24.2`). Deduplicación solo por identificadores explícitos.
8. **Informe:** un único modelo de vista para HTML (autocontenido, sin recursos remotos, CSP, `html/template`) y Markdown (con escapado). Solo se activan enlaces http(s). Sin `--output`: `./reports/<proyecto>-<AAAAMMDD-HHMMSS>.<ext>` sin sobrescribir, permisos `0600`. Nunca afirma que un proyecto sea seguro.
9. **Salida en terminal:** ruta absoluta y enlace `file://` correctamente codificado; hipervínculo OSC 8 solo si stdout es una terminal, siempre con la URL en texto plano. `--open` usa `xdg-open`/`open`/`rundll32` sin shell; si falla, el informe se conserva.
10. **Códigos de salida:** 0 completo · 1 error de uso/configuración · 2 informe parcial · 130 interrumpido.

## Consecuencias

- Sin rangos estructurados en el feed, el informe no puede decir que algo esté afectado; solo señala componentes mencionados por avisos.
- Cobertura limitada a 100 avisos por consulta.
- Salidas esperables como falsos positivos: avisos sobre el lenguaje (p. ej. PHP) se relacionan con cualquier proyecto que lo use, con versión sin verificar.

## No soportado todavía

`pnpm-lock.yaml`, `npm-shrinkwrap.json`, Python/Java/Ruby/Rust/.NET (se listan como no analizados), temas y `mu-plugins` de WordPress, imports del código fuente como evidencia, comparación de versiones contra rangos afectados y análisis de explotabilidad.

## Entregables

- Binario: `dist/mateprobe-0.2.0-linux-amd64`
- Ejemplos: `examples/audit-informe.html`, `examples/audit-informe.md`
- Configuración de ejemplo: `.env.example`; documentación: `README.md`
