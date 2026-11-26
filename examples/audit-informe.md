# Informe de auditoría — proyecto-mixto

- **Ruta:** /ejemplo/proyecto-mixto
- **Fecha del análisis:** 2026-11-25 12:00:00 UTC
- **Herramienta:** mateprobe ejemplo
- **Fuente:** API técnica y feed de DayZeroHub \(dayzerohub.site\), consultados el 2026-11-25 12:00:00 UTC; catálogo técnico generado el 2026-11-25T12:00:00Z
- **Estado:** Consulta técnica completada · Consulta completada dentro de la ventana que expone el proveedor
- **Cobertura:** Cobertura parcial

> Este informe cruza el inventario local con la API técnica y el feed de noticias de DayZeroHub; no es una base completa de vulnerabilidades. «Sin avisos encontrados» solo significa que la fuente consultada no devolvió avisos para esos componentes: no es una garantía de seguridad. Una versión dentro del rango afectado no implica explotabilidad confirmada.
>
> **La ausencia de hallazgos en la parte evaluada no permite concluir que el repositorio tenga riesgo bajo: revisá los módulos sin evaluar y los casos indeterminados.**

## Resumen

- **Proyectos o servicios detectados:** 6
- **Ecosistemas detectados:** composer, go, npm, wordpress
- **Componentes con versión resuelta \(únicos\):** 17 de 24
- **Ocurrencias de componentes:** 24 \(17 directas, 7 transitivas\)
- **Avisos únicos:** 9 \(5 con versión afectada, 3 indeterminados, 1 fuera de rango\)
- **Componentes afectados \(únicos\):** 6
- **Ocurrencias afectadas:** 6
- **Ocurrencias indeterminadas:** 1
- **Problemas de cobertura:** 8 en 3 causas

### Componentes únicos según el resultado de la evaluación

- **Versión afectada según la fuente:** 6
- **Evaluación indeterminada \(hay avisos, no se pudo decidir\):** 1
- **Versión fuera del rango afectado:** 0
- **Sin avisos encontrados en la fuente consultada \(no equivale a seguro\):** 14
- **Módulo o ecosistema sin evaluar / evaluación no disponible:** 0

## Qué hacer primero

| # | Aviso | Severidad | Componente | Corregida en | Acción sugerida (no se ejecuta) |
| --- | --- | --- | --- | --- | --- |
| 1 | CVE-2026-133185 | Crítica | github.com/elazarl/goproxy \(declarada: v1.7.0\) | 1.9.4 | en `api-go`: `go get github.com/elazarl/goproxy@v1.9.4` |
| 2 | CVE-2026-133212 | Crítica | @fastify/reply-from@9.8.0 | 9.9.0 | en `frontend`: `npm install @fastify/reply-from@9.9.0` |
| 3 | MAL-FIXTURE-0002 | Crítica | left-pad@1.3.0 | no informada | La fuente no informa una versión corregida: revisá el aviso. |
| 4 | CVE-0000-0007 | Alta | laravel/framework@v11.9.2 | 11.31.0 | Actualizá laravel/framework a 11.31.0 o superior con el gestor del proyecto \(comando no generado: gestor o workspace no determinados\). |
| 5 | CVE-0000-0006 | Baja | postcss@8.4.31 | 8.4.40 | Dependencia transitiva: actualizá la dependencia directa que la incluye o revisá la resolución \(por ejemplo con \`npm ls postcss\`\); no la agregues como dependencia directa. |

Criterios de prioridad:

- 1. Certeza de la evaluación: versión dentro del rango afectado, luego indeterminada, luego fuera de rango.
- 2. Explotación conocida \(CISA KEV\), cuando la fuente informa ese dato.
- 3. Severidad informada por la fuente \(crítica, alta, media, baja; ausente al final\).
- 4. EPSS, cuando esté disponible \(la API actual no lo informa: se muestra «no disponible»\).
- 5. Uso en producción \(producción o mixta antes que solo desarrollo\).
- 6. Puntaje CVSS \(mayor primero; ausente al final\) y, por último, el identificador.

## Avisos técnicos (API de seguridad de DayZeroHub)

La versión local se compara con los rangos del catálogo solo si la identidad está verificada, el rango es utilizable y la versión resuelta es exacta; ante cualquier duda el resultado es «No determinado». Una sección por aviso único.

### #1 — FIXTURE goproxy

- **Resultado:** Versión local dentro del rango afectado
- **Severidad:** Crítica (CVSS 9.1)
- **Identificadores:** `CVE-2026-133185`, `GHSA-fixt-0009-bbbb`, `vul_fixture0009`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** 1.9.4
- **Explotación:** Explotación conocida \(CISA KEV\)
- **EPSS:** no disponible
- **Uso:** desconocido
- **Fuentes:** ghsa

- **github.com/elazarl/goproxy \(declarada: v1.7.0\)** — Versión local dentro del rango afectado — corregida en 1.9.4 — 1 ocurrencia(s)
  - Motivo: versión declarada en go.mod, no resuelta con herramientas de Go \(suele ser la seleccionada si el go.mod está ordenado con \`go mod tidy\`\)
  - Motivo: \[ghsa\] la versión v1.7.0 está en la rama introduced 0 → fixed 1.9.4
  - Acción sugerida: en `api-go`: `go get github.com/elazarl/goproxy@v1.9.4`
  - `api-go` — directa, desconocido, manifest `api-go/go.mod`

### #2 — FIXTURE request smuggling en reply-from

- **Resultado:** Versión local dentro del rango afectado
- **Severidad:** Crítica (CVSS 9.0)
- **Identificadores:** `CVE-2026-133212`, `GHSA-fixt-0001-aaaa`, `vul_fixture0001`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** 9.9.0
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa
- **Aviso editorial:** [CVE-2026-133212: @fastify/reply-from](https://dayzerohub.site/es/advisories/cve-2026-133212-fastify-reply-from)

- **@fastify/reply-from@9.8.0** — Versión local dentro del rango afectado — corregida en 9.9.0 — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión 9.8.0 está en la rama introduced 9.0.0 → fixed 9.9.0
  - Acción sugerida: en `frontend`: `npm install @fastify/reply-from@9.9.0`
  - `frontend` — directa, producción, lockfile `frontend/package-lock.json`

### #3 — FIXTURE paquete malicioso

- **Resultado:** Versión local dentro del rango afectado
- **Severidad:** Crítica (CVSS no disponible)
- **Identificadores:** `MAL-FIXTURE-0002`, `vul_fixture0002`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** no informada por la fuente
- **Explotación:** sin información \(no equivale a «no explotado»\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** osv

- **left-pad@1.3.0** — Versión local dentro del rango afectado — corregida en no informada — 1 ocurrencia(s)
  - Motivo: \[osv\] la versión 1.3.0 figura en la lista explícita de versiones afectadas
  - Acción sugerida (`frontend`): La fuente no informa una versión corregida: revisá el aviso.
  - `frontend` — directa, producción, lockfile `frontend/package-lock.json`

### #4 — FIXTURE laravel rama

- **Resultado:** Versión local dentro del rango afectado
- **Severidad:** Alta (CVSS 8.1)
- **Identificadores:** `CVE-0000-0007`, `vul_fixture0007`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** 11.31.0
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa

- **laravel/framework@v11.9.2** — Versión local dentro del rango afectado — corregida en 11.31.0 — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión v11.9.2 está en la rama introduced 11.0.0 → fixed 11.31.0
  - Acción sugerida (`backend`): Actualizá laravel/framework a 11.31.0 o superior con el gestor del proyecto \(comando no generado: gestor o workspace no determinados\).
  - `backend` — directa, producción, lockfile `backend/composer.lock`

### #5 — FIXTURE segunda página del componente

- **Resultado:** Versión local dentro del rango afectado
- **Severidad:** Baja (CVSS 3.1)
- **Identificadores:** `CVE-0000-0006`, `vul_fixture0006`
- **Alcance:** 2 componentes · 2 ocurrencias
- **Corregida en:** 8.4.40
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa

- **postcss@8.4.31** — Versión local dentro del rango afectado — corregida en 8.4.40 — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión 8.4.31 está en la rama introduced 8.4.0 → fixed 8.4.40
  - Acción sugerida (`frontend`): Dependencia transitiva: actualizá la dependencia directa que la incluye o revisá la resolución \(por ejemplo con \`npm ls postcss\`\); no la agregues como dependencia directa.
  - `frontend` — transitiva, producción, lockfile `frontend/package-lock.json`
- **postcss@8.4.38** — Versión local dentro del rango afectado — corregida en 8.4.40 — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión 8.4.38 está en la rama introduced 8.4.0 → fixed 8.4.40
  - Acción sugerida (`frontend`): Dependencia transitiva: actualizá la dependencia directa que la incluye o revisá la resolución \(por ejemplo con \`npm ls postcss\`\); no la agregues como dependencia directa.
  - `frontend` — transitiva, desarrollo, lockfile `frontend/package-lock.json`

### #6 — FIXTURE rango GIT

- **Resultado:** No determinado
- **Severidad:** Alta (CVSS 7.5)
- **Identificadores:** `CVE-0000-0004`, `vul_fixture0004`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** no informada por la fuente
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa

- **next@14.2.3** — No determinado — 1 ocurrencia(s)
  - Motivo: \[ghsa\] rango de tipo GIT: no se compara sin commits del repositorio
  - `frontend` — directa, producción, lockfile `frontend/package-lock.json`

### #7 — FIXTURE conflicto entre fuentes

- **Resultado:** No determinado
- **Severidad:** Media (CVSS 5.3)
- **Identificadores:** `CVE-0000-0005`, `vul_fixture0005`
- **Alcance:** 2 componentes · 2 ocurrencias
- **Corregida en:** no informada por la fuente
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa, osv
- **Conflictos entre fuentes:** 1 (se aplicó el resultado más conservador)

- **postcss@8.4.31** — No determinado — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión 8.4.31 queda fuera de todas las ramas informadas
  - Motivo: \[osv\] la versión 8.4.31 queda fuera de todas las ramas informadas
  - Motivo: las fuentes discrepan \(quality.conflicts\): no se elige una en silencio
  - `frontend` — transitiva, producción, lockfile `frontend/package-lock.json`
- **postcss@8.4.38** — No determinado — 1 ocurrencia(s)
  - Motivo: \[ghsa\] la versión 8.4.38 queda fuera de todas las ramas informadas
  - Motivo: \[osv\] la versión 8.4.38 queda fuera de todas las ramas informadas
  - Motivo: las fuentes discrepan \(quality.conflicts\): no se elige una en silencio
  - `frontend` — transitiva, desarrollo, lockfile `frontend/package-lock.json`

### #8 — FIXTURE laravel rango insuficiente

- **Resultado:** No determinado
- **Severidad:** Media (CVSS 5.0)
- **Identificadores:** `CVE-0000-0008`, `vul_fixture0008`
- **Alcance:** 1 componentes · 1 ocurrencias
- **Corregida en:** no informada por la fuente
- **Explotación:** No figura en CISA KEV \(no descarta explotación no catalogada\)
- **EPSS:** no disponible
- **Uso:** producción
- **Fuentes:** ghsa

- **laravel/framework@v11.9.2** — No determinado — 1 ocurrencia(s)
  - Motivo: \[ghsa\] sin rangos ni versiones; límite inferior exclusivo no representable; restricción original: «&gt; 11.0, &lt; 11.5»
  - `backend` — directa, producción, lockfile `backend/composer.lock`

### Avisos asociados con versión fuera del rango informado (1)

| Aviso | Resumen | Componentes |
| --- | --- | --- |
| CVE-0000-0010, vul\_fixture0010 | FIXTURE goproxy otra rama | github.com/elazarl/goproxy \(declarada: v1.7.0\) |

## Cobertura: qué quedó sin evaluar

### Componentes con versión no resuelta \(rango declarado o desconocida\) — 6

Un rango no es la versión instalada: los avisos asociados quedan «No determinado».

- `api-go — github.com/gin-gonic/gin (declarada: v1.9.1)`
- `api-go — github.com/elazarl/goproxy (declarada: v1.7.0)`
- `api-go — github.com/fork/errors (declarada: v0.9.2)`
- `api-go — github.com/pkg/errors (declarada: v0.9.1)`
- `api-go — golang.org/x/text (declarada: v0.14.0)`
- … y 1 más (ver coverage.json con --export-dir)

### Formato de lockfile no soportado — 1

Solo se usaron las restricciones del manifest; no hay versiones resueltas para evaluar rangos.

- `legacy/pnpm-lock.yaml — pnpm-lock.yaml no está soportado todavía; no se analizaron las versiones resueltas (solo las restricciones de package.json)`

### Ecosistemas sin soporte \(no analizados\) — 1

El archivo se detectó pero su ecosistema aún no se analiza: sus dependencias no fueron evaluadas.

- `legacy/requirements.txt — ecosistema no soportado todavía: Python (pip)`

## Ecosistemas y proyectos

| Ecosistema | Proyectos | Inventario | Evaluación de avisos |
| --- | --- | --- | --- |
| composer | 1 | soportado | cubierto por la fuente |
| go | 1 | soportado | cubierto por la fuente |
| npm | 3 | soportado | cubierto por la fuente |
| wordpress | 1 | soportado | sin cobertura técnica \(solo feed editorial\) |
| Python \(pip\) | — | no soportado | módulo sin evaluar |

### Proyectos o servicios detectados (6)

| Ruta | Nombre | Ecosistemas | Lockfile | Workspace |
| --- | --- | --- | --- | --- |
| api-go | github.com/acme/api | go | — | — |
| backend | acme/backend | composer | — | — |
| frontend | mi-frontend | npm | frontend/package-lock.json | — |
| legacy | legacy | npm | — | — |
| site | WordPress | wordpress | — | — |
| yarnapp | yarnapp | npm | yarnapp/yarn.lock | — |

### Tecnologías detectadas

| Nombre | Tipo | Versiones | Proyectos |
| --- | --- | --- | --- |
| WordPress | CMS | 6.5.3 | 1 |
| express | framework | declarada: ^4.19.0 | 1 |
| github.com/gin-gonic/gin | framework | declarada: v1.9.1 | 1 |
| laravel/framework | framework | v11.9.2 | 1 |
| next | framework | 14.2.3 | 1 |
| react | framework | 18.2.0 | 1 |
| vue | framework | 3.4.21 | 1 |
| Go | lenguaje | declarada: 1.22 | 1 |
| Node.js | lenguaje | declarada: &gt;=20, desconocida | 3 |
| PHP | lenguaje | declarada: ^8.2 | 1 |
| TypeScript | lenguaje | desconocida | 1 |
| Plugin Sin Version | plugin | desconocida | 1 |
| WP Rocket | plugin | 3.15.4 | 1 |

## Exclusiones aplicadas

- por defecto \(directorios\): .git, node\_modules, target, dist, build, .next, .nuxt, .output, vendor, .hg, .svn, \_\_pycache\_\_, .cache, .venv, venv, coverage, .turbo, .idea, .vscode, .gradle, .terraform, bower\_components, .parcel-cache, .svelte-kit, .claude/worktrees
- índice de Git: 0 archivos tracked nunca se ignoran por .gitignore \(--ignore-git-index lo desactiva\)
- .gitignore: \(ancestro\) .gitignore \(5 reglas\)
- symlinks: no se siguen

Directorios omitidos sin recorrer (1):

- `frontend/node_modules` — regla por defecto: node\_modules

## Avisos editoriales relacionados (feed de noticias)

### Coincidencias de componente; afectación por versión sin verificar (3)

#### [CVE-2026-125812: WordPress WP Rocket plugin &lt; 3.24.2 - Remote Code Execution \(RCE\) vulnerability](https://dayzerohub.site/es/advisories/cve-2026-125812-wp-rocket)

- **Severidad informada:** Crítica \(CVSS 9.8\)
- **Identificadores:** CVE: CVE-2026-125812
- **Clasificación:** Coincidencia de componente; afectación por versión sin verificar
- **Publicado:** 2026-11-25T13:06:51+00:00
- **Aviso:** [https://dayzerohub.site/es/advisories/cve-2026-125812-wp-rocket](https://dayzerohub.site/es/advisories/cve-2026-125812-wp-rocket)
- **Resumen del aviso:** vulnerabilidad crítica \(CVSS 9.8\) en WP Media WP Rocket.
- **Componente local:** WP Rocket \(plugin, wordpress\) — versión 3.15.4 — subproyecto `site` — evidencia `site/wp-content/plugins/wp-rocket/wp-rocket.php`
  - Campos del aviso: product · regla: nombre o slug del plugin coinciden con el producto
  - Limitación: la versión local no se comparó con las versiones afectadas: el feed no incluye rangos estructurados
  - Limitación: el texto del aviso menciona «&lt; 3.24.2»; no se interpretó como rango afectado
  - Limitación: el plugin está presente en disco; no se verificó que esté activo

#### [CVE-2026-000006: Next.js middleware bypass](https://dayzerohub.site/es/advisories/cve-2026-000006-next)

- **Severidad informada:** Alta \(CVSS 8.2\)
- **Identificadores:** CVE: CVE-2026-000006
- **Clasificación:** Coincidencia de componente; afectación por versión sin verificar
- **Publicado:** 2026-11-20T11:00:00+00:00
- **Aviso:** [https://dayzerohub.site/es/advisories/cve-2026-000006-next](https://dayzerohub.site/es/advisories/cve-2026-000006-next)
- **Resumen del aviso:** Next.js permite evadir middleware.
- **Componente local:** next \(framework, npm\) — versión 14.2.3 — subproyecto `frontend` — evidencia `frontend/package-lock.json`
  - Campos del aviso: product, technology · regla: alias explícito
  - Limitación: la versión local no se comparó con las versiones afectadas: el feed no incluye rangos estructurados

#### [CVE-2026-000004: Laravel Framework before 11.31.0 allows something](https://dayzerohub.site/es/advisories/cve-2026-000004-laravel)

- **Severidad informada:** Alta \(CVSS 7.5\)
- **Identificadores:** CVE: CVE-2026-000004
- **Clasificación:** Coincidencia de componente; afectación por versión sin verificar
- **Publicado:** 2026-11-22T11:00:00+00:00
- **Aviso:** [https://dayzerohub.site/es/advisories/cve-2026-000004-laravel](https://dayzerohub.site/es/advisories/cve-2026-000004-laravel)
- **Resumen del aviso:** Aviso sobre Laravel.
- **Componente local:** laravel/framework \(framework, composer\) — versión v11.9.2 — subproyecto `backend` — evidencia `backend/composer.lock`
  - Campos del aviso: product, technology · regla: alias explícito
  - Limitación: la versión local no se comparó con las versiones afectadas: el feed no incluye rangos estructurados
  - Limitación: el texto del aviso menciona «before 11.31.0»; no se interpretó como rango afectado

## Consulta a DayZeroHub

- **Catálogo técnico — generado:** 2026-11-25T12:00:00Z
- **Catálogo técnico — última actualización:** 2026-11-25T11:50:00Z
- **Catálogo técnico — ecosistemas cubiertos:** Go \(10 avisos\), Packagist \(10 avisos\), npm \(10 avisos\)
- **Catálogo técnico — fuentes con problemas:** osv: error
- **Consulta técnica — identidades consultadas \(una vez por ecosistema y nombre\):** 20
- **Consulta técnica — con avisos asociados:** 7
- **Consulta técnica — sin avisos en el catálogo \(no equivale a seguro\):** 13
- **Consulta técnica — ecosistema sin cobertura:** 0
- **Consulta técnica — ambiguas/inválidas/con error:** 0
- **Consulta técnica — avisos retirados o rechazados \(ignorados\):** 1
- **Consulta técnica — ocurrencias sin consulta técnica \(runtimes, WordPress, etc.\):** 9
- **Consulta técnica — pedidos HTTP / reintentos:** 3 / 0

- **Feed editorial — estado:** completa
- **Feed editorial — páginas consultadas:** 2 de 2 permitidas
- **Feed editorial — avisos consultados:** 10
- **Reintentos del feed:** 0
- **Cobertura limitada por el proveedor:** sí \(el feed expone una ventana acotada de avisos recientes\)
- **Lockfiles — parseados / reutilizados por contenido idéntico:** 2 / 0

## Errores y limitaciones

- el proveedor expone como máximo 2 páginas de 20 avisos; los avisos más antiguos no están disponibles en esta consulta
- Go: go.sum no se usa como lista de dependencias y el grafo resuelto no puede determinarse sin ejecutar herramientas de Go
- A la API técnica solo se envían identidades de paquetes \(ecosistema y nombre\): nunca versiones, rutas ni contenido de archivos.
- Los imports del código fuente no se analizaron; el inventario proviene solo de manifiestos, lockfiles y metadatos.
- No se ejecutó ningún comando del proyecto ni se instalaron dependencias \(salvo que se haya pedido --maven-resolve\).

Para obtener el inventario completo y todas las ocurrencias usá --export-dir DIRECTORIO \(inventory.json, inventory.csv, findings.json, coverage.json\).
