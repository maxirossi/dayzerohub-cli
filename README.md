# mateprobe

Detecta las tecnologías de sitios web (servidor, lenguaje, CMS, frameworks, CDN, analytics…) **desde tu máquina**, a partir de dominios, URLs, IPs, CIDR o rangos de IPs. Un único ejecutable: no requiere Go, Docker, Node ni base de datos, y `scan` no envía nada a terceros (el subcomando `audit` solo consulta la API de DayZeroHub; ver [Auditoría de proyectos](#auditoría-de-proyectos-audit)).

Cada hallazgo indica **qué evidencia lo respalda y cuánto se puede confiar en él**; no solo un nombre. Pensado como insumo para MateAudit (ver [Integración](#integración-con-mateaudit)).

> mateprobe es **pasivo**: hace `GET` normales y analiza lo que el sitio responde. No enumera directorios, no hace fuerza bruta ni prueba vulnerabilidades. Usalo solo sobre sistemas propios o con autorización.

## Instalación

Descargá el binario de tu plataforma (carpeta `dist/`, ver `make dist`) y ejecutalo:

| Sistema | Archivo |
|---|---|
| Linux x86-64 / ARM64 | `mateprobe-<versión>-linux-amd64` / `-linux-arm64` |
| Windows x86-64 / ARM64 | `mateprobe-<versión>-windows-amd64.exe` / `-windows-arm64.exe` |
| macOS Intel / Apple Silicon | `mateprobe-<versión>-darwin-amd64` / `-darwin-arm64` |

```bash
chmod +x mateprobe-0.1.0-linux-amd64     # Linux/macOS
sha256sum -c SHA256SUMS --ignore-missing # opcional: verificar integridad
./mateprobe-0.1.0-linux-amd64 --version
```

En macOS los binarios no están firmados: Gatekeeper puede pedir aprobación manual (`xattr -d com.apple.quarantine <archivo>`).

### Iniciar sesión (`login`)

```bash
mateprobe login    # muestra un link y un código; lo aprobás en tu cuenta de DayZeroHub y la key queda guardada
mateprobe logout   # borra la key local (revocala también en el panel: "API técnica")
```

La key personal (`dzh_…`) se guarda en el directorio de configuración del usuario con permisos 0600 y `audit` la usa si no hay `api_key` en el entorno o el `.env`. Solo vale para la API técnica; el feed editorial usa otra clave opcional (`news_api_key`).

### Compilar desde el código

Requiere Go ≥ 1.27 (solo para compilar).

```bash
make check     # gofmt + go vet + go test -race
make build     # dist/mateprobe para tu plataforma
make dist      # 6 binarios + SHA256SUMS en dist/
make examples  # regenera examples/ desde servidores locales y fixtures
make build-linux # dist/mateprobe-<versión>-linux-amd64
```

## Uso

```bash
mateprobe scan --target ejemplo.com
mateprobe scan --target https://ejemplo.com/blog
mateprobe scan --target 192.168.1.20
mateprobe scan --target 192.168.1.0/24 --exclude 192.168.1.1
mateprobe scan --target 192.168.1.10-192.168.1.30
mateprobe scan --input objetivos.txt --concurrency 5 --rate 5
mateprobe scan --target https://ejemplo.com --resolve ejemplo.com:443:192.168.1.20
mateprobe scan --target ejemplo.com --format json --output resultado.json
mateprobe scan --input objetivos.txt --format html --output reporte.html
```

Los resultados van a **stdout** (o a `--output`); el progreso y los avisos, a **stderr** (`--quiet` los oculta).

### Objetivos

| Entrada | Qué hace |
|---|---|
| `ejemplo.com`, `1.2.3.4`, `2001:db8::1` | Prueba `http://…:80` y `https://…:443` (más los `--port`) |
| `ejemplo.com:8080` | Prueba `http` y `https` en ese puerto |
| `https://ejemplo.com:8443/ruta?q=1` | Respeta esquema, puerto, ruta y query tal cual |
| `192.168.1.0/24`, `2001:db8::/120` | CIDR (IPv4/IPv6) |
| `192.168.1.10-192.168.1.30` | Rango inclusivo (IPv4 o IPv6) |
| `--input archivo.txt` | Un objetivo por línea; se ignoran vacías y `# comentarios` |

- **Límite de tamaño:** 256 direcciones por ejecución (también IPv6). El tamaño se valida *antes* de expandir (un `/8` o `::/0` se rechaza al instante, sin consumir memoria). Para ampliarlo hay que pedirlo: `--max-addresses 1024`. Se cuentan todas las direcciones del rango, incluidas red y broadcast.
- **Exclusiones** (`--exclude`, repetible): IP, CIDR o dominio. Un dominio excluye también sus subdominios. Se reaplican en cada redirección.
- **Dedupe:** `Ejemplo.COM`, `ejemplo.com.` y `ejemplo.com` son el mismo objetivo; en cambio `http://` vs `https://`, otro puerto, otra ruta u otro hostname se conservan por separado.
- **Puertos adicionales** para objetivos sin esquema, indicando el protocolo: `--port http:8080 --port https:8443`.

### Dominio, IP, Host y SNI

`--resolve host:puerto:ip` (repetible, como `curl --resolve`) conecta a la IP indicada **manteniendo** el `Host` HTTP, el SNI TLS y la validación del certificado contra el dominio:

```bash
mateprobe scan --target https://ejemplo.com --resolve ejemplo.com:443:192.168.1.20
```

Las redirecciones a otro puerto necesitan su propia regla (p. ej. `ejemplo.com:80:IP` además de `:443:`).

Una consulta por IP describe **solo el servicio o virtual host que respondió**; no implica haber descubierto todos los sitios alojados en esa IP.

### TLS

Se valida el certificado por defecto. `--insecure` lo desactiva de forma explícita y queda marcado en el reporte (`tls_validation_disabled`, banner en el HTML, aviso en stderr). **Nunca** hay reintento silencioso sin validar.

### Redirecciones

- Se siguen las del **mismo hostname** (incluido HTTP → HTTPS), hasta `--max-redirects` (5).
- Las que van a **otro hostname** se registran pero no se siguen, salvo `--follow-external-redirects` o `--allow-host dominio` (incluye subdominios).
- Cada salto cuenta para el rate limit y reaplica exclusiones.
- Cada respuesta de la cadena se analiza por separado y las tecnologías llevan la URL y el hostname donde se observaron. Lo hallado en **otro hostname** se marca `external: true` y **no** cuenta para el estado del objetivo.

### Opciones

| Opción | Defecto | |
|---|---|---|
| `--concurrency N` | 5 | objetivos en paralelo |
| `--rate R` | 5 | solicitudes/seg **globales** (incluye redirecciones); `0` = sin límite |
| `--timeout D` | 10s | por solicitud |
| `--max-redirects N` | 5 | |
| `--max-body BYTES` | 2097152 | cuerpo **descomprimido** leído por respuesta (2 MiB) |
| `--max-addresses N` | 256 | |
| `--format F` | `table` | `table`, `json`, `csv`, `html` |
| `--output ARCHIVO` | stdout | |
| `--quiet` | | sin progreso en stderr |

User-Agent: `mateprobe/<versión> (+https://github.com/maxirossi/mateprobe)`. Ctrl+C cancela con elegancia: se emiten los resultados ya completados.

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Todos los objetivos respondieron |
| `1` | Error de uso, configuración, entrada o salida |
| `2` | Resultado **parcial**: algún objetivo sin respuesta o incompleto, pero otros sí respondieron |
| `3` | Ningún objetivo respondió |
| `130` | Interrumpido con Ctrl+C (se emiten los resultados completados) |

Un objetivo "responde" si al menos una de sus sondas obtuvo respuesta HTTP (aunque sea 404/500). Un fallo en `:80` o `:443` por separado no cuenta como objetivo caído; queda en `errors`.

## Qué significa cada resultado

Estados de un objetivo (`status`):

- `detected`: se detectaron tecnologías.
- `no_technologies`: **se obtuvo respuesta**, pero no se detectó nada.
- `unreachable`: **no se pudo consultar** (ninguna respuesta; ver `errors`: `dns`, `connection`, `timeout`, `tls`, `http`, `other`).
- `incomplete`: la ejecución se interrumpió antes de terminar el objetivo.

Cada tecnología trae:

| Campo | Valores |
|---|---|
| `detection` | `declared` (la respuesta lo afirma, p. ej. `Server: nginx/1.24.0`), `signature` (una firma coincidió), `inferred` (deducida de otra; **nunca observada directamente**) |
| `confidence` | `high`, `medium`, `low` o `unknown` (cuando no hay regla que lo justifique) |
| `version` | solo si hay evidencia; vacío si no se conoce |
| `engine` | motor/regla responsable (`wappalyzergo v0.3.11`, `mateprobe:server-header`…) |
| `evidence` | fragmento sanitizado y acotado (cabecera, nombre de cookie, `<meta>`, recurso) |
| `url`, `host`, `external` | respuesta concreta donde se observó |

Criterios de confianza de las reglas propias: **declarada** → `medium` (el servidor lo afirma pero no se verifica de forma independiente y puede estar ocultado o falseado); **firma de una sola señal** → `low`/`medium` según su especificidad; **dos o más fuentes distintas y compatibles** (p. ej. `<meta generator>` + `/wp-includes/` + cookie) suben un nivel; **inferencias** nunca suben.

Qué **no** se concluye: React no implica Node.js · WordPress no confirma MySQL (las bases de datos y SO que deduce la base de firmas se descartan) · Cloudflare no identifica el servidor de origen · una versión declarada no está verificada.

> **Evidencia de wappalyzergo:** el motor solo devuelve `nombre[:versión]` y categorías; **no expone qué patrón coincidió ni una confianza**. Esas detecciones salen con `confidence: unknown`, sin evidencia y con una nota explícita (`evidence_note`). Las reglas propias (cabeceras, cookies, meta generator, recursos HTML) sí devuelven su evidencia. Las tecnologías que el motor marca como *implicadas* por otra (WordPress ⇒ PHP) se registran como `inferred`; si una técnica propia la observó directamente, gana la observación.

### Privacidad de los reportes

No se guardan valores de cookies (solo nombres; `Set-Cookie` aparece como `nombre=[redactado]`), ni `Authorization`/tokens. Las URLs ocultan credenciales embebidas y valores de parámetros con aspecto sensible (`token`, `key`, `password`, `session`…). El texto remoto se limpia de caracteres de control y se acota.

## Formatos de salida

- **table**: legible en terminal.
- **json**: `schema_version: "1.0"`. Separa `targets[].responses` (respuestas HTTP observadas), `targets[].technologies` (hallazgos) y `targets[].errors`. Ver `examples/resultado.json`.
- **csv**: una fila por tecnología con referencia al objetivo (`target_input`, `target`, `status`, `url`…). Los objetivos sin tecnologías o sin respuesta aparecen con las columnas de tecnología vacías, y `status` las distingue. Las celdas que empiezan con `= + - @` se neutralizan contra inyección de fórmulas.
- **html**: reporte estático, autocontenido, **sin JavaScript ni recursos externos** (con CSP restrictivo). Todo dato remoto se escapa; nunca se renderiza HTML remoto.

Ejemplos generados desde fixtures locales (`make examples`): [`examples/resultado.json`](examples/resultado.json), [`examples/resultado.csv`](examples/resultado.csv), [`examples/reporte.html`](examples/reporte.html), [`examples/resultado.txt`](examples/resultado.txt).

## Auditoría de proyectos (`audit`)

`mateprobe audit` analiza un **proyecto local**, identifica sus tecnologías y dependencias, consulta la API técnica y el feed de noticias de [DayZeroHub](https://dayzerohub.site) y genera un informe HTML o Markdown. El escaneo web (`scan`) sigue funcionando igual.

```bash
mateprobe audit --path /home/maxi/Escritorio/matelabs/projects/mateturnos
mateprobe audit --path ./proyecto --format html --output ./informe.html
mateprobe audit --path ./proyecto --format md   --output ./informe.md
mateprobe audit --path ./proyecto --env-file ~/.config/mateprobe/.env --open
```

| Opción | Descripción |
|---|---|
| `--path` | Directorio a analizar. **Obligatorio.** |
| `--env-file` | Archivo de configuración. Por defecto, `.env` del directorio desde el que ejecutás. |
| `--format` | `html` o `md`. |
| `--output` | Ruta del informe. Si es un directorio (o termina en `/`) se usa allí el nombre por defecto. |
| `--open` | Abre el informe con la aplicación predeterminada (`xdg-open`, `open`, `rundll32`; sin shell). |
| `--exclude PATRÓN` | Excluye rutas (sintaxis `.gitignore`, relativas a `--path`). Repetible. |
| `--include PATRÓN` | Re-incluye rutas excluidas o ignoradas (p. ej. `.claude/worktrees/agent-x/`). Repetible. |
| `--no-gitignore` | No respeta los `.gitignore`. |
| `--no-default-excludes` | No aplica las exclusiones por defecto (`.git` nunca se recorre). |
| `--ignore-git-index` | No usa el índice de Git (ver «Descubrimiento»). |
| `--follow-symlinks` | Sigue enlaces simbólicos solo si apuntan dentro de `--path` y sin ciclos. |
| `--export-dir DIR` | Escribe `inventory.json`, `inventory.csv`, `findings.json` y `coverage.json` (0600) con el detalle completo. |
| `--maven-resolve` | **Modo Maven efectivo, explícito** (ver «Maven»). |
| `--maven-bin`, `--maven-timeout`, `--maven-profile` | Ejecutable de Maven, tiempo máximo (10 min por defecto) y perfiles `-P` (repetible). |

### Descubrimiento y exclusiones

El recorrido **poda** los directorios excluidos antes de leer su contenido (no se recorren para contarlos). Se respeta `.gitignore` con la semántica de Git: archivos anidados, patrones anclados/relativos, `**`, negaciones (`!`) y la regla de que no se puede re-incluir un archivo bajo un directorio excluido. También `.git/info/exclude`. Funciona igual sin Git y cuando `--path` es un subdirectorio de un repositorio (se aplican los `.gitignore` ancestros a los descendientes, nunca a la propia raíz). Un worktree (`.git` como *archivo*) en la raíz es un proyecto válido.

**Precedencia** (el último que coincide gana): exclusiones por defecto → `.gitignore` → `--exclude` → `--include`. Por defecto se excluyen (solo directorios, en cualquier nivel): `.git`, `.claude/worktrees`, `node_modules`, `target`, `dist`, `build`, `.next`, `.nuxt`, `.output`, `vendor`, cachés (`.cache`, `__pycache__`, `.venv`, `.gradle`, …). `--include` re-incluye aunque la exclusión venga de los defectos o de `.gitignore`; un patrón sin `/` inicial obliga a leer todos los directorios excluidos (usá rutas ancladas).

**Archivos trackeados:** Git ignora `.gitignore` para los archivos que ya están en el índice, así que mateprobe lee `.git/index` (v2–v4, sin ejecutar `git`) y no descarta un archivo trackeado por una regla de `.gitignore`. Los defectos y `--exclude` mandan sobre el índice. `--ignore-git-index` lo desactiva.

Los symlinks no se siguen por defecto; con `--follow-symlinks` solo si el destino real queda dentro de `--path` y no fue visitado. El informe lista las reglas aplicadas y los directorios omitidos con su motivo.

### Configuración

Copiá `.env.example` a `.env` y completá la clave real (`.env` está en `.gitignore`):

```
api_key=REEMPLAZAR_CON_LA_CLAVE_REAL
report_format=html
```

- Los nombres van **en minúsculas**. El archivo se lee como texto: no se ejecuta ni se expande nada (`$(...)`, `$VAR` y comillas invertidas quedan literales). No se usa `source`.
- **`api_key`**: variable de entorno del proceso → archivo `.env`. Si falta, se pide por terminal (`Ingresá tu API key de DayZeroHub:`) **sin mostrar los caracteres**. No se guarda, no se imprime y no existe un flag para pasarla por argumento.
- **Formato**: `--format` > variable de entorno `report_format` > archivo `.env` > pregunta interactiva (Enter = HTML). Un valor inválido es un error, no se ignora.
- Sin terminal interactiva y con datos faltantes, el comando termina con un mensaje claro (no queda esperando).
- Este `.env` es **tu configuración**; nunca se busca ni se carga el `.env` del proyecto analizado.

### Qué se detecta

Se leen solo manifiestos, lockfiles y metadatos; **no se ejecuta ni se instala nada** del proyecto (salvo `--maven-resolve`, explícito). Se recorren varios subproyectos (frontend, backend, servicios) con las reglas de descubrimiento de arriba.

| Ecosistema | Archivos | Notas |
|---|---|---|
| JavaScript/TypeScript | `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock` (clásico y berry) | **Workspaces** (`workspaces` con globs y `!`): cada miembro se asocia a *su* lockfile (el raíz si lo incluye; si no, el propio; nunca el de un ancestro por cercanía). Versión **resuelta** (resolución de `node_modules` sobre el grafo del lockfile) vs. **rango declarado**; directas/transitivas con la dependencia directa de origen (`via`); ámbito **producción / desarrollo / mixta** (una versión usada también en producción nunca es «desarrollo»); varias versiones de un mismo paquete se conservan. Lockfiles de contenido idéntico se parsean una sola vez, conservando cada procedencia |
| Java (Maven) | `pom.xml` | Ver «Maven» |
| PHP | `composer.json`, `composer.lock` | Laravel, Symfony y otros por nombre canónico; `require`/`require-dev` |
| Go | `go.mod`, `go.work` | Módulos, versiones **declaradas** (mínimas de MVS), `replace`. `go.sum` no se usa como lista de dependencias; el grafo resuelto no se determina sin ejecutar `go` |
| WordPress | `wp-includes/version.php`, `wp-content/plugins/*` | Versión del core y encabezados `Plugin Name`/`Version` del PHP principal. No se ejecuta PHP ni se asume que un plugin esté activo |

### Correlación con los avisos (cuatro niveles que no se mezclan)

1. **Componente identificado**: el inventario produce ecosistema + nombre con evidencia (lockfile, `go.mod`, metadatos). Solo **identidades** de paquetes (`npm`, `Packagist`, `Go`) se envían a la API técnica; los runtimes (Node.js, PHP, Go) y WordPress no se consultan ahí.
2. **Aviso asociado** (`matched`): hay avisos para esa identidad. Todavía no implica que la versión local esté afectada.
3. **Versión dentro del rango** — la decisión es **local**: se compara la versión exacta con `ranges`/`versions` según el `version_scheme` (semver y composer/WordPress; el resto queda «No determinado»), solo si `identity.status = verified` y `range_quality = usable`. Semántica OSV: `introduced` inclusivo, `fixed` exclusivo, `last_affected` inclusivo, `limit` exclusivo; cada `introduced…fixed` es una rama independiente; sin cierre el rango es abierto. Resultados: *dentro del rango afectado* · *fuera del rango informado* · *No determinado* (restricciones como `^5.0.0`, versión desconocida, rangos `GIT` o insuficientes, esquema sin comparador, conflictos entre fuentes, `replace` de Go). Las versiones de `go.mod` son «declaradas»: se evalúan con una salvedad explícita.
4. **Explotabilidad no determinada**: se muestra `known_exploited` / `not_listed_in_kev` / sin información; «sin información» nunca se presenta como «no explotado».

`no_match`, `ecosystem_not_covered` y `error` **no** significan «seguro»: se informan como «sin datos». Los avisos retirados o rechazados no son hallazgos (se cuentan aparte).

Además se consulta el **feed editorial** (`/news`) como complemento (WordPress, que el catálogo técnico no cubre, y avisos sin rangos): ahí se usan identificadores exactos, alias acotados y menciones textuales, siempre como «coincidencia de componente; versión sin verificar» o «posible coincidencia textual». Si un aviso editorial comparte CVE/GHSA con un hallazgo técnico del mismo componente, solo se muestra el técnico. Los avisos se deduplican únicamente por identificadores explícitos.

### API de DayZeroHub

Una sola `api_key` (cabecera `X-API-Key`, nunca en la query) para las cuatro URLs, definidas como constantes en `dzh/client.go` sobre `https://dayzerohub.site`:

| Método y ruta | Uso |
|---|---|
| `GET /api/v1/security/catalog` | Alcance (ecosistemas) y frescura del catálogo técnico |
| `POST /api/v1/security/packages/lookup` | Avisos por identidad, en lotes de ≤100 componentes (`limit` 100 por componente, `next_cursor` por componente, reintento solo de los `error`) |
| `GET /api/v1/security/advisories` | Catálogo técnico paginado por cursor opaco (método `Advisories`; el informe no lo necesita) |
| `GET /api/v1/news?lang=es` | Feed editorial: `{items,page,page_size,max_pages}`, hasta 5 páginas de 20 |

El cliente (`net/http`) usa timeout, cancela con Ctrl+C, limita el tamaño de la respuesta, reintenta 429/5xx/red con backoff exponencial y jitter (respetando `Retry-After`, hasta 30 s), **no reintenta 401** (los 401 repetidos pueden banear la IP; ante un 401 se cortan todas las consultas y se genera el informe parcial), no reenvía `X-API-Key` a otro origen en una redirección y tolera campos extra o `null` (contrato `dzh-security/1`). Si algo falla se genera igualmente un **informe parcial** con el inventario local y el estado «Consulta de vulnerabilidades no completada». **Privacidad:** a la API técnica solo viaja ecosistema + nombre del paquete; jamás versiones, rutas ni contenido de archivos.

### Maven

- **Modo estático (por defecto):** se leen los `pom.xml` (sin ejecutar nada ni usar la red): módulos del reactor, parent POM (`relativePath`, luego el repositorio local de solo lectura `~/.m2/repository`), propiedades (`${project.version}`, `${parent.version}`, propias), `dependencyManagement`, BOM importados, scopes (`test` → desarrollo) y perfiles `activeByDefault` (o los de `--maven-profile`). Se resuelven las dependencias **directas**; las **transitivas** y las versiones que dependen de parents/BOM/propiedades ausentes quedan como **pendientes**, agrupadas por causa en el informe. Leer un `pom.xml` no equivale a haber evaluado todo el backend.
- **Modo efectivo (`--maven-resolve`, explícito):** ejecuta `mvn dependency:tree` una sola vez sobre el reactor raíz, con timeout (`--maven-timeout`) y salida acotada. **Maven puede descargar artefactos y ejecutar plugins y extensiones del proyecto auditado** (por eso es opt-in). Nunca se usa `./mvnw` ni scripts del repositorio (un ejecutable dentro del repo auditado se rechaza). Si falta Maven, hay timeout o error, se informa «Maven: modo efectivo no completado» y queda el resultado estático.
- **Evaluación:** la API de DayZeroHub cubre Maven (identidad `grupo:artefacto`, esquema `maven`); el comparador sigue `ComparableVersion` de Maven. El catálogo Maven es pequeño: «sin avisos» no es garantía. Si el catálogo no cubriera Maven, el informe muestra «inventariado, evaluación no disponible».

### Avisos únicos, ocurrencias y prioridad

El informe separa **aviso** (con los alias CVE/GHSA que la fuente declara equivalentes unificados; avisos distintos no se fusionan por afectar el mismo paquete), **componente+versión**, **ocurrencia** (proyecto/servicio, ámbito, lockfile, vía) y **resultado de evaluación**. Una tarjeta por aviso único; si un aviso está confirmado en un servicio y es indeterminado en otro, ambos se muestran. Contadores separados: avisos únicos, componentes afectados y ocurrencias.

Prioridad (determinista y visible en el informe): certeza de la evaluación → explotación conocida (CISA KEV) → severidad → EPSS (la API actual no lo informa: «no disponible») → uso en producción → CVSS → identificador. Los datos ausentes se muestran como «no disponible», nunca como 0 o «no». Los comandos de actualización solo se sugieren (nunca se ejecutan) cuando se conocen gestor, workspace y dependencia directa; para transitivas se orienta a actualizar el padre o revisar la resolución.

### Informe

- **Compacto:** resumen accionable al inicio, tarjetas por aviso con ubicaciones en secciones colapsables, problemas de cobertura agrupados por causa (contador + ejemplos) y límites en listas repetitivas. **No se incrusta el inventario**; el detalle completo va a `--export-dir` (JSON/CSV; el CSV neutraliza celdas que empiezan con `= + - @`).
- **HTML** autocontenido: CSS embebido, sin CDN ni fuentes ni recursos remotos (con CSP restrictiva), escapado con `html/template`; solo se activan enlaces `http(s)`.
- **Markdown** con las mismas secciones: proyecto y fecha, tecnologías, subproyectos, avisos relacionados (ID, evidencia, enlaces), versiones desconocidas, archivos no analizados, páginas/avisos consultados y limitaciones. El contenido de terceros se escapa.
- Sin `--output` se guarda en `./reports/<proyecto>-<AAAAMMDD-HHMMSS>.<ext>` sin sobrescribir informes anteriores (permisos `0600`).
- Si no hay coincidencias: «No se encontraron avisos relacionados dentro de los datos consultados.» El informe nunca afirma que un proyecto sea seguro.

Al terminar se muestra el estado, un resumen, la ruta absoluta y un enlace **«Abrir informe»** (`file://`, con paths con espacios codificados). En terminales compatibles es un hipervínculo OSC 8 (algunas requieren Ctrl+clic; otras no admiten enlaces locales); siempre se imprime también la URL en texto plano. Con la salida redirigida no se emiten secuencias de escape. Si `--open` falla, el informe se conserva y se informa su ubicación.

Códigos de salida de `audit`: `0` completo · `1` error de uso/configuración · `2` informe parcial (consulta incompleta) · `130` interrumpido con Ctrl+C.

Ejemplos generados desde fixtures: [`examples/audit-informe.html`](examples/audit-informe.html) y [`examples/audit-informe.md`](examples/audit-informe.md) (`make examples`).

### No soportado todavía

`pnpm-lock.yaml` y `pnpm-workspace.yaml` (se informa y se usan solo las restricciones de `package.json`), `npm-shrinkwrap.json`, Python, Gradle, Ruby, Rust, .NET y otros ecosistemas (se listan como no analizados), temas y `mu-plugins` de WordPress, imports del código fuente, comparación de versiones de PyPI, RubyGems y NuGet, rangos `GIT`, datos técnicos de WordPress (el catálogo no los cubre todavía), mediación/exclusiones/perfiles por `jdk`/`os`/`property` de Maven sin `--maven-resolve`, y análisis de explotabilidad.

## Integración con MateAudit

El núcleo es un conjunto de paquetes Go reutilizables:

| Paquete | Responsabilidad |
|---|---|
| `targets` | parseo, límites, exclusiones y dedupe de objetivos |
| `collect` | HTTP/TLS, redirecciones, rate limit, límites de lectura |
| `detect` | wappalyzergo + reglas propias con evidencia |
| `scan` | orquestación con concurrencia y cancelación |
| `model` | resultados (contrato JSON versionado) |
| `export` | tabla, JSON, CSV, HTML |
| `redact` | sanitización y redacción |

```go
eng, _ := detect.New()
list, _ := targets.Expand([]string{"ejemplo.com"}, targets.Options{})
rep := scan.Run(ctx, scan.Config{Concurrency: 5, Collect: collect.Config{Rate: 5}}, list, eng)
// rep es un *model.Report; export.JSON(w, rep) para serializarlo
```

Alternativa sin código: consumir `--format json` (`schema_version` permite detectar cambios incompatibles).

## Limitaciones

- **Solo análisis pasivo de HTML/cabeceras:** no se ejecuta JavaScript ni se descargan los assets. Tecnologías visibles solo en runtime (SPAs con detección por `window.*`) o dentro de bundles no se ven.
- **Las firmas son una instantánea** embebida en la versión fijada de wappalyzergo (v0.3.11); no se actualizan solas. Los falsos positivos/negativos de ese catálogo se heredan.
- **Sin evidencia ni confianza** para lo que detecta solo wappalyzergo (ver arriba). Si el motor detecta directamente algo que además marca como implicado por otra tecnología y ninguna regla propia lo confirma, se registra como `inferred` (criterio conservador).
- Las **versiones** son las que el sitio declara o las que una firma extrae; no se verifican. Los servidores pueden ocultarlas o falsearlas.
- La misma tecnología puede aparecer una vez por cada URL/respuesta donde se observó (p. ej. en `http://` y `https://`).
- **HTTP/1.1** únicamente (sin HTTP/2 ni Brotli); se ignoran las variables de proxy del entorno a propósito.
- Las exclusiones de IP se evalúan sobre IPs literales de objetivos y redirecciones; **no** sobre las IPs a las que resuelve un dominio.
- El rate limit es global con ráfaga 1; el timeout se aplica por solicitud, incluidas las de redirección.
- IPv6 con zona (`fe80::1%eth0`) no está soportado.
- Los binarios de Windows y macOS se **compilan** con `make dist` pero en este desarrollo solo se **ejecutó** el de Linux x86-64.
- No hay versión de licencia del proyecto definida todavía (ver notas de licencias).

## Licencias

Ver [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). **Atención:** el código de wappalyzergo es MIT, pero la base de firmas que embebe proviene de repositorios GPL-3.0; hay que revisar esto antes de distribuir los binarios.
