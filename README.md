# mateprobe

Detecta las tecnologías de sitios web (servidor, lenguaje, CMS, frameworks, CDN, analytics…) **desde tu máquina**, a partir de dominios, URLs, IPs, CIDR o rangos de IPs. Un único ejecutable: no requiere Go, Docker, Node ni base de datos, y no envía nada a terceros.

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

### Compilar desde el código

Requiere Go ≥ 1.27 (solo para compilar).

```bash
make check     # gofmt + go vet + go test -race
make build     # dist/mateprobe para tu plataforma
make dist      # 6 binarios + SHA256SUMS en dist/
make examples  # regenera examples/ desde servidores locales
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
