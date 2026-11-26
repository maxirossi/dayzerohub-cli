<div align="center">
  <img src="docs/assets/dayzerohub.svg" alt="DayZeroHub" width="72" height="90">
  <h1>DayZeroHub CLI</h1>
  <p><strong>Auditoría de dependencias, desde tu proyecto hasta el informe.</strong></p>
  <p>
    <a href="https://github.com/maxirossi/dayzerohub-cli/releases/latest"><img src="https://img.shields.io/github/v/release/maxirossi/dayzerohub-cli?color=01A78B" alt="Última versión"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-010F26" alt="GPL-3.0"></a>
    <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-010F26" alt="Linux, macOS, Windows">
  </p>
  <p><strong>Español</strong> · <a href="README.en.md">English</a></p>
</div>
**Conocé las dependencias de tu proyecto y qué avisos de seguridad requieren tu atención.** `mateprobe`, el ejecutable de DayZeroHub CLI, analiza una carpeta local, consulta la API de DayZeroHub y genera un informe HTML o Markdown con hallazgos, evidencia y límites de cobertura.

[DayZeroHub](https://dayzerohub.site/) publica novedades sobre vulnerabilidades de criticidad media, alta y crítica. Podés registrarte, seguir tecnologías como PHP y recibir novedades por Telegram, email, Slack u otros canales habilitados en tu cuenta. El CLI lleva esos datos al contexto de tu proyecto: inventaría sus dependencias y evalúa las versiones localmente.

**Un ejecutable · Sin Go, Node ni Docker para usarlo · Informes en español e inglés**

[Instalación](#instalación) · [Primer informe](#primer-informe) · [Ecosistemas](#ecosistemas-compatibles) · [Ejemplos](#ejemplos-de-uso) · [Escanear sitios](#detectar-tecnologías-de-un-sitio-sin-cuenta) · [Privacidad](#privacidad) · [Ayuda](#solución-de-problemas)

```bash
mateprobe login
mateprobe audit --path "./mi-proyecto" --format html --open
```

## Instalación

Necesitás el ejecutable para tu sistema, una cuenta de DayZeroHub verificada y conexión a Internet para autorizar el equipo y consultar los avisos. El análisis de archivos se realiza en tu máquina.

Los bloques siguientes instalan **v0.1.0** desde [Releases](https://github.com/maxirossi/dayzerohub-cli/releases/latest), verifican el SHA-256 antes de instalar y no requieren permisos de administrador. Elegí tu sistema:

<details>
<summary><strong>Linux / macOS — copiar y pegar en Bash o Zsh</strong></summary>

Detecta Intel/AMD de 64 bits o ARM64 y deja el comando en `~/.local/bin/mateprobe`. Requiere `curl` y las herramientas de checksum del sistema.

```bash
(
  set -eu
  dzh_version="0.1.0"
  case "$(uname -s)" in
    Linux) dzh_os="linux" ;;
    Darwin) dzh_os="darwin" ;;
    *) echo "Unsupported OS" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64) dzh_arch="amd64" ;;
    aarch64|arm64) dzh_arch="arm64" ;;
    *) echo "Unsupported architecture" >&2; exit 1 ;;
  esac
  dzh_asset="mateprobe-${dzh_version}-${dzh_os}-${dzh_arch}"
  dzh_base="https://github.com/maxirossi/dayzerohub-cli/releases/download/v${dzh_version}"
  dzh_tmp="$(mktemp -d)"
  trap 'rm -rf "$dzh_tmp"' EXIT
  cd "$dzh_tmp"
  curl -fsSLO "$dzh_base/$dzh_asset"
  curl -fsSLO "$dzh_base/SHA256SUMS"
  awk -v file="$dzh_asset" '$2 == file {print}' SHA256SUMS > checksum.txt
  test "$(wc -l < checksum.txt | tr -d ' ')" = "1"
  if [ "$dzh_os" = "linux" ]; then
    sha256sum -c checksum.txt
  else
    shasum -a 256 -c checksum.txt
  fi
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$dzh_asset" "$HOME/.local/bin/mateprobe"
  "$HOME/.local/bin/mateprobe" --version
)
[ "$?" -eq 0 ] && export PATH="$HOME/.local/bin:$PATH"
```

El bloque habilita el comando en esta terminal. Para conservarlo en próximas sesiones, agregá esta línea a `~/.bashrc` si usás Bash, o a `~/.zshrc` si usás Zsh:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

</details>

<details>
<summary><strong>Windows — copiar y pegar en PowerShell</strong></summary>

Detecta x64 o ARM64, instala en `%LOCALAPPDATA%\mateprobe` y agrega el comando al `PATH` del usuario y de la sesión actual.

```powershell
& {
  $ErrorActionPreference = "Stop"
  $DzhVersion = "0.1.0"
  $DzhMachine = $env:PROCESSOR_ARCHITECTURE
  if ($env:PROCESSOR_ARCHITEW6432) { $DzhMachine = $env:PROCESSOR_ARCHITEW6432 }
  $DzhArch = switch ($DzhMachine) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported architecture: $DzhMachine" }
  }
  $DzhAsset = "mateprobe-$DzhVersion-windows-$DzhArch.exe"
  $DzhBase = "https://github.com/maxirossi/dayzerohub-cli/releases/download/v$DzhVersion"
  $DzhDir = Join-Path $env:LOCALAPPDATA "mateprobe"
  $DzhTmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
  New-Item -ItemType Directory -Path $DzhTmp | Out-Null
  try {
    $DzhBinary = Join-Path $DzhTmp $DzhAsset
    $DzhSums = Join-Path $DzhTmp "SHA256SUMS"
    Invoke-WebRequest "$DzhBase/$DzhAsset" -OutFile $DzhBinary
    Invoke-WebRequest "$DzhBase/SHA256SUMS" -OutFile $DzhSums
    $DzhPattern = '^[a-fA-F0-9]{64}\s+\*?' + [regex]::Escape($DzhAsset) + '$'
    $DzhLines = @(Get-Content $DzhSums | Where-Object { $_ -match $DzhPattern })
    if ($DzhLines.Count -ne 1) { throw "Missing or ambiguous SHA256 entry" }
    $DzhExpected = ($DzhLines[0] -split '\s+')[0]
    if ((Get-FileHash $DzhBinary -Algorithm SHA256).Hash -ne $DzhExpected) {
      throw "SHA256 mismatch: installation stopped"
    }
    New-Item -ItemType Directory -Force -Path $DzhDir | Out-Null
    Copy-Item $DzhBinary (Join-Path $DzhDir "mateprobe.exe") -Force
    $DzhUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($DzhUserPath -split ';') -notcontains $DzhDir) {
      [Environment]::SetEnvironmentVariable("Path", "$DzhUserPath;$DzhDir", "User")
    }
    if (($env:Path -split ';') -notcontains $DzhDir) { $env:Path += ";$DzhDir" }
    & (Join-Path $DzhDir "mateprobe.exe") --version
  } finally {
    Remove-Item -LiteralPath $DzhTmp -Recurse -Force
  }
}
```

</details>

<details>
<summary>Descarga manual: elegir el ejecutable</summary>

Los nombres de archivo corresponden a v0.1.0. `amd64` sirve para procesadores Intel y AMD de 64 bits; `arm64`, para ARM de 64 bits.

| Sistema | Intel / AMD de 64 bits | ARM64 |
| --- | --- | --- |
| Linux | [Descargar](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-linux-amd64) | [Descargar](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-linux-arm64) |
| macOS | [Intel](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-darwin-amd64) | [Apple Silicon](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-darwin-arm64) |
| Windows | [Descargar .exe](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-windows-amd64.exe) | [Descargar .exe](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-windows-arm64.exe) |

Compará el SHA-256 del archivo con su entrada en [SHA256SUMS](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/SHA256SUMS) antes de ejecutarlo: `sha256sum ARCHIVO` en Linux, `shasum -a 256 ARCHIVO` en macOS o `Get-FileHash ARCHIVO -Algorithm SHA256` en PowerShell. Luego renombralo a `mateprobe` (`mateprobe.exe` en Windows). En Linux/macOS, dale permiso con `chmod +x mateprobe`.

Podés ejecutarlo desde esa carpeta con `./mateprobe --version` o `.\mateprobe.exe --version`, respectivamente. Usá ese mismo prefijo para los comandos de esta guía si no lo agregaste al `PATH`.

</details>

> La release v0.1.0 publica binarios para los tres sistemas, pero indica que macOS y Windows todavía no fueron probados. Los binarios de macOS no están firmados; el sistema puede pedir una revisión antes de ejecutarlos.

## Primer informe

### 1. Creá tu cuenta y autorizá el equipo

[Registrate en DayZeroHub](https://dayzerohub.site/app/register?lang=es), verificá tu cuenta y ejecutá:

```bash
mateprobe login
```

Se abre el navegador y la terminal muestra un enlace y un código. Confirmá ese código con tu sesión de DayZeroHub. Si el navegador no se abre, copiá el enlace. La API key personal queda guardada en tu equipo; no necesitás crear un `.env`.

### 2. Elegí la carpeta que querés auditar

Reemplazá `./mi-proyecto` por la ruta de tu proyecto. Puede contener varios servicios o workspaces.

```bash
mateprobe audit --path "./mi-proyecto" --format html --open
```

El comando lee los manifiestos y lockfiles compatibles, consulta los avisos por paquete y compara las versiones en tu máquina. **En el modo predeterminado no instala dependencias ni ejecuta código del proyecto.**

### 3. Revisá el informe

Se guarda en `./reports/<proyecto>-<fecha>.html`, relativo al directorio desde el que ejecutaste el comando, y se abre en el navegador. La terminal también muestra la ruta y un enlace para abrirlo.

| En el informe | Para qué sirve |
| --- | --- |
| Resumen y prioridades | Ver qué revisar primero según la evaluación, severidad y explotación conocida disponible. |
| Avisos y evidencia | Consultar identificadores CVE/GHSA, componente, versión y fuente del hallazgo. |
| Ubicaciones | Encontrar el servicio, manifiesto o lockfile involucrado y, cuando está disponible, la dependencia de origen. |
| Cobertura | Distinguir lo evaluado de versiones desconocidas, archivos omitidos y ecosistemas sin datos. |
| Acciones sugeridas | Orientar una actualización cuando hay datos suficientes; el CLI no la ejecuta. |

**[Ver informe de ejemplo en Markdown](examples/audit-informe.md)** · [HTML de ejemplo](examples/audit-informe.html) — datos ficticios de prueba, no una auditoría real. Para ver el HTML renderizado, descargalo y abrilo en tu navegador.

> Una versión dentro del rango afectado requiere revisión; no demuestra que tu aplicación sea explotable. «Sin avisos encontrados» describe los datos consultados, no garantiza que el proyecto sea seguro.

## Ecosistemas compatibles

| Ecosistema | Archivos analizados | Alcance |
| --- | --- | --- |
| JavaScript / TypeScript | `package.json`, `package-lock.json` v1–v3, `yarn.lock` Classic/Berry | Workspaces, dependencias directas y transitivas, versiones resueltas y ámbito de uso. |
| PHP / Composer | `composer.json`, `composer.lock` | Paquetes de Composer, incluidos Laravel y Symfony; dependencias de producción y desarrollo. |
| Java / Maven | `pom.xml` | Lectura estática de módulos, parents, BOM y dependencias directas. Resolución efectiva opcional. |
| Go | `go.mod`, `go.work` | Módulos, versiones declaradas y reemplazos. No reconstruye el grafo resuelto ejecutando Go. |
| WordPress local | `wp-includes/version.php`, `wp-content/plugins/*` | Inventario del core y plugins. Avisos editoriales opcionales; sin cobertura del catálogo técnico de WordPress. |

Los lockfiles permiten distinguir una versión resuelta de un rango declarado como `^1.0.0`. Si faltan datos suficientes para comparar, el resultado queda **«No determinado»**.

**Límites actuales:** pnpm se detecta, pero sus lockfiles y workspaces no se resuelven; se usan las declaraciones de `package.json`. Tampoco se analizan `npm-shrinkwrap.json`, Python, Gradle, Ruby, Rust, .NET, temas o mu-plugins de WordPress. La cobertura de avisos depende del catálogo de DayZeroHub y se refleja en el informe.

## Ejemplos de uso

**Guardar un informe HTML en una ubicación elegida:**

```bash
mateprobe audit --path "./mi-proyecto" --format html --output "./informes/auditoria.html" --open
```

**Generar Markdown:**

```bash
mateprobe audit --path "./mi-proyecto" --format md --output "./informes/auditoria.md"
```

**Exportar el detalle completo además del informe:**

```bash
mateprobe audit --path "./mi-proyecto" --format html --export-dir "./detalle"
```

| Archivo exportado | Contenido |
| --- | --- |
| `inventory.json` / `inventory.csv` | Inventario completo de componentes. |
| `findings.json` | Hallazgos técnicos y evaluación de versiones. |
| `coverage.json` | Cobertura del análisis y sus limitaciones. |

**Excluir una carpeta:**

```bash
mateprobe audit --path "./mi-proyecto" --format html --exclude "/legacy/"
```

Por defecto se respetan `.gitignore` y `.git/info/exclude`, y se omiten dependencias instaladas, cachés y carpetas generadas como `node_modules`, `vendor`, `dist`, `build` y `target`. Los archivos ya trackeados por Git no se descartan por una regla de `.gitignore`; las exclusiones predeterminadas y `--exclude` siguen aplicándose.

**Cambiar el idioma de la interfaz y el informe:**

```bash
mateprobe --lang es audit --path "./mi-proyecto" --format html --open
mateprobe --lang en audit --path "./mi-proyecto" --format html --open
```

También podés definir `MATEPROBE_LANG=es` o `MATEPROBE_LANG=en` como variable de entorno.

<details>
<summary>Maven: incluir el árbol efectivo de dependencias</summary>

El modo predeterminado lee `pom.xml` sin ejecutar Maven; las transitivas y los parents/BOM que no puede resolver quedan pendientes. Para obtener el árbol efectivo, necesitás Maven y un JDK instalados:

```bash
mateprobe audit --path "./backend" --format html --maven-resolve --open
```

Este modo **ejecuta `mvn dependency:tree` y puede descargar artefactos y ejecutar plugins o extensiones del proyecto**. Es opcional; no usa `./mvnw`. Si falla, el informe conserva el análisis estático y muestra la limitación.

Podés ajustar `--maven-bin`, `--maven-timeout` (por defecto `10m`) y `--maven-profile` (repetible).

</details>

## Configuración opcional

Con `mateprobe login` y `--format html` ya podés empezar. Para fijar preferencias, creá un archivo de configuración separado del proyecto, por ejemplo `~/.config/mateprobe/audit.env` en Linux/macOS:

```dotenv
report_format=html
# Solo si preferís una API key manual en lugar de la guardada por login:
# api_key=TU_API_KEY_TECNICA
# Opcional, para complementar con el feed editorial (usa otra clave):
# news_api_key=TU_API_KEY_EDITORIAL
```

```bash
mateprobe audit --path "./mi-proyecto" --env-file "$HOME/.config/mateprobe/audit.env" --open
```

En Windows podés guardar ese archivo donde prefieras y pasar su ruta con `--env-file`.

| Valor | Prioridad, de mayor a menor |
| --- | --- |
| API key técnica | Variable de entorno `api_key` → archivo de configuración → clave de `login` → pregunta oculta en terminal. |
| Formato | `--format` → variable de entorno `report_format` → archivo de configuración → pregunta interactiva (Enter elige HTML). |

Los nombres `api_key`, `news_api_key` y `report_format` van **en minúsculas**. El archivo se lee como texto; no ejecuta comandos ni expande variables. No guardes claves en el repositorio.

Sin `--env-file`, se intenta leer `./.env` **del directorio actual**. No se busca un `.env` a partir de `--path`; si ejecutás desde la carpeta auditada, ambos directorios coinciden. Usá un archivo explícito si querés separar la configuración del CLI de la aplicación.

La clave personal de `login` sirve para la API técnica. `news_api_key` es opcional y corresponde al feed editorial; su ausencia no impide el informe técnico. En una ejecución sin terminal interactiva, configurá la clave y el formato de antemano.

<details>
<summary>Referencia de opciones de auditoría</summary>

| Opción | Uso |
| --- | --- |
| `--path RUTA` | Carpeta a analizar; obligatoria. |
| `--format html` / `--format md` | Formato del informe. |
| `--output RUTA` | Archivo o directorio de destino. Un archivo explícito se sobrescribe; el nombre automático conserva los informes anteriores. |
| `--open` | Abrir el informe con la aplicación predeterminada. |
| `--env-file ARCHIVO` | Archivo de configuración del CLI. |
| `--export-dir DIR` | Exportar inventario, hallazgos técnicos y cobertura. |
| `--exclude PATRÓN` | Excluir rutas con sintaxis `.gitignore`; repetible. |
| `--include PATRÓN` | Reincorporar rutas omitidas; preferí patrones anclados como `/carpeta/`. Repetible. |
| `--no-gitignore` | No aplicar las reglas de `.gitignore`. |
| `--no-default-excludes` | Desactivar exclusiones predeterminadas; `.git` nunca se recorre. |
| `--ignore-git-index` | No usar el índice de Git para reconocer archivos trackeados. |
| `--follow-symlinks` | Seguir enlaces dentro de la raíz auditada, sin ciclos. |

Precedencia de exclusiones: predeterminadas → `.gitignore` → `--exclude` → `--include`. Para consultar todas las opciones disponibles en tu versión:

```bash
mateprobe audit --help
```

</details>

## Detectar tecnologías de un sitio (sin cuenta)

`scan` no necesita cuenta, API key ni `login`, y **no envía nada a DayZeroHub**: consulta el sitio directamente desde tu equipo. Es pasivo (hace `GET` normales; no enumera directorios ni prueba vulnerabilidades). Usalo solo sobre sistemas propios o con autorización.

```bash
mateprobe scan --target ejemplo.com
mateprobe scan --target 192.168.1.0/24 --exclude 192.168.1.1
mateprobe scan --input objetivos.txt --format html --output reporte.html
```

Cada tecnología indica cómo se detectó (`declared`, `signature` o `inferred`), su confianza y la evidencia. Acepta dominios, URLs, IPs, CIDR y rangos; formatos `table`, `json`, `csv` y `html`. Todas las opciones: `mateprobe scan --help`. Detalle completo en la [referencia técnica](docs/REFERENCIA.md).

## Comandos y ayuda

`mateprobe --help` lista los comandos (`login`, `logout`, `audit`, `scan`) y `mateprobe <comando> --help` muestra las opciones de cada uno. La [referencia técnica](docs/REFERENCIA.md) cubre `scan`, la correlación de avisos, Maven, la API de DayZeroHub y la integración con MateAudit.

## Privacidad

| Operación | Qué se comparte con DayZeroHub |
| --- | --- |
| Consulta de avisos | Ecosistema y nombre de cada paquete consultado. La comparación de versiones ocurre localmente; no se suben versiones, rutas ni contenido de archivos. |
| `login` | Un nombre de instalación basado en `usuario@equipo` para identificar la autorización. La contraseña se introduce en el portal, no en el CLI. |
| Resumen de uso | En `main`, posterior a v0.1.0: versión del CLI, sistema/arquitectura, estado, conteos y un identificador derivado de un hash de la ruta. Se asocia a la cuenta cuando se usa una clave personal. |

El resumen de uso no contiene nombres de paquetes, rutas en texto, versiones de dependencias ni avisos concretos. El servidor recibe la IP y puede derivar el país. **Esto es independiente de la consulta de avisos, que sí envía nombres de paquetes.**

Para desactivar el resumen de uso, definí la variable de entorno `MATEPROBE_TELEMETRY=off` (`export MATEPROBE_TELEMETRY=off` en Bash/Zsh; `$env:MATEPROBE_TELEMETRY="off"` en PowerShell). No desactiva las consultas necesarias para la auditoría.

Los informes se guardan localmente. El HTML es autocontenido, sin JavaScript ni recursos externos. Puede incluir rutas y dependencias: revisalo antes de compartirlo.

Para borrar la credencial guardada en este equipo:

```bash
mateprobe logout
```

Para invalidar esa clave también en el servidor, revocala desde **API técnica** en el [panel de DayZeroHub](https://dayzerohub.site/app).

## Solución de problemas

| Situación | Qué revisar |
| --- | --- |
| `mateprobe: command not found` / comando no reconocido | Revisá el `PATH` de instalación o ejecutá el binario por su ruta completa. En Linux/macOS: `"$HOME/.local/bin/mateprobe" --version`. En PowerShell: `& "$env:LOCALAPPDATA\mateprobe\mateprobe.exe" --version`. |
| El checksum no coincide | No instales ese archivo; volvé a descargar el binario y `SHA256SUMS` de la misma release. |
| Código de login vencido | Ejecutá `mateprobe login` de nuevo y confirmá el código vigente. |
| API key rechazada / HTTP 401 | Revisá si `api_key` del entorno o del archivo está reemplazando la clave guardada. Corregila o volvé a autorizar con `mateprobe login`. |
| Falta configuración en CI o con salida redirigida | Proporcioná `api_key` mediante los secretos del entorno y agregá `--format html` o `--format md`. |
| Feed editorial omitido | Es opcional. En v0.1.0, omitirlo puede devolver código `2` aunque la consulta técnica esté completa. Configurá `news_api_key` si necesitás incluirlo. |
| `--open` no abre el navegador | El informe se conserva. Abrilo desde la ruta indicada; en Linux, comprobá que exista `xdg-open` y haya una sesión gráfica. |
| Informe parcial / «No determinado» | Revisá cobertura, versiones sin resolver y errores de consulta antes de sacar conclusiones. |

### Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Consulta completada; **puede haber vulnerabilidades y limitaciones de cobertura**. |
| `1` | Error de uso, configuración, lectura o escritura. |
| `2` | Informe parcial por consulta incompleta; en v0.1.0 también ocurre al omitir el feed editorial. |
| `130` | Interrupción con Ctrl+C; si ocurre durante el inventario, puede no generarse un informe. |

El código de salida indica el estado de la ejecución, no la severidad de los hallazgos. No funciona como un umbral de bloqueo por vulnerabilidades en CI.

<details>
<summary>Compilar desde el código fuente</summary>

Necesitás Git y **Go 1.27.4 o posterior**, según [go.mod](go.mod). Desde Bash/Zsh:

```bash
git clone https://github.com/maxirossi/dayzerohub-cli.git
cd dayzerohub-cli
go build -trimpath -o ./dist/mateprobe ./cmd/mateprobe
./dist/mateprobe --version
```

En Windows, compilá con `go build -trimpath -o .\dist\mateprobe.exe ./cmd/mateprobe` y ejecutá `.\dist\mateprobe.exe --version`. Para contribuir, `make check` ejecuta las comprobaciones de formato, análisis estático y tests (requiere Make).

</details>

## Licencia y enlaces

Distribuido bajo [GNU GPL v3.0](LICENSE). Atribuciones en [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

[Portal DayZeroHub](https://dayzerohub.site/) · [Descargas](https://github.com/maxirossi/dayzerohub-cli/releases/latest) · [Reportar un problema](https://github.com/maxirossi/dayzerohub-cli/issues) · [English](README.en.md)
