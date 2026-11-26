<div align="center">
  <img src="docs/assets/dayzerohub.svg" alt="DayZeroHub" width="72" height="90">
  <h1>DayZeroHub CLI</h1>
  <p><strong>Dependency auditing, from your project to a readable report.</strong></p>
  <p>
    <a href="https://github.com/maxirossi/dayzerohub-cli/releases/latest"><img src="https://img.shields.io/github/v/release/maxirossi/dayzerohub-cli?color=01A78B" alt="Latest release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-010F26" alt="GPL-3.0"></a>
    <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-010F26" alt="Linux, macOS, Windows">
  </p>
  <p><a href="README.md">Español</a> · <strong>English</strong></p>
</div>
**Understand your project's dependencies and which security advisories need your attention.** `mateprobe`, the DayZeroHub CLI executable, analyzes a local directory, queries the DayZeroHub API, and produces an HTML or Markdown report with findings, evidence, and coverage limitations.

[DayZeroHub](https://dayzerohub.site/) publishes updates about medium, high, and critical security vulnerabilities. Create an account, follow technologies such as PHP, and receive updates through Telegram, email, Slack, or other channels enabled for your account. The CLI puts that information in the context of your project by building a dependency inventory and evaluating versions locally.

**One executable · No Go, Node, or Docker required to run · Reports in English and Spanish**

[Installation](#installation) · [First report](#first-report) · [Ecosystems](#supported-ecosystems) · [Examples](#usage-examples) · [Scan websites](#detect-a-websites-technologies-no-account) · [Privacy](#privacy) · [Help](#troubleshooting)

```bash
mateprobe --lang en login
mateprobe --lang en audit --path "./my-project" --format html --open
```

## Installation

You need the executable for your system, a verified DayZeroHub account, and an Internet connection to authorize your machine and retrieve advisories. Files are analyzed on your machine.

The blocks below install **v0.1.0** from [Releases](https://github.com/maxirossi/dayzerohub-cli/releases/latest), verify SHA-256 before installation, and do not require administrator privileges. Choose your system:

<details>
<summary><strong>Linux / macOS — copy and paste into Bash or Zsh</strong></summary>

Detects 64-bit Intel/AMD or ARM64 and installs the command at `~/.local/bin/mateprobe`. Requires `curl` and your system's checksum tools.

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

The block makes the command available in this terminal. To keep it available in future sessions, add this line to `~/.bashrc` for Bash or `~/.zshrc` for Zsh:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

</details>

<details>
<summary><strong>Windows — copy and paste into PowerShell</strong></summary>

Detects x64 or ARM64, installs under `%LOCALAPPDATA%\mateprobe`, and adds the command to both your user `PATH` and the current session.

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
<summary>Manual download: choose an executable</summary>

These filenames correspond to v0.1.0. `amd64` is for 64-bit Intel and AMD processors; `arm64` is for 64-bit ARM processors.

| System | 64-bit Intel / AMD | ARM64 |
| --- | --- | --- |
| Linux | [Download](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-linux-amd64) | [Download](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-linux-arm64) |
| macOS | [Intel](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-darwin-amd64) | [Apple Silicon](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-darwin-arm64) |
| Windows | [Download .exe](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-windows-amd64.exe) | [Download .exe](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/mateprobe-0.1.0-windows-arm64.exe) |

Compare the file's SHA-256 with its entry in [SHA256SUMS](https://github.com/maxirossi/dayzerohub-cli/releases/download/v0.1.0/SHA256SUMS) before running it: use `sha256sum FILE` on Linux, `shasum -a 256 FILE` on macOS, or `Get-FileHash FILE -Algorithm SHA256` in PowerShell. Then rename it to `mateprobe` (`mateprobe.exe` on Windows). On Linux/macOS, run `chmod +x mateprobe` to make it executable.

Run it from that directory with `./mateprobe --version` or `.\mateprobe.exe --version`, respectively. Use the same prefix for the commands in this guide if you have not added it to your `PATH`.

</details>

> Release v0.1.0 provides binaries for all three systems, but notes that macOS and Windows have not yet been tested. macOS binaries are unsigned; your system may require a review before running them.

## First report

### 1. Create your account and authorize your machine

[Register with DayZeroHub](https://dayzerohub.site/app/register?lang=en), verify your account, and run:

```bash
mateprobe --lang en login
```

Your browser opens, and the terminal displays a link and a code. Confirm that code while signed in to DayZeroHub. If the browser does not open, copy the link. Your personal API key is stored on your machine; you do not need to create an `.env` file.

### 2. Choose the directory to audit

Replace `./my-project` with your project's path. It can contain multiple services or workspaces.

```bash
mateprobe --lang en audit --path "./my-project" --format html --open
```

The command reads supported manifests and lockfiles, retrieves package advisories, and compares versions on your machine. **The default mode does not install dependencies or execute project code.**

### 3. Review the report

The report is saved to `./reports/<project>-<timestamp>.html`, relative to the directory where you ran the command, and opens in your browser. The terminal also prints its path and a link to open it.

| Report section | What it helps you do |
| --- | --- |
| Summary and priorities | Decide what to review first using the evaluation, severity, and available known-exploitation data. |
| Advisories and evidence | Check CVE/GHSA identifiers, the component, version, and source behind a finding. |
| Locations | Find the relevant service, manifest, or lockfile and, when available, the originating dependency. |
| Coverage | Distinguish evaluated components from unknown versions, skipped files, and ecosystems without data. |
| Suggested actions | Plan an update when enough information is available; the CLI does not perform it. |

**[View the sample Markdown report](examples/audit-informe.md)** · [Sample HTML](examples/audit-informe.html) — Spanish samples with fictional test data, not a real audit. Download the HTML and open it in your browser to see the rendered report.

> A version within an affected range needs review; it does not prove that your application is exploitable. “No advisories found” describes the data queried and is not a guarantee that the project is secure.

## Supported ecosystems

| Ecosystem | Files analyzed | Coverage |
| --- | --- | --- |
| JavaScript / TypeScript | `package.json`, `package-lock.json` v1–v3, `yarn.lock` Classic/Berry | Workspaces, direct and transitive dependencies, resolved versions, and usage scope. |
| PHP / Composer | `composer.json`, `composer.lock` | Composer packages, including Laravel and Symfony; production and development dependencies. |
| Java / Maven | `pom.xml` | Static reading of modules, parents, BOMs, and direct dependencies. Optional effective resolution. |
| Go | `go.mod`, `go.work` | Modules, declared versions, and replacements. Does not reconstruct the resolved graph by running Go. |
| Local WordPress | `wp-includes/version.php`, `wp-content/plugins/*` | Core and plugin inventory. Optional editorial advisories; WordPress is not covered by the technical catalog. |

Lockfiles help distinguish a resolved version from a declared range such as `^1.0.0`. When there is not enough information to compare versions, the result remains **“Undetermined.”**

**Current limits:** pnpm is detected, but its lockfiles and workspaces are not resolved; declarations from `package.json` are used instead. `npm-shrinkwrap.json`, Python, Gradle, Ruby, Rust, .NET, and WordPress themes or mu-plugins are not analyzed. Advisory coverage depends on the DayZeroHub catalog and is reflected in the report.

## Usage examples

**Save an HTML report to a chosen location:**

```bash
mateprobe --lang en audit --path "./my-project" --format html --output "./reports/audit.html" --open
```

**Generate Markdown:**

```bash
mateprobe --lang en audit --path "./my-project" --format md --output "./reports/audit.md"
```

**Export the full detail alongside the report:**

```bash
mateprobe --lang en audit --path "./my-project" --format html --export-dir "./detail"
```

| Exported file | Contents |
| --- | --- |
| `inventory.json` / `inventory.csv` | Complete component inventory. |
| `findings.json` | Technical findings and version evaluations. |
| `coverage.json` | Analysis coverage and limitations. |

**Exclude a directory:**

```bash
mateprobe --lang en audit --path "./my-project" --format html --exclude "/legacy/"
```

By default, `.gitignore` and `.git/info/exclude` are respected, and installed dependencies, caches, and generated directories such as `node_modules`, `vendor`, `dist`, `build`, and `target` are skipped. Files already tracked by Git are not discarded by `.gitignore` rules; default exclusions and `--exclude` still apply.

**Change the interface and report language:**

```bash
mateprobe --lang en audit --path "./my-project" --format html --open
mateprobe --lang es audit --path "./my-project" --format html --open
```

You can also set the environment variable `MATEPROBE_LANG=en` or `MATEPROBE_LANG=es`.

<details>
<summary>Maven: include the effective dependency tree</summary>

The default mode reads `pom.xml` without running Maven; transitive dependencies and unresolved parents/BOMs remain pending. To obtain the effective tree, you need Maven and a JDK installed:

```bash
mateprobe --lang en audit --path "./backend" --format html --maven-resolve --open
```

This mode **runs `mvn dependency:tree` and may download artifacts and execute project plugins or extensions**. It is optional and does not use `./mvnw`. If it fails, the report retains the static analysis and shows the limitation.

You can adjust `--maven-bin`, `--maven-timeout` (default `10m`), and `--maven-profile` (repeatable).

</details>

## Optional configuration

`mateprobe login` and `--format html` are enough to get started. To save preferences, create a configuration file outside your project, such as `~/.config/mateprobe/audit.env` on Linux/macOS:

```dotenv
report_format=html
# Only if you prefer a manual API key over the one saved by login:
# api_key=YOUR_TECHNICAL_API_KEY
# Optional, to add the editorial feed (uses a separate key):
# news_api_key=YOUR_EDITORIAL_API_KEY
```

```bash
mateprobe --lang en audit --path "./my-project" --env-file "$HOME/.config/mateprobe/audit.env" --open
```

On Windows, save the file wherever you prefer and pass its path with `--env-file`.

| Setting | Priority, highest first |
| --- | --- |
| Technical API key | `api_key` environment variable → configuration file → saved `login` key → hidden terminal prompt. |
| Format | `--format` → `report_format` environment variable → configuration file → interactive prompt (Enter selects HTML). |

The names `api_key`, `news_api_key`, and `report_format` are **lowercase**. The file is read as text; commands are not executed and variables are not expanded. Do not commit keys to your repository.

Without `--env-file`, the CLI tries to read `./.env` **in the current directory**. It does not locate an `.env` through `--path`; if you run it from the audited directory, those locations are the same. Use an explicit file to keep CLI configuration separate from your application.

The personal key obtained through `login` works with the technical API. The optional `news_api_key` is for the editorial feed; omitting it does not prevent the technical report. For non-interactive runs, configure both the key and report format beforehand.

<details>
<summary>Audit options reference</summary>

| Option | Purpose |
| --- | --- |
| `--path PATH` | Directory to analyze; required. |
| `--format html` / `--format md` | Report format. |
| `--output PATH` | Destination file or directory. An explicit filename is overwritten; automatic names preserve previous reports. |
| `--open` | Open the report with the default application. |
| `--env-file FILE` | CLI configuration file. |
| `--export-dir DIR` | Export inventory, technical findings, and coverage. |
| `--exclude PATTERN` | Exclude paths using `.gitignore` syntax; repeatable. |
| `--include PATTERN` | Re-include skipped paths; prefer anchored patterns such as `/directory/`. Repeatable. |
| `--no-gitignore` | Do not apply `.gitignore` rules. |
| `--no-default-excludes` | Disable default exclusions; `.git` is never traversed. |
| `--ignore-git-index` | Do not use the Git index to identify tracked files. |
| `--follow-symlinks` | Follow links within the audited root, without cycles. |

Exclusion precedence: defaults → `.gitignore` → `--exclude` → `--include`. To see all options available in your version:

```bash
mateprobe --lang en audit --help
```

</details>

## Detect a website's technologies (no account)

`scan` needs no account, API key or `login`, and **sends nothing to DayZeroHub**: it queries the site directly from your machine. It is passive (ordinary `GET` requests; it does not enumerate directories or probe for vulnerabilities). Use it only on systems you own or are authorized to test.

```bash
mateprobe scan --target example.com
mateprobe scan --target 192.168.1.0/24 --exclude 192.168.1.1
mateprobe scan --input targets.txt --format html --output report.html
```

Each technology states how it was detected (`declared`, `signature` or `inferred`), its confidence and the evidence. It accepts domains, URLs, IPs, CIDR and ranges; formats `table`, `json`, `csv` and `html`. All options: `mateprobe scan --help`. Full detail in the [technical reference](docs/REFERENCE.md).

## Commands and help

`mateprobe --help` lists the commands (`login`, `logout`, `audit`, `scan`) and `mateprobe <command> --help` shows each one's options. The [technical reference](docs/REFERENCE.md) covers `scan`, advisory correlation, Maven, the DayZeroHub API and the MateAudit integration.

## Privacy

| Operation | What is shared with DayZeroHub |
| --- | --- |
| Advisory lookup | The ecosystem and name of each queried package. Version comparison happens locally; versions, paths, and file contents are not uploaded. |
| `login` | An installation name based on `user@host` to identify the authorization. You enter your password on the portal, not in the CLI. |
| Usage summary | On `main`, after v0.1.0: CLI version, OS/architecture, status, counts, and an identifier derived from a hash of the path. Associated with your account when using a personal key. |

The usage summary does not contain package names, plaintext paths, dependency versions, or individual advisories. The server receives your IP and may derive your country. **This is separate from advisory lookups, which do send package names.**

To disable usage summaries, set the environment variable `MATEPROBE_TELEMETRY=off` (`export MATEPROBE_TELEMETRY=off` in Bash/Zsh; `$env:MATEPROBE_TELEMETRY="off"` in PowerShell). This does not disable the queries required for the audit.

Reports are saved locally. HTML is self-contained, with no JavaScript or external resources. Reports may include paths and dependency details; review them before sharing.

To remove the credential stored on this machine:

```bash
mateprobe --lang en logout
```

To invalidate the key on the server as well, revoke it under **Technical API** in the [DayZeroHub dashboard](https://dayzerohub.site/app).

## Troubleshooting

| Situation | What to check |
| --- | --- |
| `mateprobe: command not found` / command not recognized | Check the installation `PATH`, or use the executable's full path. On Linux/macOS: `"$HOME/.local/bin/mateprobe" --version`. In PowerShell: `& "$env:LOCALAPPDATA\mateprobe\mateprobe.exe" --version`. |
| Checksum mismatch | Do not install that file; download the binary and `SHA256SUMS` again from the same release. |
| Login code expired | Run `mateprobe login` again and confirm the current code. |
| API key rejected / HTTP 401 | Check whether `api_key` in your environment or configuration file overrides the saved key. Correct it or authorize again with `mateprobe login`. |
| Missing configuration in CI or with redirected output | Supply `api_key` through your environment's secret settings and add `--format html` or `--format md`. |
| Editorial feed skipped | It is optional. In v0.1.0, skipping it can return code `2` even when the technical query completed. Set `news_api_key` if you need it. |
| `--open` does not launch a browser | The report is still saved. Open the printed path; on Linux, check that `xdg-open` and a graphical session are available. |
| Partial report / “Undetermined” | Review coverage, unresolved versions, and query errors before drawing conclusions. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Query completed; **vulnerabilities and coverage limitations may still exist**. |
| `1` | Usage, configuration, read, or write error. |
| `2` | Partial report due to an incomplete query; in v0.1.0 this also occurs when the editorial feed is skipped. |
| `130` | Interrupted with Ctrl+C; interruption during inventory may leave no report. |

The exit code describes execution status, not the severity of findings. It does not provide a vulnerability threshold for blocking CI.

<details>
<summary>Build from source</summary>

Requires Git and **Go 1.27.4 or later**, as declared in [go.mod](go.mod). From Bash/Zsh:

```bash
git clone https://github.com/maxirossi/dayzerohub-cli.git
cd dayzerohub-cli
go build -trimpath -o ./dist/mateprobe ./cmd/mateprobe
./dist/mateprobe --version
```

On Windows, build with `go build -trimpath -o .\dist\mateprobe.exe ./cmd/mateprobe` and run `.\dist\mateprobe.exe --version`. For contributions, `make check` runs formatting checks, static analysis, and tests (requires Make).

</details>

## License and links

Distributed under [GNU GPL v3.0](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attributions.

[DayZeroHub portal](https://dayzerohub.site/) · [Downloads](https://github.com/maxirossi/dayzerohub-cli/releases/latest) · [Report an issue](https://github.com/maxirossi/dayzerohub-cli/issues) · [Español](README.md)
