# mateprobe

[Español](README.md) · **English**

**A single-binary CLI.** Type `mateprobe audit` and it reads your project, inventories its dependencies, cross-checks them against [DayZeroHub](https://dayzerohub.site) advisories and gives you back a report of what actually affects you. With `mateprobe scan` it detects any site's technologies, from your own machine.

Every finding states **what evidence backs it and how far it can be trusted**, not just a name. No Go, Docker, Node or database required.

> mateprobe is **passive**: it makes ordinary `GET` requests and reads what the site answers. It does not enumerate directories, brute-force or probe for vulnerabilities. Use it only on systems you own or are authorized to test.

```
mateprobe login                                  # authorize this machine with your DayZeroHub account
mateprobe audit --path ./my-project --open       # audit a local project and open the report
mateprobe scan --target example.com              # detect a site's technologies
```

```
reports/
└── my-project-20260101-120000.html    self-contained report, no JS or external resources
--export-dir/
├── inventory.json / inventory.csv     every detected component
├── findings.json                      advisories and their evaluation
└── coverage.json                      what was analyzed and what was not (with the reason)
```

## Installation

**Requires:** just the binary. Download it from [**Releases**](https://github.com/maxirossi/dayzerohub-cli/releases/latest).

| System | File |
|---|---|
| Linux x86-64 / ARM64 | `mateprobe-<version>-linux-amd64` / `-linux-arm64` |
| Windows x86-64 / ARM64 | `mateprobe-<version>-windows-amd64.exe` / `-windows-arm64.exe` |
| macOS Intel / Apple Silicon | `mateprobe-<version>-darwin-amd64` / `-darwin-arm64` |

#### Linux

```bash
V=0.1.0; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')   # amd64 or arm64
BASE=https://github.com/maxirossi/dayzerohub-cli/releases/download/v$V
curl -fLO $BASE/mateprobe-$V-linux-$ARCH && curl -fLO $BASE/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing                  # verify integrity
mkdir -p ~/.local/bin && install mateprobe-$V-linux-$ARCH ~/.local/bin/mateprobe
mateprobe --version
```

#### macOS

```bash
V=0.1.0; ARCH=$(uname -m | sed 's/x86_64/amd64/')          # amd64 (Intel) or arm64 (Apple Silicon)
BASE=https://github.com/maxirossi/dayzerohub-cli/releases/download/v$V
curl -fLO $BASE/mateprobe-$V-darwin-$ARCH && curl -fLO $BASE/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing              # verify integrity
xattr -d com.apple.quarantine mateprobe-$V-darwin-$ARCH   # the binaries are not signed
mkdir -p ~/.local/bin && install mateprobe-$V-darwin-$ARCH ~/.local/bin/mateprobe
mateprobe --version
```

#### Windows (PowerShell)

```powershell
$V = "0.1.0"; $Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$Base = "https://github.com/maxirossi/dayzerohub-cli/releases/download/v$V"
Invoke-WebRequest "$Base/mateprobe-$V-windows-$Arch.exe" -OutFile mateprobe.exe
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
Get-FileHash mateprobe.exe -Algorithm SHA256          # compare with the windows-$Arch line in SHA256SUMS
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\mateprobe" | Out-Null
Move-Item -Force mateprobe.exe "$env:LOCALAPPDATA\mateprobe\mateprobe.exe"
[Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path','User'));$env:LOCALAPPDATA\mateprobe", "User")
```

Open a new terminal and run `mateprobe --version`. If SmartScreen warns you, the binary is not signed yet.

> **`mateprobe: command not found`:** the binary is not on your `PATH`. If `~/.local/bin` is missing, add it to `~/.bashrc` or `~/.zshrc`: `export PATH="$HOME/.local/bin:$PATH"`. For a system-wide install: `sudo install <binary> /usr/local/bin/mateprobe`.

Then:

```
mateprobe login
```

`mateprobe login` shows you a link and a code. Open the link with your [DayZeroHub](https://dayzerohub.site/app) session (a registered, verified account is required), confirm the code, and the terminal receives a **personal API key** that is stored on your machine. You manage (and revoke) it from the **Technical API** section of the dashboard. `mateprobe logout` deletes the local key.

<details>
<summary>Build from source</summary>

Requires Go ≥ 1.27 (only to build). Repository: <https://github.com/maxirossi/dayzerohub-cli>.

```bash
make check       # gofmt + go vet + go test -race
make build       # dist/mateprobe for your platform
make dist        # 6 binaries + SHA256SUMS in dist/
make examples    # regenerate examples/ from local servers and fixtures
make build-linux # dist/mateprobe-<version>-linux-amd64
```

</details>

## Usage

```
mateprobe audit --path ./project                           # audit a local project
mateprobe audit --path ./project --format md --output ./report.md
mateprobe audit --path ./project --export-dir ./out        # full inventory and findings
mateprobe audit --path ./project --maven-resolve           # effective Maven mode (opt-in)

mateprobe scan --target example.com                        # one domain
mateprobe scan --target 192.168.1.0/24 --exclude 192.168.1.1
mateprobe scan --input targets.txt --format html --output report.html

mateprobe --lang es audit --path ./mi-proyecto             # language: es | en (or MATEPROBE_LANG)
```

Works with these ecosystems:

| Type | Files | Extraction |
|------|-------|------------|
| JavaScript/TypeScript | `package.json`, `package-lock.json`, `yarn.lock` | Workspaces, resolved version vs. range, direct/transitive |
| Java | `pom.xml` | Reactor, parents, BOMs; effective mode with `--maven-resolve` |
| PHP | `composer.json`, `composer.lock` | Laravel, Symfony and others |
| Go | `go.mod`, `go.work` | Modules and `replace` |
| WordPress | `wp-includes/version.php`, `wp-content/plugins/*` | Core and plugins |
| Websites | domains, URLs, IPs, CIDR, ranges | Headers, cookies, `<meta>`, HTML resources, signatures |

## What you get

**Unique advisories** - one per advisory, with CVE/GHSA aliases merged and its occurrences (service, scope, lockfile, path).

**Local version evaluation** - the *inside / outside range* decision is made on your machine; only ecosystem + package name reach the API, never versions, paths or files.

**Deterministic priority** - certainty → known exploitation (CISA KEV) → severity → EPSS → production use → CVSS. Missing data is shown as "not available", never as 0.

**Honest coverage** - everything that could not be analyzed is listed with its reason. The report never claims a project is safe.

**Privacy** - cookie values and tokens are never stored, URLs hide credentials, and the audited project's own `.env` is never loaded.

Every `scan` technology is tagged `declared`, `signature` or `inferred`, with its `confidence`: you always know what was observed and what was deduced.

## Stack

Go + wappalyzergo + `net/http`. One static binary, no server, runs entirely locally (`scan` sends nothing to third parties; `login` and `audit` only talk to DayZeroHub).

---

# Reference

## Detailed usage

```bash
mateprobe scan --target example.com
mateprobe scan --target https://example.com/blog
mateprobe scan --target 192.168.1.20
mateprobe scan --target 192.168.1.0/24 --exclude 192.168.1.1
mateprobe scan --target 192.168.1.10-192.168.1.30
mateprobe scan --input targets.txt --concurrency 5 --rate 5
mateprobe scan --target https://example.com --resolve example.com:443:192.168.1.20
mateprobe scan --target example.com --format json --output result.json
mateprobe scan --input targets.txt --format html --output report.html
```

Results go to **stdout** (or to `--output`); progress and warnings go to **stderr** (`--quiet` hides them).

### Targets

| Input | What it does |
|---|---|
| `example.com`, `1.2.3.4`, `2001:db8::1` | Probes `http://…:80` and `https://…:443` (plus any `--port`) |
| `example.com:8080` | Probes `http` and `https` on that port |
| `https://example.com:8443/path?q=1` | Keeps scheme, port, path and query as given |
| `192.168.1.0/24`, `2001:db8::/120` | CIDR (IPv4/IPv6) |
| `192.168.1.10-192.168.1.30` | Inclusive range (IPv4 or IPv6) |
| `--input file.txt` | One target per line; blank lines and `# comments` are ignored |

- **Size limit:** 256 addresses per run (IPv6 too). The size is validated *before* expanding (a `/8` or `::/0` is rejected instantly, without consuming memory). To raise it you must ask explicitly: `--max-addresses 1024`. Every address in the range is counted, including network and broadcast.
- **Exclusions** (`--exclude`, repeatable): IP, CIDR or domain. A domain also excludes its subdomains. They are reapplied on every redirect.
- **Dedupe:** `Example.COM`, `example.com.` and `example.com` are the same target; by contrast, `http://` vs `https://`, a different port, a different path or a different hostname are kept separate.
- **Additional ports** for targets without a scheme, specifying the protocol: `--port http:8080 --port https:8443`.

### Domain, IP, Host and SNI

`--resolve host:port:ip` (repeatable, like `curl --resolve`) connects to the given IP while **keeping** the HTTP `Host`, the TLS SNI and certificate validation against the domain:

```bash
mateprobe scan --target https://example.com --resolve example.com:443:192.168.1.20
```

Redirects to another port need their own rule (e.g. `example.com:80:IP` in addition to `:443:`).

A query by IP describes **only the service or virtual host that answered**; it does not imply that every site hosted on that IP has been discovered.

### TLS

The certificate is validated by default. `--insecure` disables validation explicitly and is flagged in the report (`tls_validation_disabled`, a banner in the HTML, a warning on stderr). There is **never** a silent retry without validation.

### Redirects

- Redirects to the **same hostname** are followed (including HTTP → HTTPS), up to `--max-redirects` (5).
- Those going to **another hostname** are recorded but not followed, unless `--follow-external-redirects` or `--allow-host domain` (includes subdomains) is used.
- Every hop counts toward the rate limit and reapplies exclusions.
- Each response in the chain is analyzed separately and technologies carry the URL and hostname where they were observed. Anything found on **another hostname** is flagged `external: true` and does **not** count toward the target's status.

### Options

| Option | Default | |
|---|---|---|
| `--concurrency N` | 5 | targets in parallel |
| `--rate R` | 5 | **global** requests/sec (including redirects); `0` = unlimited |
| `--timeout D` | 10s | per request |
| `--max-redirects N` | 5 | |
| `--max-body BYTES` | 2097152 | **decompressed** body read per response (2 MiB) |
| `--max-addresses N` | 256 | |
| `--format F` | `table` | `table`, `json`, `csv`, `html` |
| `--output FILE` | stdout | |
| `--quiet` | | no progress on stderr |

User-Agent: `mateprobe/<version> (+https://github.com/maxirossi/mateprobe)`. Ctrl+C cancels gracefully: results already completed are emitted.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All targets responded |
| `1` | Usage, configuration, input or output error |
| `2` | **Partial** result: some target unanswered or incomplete, but others did respond |
| `3` | No target responded |
| `130` | Interrupted with Ctrl+C (completed results are emitted) |

A target "responds" if at least one of its probes got an HTTP response (even a 404/500). A failure on `:80` or `:443` alone does not count as a down target; it is kept in `errors`.

## What each result means

Target states (`status`):

- `detected`: technologies were detected.
- `no_technologies`: **a response was obtained**, but nothing was detected.
- `unreachable`: **could not be queried** (no response at all; see `errors`: `dns`, `connection`, `timeout`, `tls`, `http`, `other`).
- `incomplete`: the run was interrupted before the target finished.

Each technology carries:

| Field | Values |
|---|---|
| `detection` | `declared` (the response states it, e.g. `Server: nginx/1.24.0`), `signature` (a signature matched), `inferred` (deduced from another one; **never observed directly**) |
| `confidence` | `high`, `medium`, `low` or `unknown` (when no rule justifies it) |
| `version` | only if there is evidence; empty if unknown |
| `engine` | engine/rule responsible (`wappalyzergo v0.3.11`, `mateprobe:server-header`…) |
| `evidence` | sanitized, bounded snippet (header, cookie name, `<meta>`, resource) |
| `url`, `host`, `external` | the specific response where it was observed |

Confidence criteria for our own rules: **declared** → `medium` (the server asserts it but it is not independently verified and may be hidden or spoofed); **single-signal signature** → `low`/`medium` depending on its specificity; **two or more distinct, compatible sources** (e.g. `<meta generator>` + `/wp-includes/` + cookie) raise it one level; **inferences** never go up.

What is **not** concluded: React does not imply Node.js · WordPress does not confirm MySQL (databases and operating systems deduced by the signature base are discarded) · Cloudflare does not identify the origin server · a declared version is not verified.

> **wappalyzergo evidence:** the engine only returns `name[:version]` and categories; it **does not expose which pattern matched or any confidence**. Those detections come out with `confidence: unknown`, no evidence and an explicit note (`evidence_note`). Our own rules (headers, cookies, meta generator, HTML resources) do return their evidence. Technologies the engine marks as *implied* by another (WordPress ⇒ PHP) are recorded as `inferred`; if one of our own techniques observed it directly, the observation wins.

### Report privacy

Cookie values are not stored (names only; `Set-Cookie` appears as `name=[redactado]`), nor are `Authorization`/tokens. URLs hide embedded credentials and values of parameters that look sensitive (`token`, `key`, `password`, `session`…). Remote text is stripped of control characters and bounded.

## Output formats

- **table**: readable in a terminal.
- **json**: `schema_version: "1.0"`. Separates `targets[].responses` (observed HTTP responses), `targets[].technologies` (findings) and `targets[].errors`. See `examples/resultado.json`.
- **csv**: one row per technology with a reference to the target (`target_input`, `target`, `status`, `url`…). Targets with no technologies or no response appear with empty technology columns, and `status` tells them apart. Cells starting with `= + - @` are neutralized against formula injection.
- **html**: static, self-contained report, **with no JavaScript or external resources** (with a restrictive CSP). All remote data is escaped; remote HTML is never rendered.

Examples generated from local fixtures (`make examples`): [`examples/resultado.json`](examples/resultado.json), [`examples/resultado.csv`](examples/resultado.csv), [`examples/reporte.html`](examples/reporte.html), [`examples/resultado.txt`](examples/resultado.txt).

## Project audit (`audit`)

`mateprobe audit` analyzes a **local project**, identifies its technologies and dependencies, queries the [DayZeroHub](https://dayzerohub.site) technical API and news feed, and generates an HTML or Markdown report. Web scanning (`scan`) keeps working as before.

```bash
mateprobe audit --path ./my-project
mateprobe audit --path ./project --format html --output ./report.html
mateprobe audit --path ./project --format md   --output ./report.md
mateprobe audit --path ./project --env-file ~/.config/mateprobe/.env --open
```

| Option | Description |
|---|---|
| `--path` | Directory to analyze. **Required.** |
| `--env-file` | Configuration file. Defaults to the `.env` in the directory you run from. |
| `--format` | `html` or `md`. |
| `--output` | Report path. If it is a directory (or ends in `/`), the default file name is used there. |
| `--open` | Opens the report with the default application (`xdg-open`, `open`, `rundll32`; no shell). |
| `--exclude PATTERN` | Excludes paths (`.gitignore` syntax, relative to `--path`). Repeatable. |
| `--include PATTERN` | Re-includes excluded or ignored paths (e.g. `.claude/worktrees/agent-x/`). Repeatable. |
| `--no-gitignore` | Does not honor `.gitignore` files. |
| `--no-default-excludes` | Does not apply the default exclusions (`.git` is never walked). |
| `--ignore-git-index` | Does not use the Git index (see "Discovery"). |
| `--follow-symlinks` | Follows symlinks only if they point inside `--path` and without cycles. |
| `--export-dir DIR` | Writes `inventory.json`, `inventory.csv`, `findings.json` and `coverage.json` (0600) with the full detail. |
| `--maven-resolve` | **Effective Maven mode, explicit** (see "Maven"). |
| `--maven-bin`, `--maven-timeout`, `--maven-profile` | Maven executable, maximum time (10 min by default) and `-P` profiles (repeatable). |

### Discovery and exclusions

The walk **prunes** excluded directories before reading their contents (they are not traversed just to count them). `.gitignore` is honored with Git semantics: nested files, anchored/relative patterns, `**`, negations (`!`) and the rule that a file cannot be re-included under an excluded directory. `.git/info/exclude` too. It works the same without Git and when `--path` is a subdirectory of a repository (ancestor `.gitignore` files apply to descendants, never to the root itself). A worktree (`.git` as a *file*) at the root is a valid project.

**Precedence** (the last match wins): default exclusions → `.gitignore` → `--exclude` → `--include`. By default these are excluded (directories only, at any level): `.git`, `.claude/worktrees`, `node_modules`, `target`, `dist`, `build`, `.next`, `.nuxt`, `.output`, `vendor`, caches (`.cache`, `__pycache__`, `.venv`, `.gradle`, …). `--include` re-includes even if the exclusion comes from the defaults or from `.gitignore`; a pattern without a leading `/` forces reading all excluded directories (use anchored paths).

**Tracked files:** Git ignores `.gitignore` for files already in the index, so mateprobe reads `.git/index` (v2–v4, without running `git`) and does not discard a tracked file because of a `.gitignore` rule. Defaults and `--exclude` take precedence over the index. `--ignore-git-index` turns it off.

Symlinks are not followed by default; with `--follow-symlinks` only if the real target lies inside `--path` and has not been visited. The report lists the applied rules and the skipped directories with their reason.

### Configuration

With `mateprobe login` no configuration file is needed. If you prefer (or need) to configure it by hand, copy `.env.example` to `.env` and fill in the values (`.env` is in `.gitignore`):

```
api_key=REPLACE_WITH_THE_REAL_KEY
report_format=html
news_api_key=OPTIONAL
```

- Names are **lowercase**. The file is read as text: nothing is executed or expanded (`$(...)`, `$VAR` and backticks stay literal). `source` is not used.
- **`api_key`** (technical API): process environment variable → `.env` file → key stored by `mateprobe login` → terminal prompt (`Enter your DayZeroHub API key:`) **without echoing the characters**. It is never printed and there is no flag to pass it as an argument. The normal case is to configure nothing: `mateprobe login` is enough.
- **`news_api_key`** (optional): editorial feed key (`/v1/news`), which is **a different API with a different key**. The `login` key is only valid for the technical API; without `news_api_key` the editorial feed is skipped with a warning and the report is still generated with the technical data.
- **Format**: `--format` > `report_format` environment variable > `.env` file > interactive prompt (Enter = HTML). An invalid value is an error, not ignored.
- Without an interactive terminal and with missing data, the command exits with a clear message (it does not hang waiting).
- This `.env` is **your configuration**; the `.env` of the analyzed project is never looked up or loaded.

### What is detected

Only manifests, lockfiles and metadata are read; **nothing from the project is executed or installed** (except `--maven-resolve`, which is explicit). Several subprojects (frontend, backend, services) are traversed with the discovery rules above.

| Ecosystem | Files | Notes |
|---|---|---|
| JavaScript/TypeScript | `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock` (classic and berry) | **Workspaces** (`workspaces` with globs and `!`): each member is associated with *its* lockfile (the root one if it includes it; otherwise its own; never an ancestor's by proximity). **Resolved** version (`node_modules` resolution over the lockfile graph) vs. **declared range**; direct/transitive with the originating direct dependency (`via`); **production / development / mixed** scope (a version also used in production is never "development"); multiple versions of the same package are kept. Lockfiles with identical content are parsed only once, keeping each provenance |
| Java (Maven) | `pom.xml` | See "Maven" |
| PHP | `composer.json`, `composer.lock` | Laravel, Symfony and others by canonical name; `require`/`require-dev` |
| Go | `go.mod`, `go.work` | Modules, **declared** versions (MVS minimums), `replace`. `go.sum` is not used as a dependency list; the resolved graph cannot be determined without running `go` |
| WordPress | `wp-includes/version.php`, `wp-content/plugins/*` | Core version and `Plugin Name`/`Version` headers of the main PHP file. PHP is not executed and a plugin is not assumed to be active |

### Correlation with advisories (four levels that are not mixed)

1. **Identified component**: the inventory produces ecosystem + name with evidence (lockfile, `go.mod`, metadata). Only package **identities** (`npm`, `Packagist`, `Go`) are sent to the technical API; runtimes (Node.js, PHP, Go) and WordPress are not queried there.
2. **Associated advisory** (`matched`): there are advisories for that identity. It does not yet imply that the local version is affected.
3. **Version within range** — the decision is **local**: the exact version is compared against `ranges`/`versions` according to the `version_scheme` (semver and composer/WordPress; the rest stays "Undetermined"), only if `identity.status = verified` and `range_quality = usable`. OSV semantics: `introduced` inclusive, `fixed` exclusive, `last_affected` inclusive, `limit` exclusive; each `introduced…fixed` is an independent branch; without a closing bound the range is open. Outcomes: *within the affected range* · *outside the reported range* · *Undetermined* (constraints such as `^5.0.0`, unknown version, `GIT` or insufficient ranges, a scheme without a comparator, conflicts between sources, Go `replace`). `go.mod` versions are "declared": they are evaluated with an explicit caveat.
4. **Exploitability not determined**: `known_exploited` / `not_listed_in_kev` / no information is shown; "no information" is never presented as "not exploited".

`no_match`, `ecosystem_not_covered` and `error` do **not** mean "safe": they are reported as "no data". Withdrawn or rejected advisories are not findings (they are counted separately).

The **editorial feed** (`/news`) is also queried as a complement (WordPress, which the technical catalog does not cover, and advisories without ranges): exact identifiers, bounded aliases and textual mentions are used there, always as "component match; version not verified" or "possible textual match". If an editorial advisory shares a CVE/GHSA with a technical finding for the same component, only the technical one is shown. Advisories are deduplicated solely by explicit identifiers.

### DayZeroHub API

Keys travel in the `X-API-Key` header (never in the query). `/api/v1/security/*` routes use the personal `api_key` (the one from `login`); `/api/v1/news` uses `news_api_key`. The URLs are constants in `dzh/client.go` on top of `https://dayzerohub.site`:

| Method and route | Use |
|---|---|
| `GET /api/v1/security/catalog` | Scope (ecosystems) and freshness of the technical catalog |
| `POST /api/v1/security/packages/lookup` | Advisories by identity, in batches of ≤100 components (`limit` 100 per component, `next_cursor` per component, retry only of the `error` ones) |
| `GET /api/v1/security/advisories` | Technical catalog paginated by opaque cursor (`Advisories` method; the report does not need it) |
| `GET /api/v1/news?lang=es` | (with `news_api_key`) Editorial feed: `{items,page,page_size,max_pages}`, up to 5 pages of 20 |

The client (`net/http`) uses a timeout, cancels on Ctrl+C, caps the response size, retries 429/5xx/network errors with exponential backoff and jitter (honoring `Retry-After`, up to 30 s), **does not retry 401** (repeated 401s can get the IP banned; on a 401 all queries are stopped and the partial report is generated), does not forward `X-API-Key` to another origin on a redirect and tolerates extra or `null` fields (`dzh-security/1` contract). If something fails, a **partial report** is still generated with the local inventory and the status "Vulnerability query not completed". **Privacy:** only ecosystem + package name travel to the technical API; never versions, paths or file contents.

### Maven

- **Static mode (default):** `pom.xml` files are read (nothing is executed and no network is used): reactor modules, parent POM (`relativePath`, then the read-only local repository `~/.m2/repository`), properties (`${project.version}`, `${parent.version}`, custom ones), `dependencyManagement`, imported BOMs, scopes (`test` → development) and `activeByDefault` profiles (or those from `--maven-profile`). **Direct** dependencies are resolved; **transitive** ones and versions that depend on missing parents/BOMs/properties remain **pending**, grouped by cause in the report. Reading a `pom.xml` is not the same as having evaluated the whole backend.
- **Effective mode (`--maven-resolve`, explicit):** runs `mvn dependency:tree` once over the root reactor, with a timeout (`--maven-timeout`) and bounded output. **Maven may download artifacts and run plugins and extensions of the audited project** (hence opt-in). `./mvnw` and repository scripts are never used (an executable inside the audited repo is rejected). If Maven is missing, times out or fails, "Maven: effective mode not completed" is reported and the static result remains.
- **Evaluation:** the DayZeroHub API covers Maven (identity `group:artifact`, scheme `maven`); the comparator follows Maven's `ComparableVersion`. The Maven catalog is small: "no advisories" is not a guarantee. If the catalog did not cover Maven, the report shows "inventoried, evaluation not available".

### Unique advisories, occurrences and priority

The report separates **advisory** (with the CVE/GHSA aliases the source declares equivalent merged; distinct advisories are not merged just because they affect the same package), **component+version**, **occurrence** (project/service, scope, lockfile, path) and **evaluation result**. One card per unique advisory; if an advisory is confirmed in one service and undetermined in another, both are shown. Separate counters: unique advisories, affected components and occurrences.

Priority (deterministic and visible in the report): evaluation certainty → known exploitation (CISA KEV) → severity → EPSS (the current API does not report it: "not available") → production use → CVSS → identifier. Missing data is shown as "not available", never as 0 or "no". Update commands are only suggested (never executed) when the package manager, workspace and direct dependency are known; for transitive ones, the guidance is to update the parent or review the resolution.

### Report

- **Compact:** actionable summary at the top, one card per advisory with locations in collapsible sections, coverage problems grouped by cause (counter + examples) and limits on repetitive lists. **The inventory is not embedded**; the full detail goes to `--export-dir` (JSON/CSV; the CSV neutralizes cells starting with `= + - @`).
- **HTML** is self-contained: embedded CSS, no CDN, fonts or remote resources (with a restrictive CSP), escaped with `html/template`; only `http(s)` links are enabled.
- **Markdown** with the same sections: project and date, technologies, subprojects, related advisories (ID, evidence, links), unknown versions, files not analyzed, pages/advisories queried and limitations. Third-party content is escaped.
- Without `--output` it is saved to `./reports/<project>-<YYYYMMDD-HHMMSS>.<ext>` without overwriting earlier reports (`0600` permissions).
- If there are no matches: "No related advisories were found within the queried data." The report never claims that a project is safe.

When finished it shows the status, a summary, the absolute path and an **"Open report"** link (`file://`, with paths containing spaces encoded). In compatible terminals it is an OSC 8 hyperlink (some require Ctrl+click; others do not support local links); the URL is always also printed as plain text. With redirected output no escape sequences are emitted. If `--open` fails, the report is kept and its location is reported.

`audit` exit codes: `0` complete · `1` usage/configuration error · `2` partial report (incomplete query) · `130` interrupted with Ctrl+C.

Examples generated from fixtures: [`examples/audit-informe.html`](examples/audit-informe.html) and [`examples/audit-informe.md`](examples/audit-informe.md) (`make examples`). The report is produced in the active language (`--lang`).

### Not supported yet

`pnpm-lock.yaml` and `pnpm-workspace.yaml` (reported, and only the `package.json` constraints are used), `npm-shrinkwrap.json`, Python, Gradle, Ruby, Rust, .NET and other ecosystems (listed as not analyzed), WordPress themes and `mu-plugins`, source code imports, version comparison for PyPI, RubyGems and NuGet, `GIT` ranges, WordPress technical data (the catalog does not cover it yet), Maven mediation/exclusions/profiles by `jdk`/`os`/`property` without `--maven-resolve`, and exploitability analysis.

## Integration with MateAudit

The core is a set of reusable Go packages:

| Package | Responsibility |
|---|---|
| `targets` | parsing, limits, exclusions and dedupe of targets |
| `collect` | HTTP/TLS, redirects, rate limit, read limits |
| `detect` | wappalyzergo + own rules with evidence |
| `scan` | orchestration with concurrency and cancellation |
| `model` | results (versioned JSON contract) |
| `export` | table, JSON, CSV, HTML |
| `redact` | sanitization and redaction |

```go
eng, _ := detect.New()
list, _ := targets.Expand([]string{"example.com"}, targets.Options{})
rep := scan.Run(ctx, scan.Config{Concurrency: 5, Collect: collect.Config{Rate: 5}}, list, eng)
// rep is a *model.Report; export.JSON(w, rep) to serialize it
```

No-code alternative: consume `--format json` (`schema_version` lets you detect breaking changes).

## Limitations

- **Passive HTML/header analysis only:** JavaScript is not executed and assets are not downloaded. Technologies visible only at runtime (SPAs detected through `window.*`) or inside bundles are not seen.
- **Signatures are a snapshot** embedded in the pinned wappalyzergo version (v0.3.11); they do not update themselves. False positives/negatives of that catalog are inherited.
- **No evidence or confidence** for what only wappalyzergo detects (see above). If the engine directly detects something that it also marks as implied by another technology and none of our own rules confirms it, it is recorded as `inferred` (conservative criterion).
- **Versions** are those the site declares or those a signature extracts; they are not verified. Servers may hide or spoof them.
- The same technology may appear once per URL/response where it was observed (e.g. on both `http://` and `https://`).
- **HTTP/1.1** only (no HTTP/2 or Brotli); environment proxy variables are deliberately ignored.
- IP exclusions are evaluated against literal IPs of targets and redirects; **not** against the IPs a domain resolves to.
- The rate limit is global with burst 1; the timeout applies per request, including redirect requests.
- IPv6 with a zone (`fe80::1%eth0`) is not supported.
- The Windows and macOS binaries are **built** with `make dist`, but in this development only the Linux x86-64 one was **run**.

## License

mateprobe is distributed under the **GNU General Public License v3.0** ([`LICENSE`](LICENSE)). The detection engine embeds a signature base derived from GPL-3.0 repositories, so the whole is licensed under the same license; the source code of every version is in this repository (the `vX.Y.Z` tag matches the release binary). Third-party attributions are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
