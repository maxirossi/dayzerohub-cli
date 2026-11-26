package main

import "github.com/maxirossi/mateprobe/i18n"

// Los textos de ayuda en español viven junto a cada comando (usage, auditUsage, loginUsage); aquí están las versiones en inglés.

const usageEN = `mateprobe — local security scanner: detects web technologies and audits dependencies against DayZeroHub

Usage:
  mateprobe <command> [options]

Commands:
  login     authorize this machine with your DayZeroHub account and store your API key
  logout    delete the API key stored on this machine
  audit     audit a local project (dependencies vs. DayZeroHub advisories)
  scan      detect the technologies of websites (domains, URLs, IPs, CIDR)
  version   show the version
  help      show this help

Global options:
  --lang es|en      interface language (also MATEPROBE_LANG; otherwise the system locale)
  -h, --help        help (also: mateprobe <command> --help)
  -v, --version     version

Examples:
  mateprobe login
  mateprobe audit --path ./my-project --open
  mateprobe scan --target example.com

More information: https://github.com/maxirossi/dayzerohub-cli
`

const scanUsageEN = `mateprobe scan — local web technology detection

Usage:
  mateprobe scan --target X [options]

Targets (at least one of --target / --input):
  --target X        domain, URL, IP, CIDR or IPv4/IPv6 range (repeatable)
  --input FILE      file with one target per line; # = comment (repeatable)
  --exclude X       IP, CIDR or domain to exclude, also on redirects (repeatable)
  --max-addresses N maximum IP addresses per run (default 256)

Connection:
  --port PROTO:N    extra port for targets without a scheme: http:8080, https:8443 (repeatable)
  --resolve H:P:IP  connect to IP while keeping Host and SNI = H (repeatable)
  --insecure        do NOT validate TLS certificates (flagged in the report)

Request control:
  --concurrency N   parallel requests (5)
  --rate R          requests per second, global; 0 = unlimited (5)
  --timeout D       timeout per request (10s)
  --max-redirects N maximum redirects per request (5)
  --max-body BYTES  maximum decompressed body read (2097152)
  --follow-external-redirects  follow redirects to other hostnames
  --allow-host H    follow redirects to H and its subdomains (repeatable)

Output:
  --format F        table (default) | json | csv | html
  --output FILE     write to FILE instead of stdout
  --quiet           do not show progress on stderr

Exit codes:
  0 all targets answered · 1 usage/input/output error
  2 partial results (some target without a response) · 3 no target answered
  130 interrupted with Ctrl+C (completed results are emitted)
`

const auditUsageEN = `mateprobe audit — local project inventory cross-checked against DayZeroHub advisories

Usage:
  mateprobe audit --path /path/to/project [options]

Options:
  --path PATH       directory to analyze (required)
  --env-file FILE   configuration file (default ./.env in the current directory)
  --format F        html | md (if missing: report_format from the environment or .env, or you are asked)
  --output FILE     report path (default ./reports/<project>-<date>.<ext>)
  --open            open the report with the default application

Discovery (what is walked):
  --exclude PATTERN exclude paths (.gitignore syntax, relative to --path); repeatable
  --include PATTERN re-include excluded or ignored paths (e.g. .claude/worktrees/agent-x/); repeatable
  --no-gitignore    do not honor .gitignore files
  --no-default-excludes
                    do not apply the default exclusions (node_modules, target, dist, build,
                    .next, .claude/worktrees, vendor, caches...). .git is never walked
  --ignore-git-index do not use the Git index: by default tracked files are never ignored by .gitignore
  --follow-symlinks follow symlinks only if they point inside --path (no cycles)
  Precedence (last match wins): defaults → .gitignore → --exclude → --include.

Optional outputs:
  --export-dir DIR  writes inventory.json, inventory.csv, findings.json and coverage.json (0600)
  --host            adds the machine to the inventory: operating system, kernel (Linux) and browsers
                    (Linux, macOS and Windows; reads /etc/os-release, sw_vers, "ver", the Windows registry and
                    "<browser> --version"; queried only if the API catalog covers their ecosystem)

Maven (by default only a static read of pom.xml; nothing is executed):
  --maven-resolve   EXPLICIT MODE: runs "mvn dependency:tree" to get the effective tree.
                    Maven may download artifacts and run plugins/extensions of the audited
                    project. ./mvnw is never used. With a timeout; if it fails, the static result remains.
  --maven-bin PATH  Maven executable (default "mvn" from PATH)
  --maven-timeout D maximum time for the effective mode (default 10m)
  --maven-profile P active profile (-P); repeatable

Configuration (lowercase names, in the environment or in the --env-file file):
  api_key           DayZeroHub key (technical API); if missing, the one from "mateprobe login" is used, otherwise you are asked
  news_api_key      optional: editorial feed key (/v1/news); without it the feed is skipped
  report_format     html | md

The analysis is local and read-only: it does not run or install anything from the project.
Exit codes: 0 ok · 1 usage/configuration error · 2 partial report
(incomplete query) · 130 interrupted with Ctrl+C.
`

const loginUsageEN = `Usage:
  mateprobe login    authorize this machine with your DayZeroHub account and store a personal API key
  mateprobe logout   delete the API key stored on this machine (also revoke it in the panel)

The key is stored in the user's config directory with 0600 permissions and is used by "mateprobe audit".
`

func usageText() string      { return i18n.Tr(usage, usageEN) }
func scanUsageText() string  { return i18n.Tr(scanUsage, scanUsageEN) }
func auditUsageText() string { return i18n.Tr(auditUsage, auditUsageEN) }
func loginUsageText() string { return i18n.Tr(loginUsage, loginUsageEN) }
