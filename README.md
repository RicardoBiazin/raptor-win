# raptor-win

**A Windows-friendly SAST runner** — Semgrep + [RAPTOR](https://github.com/gadievron/raptor)'s
open-source rule set + Semgrep Registry packs, with language auto-detection, de-duplication,
severity triage and a readable report. Works on **Windows, macOS and Linux** with just Python.

> Not affiliated with the RAPTOR project. `raptor-win` packages the **static-analysis** slice
> of that ecosystem so you can run it from a plain shell — no Docker, no WSL, nothing to compile.

## Why

RAPTOR is a great autonomous security-research framework, but its *dynamic* half (Landlock/seccomp
sandbox, the `rr` debugger, AFL++ fuzzing) is **Linux-only**. Its *static* half — Semgrep plus a
curated, adversarially-tested rule set — is fully portable. `raptor-win` runs exactly that static
half, so you can scan a codebase on Windows in one command.

For the **full** RAPTOR (fuzzing, crash replay, exploit/patch generation, the autonomous loop), use
**WSL2** or the official **Docker devcontainer** — those need a real Linux kernel.

## What it does / doesn't do

| Does | Doesn't |
|------|---------|
| Static analysis (Semgrep) | Run/execute any target code |
| RAPTOR rules + Registry packs (auto by language) | Fuzzing, binary analysis, `rr` |
| **Dependency scanning (SCA) via OSV.dev** (`--sca`) | Generate exploits or patches |
| **Typosquat detection** on dependency names (`--sca`) | — |
| **Secret scanning (`--secrets`)**, incl. secret files not in `.gitignore` | — |
| De-dup, severity triage, tooling/test heuristic | Need a sandbox (it never executes code) |
| Console + Markdown + **SARIF** + raw JSON report | — |
| Diff mode (`--changed`) + CI exit codes (`--fail-on`) | — |

## Install

```bash
python -m pip install semgrep      # the only dependency
git clone https://github.com/RicardoBiazin/raptor-win.git
```

On Windows, make sure the Python **Scripts** folder (where pip puts `semgrep.exe`) is on your PATH,
or just use the launcher `raptor-win.ps1`, which finds it for you.

## Usage

```bash
# scan a project
python raptor_win.py path/to/your/project

# write a Markdown report and the raw JSON
python raptor_win.py path/to/project --md report.md --json-out findings.json

# CI gate: exit 1 if there is a real (non-tooling) finding at HIGH or above
python raptor_win.py path/to/project --fail-on HIGH

# only the RAPTOR rules, no Registry packs
python raptor_win.py path/to/project --no-registry
```

Windows launcher (puts `semgrep` on PATH automatically):

```powershell
.\raptor-win.ps1 path\to\your\project --md report.md
```

### Options

- `--md FILE` — write a Markdown report.
- `--sarif FILE` — write a SARIF 2.1.0 report you can upload to **GitHub Code Scanning**
  (`github/codeql-action/upload-sarif`), so findings show up in the repo's Security tab.
- `--json-out FILE` — write Semgrep's raw JSON.
- `--changed REF` — scan **only files changed since a git ref** (e.g. `origin/main`). Perfect for
  pull-request / CI gating: fast, and it fails only on *new* problems.
- `--secrets` — also run **secret scanning**. Two things, and the second is the one
  content scanners don't do:

  1. **Credential patterns** in file contents — private keys, AWS/GitHub/Slack/Stripe/Google
     tokens, Supabase `sb_secret_`, OpenAI `sk-`, Groq `gsk_`, NVIDIA `nvapi-`, JWTs, passwords
     embedded in connection strings, plus long literals assigned to secret-looking names.
  2. **Secret-bearing files that git isn't ignoring.** A `.env` outside `.gitignore` hasn't
     leaked *yet* — it leaks on the next `git add -A`, and by then the only real fix is rotating
     the credential. This check asks git directly, so it can't false-positive.

  Runs without Semgrep (`--secrets --no-raptor --no-registry`). Findings join the normal list, so
  they flow through the console, Markdown, SARIF and `--fail-on` with no special handling.

  Precision over recall, deliberately: named provider prefixes instead of entropy scoring. An
  entropy scanner flags every lockfile hash and build id, and a noisy report is a report nobody
  reads. Measured on three real repositories: **0 false positives**.

- `--sca` — also run **dependency scanning (SCA)**: parses `requirements.txt`, `package-lock.json`,
  `poetry.lock`, `Pipfile.lock`, **and enumerates packages actually installed in a project's `.venv`**
  (so unpinned `requirements.txt` still gets checked), then queries **OSV.dev** (free, no key) and
  reports known CVEs per package, with the fixed version and a link. SCA findings join SAST and
  secrets in Markdown, SARIF, accepted-risk baselines and `--fail-on`. Runs standalone too
  (`--sca --no-registry --no-raptor` = SCA only, no Semgrep needed).
- `--no-raptor` / `--no-registry` — drop one of the rule sources.
- `--raptor-rules DIR` — point at a different RAPTOR rules folder (e.g. your own RAPTOR checkout).
- `--exclude PATTERN` — extra exclusion (repeatable). `node_modules`, `.git`, `dist`, `venv`,
  `site-packages`, `.tox`, build/cache dirs, etc. are excluded by default.
- `--baseline [FILE]` — **accepted risks**, checked instead of just documented. Reads
  `.raptor-baseline.toml` (or the file you name) and drops those findings from the `--fail-on`
  count. What makes it different from a plain ignore-list:

  - **`motivo` is required.** No justification means it isn't an accepted risk, it's a hidden one.
    The scan exits 2 if an entry has no real reason.
  - **`ate` is an expiry date.** When it passes, the finding counts again and the tool says the
    deadline lapsed. "Deferred until the next toolchain bump" stops meaning "forever".
  - **Orphan entries are reported** — the finding was fixed and the waiver was left behind.
  - Accepted findings **stay in the report**, marked. Hiding them would be the same blindness the
    file exists to prevent; it changes what *fails*, not what you *see*.

  ```toml
  [[aceito]]
  regra  = "GHSA-qwww-vcr4-c8h2"
  caminho = "package-lock.json"
  motivo = "RSC Mode CSRF: this is a HashRouter SPA, no RSC and no route actions."
  ate    = 2026-11-01
  por    = "ricardo"
  ```

- `--sugerir-baseline` — prints a TOML template for findings not yet waived, for you to paste and
  fill in. Deliberately *not* written straight to the file: a command that accepts everything at
  once is a rubber stamp, and then the baseline stops meaning "someone looked".

- `--fail-on {CRITICAL,ERROR,HIGH,WARNING,MEDIUM,INFO,LOW}` — non-zero exit if a real finding at/above
  that severity exists.

### In CI (pull-request gate)

```bash
# scan only what changed in the PR, emit SARIF, fail on HIGH+
python raptor_win.py . --changed origin/main --sarif results.sarif --fail-on HIGH
# then, in GitHub Actions:  uses: github/codeql-action/upload-sarif  with: sarif_file: results.sarif
```

## Scan many projects at once (`scan-all.ps1`)

To scan **every project under a folder** (each subdirectory = one project) and get a combined
report — ideal for a scheduled/recurring security sweep on Windows:

```powershell
.\scan-all.ps1 -Base C:\DEV
```

It runs SAST + SCA per project, writes `*.sast.md` and `*.log.txt` per project plus a combined
`RESUMO.md` under `C:\DEV\_raptor-reports\<timestamp>\`. It **only verifies and reports** — it never
changes code or pushes (that stays a human decision after reviewing the report). Schedule it, e.g.,
weekly, with Windows Task Scheduler:

```powershell
schtasks /create /tn "raptor-win weekly" /sc weekly /d MON /st 09:00 /f `
  /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\DEV\raptor-win\scan-all.ps1 -Base C:\DEV"
```

## Triage built in

The console prints `total: N · exigem atenção: M` — *M* is what needs a human decision. Three
classes are separated:

| Class | Counts toward "exigem atenção"? | Why |
|---|---|---|
| Taint (SSRF / path-traversal / injection) inside **tests, scripts, tooling** | No | Those paths reach *your own* known endpoints, not attacker input |
| Any finding inside a **deliberately-vulnerable fixture** (`sample_vuln/`, `vuln_samples/`, …) | No | The flaw is the file's expected content — a scanner ships these to prove it detects |
| Anything else in test/tooling code (weak hash, `shell=True`, …) | **Yes** | Test code runs for real, on dev machines and in CI |

Nothing is hidden: every finding stays in the report with its severity and its label. Only the
counter changes.

Test paths are recognised in **English and Portuguese** — `tests/`, `testes/`, `test_foo.py`,
`teste_foo.py`, `foo_test.py`, `foo_teste.py`, `foo.spec.ts`. A verb like `testar_conexao.py`
("to test") is *not* treated as a test file.

For secret files, severity follows the **content**, not the filename: a versioned `.env.demo`
holding only `MARCA=PDV Demo` is reported at `INFO` (the warning still fires — a secret written
there tomorrow lands in history), while the same file holding a real key is `HIGH`. Naming
conventions for templates vary (`.env.demo`, `.env.local`, `.env.ci`), and judging by name is
wrong in both directions.

Static analysis reports *possibilities*; you still validate exploitability.

## Contributors

- [Ricardo Biazin](https://github.com/RicardoBiazin) — creator and maintainer.
- **OpenAI Codex** — AI-assisted code review, implementation and testing.

## Credits & licence

- `raptor-win` (this wrapper): **MIT** — see `LICENSE`.
- Bundled rules under `rules/raptor/` are from the **RAPTOR** project by Gadi Evron, Daniel Cuthbert,
  Thomas Dullien (Halvar Flake), Michael Bargury and John Cartwright — redistributed under their
  **MIT** licence. See `THIRD_PARTY/RAPTOR-LICENSE.txt` and `NOTICE`. Some RAPTOR rules reference
  CodeQL, which has its own non-commercial licence; `raptor-win` itself does not run CodeQL.
- Rules under `rules/raptorwin/` are authored for `raptor-win` (MIT, same as the wrapper), kept
  separate so the RAPTOR credit above stays unambiguous. Current set:
  - `supabase/rls-anon-select` — Postgres/Supabase Row Level Security `SELECT` policy granted to the
    `anon` role. RLS filters rows, not columns, so every column of the matching rows is world-readable
    (stock, cost, internal codes, PII). Flags the pattern for review; the fix is a column-limited view.
  - `supabase/security-definer-view` — view created `WITH (security_invoker = false)` (SECURITY
    DEFINER): runs as the owner and bypasses the querying user's RLS. Prefer `security_invoker = true`.
  - `supabase/function-search-path-mutable` — `SECURITY DEFINER` function with no `SET search_path`,
    open to search-path hijacking. Fix: pin `SET search_path = '' ` (or an explicit schema list).
  - `supabase/grant-execute-anon-public` — `EXECUTE` on a function granted to `anon`/`PUBLIC`, making
    it callable unauthenticated via the REST RPC API; risky when the function is `SECURITY DEFINER`.
  - `supabase/rls-init-auth-uid` — performance: RLS policy calls `auth.uid()`/`auth.role()`/`auth.jwt()`
    directly (re-evaluated per row); wrap as `(select auth.uid())` so the planner caches it.
- `sql_lint.py` — cross-statement SQL checks that Semgrep (one match per snippet) can't correlate,
  run automatically over `*.sql` and merged into the same report:
  - `sql.duplicate-index` — two `create index` on the same table with identical columns/uniqueness.
  - `sql.multiple-permissive-policies` — more than one PERMISSIVE policy for the same table+action+role
    (Postgres ORs them per row); consolidate into one. `RESTRICTIVE` policies are excluded.
- Semgrep and its Registry packs are © r2c/Semgrep, used per their terms.
