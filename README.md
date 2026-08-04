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
- `--sca` — also run **dependency scanning (SCA)**: parses `requirements.txt` and `package-lock.json`,
  queries **OSV.dev** (free, no key) and reports known CVEs per package, with the fixed version and a
  link. Runs standalone too (`--sca --no-registry --no-raptor` = SCA only, no Semgrep needed).
- `--no-raptor` / `--no-registry` — drop one of the rule sources.
- `--raptor-rules DIR` — point at a different RAPTOR rules folder (e.g. your own RAPTOR checkout).
- `--exclude PATTERN` — extra exclusion (repeatable). `node_modules`, `.git`, `dist`, `venv`,
  `site-packages`, `.tox`, build/cache dirs, etc. are excluded by default.
- `--fail-on {CRITICAL,ERROR,HIGH,WARNING,MEDIUM,INFO,LOW}` — non-zero exit if a real finding at/above
  that severity exists.

### In CI (pull-request gate)

```bash
# scan only what changed in the PR, emit SARIF, fail on HIGH+
python raptor_win.py . --changed origin/main --sarif results.sarif --fail-on HIGH
# then, in GitHub Actions:  uses: github/codeql-action/upload-sarif  with: sarif_file: results.sarif
```

## Triage built in

Taint findings (SSRF / path-traversal / injection) inside **tests, scripts and tooling** are tagged
*"provável falso-positivo"* — those paths usually reach *your own* known endpoints/paths, not
attacker-controlled input, so they are rarely exploitable. Findings outside tooling are what you
should confirm first. Static analysis reports *possibilities*; you still validate exploitability.

## Credits & licence

- `raptor-win` (this wrapper): **MIT** — see `LICENSE`.
- Bundled rules under `rules/raptor/` are from the **RAPTOR** project by Gadi Evron, Daniel Cuthbert,
  Thomas Dullien (Halvar Flake), Michael Bargury and John Cartwright — redistributed under their
  **MIT** licence. See `THIRD_PARTY/RAPTOR-LICENSE.txt` and `NOTICE`. Some RAPTOR rules reference
  CodeQL, which has its own non-commercial licence; `raptor-win` itself does not run CodeQL.
- Semgrep and its Registry packs are © r2c/Semgrep, used per their terms.
