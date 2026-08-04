#!/usr/bin/env python3
"""raptor-win — a Windows-friendly SAST runner.

Runs Semgrep with RAPTOR's open-source rule set *plus* Semgrep Registry security
packs, auto-detecting the languages in the target, then deduplicates and triages
the findings into a readable report (console / Markdown / JSON).

Why this exists
---------------
The RAPTOR framework (https://github.com/gadievron/raptor) is Linux-only for its
dynamic half (Landlock/seccomp sandbox, rr, AFL++ fuzzing). Its *static* half —
Semgrep + a curated rule set — is perfectly portable. `raptor-win` packages that
static half so you can scan a codebase from a plain Windows shell (works on
macOS/Linux too), with no Docker/WSL and nothing to compile.

It is NOT affiliated with the RAPTOR project. The bundled rules under
`rules/raptor/` are RAPTOR's, redistributed under their MIT licence (see
THIRD_PARTY/RAPTOR-LICENSE.txt). Everything else here is a thin wrapper.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAPTOR_RULES = HERE / "rules" / "raptor"

# Extensions -> Semgrep Registry packs to add when that language is present.
LANG_PACKS: dict[str, list[str]] = {
    ".ts": ["p/typescript"], ".tsx": ["p/typescript", "p/react"],
    ".js": ["p/javascript"], ".jsx": ["p/react"], ".mjs": ["p/javascript"], ".cjs": ["p/javascript"],
    ".py": ["p/python"], ".go": ["p/golang"], ".rb": ["p/ruby"], ".java": ["p/java"],
    ".php": ["p/php"], ".cs": ["p/csharp"], ".c": ["p/c"], ".h": ["p/c"], ".cpp": ["p/cpp"],
    ".tf": ["p/terraform"], ".dockerfile": ["p/dockerfile"], ".yml": [], ".yaml": [],
}
# Packs added regardless of language.
ALWAYS_PACKS = ["p/secrets"]

# Directories never worth scanning (dependencies, build output, generated caches).
# Scanning third-party code just floods the report with other people's findings.
SKIP_DIRS = {
    # deps / envs
    "node_modules", ".venv", "venv", "site-packages", ".tox", ".eggs", "eggs",
    "vendor", "bower_components",
    # build output
    "dist", "build", "out", ".out", "target", ".next", ".nuxt", ".svelte-kit",
    ".angular", ".serverless", ".terraform",
    # caches / vcs / tooling
    ".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".gradle", ".cache", "htmlcov",
}

# Severity ordering (Semgrep uses ERROR/WARNING/INFO; registry rules also emit
# CRITICAL/HIGH/MEDIUM/LOW in extra.severity/metadata).
SEV_RANK = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3, "MEDIUM": 4, "INFO": 5, "LOW": 6}
# Map to SARIF levels (GitHub Code Scanning understands error/warning/note).
SARIF_LEVEL = {"CRITICAL": "error", "ERROR": "error", "HIGH": "error",
               "WARNING": "warning", "MEDIUM": "warning", "INFO": "note", "LOW": "note"}

# Paths that are dev tooling / tests — taint findings there are usually false
# positives (they hit *your own* known endpoints/paths, not attacker input).
TOOLING_RE = re.compile(
    r"(^|[\\/])(tests?|spec|specs|__tests__|scripts?|tools?|examples?|fixtures?|e2e|benchmarks?)([\\/]|$)"
    r"|(test|spec|pentest|verificar|verify|conferir|doctor|smoke)\.",
    re.IGNORECASE,
)
TAINT_CATEGORIES = ("ssrf", "path_traversal", "path-traversal", "injection", "traversal")


def find_semgrep() -> str | None:
    """Locate the semgrep executable, including the Windows per-user Scripts dir
    that pip does not always add to PATH."""
    exe = shutil.which("semgrep")
    if exe:
        return exe
    candidates: list[Path] = []
    import sysconfig
    for key in ("scripts", "purelib"):
        try:
            candidates.append(Path(sysconfig.get_path(key)) / "semgrep.exe")
        except Exception:
            pass
    # pip --user location on Windows Store Python
    try:
        import site
        for base in site.getsitepackages() + [site.getusersitepackages()]:
            candidates.append(Path(base).parent / "Scripts" / "semgrep.exe")
    except Exception:
        pass
    for c in candidates:
        if c and c.exists():
            return str(c)
    return None


def detect_languages(targets: list[Path]) -> set[str]:
    exts: set[str] = set()
    for t in targets:
        if t.is_file():
            exts.add(t.suffix.lower())
            continue
        for p in t.rglob("*"):
            if p.is_dir():
                if p.name in SKIP_DIRS:
                    # prune by skipping; rglob can't prune, so we filter on files below
                    continue
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            exts.add(p.suffix.lower())
    return exts


def build_configs(exts: set[str], use_raptor: bool, use_registry: bool,
                  raptor_rules: Path) -> list[str]:
    configs: list[str] = []
    if use_raptor and raptor_rules.exists():
        configs.append(str(raptor_rules))
    if use_registry:
        packs: list[str] = list(ALWAYS_PACKS)
        for e in exts:
            packs += LANG_PACKS.get(e, [])
        # dedup, keep order
        seen: set[str] = set()
        for p in packs:
            if p not in seen:
                seen.add(p)
                configs.append(p)
    return configs


def severity_of(res: dict) -> str:
    extra = res.get("extra", {})
    meta = extra.get("metadata", {}) or {}
    for key in (meta.get("severity"), extra.get("severity")):
        if key:
            k = str(key).upper()
            if k in SEV_RANK:
                return k
    return "INFO"


def run_semgrep(semgrep: str, configs: list[str], targets: list[Path], excludes: list[str]) -> dict:
    cmd = [semgrep, "--json", "--metrics=off", "--quiet", "--disable-version-check"]
    for c in configs:
        cmd += ["--config", c]
    for d in SKIP_DIRS:
        cmd += ["--exclude", d]
    for ex in excludes:
        cmd += ["--exclude", ex]
    cmd += [str(t) for t in targets]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if not proc.stdout.strip():
        sys.stderr.write(proc.stderr or "semgrep produced no output\n")
        raise SystemExit(2)
    return json.loads(proc.stdout)


def classify_context(path: str, check_id: str) -> str:
    is_tooling = bool(TOOLING_RE.search(path))
    is_taint = any(cat in check_id.lower() for cat in TAINT_CATEGORIES)
    if is_tooling and is_taint:
        return "tooling/test (triagem: provável falso-positivo — alvo próprio, não entrada externa)"
    if is_tooling:
        return "tooling/test"
    return ""


def collect(sg: dict) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in sg.get("results", []):
        path = r.get("path", "")
        line = r.get("start", {}).get("line", 0)
        cid = r.get("check_id", "")
        key = (cid, path, line)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "rule": cid,
            "severity": severity_of(r),
            "path": path,
            "line": line,
            "message": (r.get("extra", {}).get("message", "") or "").strip(),
            "context": classify_context(path, cid),
        })
    out.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))
    return out


def short_rule(rule: str) -> str:
    return rule.split(".")[-1] if "." in rule else rule


def render_console(findings: list[dict], files_scanned: int, rules_run: int) -> None:
    by_sev = Counter(f["severity"] for f in findings)
    print("\n" + "=" * 62)
    print(" raptor-win — relatório SAST")
    print("=" * 62)
    print(f" arquivos escaneados : {files_scanned}")
    print(f" regras executadas   : {rules_run}")
    order = sorted(by_sev, key=lambda s: SEV_RANK.get(s, 9))
    print(" achados por severidade: " + (", ".join(f"{s}={by_sev[s]}" for s in order) or "0"))
    real = [f for f in findings if "provável falso-positivo" not in f["context"]]
    print(f" total: {len(findings)}  ·  fora de tooling/teste: {len(real)}")
    print("-" * 62)
    if not findings:
        if files_scanned == 0:
            print(" ⚠ 0 arquivos escaneáveis. O Semgrep ignora por padrão pastas como")
            print("   test/ tests/ fixtures/ node_modules/ .venv/ — aponte para o código-")
            print("   fonte (ex.: 'src' ou a raiz do app), não para uma pasta de testes.")
        else:
            print(" Nenhum achado. ✅")
        return
    for f in findings:
        tag = f"  [{f['context']}]" if f["context"] else ""
        print(f" [{f['severity']:<8}] {short_rule(f['rule'])}")
        print(f"   {f['path']}:{f['line']}{tag}")
        if f["message"]:
            print(f"   {f['message'][:160]}")
        print()
    print("Triagem: findings marcados como 'provável falso-positivo' são de taint")
    print("(SSRF/path-traversal/injeção) em scripts/testes que acessam seus próprios")
    print("recursos — reveja, mas normalmente não são exploráveis. Confirme os demais.")


def render_markdown(findings: list[dict], target: str, files_scanned: int, rules_run: int) -> str:
    by_sev = Counter(f["severity"] for f in findings)
    order = sorted(by_sev, key=lambda s: SEV_RANK.get(s, 9))
    lines = [
        f"# raptor-win — relatório SAST",
        "",
        f"- **Alvo:** `{target}`",
        f"- **Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- **Arquivos escaneados:** {files_scanned}",
        f"- **Regras executadas:** {rules_run}",
        f"- **Achados:** {len(findings)} (" + (", ".join(f"{s}: {by_sev[s]}" for s in order) or "0") + ")",
        "",
        "| Sev | Regra | Local | Contexto |",
        "|-----|-------|-------|----------|",
    ]
    for f in findings:
        lines.append(
            f"| {f['severity']} | `{short_rule(f['rule'])}` | `{f['path']}:{f['line']}` | {f['context'] or '-'} |"
        )
    lines += [
        "",
        "> Triagem: findings em `tooling/test` de categorias de taint (SSRF/path-traversal/injeção)",
        "> costumam ser falsos-positivos (acessam recursos próprios, não entrada de terceiros).",
        "> As regras `rules/raptor/` são do projeto RAPTOR (MIT). Ver `THIRD_PARTY/RAPTOR-LICENSE.txt`.",
    ]
    return "\n".join(lines)


def to_sarif(findings: list[dict]) -> dict:
    """SARIF 2.1.0 mínimo e válido — pronto para o GitHub Code Scanning."""
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f["rule"]
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": short_rule(rid)}})
        try:
            uri = os.path.relpath(f["path"]).replace("\\", "/")
        except ValueError:
            uri = f["path"].replace("\\", "/")
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"] or short_rule(rid)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, int(f["line"] or 1))},
            }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "raptor-win",
                "informationUri": "https://github.com/RicardoBiazin/raptor-win",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def changed_files(target: Path, ref: str) -> "list[Path] | None":
    """Arquivos alterados desde `ref` (git). None = git indisponível/não é repo."""
    root = target if target.is_dir() else target.parent
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if top.returncode != 0:
        return None
    base = Path(top.stdout.strip())
    diff = subprocess.run(["git", "-C", str(base), "diff", "--name-only", ref],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        return None
    files = []
    for line in diff.stdout.splitlines():
        p = (base / line).resolve()
        if p.is_file() and str(p).startswith(str(target)):
            files.append(p)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="raptor-win",
        description="SAST runner (Semgrep + RAPTOR rules + registry packs) para Windows/macOS/Linux.",
    )
    ap.add_argument("target", nargs="+", help="pasta(s) ou arquivo(s) a escanear")
    ap.add_argument("--md", metavar="FILE", help="escreve relatório Markdown")
    ap.add_argument("--sarif", metavar="FILE", help="escreve SARIF 2.1.0 (upload no GitHub Code Scanning)")
    ap.add_argument("--json-out", metavar="FILE", help="escreve o JSON bruto do Semgrep")
    ap.add_argument("--changed", metavar="REF", help="escanear só arquivos alterados desde <ref> git (ex.: origin/main)")
    ap.add_argument("--no-raptor", action="store_true", help="não usar as regras do RAPTOR")
    ap.add_argument("--no-registry", action="store_true", help="não usar os packs do Semgrep Registry")
    ap.add_argument("--raptor-rules", metavar="DIR", help="caminho alternativo para as regras do RAPTOR")
    ap.add_argument("--exclude", action="append", default=[], help="padrão de exclusão (repetível)")
    ap.add_argument("--fail-on", choices=list(SEV_RANK), help="sai com código 1 se houver achado real >= esta severidade")
    args = ap.parse_args()

    semgrep = find_semgrep()
    if not semgrep:
        sys.stderr.write(
            "Semgrep não encontrado. Instale com:\n"
            "  python -m pip install semgrep\n"
            "e garanta que a pasta Scripts do Python esteja no PATH.\n"
        )
        return 2

    targets = [Path(t).resolve() for t in args.target]
    for t in targets:
        if not t.exists():
            sys.stderr.write(f"alvo inexistente: {t}\n")
            return 2

    if args.changed:
        cf = changed_files(targets[0], args.changed)
        if cf is None:
            sys.stderr.write("--changed: git indisponível ou o alvo não é um repositório git.\n")
            return 2
        if not cf:
            print(f"Nenhum arquivo alterado desde {args.changed}. Nada a escanear. ✅")
            return 0
        targets = cf
        print(f"modo --changed: {len(targets)} arquivo(s) alterado(s) desde {args.changed}")

    raptor_rules = Path(args.raptor_rules).resolve() if args.raptor_rules else RAPTOR_RULES
    exts = detect_languages(targets)
    configs = build_configs(exts, not args.no_raptor, not args.no_registry, raptor_rules)
    if not configs:
        sys.stderr.write("nenhuma configuração de regra selecionada.\n")
        return 2

    print(f"raptor-win: semgrep={semgrep}")
    print(f"linguagens detectadas: {', '.join(sorted(e for e in exts if e)) or '—'}")
    print(f"configs: {', '.join(configs)}")

    sg = run_semgrep(semgrep, configs, targets, args.exclude)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(sg, indent=2), encoding="utf-8")

    findings = collect(sg)
    files_scanned = len(sg.get("paths", {}).get("scanned", [])) or 0
    rules_run = len({r.get("check_id") for r in sg.get("results", [])})

    render_console(findings, files_scanned, rules_run)
    if args.md:
        Path(args.md).write_text(render_markdown(findings, str(targets[0]), files_scanned, rules_run), encoding="utf-8")
        print(f"\nMarkdown: {args.md}")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
        print(f"SARIF: {args.sarif}")

    if args.fail_on:
        floor = SEV_RANK[args.fail_on]
        real = [f for f in findings if "provável falso-positivo" not in f["context"]
                and SEV_RANK.get(f["severity"], 9) <= floor]
        if real:
            print(f"\nfail-on={args.fail_on}: {len(real)} achado(s) real(is) >= {args.fail_on}.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
