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
import urllib.request
from collections import Counter, defaultdict

import baseline as baseline_mod
import secrets_scan

# O CONSOLE DO WINDOWS NÃO É UTF-8 POR PADRÃO. Ele abre em cp1252, que não
# tem "✅" nem os caracteres de moldura do relatório — e o `print` levanta
# UnicodeEncodeError. O efeito era um traceback no lugar do resultado,
# justamente quando NÃO havia achados (o caminho mais comum), e acentos
# corrompidos no resto ("relat�rio"). Numa ferramenta que se anuncia
# Windows-friendly, era o defeito mais caro que ela tinha.
#
# `errors="replace"` em vez de deixar estourar: um terminal antigo que não
# renderize um símbolo deve mostrar "?" ali, não derrubar a varredura
# inteira depois de ela já ter feito todo o trabalho.
for _fluxo in (sys.stdout, sys.stderr):
    try:
        _fluxo.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass   # fluxo redirecionado ou Python sem reconfigure: segue
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
    r"(^|[\\/])(tests?|spec|specs|__tests__|scripts?|tools?|examples?|fixtures?|e2e|benchmarks?|migrations?)([\\/]|$)"
    # scripts/tests/migrations do supabase/ — MENOS as Edge Functions, que são runtime
    r"|(^|[\\/])supabase[\\/](?!functions[\\/])"
    r"|(test|spec|pentest|verificar|verify|conferir|doctor|smoke|sessao|session|validar|sincroniz|sync|migrar|preparar|diagnostico|seed|stamp)\.",
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


# ── SCA (Software Composition Analysis) via OSV.dev — só stdlib, sem chave ──────
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SCA_MANIFESTS = ("requirements.txt", "package-lock.json", "poetry.lock", "Pipfile.lock")
SCA_DETAIL_CAP = 120  # nº máx. de detalhes de vuln buscados (evita floods)


def find_manifests(targets: list[Path]) -> list[Path]:
    out: list[Path] = []
    for t in targets:
        if t.is_file() and t.name in SCA_MANIFESTS:
            out.append(t)
            continue
        if t.is_dir():
            for p in t.rglob("*"):
                if p.name in SCA_MANIFESTS and p.is_file() and not any(x in SKIP_DIRS for x in p.parts):
                    out.append(p)
    return out


def parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    deps = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9._+!-]+)", line)
        if m:  # só pinado (name==version) dá para consultar versão exata
            deps.append(("PyPI", m.group(1), m.group(2)))
    return deps


def parse_package_lock(path: Path) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out: set[tuple[str, str, str]] = set()
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        for k, v in pkgs.items():
            name = k.split("node_modules/")[-1]
            ver = (v or {}).get("version")
            if name and ver:
                out.add(("npm", name, ver))
    else:  # v1: dependencies recursivo
        def walk(deps):
            for name, v in (deps or {}).items():
                ver = (v or {}).get("version")
                if ver:
                    out.add(("npm", name, ver))
                walk((v or {}).get("dependencies"))
        walk(data.get("dependencies"))
    return sorted(out)


def parse_poetry_lock(path: Path) -> list[tuple[str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for block in text.split("[[package]]")[1:]:
        n = re.search(r'name\s*=\s*"([^"]+)"', block)
        v = re.search(r'version\s*=\s*"([^"]+)"', block)
        if n and v:
            out.append(("PyPI", n.group(1), v.group(1)))
    return out


def parse_pipfile_lock(path: Path) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out = []
    for sect in ("default", "develop"):
        for name, meta in (data.get(sect) or {}).items():
            m = re.match(r"==\s*([\w.\-+!]+)", str((meta or {}).get("version", "")))
            if m:
                out.append(("PyPI", name, m.group(1)))
    return out


def enumerate_venv(target: Path) -> list[tuple[str, str, str]]:
    """Pacotes REALMENTE instalados num .venv/venv sob o alvo (via *.dist-info) —
    cobre projetos com requirements.txt sem versão pinada."""
    out: list[tuple[str, str, str]] = []
    venvs: list[Path] = []
    for name in (".venv", "venv"):
        venvs += [p for p in list(target.glob(name)) + list(target.glob("*/" + name)) if p.is_dir()]
    for vd in venvs:
        sps = list(vd.glob("Lib/site-packages")) + list(vd.glob("lib/*/site-packages"))
        for sp in sps:
            for di in sp.glob("*.dist-info"):
                m = re.match(r"^(.+)-([^-]+)\.dist-info$", di.name)
                if m:
                    out.append(("PyPI", m.group(1).replace("_", "-"), m.group(2)))
    return out


def _osv_severity(v: dict) -> str:
    ds = (v.get("database_specific") or {}).get("severity")
    if ds:
        return str(ds).upper()
    for s in v.get("severity", []) or []:
        sc = str(s.get("score", ""))
        m = re.search(r"/S:.|(\d+\.\d+)$", sc)  # tenta um número CVSS ao final
        num = re.search(r"(\d+\.\d+)", sc)
        if num:
            f = float(num.group(1))
            return "CRITICAL" if f >= 9 else "HIGH" if f >= 7 else "MEDIUM" if f >= 4 else "LOW"
    return "UNKNOWN"


def _osv_fixed(v: dict) -> str:
    fixes = []
    for aff in v.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixes.append(ev["fixed"])
    return ", ".join(sorted(set(fixes)))


def run_sca(targets: list[Path]) -> "dict | None":
    manifests = find_manifests(targets)
    parsers = {
        "requirements.txt": parse_requirements, "package-lock.json": parse_package_lock,
        "poetry.lock": parse_poetry_lock, "Pipfile.lock": parse_pipfile_lock,
    }
    deps: list[tuple[str, str, str]] = []
    sources: list[str] = []
    for m in manifests:
        got = parsers[m.name](m)
        if got:
            deps += got
            sources.append(m.name)
    for t in targets:  # pacotes instalados em .venv (cobre requirements sem pin)
        if t.is_dir():
            venv_deps = enumerate_venv(t)
            if venv_deps:
                deps += venv_deps
                sources.append(".venv (instalados)")
    # dedup preservando ordem
    seen: set = set()
    deps = [d for d in deps if not (d in seen or seen.add(d))]
    if not deps:
        return {"sources": sources, "deps": 0, "vulns": {}}
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in deps]
    hits: dict[tuple, list[str]] = {}
    try:
        for i in range(0, len(queries), 500):
            body = json.dumps({"queries": queries[i:i + 500]}).encode()
            req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.loads(r.read()).get("results", [])
            for dep, item in zip(deps[i:i + 500], res):
                ids = [x["id"] for x in (item.get("vulns") or [])]
                if ids:
                    hits[dep] = ids
    except Exception as ex:
        return {"error": str(ex), "sources": sources, "deps": len(deps)}
    # busca detalhes (limitada) para severidade/summary/fix
    details: dict[str, dict] = {}
    uniq = [vid for ids in hits.values() for vid in ids]
    for vid in list(dict.fromkeys(uniq))[:SCA_DETAIL_CAP]:
        try:
            with urllib.request.urlopen(OSV_VULN + vid, timeout=15) as r:
                details[vid] = json.loads(r.read())
        except Exception:
            details[vid] = {}
    return {"sources": sources, "deps": len(deps), "vulns": hits, "details": details}


def render_secrets(achados: list[dict]) -> None:
    print()
    print("=" * 62)
    print(" raptor-win — credenciais")
    print("=" * 62)
    if not achados:
        print(" Nenhuma credencial exposta. ✅")
        print(" (inclui: nenhum arquivo de segredo fora do .gitignore)")
        return

    porsev = Counter(a["severity"] for a in achados)
    print(" " + "  ".join(f"{k}: {porsev[k]}" for k in SEV_RANK if porsev.get(k)))
    print("-" * 62)
    for a in achados:
        onde = a["path"] + (f":{a['line']}" if a["line"] else "")
        print(f" [{a['severity']:<8}] {short_rule(a['rule'])}")
        print(f"            {onde}")
        print(f"            {a['message']}")
    print("-" * 62)
    # O QUE FAZER importa mais que O QUE FOI ACHADO. Tirar do arquivo não
    # desfaz nada: se já foi comitado, está no histórico, e quem clonou
    # tem uma cópia. A única correção real é rotacionar.
    if any(a["rule"] != "secrets.arquivo-nao-ignorado" for a in achados):
        print(" Credencial já commitada NÃO se corrige apagando a linha: ela fica")
        print(" no histórico e em cada clone. Rotacione a credencial primeiro,")
        print(" depois limpe o arquivo.")


def render_sca(sca: dict) -> None:
    print("\n" + "=" * 62)
    print(" raptor-win — SCA (dependências vulneráveis · OSV.dev)")
    print("=" * 62)
    if sca.get("error"):
        print(f" ⚠ OSV indisponível ({sca['error']}). {sca.get('deps', 0)} dependência(s) não checada(s).")
        return
    srcs = sca.get("sources", [])
    print(f" fontes: {', '.join(dict.fromkeys(srcs)) or '—'}  ·  dependências verificadas: {sca.get('deps', 0)}")
    hits = sca.get("vulns", {})
    if not hits:
        print(" Nenhuma dependência vulnerável conhecida. ✅")
        return
    det = sca.get("details", {})
    for (eco, name, ver), ids in sorted(hits.items()):
        print(f"\n {eco}  {name}@{ver} — {len(ids)} vuln(s)")
        for vid in ids:
            v = det.get(vid, {})
            sev = _osv_severity(v) if v else "?"
            fixed = _osv_fixed(v) if v else ""
            summ = (v.get("summary") or (v.get("details", "")[:80]) or "").strip().replace("\n", " ")
            print(f"   [{sev:<8}] {vid}  {summ[:90]}")
            print(f"     corrigido em: {fixed or '—'}   ·   https://osv.dev/vulnerability/{vid}")


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
    ap.add_argument("--sca", action="store_true", help="também checar dependências vulneráveis (requirements.txt / package-lock.json) via OSV.dev")
    ap.add_argument("--secrets", action="store_true", help="também procurar credenciais no repositório e arquivos de segredo fora do .gitignore")
    ap.add_argument("--no-raptor", action="store_true", help="não usar as regras do RAPTOR")
    ap.add_argument("--no-registry", action="store_true", help="não usar os packs do Semgrep Registry")
    ap.add_argument("--raptor-rules", metavar="DIR", help="caminho alternativo para as regras do RAPTOR")
    ap.add_argument("--exclude", action="append", default=[], help="padrão de exclusão (repetível)")
    ap.add_argument("--baseline", metavar="FILE", nargs="?", const=baseline_mod.NOME_PADRAO,
                    help=f"arquivo de riscos aceitos (padrao: {baseline_mod.NOME_PADRAO} se existir)")
    ap.add_argument("--sugerir-baseline", action="store_true",
                    help="imprime um modelo TOML para os achados ainda nao dispensados")
    ap.add_argument("--fail-on", choices=list(SEV_RANK), help="sai com código 1 se houver achado real >= esta severidade")
    args = ap.parse_args()

    semgrep = find_semgrep()

    targets = [Path(t).resolve() for t in args.target]
    for t in targets:
        if not t.exists():
            sys.stderr.write(f"alvo inexistente: {t}\n")
            return 2

    sca_targets = list(targets)  # SCA usa os alvos originais (dirs), não a lista do --changed

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
    if not configs and not args.sca and not args.secrets:
        sys.stderr.write("nenhuma configuração de regra selecionada (e --sca não foi pedido).\n")
        return 2

    findings: list[dict] = []
    files_scanned = rules_run = 0
    if configs:
        if not semgrep:
            sys.stderr.write(
                "Semgrep não encontrado (necessário para a análise estática). Instale:\n"
                "  python -m pip install semgrep\n"
                "e garanta a pasta Scripts do Python no PATH — ou use só o SCA com --no-raptor --no-registry --sca.\n"
            )
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

    # Os achados de credencial entram na MESMA lista dos de código, de
    # propósito: assim atravessam console, Markdown, SARIF e --fail-on sem
    # nenhum tratamento à parte. Um segredo comitado é achado de segurança
    # como outro qualquer — não merece um relatório separado que ninguém lê.
    if args.secrets:
        seg = secrets_scan.escanear(sca_targets, SKIP_DIRS)
        findings = sorted(findings + seg,
                          key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))
        render_secrets(seg)
        if args.md:
            Path(args.md).write_text(
                render_markdown(findings, str(targets[0]), files_scanned if configs else 0,
                                rules_run if configs else 0),
                encoding="utf-8")
        if args.sarif:
            Path(args.sarif).write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")

    if args.sca:
        render_sca(run_sca(sca_targets))

    # RISCOS ACEITOS. Aplicado no fim, sobre a lista já completa: o
    # baseline muda o que REPROVA, não o que é mostrado. Achado dispensado
    # continua no relatório, marcado — sumir com ele seria a mesma cegueira
    # que o arquivo existe para evitar.
    alvo_baseline = args.baseline
    if alvo_baseline is None and Path(baseline_mod.NOME_PADRAO).exists():
        alvo_baseline = baseline_mod.NOME_PADRAO
    if alvo_baseline:
        cam = Path(alvo_baseline)
        if not cam.exists():
            print(f"baseline não encontrado: {cam}", file=sys.stderr)
            return 2
        try:
            entradas = baseline_mod.carregar(cam)
        except baseline_mod.ErroBaseline as e:
            print(str(e), file=sys.stderr)
            return 2
        findings, resumo = baseline_mod.aplicar(findings, entradas)
        baseline_mod.render(resumo)

    if args.sugerir_baseline:
        print()
        print(baseline_mod.prox_de_aceitar(findings))

    if args.fail_on and (configs or args.secrets):
        floor = SEV_RANK[args.fail_on]
        real = [f for f in findings if "provável falso-positivo" not in f["context"]
                and not f.get("aceito")
                and SEV_RANK.get(f["severity"], 9) <= floor]
        if real:
            print(f"\nfail-on={args.fail_on}: {len(real)} achado(s) real(is) >= {args.fail_on}.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
