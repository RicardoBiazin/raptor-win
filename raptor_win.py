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
THIRD_PARTY/RAPTOR-LICENSE.txt). Rules under `rules/raptorwin/` are authored for
raptor-win itself. Everything else here is a thin wrapper.
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
import db_audit
import secrets_scan
import sql_lint
import typosquat

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
# Rules authored for raptor-win itself (NOT from the RAPTOR project). Kept in a
# separate folder so the provenance — and the MIT credit to RAPTOR — stays honest.
WIN_RULES = HERE / "rules" / "raptorwin"

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
SEV_RANK = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3,
            "UNKNOWN": 3, "MEDIUM": 4, "INFO": 5, "LOW": 6}
# Map to SARIF levels (GitHub Code Scanning understands error/warning/note).
SARIF_LEVEL = {"CRITICAL": "error", "ERROR": "error", "HIGH": "error",
               "WARNING": "warning", "UNKNOWN": "warning", "MEDIUM": "warning",
               "INFO": "note", "LOW": "note"}

# Paths that are dev tooling / tests — taint findings there are usually false
# positives (they hit *your own* known endpoints/paths, not attacker input).
#
# Duas lacunas medidas em repositórios reais e fechadas aqui:
#
#   1. NOME DE TESTE EM PORTUGUÊS. `tests?` casa "test/" e "tests/", não
#      "teste/"/"testes/", e a regra de nome de arquivo exigia ponto logo depois
#      ("app.test.ts"), então `teste_injecao.py` era contado como código de
#      produção. Em base escrita em português isso não é exceção, é o padrão.
#
#   2. AMOSTRA DELIBERADAMENTE VULNERÁVEL. Um scanner de segurança carrega
#      fixtures com falhas plantadas para provar que detecta. `fixtures/` já
#      estava coberto; `sample_vuln/` — o nome que o próprio raptor-win usa —
#      não estava, e a ferramenta acusava a si mesma como se fosse código real.
TOOLING_RE = re.compile(
    r"(^|[\\/])(tests?|testes?|spec|specs|__tests__|scripts?|tools?|examples?"
    r"|fixtures?|e2e|benchmarks?|migrations?|testdata|test[_-]data)([\\/]|$)"
    # scripts/tests/migrations do supabase/ — MENOS as Edge Functions, que são runtime
    r"|(^|[\\/])supabase[\\/](?!functions[\\/])"
    # prefixo de arquivo de teste: test_foo.py, teste_foo.py, spec-foo.js
    r"|(^|[\\/])(test|teste|spec|pentest)[_-]"
    # sufixo de arquivo de teste: foo_test.py, foo_teste.py, foo-spec.js
    r"|[_-](test|teste|spec)s?\."
    r"|(test|spec|pentest|verificar|verify|conferir|doctor|smoke|sessao|session|validar|sincroniz|sync|migrar|preparar|diagnostico|seed|stamp)\.",
    re.IGNORECASE,
)
TAINT_CATEGORIES = ("ssrf", "path_traversal", "path-traversal", "injection", "traversal")

# Amostra com vulnerabilidade PLANTADA de propósito.
#
# Diferente de código de teste, que roda de verdade e cujos achados ainda podem
# valer atenção: aqui a falha é o conteúdo esperado do arquivo. Um scanner de
# segurança carrega fixtures assim para provar que detecta — o próprio raptor-win
# tem `sample_vuln/` — e acusá-las como problema faz a ferramenta se auto-reportar
# e enche o relatório de ruído que ninguém pode corrigir.
FIXTURE_VULN_RE = re.compile(
    r"(^|[\\/])(sample[_-]?vulns?|vuln[_-]?samples?|vulnerable[_-]?samples?"
    r"|insecure[_-]?samples?)([\\/]|$)",
    re.IGNORECASE,
)


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
    # raptor-win's own authored rules load alongside the RAPTOR set — both are
    # "our curated rules" as opposed to the Registry packs — and share the
    # `--no-raptor` gate.
    if use_raptor and WIN_RULES.exists():
        configs.append(str(WIN_RULES))
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

    # `semgrep.exe` é um invólucro: ele localiza as regras e delega a
    # análise a `pysemgrep`, que invoca PELO NOME PURO. Quando o pip
    # instalou em `%APPDATA%\Python\PythonXXX\Scripts` sem acrescentar
    # esse diretório ao PATH — o padrão no Windows —, `find_semgrep()`
    # acha o executável por caminho absoluto, roda, e o processo FILHO
    # falha com "pysemgrep: No such file or directory". O erro cita um
    # programa que o usuário nunca chamou e que está instalado, ao lado
    # do que funcionou; é difícil de ler e não sugere a causa.
    #
    # Basta pôr no PATH do subprocesso o diretório de onde o próprio
    # semgrep veio: quem está ali é exatamente o par que falta.
    env = os.environ.copy()
    pasta = str(Path(semgrep).parent)
    if pasta and pasta not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = pasta + os.pathsep + env.get("PATH", "")

    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    if not proc.stdout.strip():
        sys.stderr.write(proc.stderr or "semgrep produced no output\n")
        if "pysemgrep" in (proc.stderr or ""):
            sys.stderr.write(
                f"\nDica: o semgrep foi encontrado em {pasta}, mas o componente\n"
                "pysemgrep não. Confira se os dois estão nessa pasta:\n"
                "  python -m pip install --force-reinstall semgrep\n",
            )
        raise SystemExit(2)
    return json.loads(proc.stdout)


def classify_context(path: str, check_id: str) -> str:
    if FIXTURE_VULN_RE.search(path):
        return "fixture (vulnerabilidade plantada — não é código de produção)"
    is_tooling = bool(TOOLING_RE.search(path))
    is_taint = any(cat in check_id.lower() for cat in TAINT_CATEGORIES)
    if is_tooling and is_taint:
        return "tooling/test (triagem: provável falso-positivo — alvo próprio, não entrada externa)"
    if is_tooling:
        return "tooling/test"
    return ""


# Contextos que NÃO exigem ação: taint em código próprio e fixture plantada.
DISPENSA_ATENCAO = ("provável falso-positivo", "fixture (")


def exigem_atencao(findings: list[dict]) -> list[dict]:
    """Achados que pedem decisão humana.

    O nome antigo do contador — "fora de tooling/teste" — descrevia errado o que
    ele filtrava: um `md5` ou `shell=True` dentro de `tests/` recebia o rótulo
    tooling e ainda assim entrava na conta, porque o filtro só removia o texto
    "provável falso-positivo" (que exige tooling E categoria de taint). Achado em
    código de teste continua contando — teste roda de verdade —, mas fixture com
    falha plantada não, e o rótulo agora diz o que faz.
    """
    return [f for f in findings
            if not any(marca in f["context"] for marca in DISPENSA_ATENCAO)]


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
    print(" raptor-win — relatório consolidado")
    print("=" * 62)
    print(f" arquivos SAST       : {files_scanned}")
    # "regras COM ACHADO", não "executadas": este número conta check_ids
    # distintos entre os resultados. Rotulado como "executadas" ele dizia
    # sempre 0 num scan limpo, sugerindo que nada tinha rodado — e, pior,
    # não distinguia isso de um scan em que realmente nada rodou.
    print(f" regras com achado   : {rules_run}")
    order = sorted(by_sev, key=lambda s: SEV_RANK.get(s, 9))
    print(" achados por severidade: " + (", ".join(f"{s}={by_sev[s]}" for s in order) or "0"))
    real = [f for f in exigem_atencao(findings) if not f.get("aceito")]
    print(f" total: {len(findings)}  ·  exigem atenção: {len(real)}")
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
        f"# raptor-win — relatório consolidado",
        "",
        f"- **Alvo:** `{target}`",
        f"- **Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- **Arquivos SAST:** {files_scanned}",
        f"- **Regras com achado:** {rules_run}",
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
        "> As regras `rules/raptor/` são do projeto RAPTOR (MIT); `rules/raptorwin/` são do próprio raptor-win. Ver `THIRD_PARTY/RAPTOR-LICENSE.txt`.",
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
        result = {
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"] or short_rule(rid)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, int(f["line"] or 1))},
            }}],
        }
        if f.get("aceito"):
            aceite = f["aceito"]
            result["suppressions"] = [{
                "kind": "external",
                "justification": aceite.get("motivo", "Risco aceito no baseline"),
            }]
        results.append(result)
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
    target = target.resolve()
    files = []
    for line in diff.stdout.splitlines():
        p = (base / line).resolve()
        dentro = p == target if target.is_file() else p.is_relative_to(target)
        if p.is_file() and dentro:
            files.append(p)
    return files


# ── SCA (Software Composition Analysis) via OSV.dev — só stdlib, sem chave ──────
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SCA_MANIFESTS = ("requirements.txt", "package-lock.json", "poetry.lock", "Pipfile.lock")
SCA_DETAIL_CAP = 120  # nº máx. de detalhes de vuln buscados (evita floods)


def _e_manifesto(nome: str) -> bool:
    """Aceita `requirements-dev.txt`, `requirements-extras.txt` e afins.

    Casar so' o nome exato deixava de fora a convencao mais comum de dividir
    dependencias por ambiente -- e o arquivo ignorado nao gerava aviso nenhum,
    so' sumia do relatorio.
    """
    return nome in SCA_MANIFESTS or (
        nome.startswith("requirements") and nome.endswith(".txt"))


def find_manifests(targets: list[Path]) -> list[Path]:
    out: list[Path] = []
    for t in targets:
        if t.is_file() and _e_manifesto(t.name):
            out.append(t)
            continue
        if t.is_dir():
            for p in t.rglob("*"):
                if _e_manifesto(p.name) and p.is_file() and not any(x in SKIP_DIRS for x in p.parts):
                    out.append(p)
    return out


def parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    deps = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9._+!-]+)", line)
        if m:  # pinado (name==version): da' para consultar a versao exata no OSV
            deps.append(("PyPI", m.group(1), m.group(2)))
            continue
        # SEM PIN (`>=`, `~=`, `>`, ou nome solto). Nao da' para perguntar ao OSV
        # por uma versao que o arquivo nao declara -- mas DESCARTAR era pior:
        # um requirements.txt inteiro em `>=` produzia "0 dependencias
        # verificadas -- nenhuma vulneravel ✅", um "tudo certo" falso. A versao
        # fica vazia, o nome segue para o typosquat (que so' precisa do nome) e
        # o relatorio diz quantas ficaram sem checagem de versao.
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*(?:[<>=~!]|$)", line)
        if m:
            deps.append(("PyPI", m.group(1), ""))
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
        normalized = {"MODERATE": "MEDIUM"}.get(str(ds).upper(), str(ds).upper())
        return normalized if normalized in SEV_RANK else "UNKNOWN"
    for s in v.get("severity", []) or []:
        sc = str(s.get("score", ""))
        # Um vetor normalmente começa por ``CVSS:3.1``. Tratar esse 3.1 como
        # score classificava vulnerabilidades graves como LOW. Só aceitamos
        # um score numérico explícito; aproximar um vetor produz precisão falsa.
        num = re.fullmatch(r"\s*(10(?:\.0)?|[0-9](?:\.\d+)?)\s*", sc)
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
    dep_paths: dict[tuple[str, str, str], str] = {}
    sources: list[str] = []
    for m in manifests:
        # Despacho por nome EXATO quebrava nas variantes que a descoberta passou
        # a aceitar (`requirements-nuvem.txt` levantava KeyError e derrubava a
        # varredura inteira). Qualquer `requirements*.txt` usa o mesmo parser.
        parser = parsers.get(m.name)
        if parser is None and m.name.startswith("requirements"):
            parser = parse_requirements
        if parser is None:
            continue
        got = parser(m)
        if got:
            deps += got
            for dep in got:
                dep_paths.setdefault(dep, str(m))
            sources.append(m.name)
    for t in targets:  # pacotes instalados em .venv (cobre requirements sem pin)
        if t.is_dir():
            venv_deps = enumerate_venv(t)
            if venv_deps:
                deps += venv_deps
                for dep in venv_deps:
                    dep_paths.setdefault(dep, str(t / ".venv"))
                sources.append(".venv (instalados)")
    # DEDUP COM NOME NORMALIZADO (PEP 503), preservando ordem.
    #
    # Sem normalizar, o mesmo pacote entrava duas vezes quando vinha de duas
    # fontes que escrevem o nome diferente: `requirements.txt` traz `Pillow`
    # (como o autor digitou) e o `.dist-info` do venv traz `pillow`. Resultado
    # medido em 21/08/2026: 26 advisories da Pillow contadas 2x, inflando o
    # relatorio e o total de dependencias -- e dando a impressao de que o projeto
    # tem mais problema do que tem.
    #
    # PEP 503: comparar nomes de pacote Python em minusculas, com `-`, `_` e `.`
    # colapsados num unico `-`. Guardo a PRIMEIRA grafia vista, que e' a do
    # arquivo do projeto, para o relatorio falar a lingua do usuario.
    def _chave(dep: tuple[str, str, str]) -> tuple[str, str, str]:
        eco, nome, ver = dep
        if eco == "PyPI":
            nome = re.sub(r"[-_.]+", "-", nome).lower()
        return (eco, nome, ver)

    seen: set = set()
    deps = [d for d in deps if not (_chave(d) in seen or seen.add(_chave(d)))]
    if not deps:
        return {"sources": sources, "deps": 0, "vulns": {}}
    # O OSV exige versao exata; os sem pin ficam de fora DA CONSULTA, nunca do
    # relatorio (ver `sem_pin` abaixo).
    pinados = [d for d in deps if d[2]]
    sem_pin = [d for d in deps if not d[2]]
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in pinados]
    hits: dict[tuple, list[str]] = {}
    try:
        for i in range(0, len(queries), 500):
            body = json.dumps({"queries": queries[i:i + 500]}).encode()
            req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.loads(r.read()).get("results", [])
            for dep, item in zip(pinados[i:i + 500], res):
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
    findings: list[dict] = []
    for dep, ids in hits.items():
        eco, name, ver = dep
        for vid in ids:
            vuln = details.get(vid, {})
            fixed = _osv_fixed(vuln) if vuln else ""
            summary = (vuln.get("summary") or "Vulnerabilidade conhecida na dependência").strip()
            message = f"{name}@{ver}: {summary}"
            if fixed:
                message += f"; corrigido em {fixed}"
            message += f"; https://osv.dev/vulnerability/{vid}"
            findings.append({
                "rule": vid,
                "severity": _osv_severity(vuln) if vuln else "UNKNOWN",
                "path": dep_paths.get(dep, ""),
                "line": 1,
                "message": message,
                "context": f"SCA · {eco}",
            })
    # TYPOSQUAT. Roda sobre as mesmas dependencias ja' parseadas, entao nao
    # custa I/O nem uma linha de manifesto a mais. E' o complemento necessario
    # do OSV: pacote malicioso publicado ha' minutos nao tem CVE nenhum, e
    # portanto passa limpo pela checagem de vulnerabilidade -- o unico sinal
    # disponivel e' o nome ser quase o de um pacote popular.
    squat = typosquat.escanear(deps)
    for a in squat:
        findings.append({
            "rule": "typosquat",
            "severity": a["severity"].upper(),
            "path": dep_paths.get((a["ecosystem"], a["name"], a["version"]), ""),
            "line": 1,
            "message": (f"{a['name']}@{a['version']}: {a['reason']}"),
            "context": f"SCA · {a['ecosystem']}",
        })
    return {"sources": sources, "deps": len(deps), "vulns": hits,
            "details": details, "findings": findings, "typosquat": squat,
            "pinados": len(pinados), "sem_pin": sorted({n for (_e, n, _v) in sem_pin})}


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


def _render_typosquat(achados: list[dict]) -> None:
    """Sai ANTES da lista de CVEs: nome suspeito e' mais urgente que CVE antigo."""
    cobertos = ", ".join(typosquat.ecossistemas_cobertos()) or "—"
    if not achados:
        print(f" Nenhum nome parecido com pacote popular ({cobertos}). ✅")
        return
    print(f"\n ⚠ {len(achados)} dependência(s) com nome parecido com pacote popular:")
    for a in achados:
        print(f"   [{a['severity'].upper():<6}] {a['ecosystem']}  {a['name']}@{a['version']}")
        print(f"     {a['reason']}")


def render_sca(sca: dict) -> None:
    print("\n" + "=" * 62)
    print(" raptor-win — SCA (dependências vulneráveis · OSV.dev)")
    print("=" * 62)
    if sca.get("error"):
        print(f" ⚠ OSV indisponível ({sca['error']}). {sca.get('deps', 0)} dependência(s) não checada(s).")
        return
    srcs = sca.get("sources", [])
    pinados = sca.get("pinados", sca.get("deps", 0))
    print(f" fontes: {', '.join(dict.fromkeys(srcs)) or '—'}  ·  "
          f"dependências encontradas: {sca.get('deps', 0)}  ·  "
          f"com versão fixada (checadas no OSV): {pinados}")
    # Dizer o que NAO foi checado importa mais que o check verde: sem isto, um
    # requirements.txt todo em `>=` exibia "nenhuma vulnerável ✅" sem que uma
    # unica dependencia tivesse sido consultada.
    sem_pin = sca.get("sem_pin", [])
    if sem_pin:
        amostra = ", ".join(sem_pin[:6]) + ("…" if len(sem_pin) > 6 else "")
        print(f" ⚠ {len(sem_pin)} sem versão fixada — NÃO checadas contra CVE: {amostra}")
        print("   (fixe com `==` ou gere um lock para que possam ser verificadas)")
    _render_typosquat(sca.get("typosquat", []))
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


def run_db_audit(args) -> dict:
    """Auditoria SOMENTE-LEITURA do catálogo, se `--db-audit` foi pedido.

    Mesma forma de retorno de `run_sca()` de propósito: assim o padrão de teste
    `mock.patch.object(raptor_win, "run_db_audit", ...)` vale igual.

    Credencial vem só do ambiente. Nenhum host, usuário, senha ou token entra no
    retorno — o que sai daqui pode ir para relatório commitado.
    """
    try:
        consultar, backend = db_audit.abrir_backend(
            os.environ, args.db_backend, args.db_timeout, args.db_project_ref or "")
        cap = db_audit.preflight(consultar)
        achados = db_audit.escanear(
            consultar,
            schemas_incluidos=frozenset(args.db_schema) if args.db_schema else None,
            capacidades=cap)
        return {"findings": achados, "backend": backend, "capacidades": cap}
    except db_audit.ErroBanco as e:
        return {"findings": [], "backend": args.db_backend, "error": str(e)}


def render_db(res: dict) -> None:
    print("\n" + "=" * 62)
    print(" raptor-win — catálogo Postgres/Supabase (SOMENTE LEITURA)")
    print("=" * 62)
    if res.get("error"):
        print(f" ✗ auditoria NÃO realizada: {res['error']}")
        return
    cap = res.get("capacidades", {})
    # Nada de host, usuário, senha ou token: só o que é público ou booleano.
    garantia = ("imposta pelo servidor (default_transaction_read_only=on)"
                if cap.get("somente_leitura") else "do lado cliente (SQL constante + guarda)")
    print(f" backend: {res.get('backend', '?')}  ·  Postgres {cap.get('versao', '?')}")
    print(f" somente-leitura: {garantia}")
    print(f" papéis de cliente presentes: "
          f"anon={'sim' if cap.get('tem_anon') else 'não'}  "
          f"authenticated={'sim' if cap.get('tem_auth') else 'não'}")
    n = len(res.get("findings", []))
    print(f" achados de catálogo: {n}" if n else " Nenhum achado de catálogo. ✅")


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
    ap.add_argument("--db-audit", action="store_true",
                    help="auditar o catálogo Postgres/Supabase ao vivo (SOMENTE LEITURA; "
                         "credencial só por variável de ambiente)")
    ap.add_argument("--db-backend", choices=["auto", "api", "psql"], default="auto",
                    help="como falar com o banco (padrão: auto)")
    ap.add_argument("--db-project-ref", metavar="REF",
                    help="ref do projeto Supabase (NÃO é segredo; sobrepõe SUPABASE_PROJECT_REF)")
    ap.add_argument("--db-schema", action="append", default=[], metavar="NOME",
                    help="restringe a auditoria a estes schemas (repetível)")
    ap.add_argument("--db-timeout", type=int, default=30, metavar="SEG",
                    help="tempo limite por consulta ao banco (padrão: 30)")
    ap.add_argument("--no-raptor", action="store_true", help="não usar as regras do RAPTOR")
    ap.add_argument("--no-registry", action="store_true", help="não usar os packs do Semgrep Registry")
    ap.add_argument("--raptor-rules", metavar="DIR", help="caminho alternativo para as regras do RAPTOR")
    ap.add_argument("--exclude", action="append", default=[], help="padrão de exclusão (repetível)")
    ap.add_argument("--baseline", metavar="FILE", nargs="?", const=baseline_mod.NOME_PADRAO,
                    help=f"arquivo de riscos aceitos (padrao: {baseline_mod.NOME_PADRAO} se existir)")
    ap.add_argument("--sugerir-baseline", action="store_true",
                    help="imprime um modelo TOML para os achados ainda nao dispensados")
    ap.add_argument("--fail-on", choices=[s for s in SEV_RANK if s != "UNKNOWN"],
                    help="sai com código 1 se houver achado real >= esta severidade")
    args = ap.parse_args()

    semgrep = find_semgrep()

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
    if not configs and not args.sca and not args.secrets and not args.db_audit:
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

        # ERROS DO SEMGREP SÃO FATAIS, e não uma nota de rodapé.
        #
        # Quando um pacote do registro não pode ser baixado, o Semgrep
        # devolve JSON VÁLIDO com `results: []` e registra o 404 em
        # `errors[]` com `level: "error"`. O relatório, sem isto,
        # imprimia "Nenhum achado ✅" — indistinguível de código limpo, e
        # pior que erro nenhum, porque produz confiança onde não houve
        # análise.
        #
        # Só `level == "error"` derruba. Medido antes de escrever: um
        # arquivo-fonte com sintaxe inválida NÃO entra em `errors[]` (o
        # Semgrep o ignora em silêncio), então isto não transforma um
        # .js minificado no meio do repositório em build quebrada. O que
        # sobra em nível de aviso segue como aviso.
        erros = [e for e in sg.get("errors", [])
                 if e and str(e.get("level", "error")).lower() == "error"]
        if erros:
            sys.stderr.write("\nO Semgrep relatou erros — a análise NÃO é confiável:\n")
            for e in erros[:10]:
                msg = e.get("long_msg") or e.get("message") or json.dumps(e)
                sys.stderr.write(f"  · {str(msg)[:300]}\n")
            sys.stderr.write(
                "\nUm relatório vazio aqui significaria 'não analisei', não 'está limpo'.\n")
            return 2

    # Checagens SQL que olham vários comandos (índice duplicado, policies
    # permissivas múltiplas). Locais e baratas — rodam sempre e entram na mesma
    # lista. O Semgrep, uma regra por trecho, não faz essa correlação.
    sqlf = sql_lint.escanear(targets, SKIP_DIRS)
    if sqlf:
        # Mesma classificação de contexto dos achados do Semgrep (fixture/teste/
        # tooling), para que a contagem "exigem atenção" trate SQL igual ao resto.
        for f in sqlf:
            f["context"] = classify_context(f["path"], f["rule"])
        findings = sorted(findings + sqlf,
                          key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))

    # Os achados de credencial entram na MESMA lista dos de código, de
    # propósito: assim atravessam console, Markdown, SARIF e --fail-on sem
    # nenhum tratamento à parte. Um segredo comitado é achado de segurança
    # como outro qualquer — não merece um relatório separado que ninguém lê.
    if args.secrets:
        seg = secrets_scan.escanear(targets, SKIP_DIRS)
        findings = sorted(findings + seg,
                          key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))
        render_secrets(seg)

    sca = None
    if args.sca:
        sca = run_sca(targets)
        render_sca(sca)
        if not sca.get("error"):
            findings = sorted(findings + sca.get("findings", []),
                              key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))

    dbres = None
    if args.db_audit:
        dbres = run_db_audit(args)
        render_db(dbres)
        # Auditoria PEDIDA que não completou sai 2, e não avisa-e-continua como
        # a SCA: uma falha de SCA deixa o resultado do SAST válido, mas uma
        # execução só-de-banco que imprime "Nenhum achado ✅" depois de não
        # conseguir conectar é uma mentira debaixo de um gate de CI.
        if dbres.get("error"):
            sys.stderr.write(
                "auditoria de banco NÃO realizada — o relatório não é confiável.\n")
            return 2
        # SEM classify_context() aqui, ao contrário do bloco do sql_lint: os
        # achados de catálogo já trazem `context`, e medido que `db:test.foo()` e
        # `db:seed.aplicar()` casam TOOLING_RE — um schema ou função chamado
        # `test`/`seed` sairia da conta de "exigem atenção" em silêncio.
        findings = sorted(findings + dbres.get("findings", []),
                          key=lambda f: (SEV_RANK.get(f["severity"], 9), f["path"], f["line"]))

    # RISCOS ACEITOS. Aplicado no fim, sobre a lista já completa: o
    # baseline muda o que REPROVA, não o que é mostrado. Achado dispensado
    # continua no relatório, marcado — sumir com ele seria a mesma cegueira
    # que o arquivo existe para evitar.
    # O baseline padrão é procurado no diretório atual E ao lado do projeto
    # escaneado. Só o primeiro não bastava: numa varredura de vários repositórios
    # (scan-all.ps1 roda de fora, com o alvo por parâmetro), o arquivo de riscos
    # aceitos de cada projeto era ignorado em silêncio — e o projeto voltava a
    # reprovar por um risco que já tinha sido decidido e justificado.
    alvo_baseline = args.baseline
    if alvo_baseline is None:
        raiz_alvo = targets[0] if targets[0].is_dir() else targets[0].parent
        for candidato in (Path(baseline_mod.NOME_PADRAO), raiz_alvo / baseline_mod.NOME_PADRAO):
            if candidato.exists():
                alvo_baseline = str(candidato)
                break
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
        # O contador acima foi impresso ANTES do baseline. Sem esta linha, a
        # saída afirma "exigem atenção: N" e três linhas depois dispensa N —
        # duas contas verdadeiras que se contradizem na leitura. Os achados
        # dispensados continuam no relatório (é o que o baseline promete); o
        # que se corrige aqui é só o número final.
        restantes = [f for f in exigem_atencao(findings) if not f.get("aceito")]
        print(f" exigem atenção após o baseline: {len(restantes)}")

    # Todos os formatos são gerados somente depois de reunir SAST, credenciais
    # e SCA e de aplicar o baseline. Assim preservam a mesma visão dos achados.
    if findings or configs or args.db_audit:
        render_console(findings, files_scanned, rules_run)
    if args.md:
        Path(args.md).write_text(
            render_markdown(findings, str(targets[0]), files_scanned, rules_run),
            encoding="utf-8")
        print(f"\nMarkdown: {args.md}")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
        print(f"SARIF: {args.sarif}")

    if args.sugerir_baseline:
        print()
        print(baseline_mod.prox_de_aceitar(findings))

    if args.fail_on and (configs or args.secrets or args.sca or args.db_audit):
        floor = SEV_RANK[args.fail_on]
        real = [f for f in exigem_atencao(findings)
                if not f.get("aceito")
                and SEV_RANK.get(f["severity"], 9) <= floor]
        if real:
            print(f"\nfail-on={args.fail_on}: {len(real)} achado(s) real(is) >= {args.fail_on}.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
