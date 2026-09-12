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
import headers_lint
import supply_chain
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
    # Cache das CLIs de deploy. `.netlify/` guarda uma COPIA do netlify.toml e
    # as functions empacotadas; esta' no .gitignore de todo projeto. Ler dali
    # produz achado sobre arquivo gerado -- e pior, manda o usuario editar um
    # arquivo que o proximo deploy sobrescreve.
    ".netlify", ".vercel",
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


_CWE_RE = re.compile(r"CWE-\d+")


def _cwe_de(metadata: dict) -> list[str]:
    """Extrai os identificadores CWE do metadata de uma regra Semgrep.

    O campo vem em tres formatos conforme quem escreveu a regra: string,
    lista de strings, e com ou sem o titulo depois do numero
    ("CWE-79: Improper Neutralization..."). Normalizo para so' o
    identificador, que e' o que as ferramentas downstream casam.
    """
    bruto = metadata.get("cwe")
    if not bruto:
        return []
    if isinstance(bruto, str):
        bruto = [bruto]
    achados: list[str] = []
    for item in bruto:
        for m in _CWE_RE.findall(str(item)):
            if m not in achados:
                achados.append(m)
    return achados


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
            "cwe": _cwe_de(r.get("extra", {}).get("metadata") or {}),
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
        # `properties.tags` com o CWE e' onde as ferramentas downstream o
        # procuram -- o parser SARIF do Faraday, por exemplo, popula o campo
        # CWE dele exatamente dali. Sem isto o SARIF do raptor-win e' valido,
        # mas chega do outro lado sem classificacao nenhuma.
        if rid not in rules:
            regra = {"id": rid, "shortDescription": {"text": short_rule(rid)}}
            tags = f.get("cwe") or []
            if tags:
                regra["properties"] = {"tags": list(tags)}
            rules[rid] = regra
        elif f.get("cwe") and "properties" not in rules[rid]:
            # O mesmo rule id pode aparecer primeiro num achado sem metadata
            # (um de baseline, por exemplo) e so' depois num com CWE.
            rules[rid]["properties"] = {"tags": list(f["cwe"])}
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
SCA_MANIFESTS = ("requirements.txt", "package-lock.json", "npm-shrinkwrap.json",
                 "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "Pipfile.lock")

# Workflows do GitHub Actions. As `uses:` de um workflow SAO dependencias --
# codigo de terceiro que roda com o token do repositorio -- e o OSV as indexa
# no ecossistema "GitHub Actions" (foi assim que o tj-actions/changed-files
# comprometido em 03/2025 entrou na base). Ate' aqui o raptor-win nao olhava
# para elas: um repo sem manifesto nenhum e com 10 actions de terceiros
# recebia "0 dependencias verificadas ✅".
GHA_ACTION_FILES = ("action.yml", "action.yaml")
SCA_DETAIL_CAP = 120  # nº máx. de detalhes de vuln buscados (evita floods)


def _e_manifesto(nome: str) -> bool:
    """Aceita `requirements-dev.txt`, `requirements-extras.txt` e afins.

    Casar so' o nome exato deixava de fora a convencao mais comum de dividir
    dependencias por ambiente -- e o arquivo ignorado nao gerava aviso nenhum,
    so' sumia do relatorio.
    """
    return nome in SCA_MANIFESTS or (
        nome.startswith("requirements") and nome.endswith(".txt"))


def _e_workflow_gha(p: Path) -> bool:
    """Workflow (`.github/workflows/*.yml`) ou action composta (`action.yml`).

    Casa pelo DIRETORIO, nao so' pelo nome: `.github/workflows/ci.yml` nao tem
    nada no nome que o distinga de qualquer outro YAML do projeto, e aceitar
    todo `*.yml` encheria o relatorio de docker-compose e config de CI alheia.
    """
    if p.suffix.lower() not in (".yml", ".yaml"):
        return False
    if p.name in GHA_ACTION_FILES:
        return True
    partes = [x.lower() for x in p.parts]
    return "workflows" in partes and ".github" in partes


def find_manifests(targets: list[Path]) -> list[Path]:
    out: list[Path] = []
    for t in targets:
        if t.is_file() and (_e_manifesto(t.name) or _e_workflow_gha(t)):
            out.append(t)
            continue
        if t.is_dir():
            for p in t.rglob("*"):
                if any(x in SKIP_DIRS for x in p.parts) or not p.is_file():
                    continue
                if _e_manifesto(p.name) or _e_workflow_gha(p):
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
    return _sem_versao_redundante(out)


_ASPAS = "\"'"  # os dois tipos de aspas que YAML/yarn usam em volta das chaves


def _nome_versao_npm(spec: str) -> tuple[str, str] | None:
    """Separa `nome@versao` de um spec npm, respeitando o escopo.

    O `@` do escopo nao e' separador: em `@scope/name@1.0` quem divide e' o
    SEGUNDO `@`. Partir no primeiro devolveria nome vazio e versao
    `scope/name@1.0` -- consulta que o OSV responde com nada, ou seja, um
    "limpo" falso para todo pacote com escopo.
    """
    spec = spec.strip().strip(_ASPAS)
    if spec.startswith("@"):
        barra = spec.find("/")
        if barra == -1:
            return None
        at = spec.find("@", barra)
    else:
        at = spec.find("@")
    if at <= 0 or at >= len(spec) - 1:
        return None
    return spec[:at], spec[at + 1:]


# Versao que nao veio do registro publico: o OSV nao tem o que casar com
# `file:`, `workspace:` ou um tarball. Entram no relatorio sem versao -- o nome
# ainda serve para o typosquat --, nunca como "checado".
_NPM_FORA_DO_REGISTRO = ("file:", "link:", "workspace:", "http:", "https:",
                         "git:", "git+", "github:", "portal:", "patch:")


def _limpa_versao_npm(versao: str) -> str:
    """Tira as anotacoes que o pnpm/yarn grudam na versao.

    O pnpm codifica a resolucao de peer-dep na propria chave, em dois formatos:
    v6+ `29.0.3(typescript@5.0)` e v5 `29.0.3_typescript@5.0.0`. O yarn Berry
    usa `npm:` como protocolo (`lodash@npm:4.17.21`). Nada disso e' versao para
    o OSV -- e mandar `29.0.3(typescript@5.0)` significa receber lista vazia.
    """
    versao = versao.strip().strip(_ASPAS)
    if versao.startswith("npm:"):
        versao = versao[4:]
        # `@scope/real@1.0` = alias do yarn: o que vale e' o pacote de verdade.
        alvo = _nome_versao_npm(versao)
        if alvo:
            versao = alvo[1]
    for corte in ("(", "_"):
        i = versao.find(corte)
        if i > 0:
            versao = versao[:i]
    if versao.startswith(_NPM_FORA_DO_REGISTRO):
        return ""
    return versao


_CHAVE_V6 = re.compile(r"^/(?P<nome>(?:@[^/]+/)?[^/@]+)@(?P<versao>.+)$")
_CHAVE_V5 = re.compile(r"^/(?P<nome>(?:@[^/]+/)?[^/]+)/(?P<versao>.+)$")


def _sem_versao_redundante(deps: set) -> list[tuple[str, str, str]]:
    """Descarta a linha SEM versao de um pacote que ja' tem outra COM versao.

    O yarn Berry registra um pacote duas vezes quando ele leva patch embutido:
    `typescript@npm:^5.5.3` (versao 5.9.3) e
    `typescript@patch:typescript@npm%3A^5.5.3#optional!builtin<...>`, cujo
    intervalo `patch:` nao e' do registro e portanto nao rende versao. Guardar
    as duas faz o `typescript` aparecer na lista de "sem versao fixada -- NAO
    checadas" mesmo tendo sido checado na outra linha: um aviso que manda o
    usuario fixar o que ja' esta' fixo.

    So' cai a linha vazia que TEM par versionado. A do pacote local
    (`meu-pkg@file:../meu`), que nao tem par, fica -- essa nao foi checada
    mesmo, e calar seria o erro oposto.
    """
    com_versao = {(e, n) for (e, n, v) in deps if v}
    return sorted(d for d in deps if d[2] or (d[0], d[1]) not in com_versao)


def parse_pnpm_lock(path: Path) -> list[tuple[str, str, str]]:
    """Le' `pnpm-lock.yaml` sem depender de um parser YAML.

    Tres formatos dividem o mesmo nome de arquivo, e as chaves mudam nos tres:

        v5 (pnpm 7-)   packages:  `/lodash/4.17.21`
        v6 (pnpm 8)    packages:  `/lodash@4.17.21`
        v9 (pnpm 9+)   packages:  `lodash@4.17.21`, e o grafo resolvido migra
                                  para um mapa irmao `snapshots:`

    So' preciso do conjunto (nome, versao), e ele esta' inteiro nas CHAVES
    desses dois mapas -- entao varro linha a linha em vez de trazer o PyYAML,
    que seria a unica dependencia do raptor-win alem do semgrep. Uno `packages`
    com `snapshots`: no v9 ha' transitiva que so' existe no segundo.
    """
    try:
        texto = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: set[tuple[str, str, str]] = set()
    dentro = False
    for raw in texto.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():                       # chave de topo
            dentro = raw.split(":", 1)[0].strip() in ("packages", "snapshots")
            continue
        if not dentro:
            continue
        # Entrada do mapa: exatamente um nivel de indentacao e termina em `:`.
        if len(raw) - len(raw.lstrip()) != 2 or not raw.rstrip().endswith(":"):
            continue
        chave = raw.strip()[:-1].strip().strip(_ASPAS)
        if chave.startswith("/"):
            # v6 ANTES de v5, e as duas ancoradas. Cair no separador errado da'
            # nome torto sem erro nenhum: em `/jest/29.0.3_typescript@5.0.0`
            # (v5) uma busca solta pelo `@` parte no `@` do peer-dep e produz
            # `jest/29.0.3_typescript@5.0.0` -> nome `jest/29.0.3_typescript`,
            # versao `5.0.0`. O OSV responde vazio, e a dependencia consta
            # como checada. Por isso o segmento do nome em _CHAVE_V6 proibe
            # `/` e `@`: assim a forma v5 nao casa com ela e desce para v5.
            m = _CHAVE_V6.match(chave) or _CHAVE_V5.match(chave)
            if not m:
                continue
            nv = (m.group("nome"), m.group("versao"))
        else:
            nv = _nome_versao_npm(chave)
        if nv is None:
            continue
        nome, versao = nv[0], _limpa_versao_npm(nv[1])
        if nome:
            out.add(("npm", nome, versao))
    return _sem_versao_redundante(out)


def parse_yarn_lock(path: Path) -> list[tuple[str, str, str]]:
    """Le' `yarn.lock` -- classico (v1) e Berry (v2+), pelo mesmo caminho.

    O v1 NAO e' YAML valido (valores vem com aspas embutidas), entao um parser
    YAML nao resolveria os dois de qualquer jeito. Mas as duas formas tem a
    mesma silhueta: um cabecalho de bloco na coluna 0 com o(s) descritor(es), e
    uma linha `version` indentada dentro. E' o que eu leio.

        v1      "@types/node@^20.5.0", "@types/node@^20.10.0":
                  version "20.11.5"
        Berry   "lodash@npm:^4.17.21":
                  version: 4.17.21

    O nome sai do descritor (o intervalo pedido nao interessa); a versao
    RESOLVIDA sai da linha `version`, que e' a que o OSV sabe casar.
    """
    try:
        texto = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: set[tuple[str, str, str]] = set()
    nome_atual = ""
    do_registro = True
    for raw in texto.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            nome_atual = ""
            if not raw.rstrip().endswith(":"):
                continue
            primeiro = raw.rstrip()[:-1].split(",")[0]
            nv = _nome_versao_npm(primeiro)
            # `__metadata:` do Berry e outras chaves de topo nao sao pacote.
            if nv:
                nome_atual = nv[0]
                # O intervalo do descritor e' que diz se o pacote veio do
                # registro. `meu-pkg@file:../meu` e `meu-app@workspace:.` tem
                # bloco `version` como qualquer outro -- "0.0.0",
                # "0.0.0-use.local" --, e essa versao NAO existe no npm. Sem
                # olhar aqui, o pacote local entrava na consulta, voltava sem
                # advisory (obvio: o OSV nunca ouviu falar dele) e era contado
                # como "checado". O nome segue para o typosquat; a versao, nao.
                do_registro = not nv[1].startswith(_NPM_FORA_DO_REGISTRO)
            continue
        if not nome_atual:
            continue
        corpo = raw.strip()
        if corpo.startswith("version"):
            valor = corpo[len("version"):].lstrip(": ").strip()
            versao = _limpa_versao_npm(valor) if do_registro else ""
            out.add(("npm", nome_atual, versao))
            nome_atual = ""
    return _sem_versao_redundante(out)


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


# Casa `uses: owner/repo@ref` e `uses: owner/repo/sub@ref`, com ou sem aspas
# YAML (`uses: "actions/checkout@v5"` e' legal e comum -- o padrao so'-sem-aspas
# do upstream pulava essas linhas em silencio). O intervalo inicial e'
# `\s*(?:-\s*)?`: os trechos de espaco ficam separados por um `-` obrigatorio,
# entao uma linha longa so' de espacos nao explora O(n^2) particoes.
_GHA_USES_RE = re.compile(
    r"""^\s*(?:-\s*)?uses\s*:\s*
        (?P<q>["']?)
        (?P<spec>[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+)
        (?P=q)
        \s*(?:\#.*)?$""",
    re.VERBOSE,
)


def parse_gha_workflow(path: Path) -> list[tuple[str, str, str]]:
    """Extrai as `uses:` de um workflow como dependencias "GitHub Actions".

    Fica de fora: `uses: ./acao-local` (codigo do proprio repo, nao e' terceiro)
    e `docker://imagem@digest` (outro modelo de ameaca -- imagem, nao action).
    """
    try:
        texto = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[tuple[str, str, str]] = []
    for raw in texto.splitlines():
        m = _GHA_USES_RE.match(raw)
        if not m:
            continue
        spec = m.group("spec")
        if spec.startswith(("./", "../", "docker://")):
            continue
        action, _, ref = spec.rpartition("@")
        if "/" not in action or not ref:
            continue
        out.append(("GitHub Actions", action, ref))
    return out


def _versao_gha(ref: str) -> tuple[int, ...] | None:
    """Converte a ref de uma action em tupla comparavel, ou None.

    None para SHA de 40 digitos e para nomes de branch: nao da' para ordenar
    `@main` contra `fixed: 46.0.1`. O chamador reporta esses casos como
    "revisar", nunca como limpos -- um pin em branch e' MAIS exposto, nao menos.
    """
    m = re.match(r"^v?(\d+(?:\.\d+)*)$", ref.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


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


OSV_QUERY = "https://api.osv.dev/v1/query"


def _consulta_gha(deps: list[tuple[str, str, str]]) -> tuple[dict, dict, list]:
    """Consulta o OSV para actions e casa a versao LOCALMENTE.

    Por que nao entra no `querybatch` com as outras: o OSV aceita o ecossistema
    "GitHub Actions", mas NAO sabe ordenar as versoes dele. Medido em 12/09/2026
    contra o `tj-actions/changed-files` (o comprometido de 03/2025):

        query name+version 45.0.7  -> []            <- "limpo", falso
        query so' name              -> 2 advisories  <- a verdade

    Mandar action com versao no batch, portanto, devolve sempre lista vazia:
    seria uma checagem que so' sabe dizer "tudo bem". Entao pergunto pelo NOME,
    recebo os advisories do pacote, e comparo a ref com o `fixed` aqui.

    Devolve (hits, detalhes, revisar) -- `revisar` sao as actions com advisory
    cuja ref nao da' para ordenar (SHA, branch) ou cujo `fixed` cai dentro do
    mesmo major de uma tag flutuante.
    """
    hits: dict[tuple, list[str]] = {}
    detalhes: dict[str, dict] = {}
    revisar: list[dict] = []
    porname: dict[str, list[dict]] = {}
    for nome in dict.fromkeys(n for (_e, n, _v) in deps):
        body = json.dumps({"package": {"name": nome, "ecosystem": "GitHub Actions"}}).encode()
        req = urllib.request.Request(OSV_QUERY, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                porname[nome] = json.loads(r.read()).get("vulns") or []
        except Exception:
            porname[nome] = []          # degrada: nunca inventa "limpo" nem erro fatal
    for dep in deps:
        _eco, nome, ref = dep
        for vuln in porname.get(nome, []):
            vid = vuln["id"]
            detalhes[vid] = vuln
            corrigido = _versao_gha(_osv_fixed(vuln))
            atual = _versao_gha(ref)
            if atual is None or corrigido is None:
                revisar.append({"name": nome, "ref": ref, "id": vid, "motivo":
                                "ref nao ordenavel (SHA ou branch)" if atual is None
                                else "advisory sem versao corrigida publicada"})
                continue
            if atual >= corrigido:
                continue
            # Tag de major solto (`@v5`) flutua: hoje ela aponta para o 5.x mais
            # recente. Se o `fixed` esta' DENTRO do mesmo major, o repo
            # provavelmente ja' pegou a correcao sem mudar o workflow -- acusar
            # como vulneravel seria falso positivo. So' o major menor e' certeza.
            if len(atual) == 1 and len(corrigido) > 1 and atual[0] == corrigido[0]:
                revisar.append({"name": nome, "ref": ref, "id": vid, "motivo":
                                f"tag flutuante @{ref}; corrigido em {_osv_fixed(vuln)}"})
                continue
            hits.setdefault(dep, []).append(vid)
    return hits, detalhes, revisar


def run_sca(targets: list[Path]) -> "dict | None":
    manifests = find_manifests(targets)
    parsers = {
        "requirements.txt": parse_requirements, "package-lock.json": parse_package_lock,
        # npm-shrinkwrap.json tem EXATAMENTE o formato do package-lock e tem
        # precedencia sobre ele quando os dois existem. Sem esta linha, um
        # projeto que publica shrinkwrap era lido como se nao tivesse lock.
        "npm-shrinkwrap.json": parse_package_lock,
        "pnpm-lock.yaml": parse_pnpm_lock, "yarn.lock": parse_yarn_lock,
        "poetry.lock": parse_poetry_lock, "Pipfile.lock": parse_pipfile_lock,
    }
    deps: list[tuple[str, str, str]] = []
    dep_paths: dict[tuple[str, str, str], str] = {}
    sources: list[str] = []
    vazios: list[str] = []
    for m in manifests:
        # Despacho por nome EXATO quebrava nas variantes que a descoberta passou
        # a aceitar (`requirements-nuvem.txt` levantava KeyError e derrubava a
        # varredura inteira). Qualquer `requirements*.txt` usa o mesmo parser.
        parser = parsers.get(m.name)
        if parser is None and m.name.startswith("requirements"):
            parser = parse_requirements
        if parser is None and _e_workflow_gha(m):
            parser = parse_gha_workflow
        if parser is None:
            continue
        got = parser(m)
        if got:
            deps += got
            for dep in got:
                dep_paths.setdefault(dep, str(m))
            sources.append(m.name)
        else:
            # Manifesto que EXISTE e nao rendeu linha nenhuma. Descartar em
            # silencio -- ele nem entrava em `sources` -- e' o pior resultado
            # possivel: o relatorio conclui "0 dependencias verificadas ✅"
            # sobre um projeto que declara dependencia, e quem le' entende que
            # esta' tudo checado. Pode ser lock genuinamente vazio, ou pode ser
            # um formato que eu achei que sabia ler e nao sei. Os dois casos
            # merecem o nome do arquivo no relatorio; qual dos dois e', quem
            # decide e' quem conhece o projeto.
            vazios.append(str(m))
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
        return {"sources": sources, "deps": 0, "vulns": {}, "vazios": vazios}
    # O OSV exige versao exata; os sem pin ficam de fora DA CONSULTA, nunca do
    # relatorio (ver `sem_pin` abaixo).
    # Actions saem do batch: o OSV nao ordena as versoes desse ecossistema, entao
    # elas vao por `_consulta_gha` (nome + comparacao local). Ver o docstring de la'.
    gha = [d for d in deps if d[0] == "GitHub Actions"]
    deps_osv = [d for d in deps if d[0] != "GitHub Actions"]
    pinados = [d for d in deps_osv if d[2]]
    sem_pin = [d for d in deps_osv if not d[2]]
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
        return {"error": str(ex), "sources": sources, "deps": len(deps),
                "vazios": vazios}
    gha_hits, gha_details, gha_revisar = _consulta_gha(gha) if gha else ({}, {}, [])
    hits.update(gha_hits)
    # busca detalhes (limitada) para severidade/summary/fix
    details: dict[str, dict] = dict(gha_details)
    uniq = [vid for ids in hits.values() for vid in ids]
    for vid in [v for v in dict.fromkeys(uniq) if v not in details][:SCA_DETAIL_CAP]:
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
    for r in gha_revisar:
        findings.append({
            "rule": r["id"],
            "severity": "INFO",
            "path": dep_paths.get(("GitHub Actions", r["name"], r["ref"]), ""),
            "line": 1,
            "message": (f"{r['name']}@{r['ref']}: advisory conhecido nesta action, "
                        f"mas nao da' para confirmar pela ref ({r['motivo']}); "
                        f"confira https://osv.dev/vulnerability/{r['id']}"),
            "context": "SCA · GitHub Actions",
        })
    return {"sources": sources, "deps": len(deps), "vulns": hits,
            "gha_revisar": gha_revisar, "gha": len(gha), "vazios": vazios,
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
        for caminho in sca.get("vazios", []):
            print(f" ⚠ {caminho}: nenhuma dependência extraída deste arquivo")
        return
    srcs = sca.get("sources", [])
    pinados = sca.get("pinados", sca.get("deps", 0))
    # As actions nao entram em `pinados` (vao por outro caminho no OSV, ver
    # `_consulta_gha`). Sem contar a parte delas aqui, o relatorio mostraria
    # "20 encontradas / 12 checadas" e daria a entender que 8 ficaram de fora.
    n_gha = sca.get("gha", 0)
    linha = (f" fontes: {', '.join(dict.fromkeys(srcs)) or '—'}  ·  "
             f"dependências encontradas: {sca.get('deps', 0)}  ·  "
             f"com versão fixada (checadas no OSV): {pinados}")
    if n_gha:
        linha += f"  ·  actions do GitHub: {n_gha}"
    print(linha)
    # Dizer o que NAO foi checado importa mais que o check verde: sem isto, um
    # requirements.txt todo em `>=` exibia "nenhuma vulnerável ✅" sem que uma
    # unica dependencia tivesse sido consultada.
    sem_pin = sca.get("sem_pin", [])
    if sem_pin:
        amostra = ", ".join(sem_pin[:6]) + ("…" if len(sem_pin) > 6 else "")
        print(f" ⚠ {len(sem_pin)} sem versão fixada — NÃO checadas contra CVE: {amostra}")
        print("   (fixe com `==` ou gere um lock para que possam ser verificadas)")
    # Mesmo espirito do aviso acima: dizer o que NAO foi checado vale mais que
    # o visto verde. Um lock ilegivel some do relatorio inteiro se ninguem o
    # nomear -- e o silencio se parece exatamente com "esta' tudo certo".
    for caminho in sca.get("vazios", []):
        print(f" ⚠ {caminho}: nenhuma dependência extraída deste arquivo")
    if sca.get("vazios"):
        print("   (ou o arquivo está vazio, ou o raptor-win não soube lê-lo —")
        print("    confira antes de tratar o resultado como 'sem dependências')")
    _render_typosquat(sca.get("typosquat", []))
    for r in sca.get("gha_revisar", []):
        print(f" ⚠ {r['name']}@{r['ref']}: advisory {r['id']} nesta action, "
              f"não confirmável pela ref ({r['motivo']})")
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
    # Cabeçalhos de segurança do host estático (netlify.toml / _headers /
    # vercel.json). Mesma natureza do sql_lint: leitura local, sem rede, sem
    # flag. E mesma razão de existir -- o Semgrep olha código, e esta
    # configuração não é código, então ninguém olhava.
    sqlf = (headers_lint.escanear(targets, SKIP_DIRS)
            + supply_chain.escanear(targets, SKIP_DIRS)
            + sql_lint.escanear(targets, SKIP_DIRS))
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
