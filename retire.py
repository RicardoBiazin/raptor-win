"""Bibliotecas JS com vulnerabilidade conhecida no que o site publicado serve.

Usa a base do Retire.js (Apache-2.0), atualizada toda semana pela rotina de
sync em `data/terceiros/`. O SCA olha o lockfile; isto olha o que está NO AR:
pega o deploy velho que o lockfile corrigido não prova, e funciona em site sem
repositório (CDN no `<script>`, site estático legado).

Só as formas passivas da base: `uri`, `filename` e `filecontent`. As formas
`func`/`ast`/`hashes` exigem executar ou parsear o JS, e ficam de fora.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

DADOS = Path(__file__).resolve().parent / "data" / "terceiros"
BASE = DADOS / "retire-jsrepository.json"
BACKDOOR = DADOS / "retire-backdoored.json"
# O marcador de versão da base vira este grupo (o mesmo do próprio Retire.js).
_VERSAO = r"[0-9][0-9.a-z_\-]+"
# Banner de biblioteca fica no topo; o resto do bundle minificado é uma linha
# de centenas de KB, onde padrão com `.*` fica quadrático.
MAX_CONTEUDO = 512 * 1024
_RE_SUFIXO = re.compile(r"(?:[.\-](?:min|slim|prod|production|js|umd|esm|bundle))+$")
_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _compilar(padroes: list[str]) -> list[re.Pattern]:
    out = []
    for p in padroes or []:
        try:
            out.append(re.compile(p.replace("§§version§§", _VERSAO)))
        except re.error:
            continue  # sintaxe só do JS: a base tem um ou dois desses
    return out


@lru_cache(maxsize=1)
def _base() -> dict:
    try:
        dados = json.loads(BASE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    libs = {}
    for nome, lib in dados.items():
        if nome == "retire-example" or not isinstance(lib, dict):
            continue
        ext = lib.get("extractors") or {}
        libs[nome] = {
            "uri": _compilar(ext.get("uri")),
            "filename": _compilar(ext.get("filename")),
            "filecontent": _compilar(ext.get("filecontent")),
            "vulns": lib.get("vulnerabilities") or [],
        }
    return libs


@lru_cache(maxsize=1)
def _backdoors() -> list[tuple[str, str, re.Pattern]]:
    try:
        dados = json.loads(BACKDOOR.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for nome, itens in dados.items():
        for item in itens or []:
            for p in item.get("extractors") or []:
                try:
                    out.append((nome, item.get("summary", ""), re.compile(p)))
                except re.error:
                    continue
    return out


def disponivel() -> bool:
    return bool(_base())


def _partes(v: str) -> list:
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-_]", v.lower()) if x]


def comparar(a: str, b: str) -> int:
    """-1, 0, 1. Pré-lançamento (texto) vem antes do lançamento: 1.0.0-beta < 1.0.0."""
    pa, pb = _partes(a), _partes(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else None
        y = pb[i] if i < len(pb) else None
        if x == y:
            continue
        if x is None:
            return 1 if isinstance(y, str) else -1
        if y is None:
            return -1 if isinstance(x, str) else 1
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return 1
        if isinstance(y, int):
            return -1
        return -1 if x < y else 1
    return 0


def detectar(url: str, texto: str) -> dict[str, str]:
    """{biblioteca: versão} achadas na URL, no nome do arquivo ou no conteúdo."""
    achadas: dict[str, str] = {}
    caminho = urlparse(url).path
    arquivo = caminho.rsplit("/", 1)[-1]
    inicio = texto[:MAX_CONTEUDO]
    for nome, lib in _base().items():
        for tipo, alvo in (("uri", caminho), ("filename", arquivo), ("filecontent", inicio)):
            for rx in lib[tipo]:
                m = rx.search(alvo)
                if m and m.groups() and m.group(1):
                    # O grupo é guloso (o banner precisa disso) e, no nome do
                    # arquivo, engole o `.min` de `jquery-1.11.0.min.js`.
                    achadas[nome] = _RE_SUFIXO.sub("", m.group(1)).rstrip(".-_")
                    break
            if nome in achadas:
                break
    return achadas


def vulnerabilidades(nome: str, versao: str) -> list[dict]:
    out = []
    for v in _base().get(nome, {}).get("vulns", []):
        abaixo, desde = v.get("below"), v.get("atOrAbove")
        try:
            if abaixo and comparar(versao, abaixo) >= 0:
                continue
            if desde and comparar(versao, desde) < 0:
                continue
        except TypeError:
            continue
        out.append(v)
    return out


def backdoor(url: str) -> str | None:
    """Resumo do aviso se a URL é de host sabidamente comprometido (polyfill.io…)."""
    for _nome, resumo, rx in _backdoors():
        if rx.search(url):
            return resumo or "host de script comprometido"
    return None


def resumo_vulns(vulns: list[dict]) -> tuple[str, list[str], list[str]]:
    """(severidade máxima, CVEs, CWEs)."""
    ordem = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sev = max((_SEV.get(str(v.get("severity", "")).lower(), "MEDIUM") for v in vulns),
              key=ordem.index, default="MEDIUM")
    cves = sorted({c for v in vulns for c in (v.get("identifiers") or {}).get("CVE") or []})
    cwes = sorted({c for v in vulns for c in v.get("cwe") or [] if str(c).startswith("CWE-")})
    return sev, cves, cwes
