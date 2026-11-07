"""Quais CVEs das dependências estão sendo exploradas de fato.

O OSV diz que a versão é vulnerável; não diz se alguém está explorando. Duas
fontes públicas respondem isso:

- **CISA KEV** (Known Exploited Vulnerabilities): catálogo de CVEs com
  exploração confirmada em ataque real. Estar nele é fato, não estimativa —
  por isso o achado sobe para pelo menos HIGH.
- **EPSS** (FIRST.org): probabilidade estimada de exploração nos próximos 30
  dias. É estimativa: só anota, não muda severidade.

O catálogo KEV inteiro (~1,5 MB) fica em cache por 24 h. Sem rede, vale o cache
velho, e o relatório diz de quando ele é. Sem rede e sem cache, o relatório diz
que a checagem NÃO foi feita: ausência de marca não pode parecer "nenhuma
explorada".
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from datetime import datetime
from pathlib import Path

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Espelho oficial da própria CISA no GitHub, para quando o site principal falha.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
EPSS_LOTE = 100
CACHE_HORAS = 24
UA = "raptor-win (https://github.com/RicardoBiazin/raptor-win)"
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _buscar_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def pasta_cache() -> Path:
    base = (os.environ.get("RAPTOR_WIN_CACHE") or os.environ.get("LOCALAPPDATA")
            or os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache"))
    return Path(base) / "raptor-win"


def _indice_kev(dados) -> dict[str, str] | None:
    """{CVE: dateAdded}. None se o JSON não tem a forma do catálogo."""
    if not isinstance(dados, dict) or not isinstance(dados.get("vulnerabilities"), list):
        return None
    return {v["cveID"]: v.get("dateAdded", "") for v in dados["vulnerabilities"]
            if isinstance(v, dict) and isinstance(v.get("cveID"), str)}


def carregar_kev(buscar=_buscar_json, pasta: Path | None = None,
                 agora: float | None = None) -> tuple[dict[str, str] | None, str]:
    """Devolve (índice, origem). Origem diz de onde veio, para o relatório."""
    arq = (pasta or pasta_cache()) / "kev.json"
    agora = time.time() if agora is None else agora
    cache = None
    try:
        cache = _indice_kev(json.loads(arq.read_text(encoding="utf-8")))
        idade = agora - arq.stat().st_mtime
        if cache is not None and idade < CACHE_HORAS * 3600:
            return cache, "cache de hoje"
    except (OSError, ValueError):
        cache = None
    for url in KEV_URLS:
        try:
            dados = buscar(url)
        except Exception:
            continue
        indice = _indice_kev(dados)
        if indice:
            try:
                arq.parent.mkdir(parents=True, exist_ok=True)
                arq.write_text(json.dumps(dados), encoding="utf-8")
            except OSError:
                pass
            return indice, "baixado agora"
    if cache is not None:
        quando = datetime.fromtimestamp(arq.stat().st_mtime).strftime("%Y-%m-%d")
        return cache, f"cache de {quando} (sem rede para atualizar)"
    return None, "indisponível"


def carregar_epss(cves: list[str], buscar=_buscar_json) -> dict[str, tuple[float, float]] | None:
    """{CVE: (epss, percentil)}. None se a consulta falhou."""
    out: dict[str, tuple[float, float]] = {}
    try:
        for i in range(0, len(cves), EPSS_LOTE):
            dados = buscar(EPSS_URL + ",".join(cves[i:i + EPSS_LOTE]))
            for d in dados.get("data", []):
                out[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
    except Exception:
        return None
    return out


def cves_de(vid: str, detalhe: dict) -> list[str]:
    """O id do OSV (GHSA-…, PYSEC-…) quase nunca é o CVE: ele está em `aliases`."""
    ids = [vid] + list((detalhe or {}).get("aliases") or [])
    return list(dict.fromkeys(i for i in ids if isinstance(i, str) and _RE_CVE.match(i)))


def anotar(findings: list[dict], detalhes: dict, buscar=_buscar_json,
           pasta: Path | None = None) -> dict:
    """Marca os achados do OSV (os que têm `osv_id`) com KEV e EPSS.

    Devolve o estado das duas consultas para o relatório dizer o que foi e o que
    não foi checado.
    """
    alvo = [f for f in findings if f.get("osv_id")]
    por_achado = {id(f): cves_de(f["osv_id"], detalhes.get(f["osv_id"], {})) for f in alvo}
    cves = sorted({c for cs in por_achado.values() for c in cs})
    estado = {"cves": len(cves), "kev_origem": None, "kev": [], "epss": None}
    if not cves:
        return estado
    kev, origem = carregar_kev(buscar, pasta)
    estado["kev_origem"] = origem
    epss = carregar_epss(cves, buscar)
    estado["epss"] = epss is not None
    for f in alvo:
        cs = por_achado[id(f)]
        datas = sorted(kev[c] for c in cs if kev and c in kev)
        if datas:
            f["kev"] = datas[0]
            estado["kev"].append(f["osv_id"])
            if f["severity"] != "CRITICAL":
                f["severidade_osv"] = f["severity"]
                f["severity"] = "HIGH"
            f["message"] += f"; EXPLORADA EM ATAQUE REAL (CISA KEV desde {datas[0]})"
        notas = [epss[c] for c in cs if epss and c in epss]
        if notas:
            e, p = max(notas)
            f["epss"] = e
            f["message"] += f"; EPSS {e:.1%} de chance de exploração em 30 dias (percentil {p:.0%})"
    return estado


def linha_relatorio(estado: dict | None) -> str | None:
    if not estado or not estado.get("cves"):
        return None
    if estado["kev_origem"] == "indisponível":
        kev = "CISA KEV NÃO consultado (sem rede e sem cache)"
    else:
        kev = f"{len(estado['kev'])} explorada(s) em ataque real (CISA KEV, {estado['kev_origem']})"
    epss = "EPSS anotado" if estado["epss"] else "EPSS NÃO consultado"
    return f"- **Exploração:** {estado['cves']} CVE(s) verificada(s); {kev}; {epss}"
