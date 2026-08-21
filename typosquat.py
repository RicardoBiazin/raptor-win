"""Typosquat detection for dependencies — the supply-chain leg of raptor-win.

SCA answers "does this dependency have a known CVE?". It cannot answer the
question that matters when the attack is *fresh*: **is this dependency even the
package you think it is?** A name one keystroke away from a very popular package
(`loadash` for `lodash`, `python-dateutil` vs `python-dateutils`) has no CVE,
because nobody has reported it yet — it is malicious by construction, published
minutes ago, and OSV.dev has never heard of it.

This module compares every dependency name against a bundled list of the most
popular packages per ecosystem and reports the near-misses.

Ported from RAPTOR's `packages/sca/supply_chain/typosquat.py` (MIT). The
algorithm, the thresholds and the bundled popularity data are theirs; the
packaging into a single dependency-free module is raptor-win's. See NOTICE.

Precision matters more than recall here. A scanner that cries wolf on every
dependency gets muted, so:

  * an exact hit in the popular list is the popular package — never flagged;
  * a hand-vetted allowlist covers real projects that legitimately sit one edit
    from a famous name (`preact` vs `react`);
  * distance drives severity, because distance-1 is far more suspicious than
    distance-2, and a scoped bare-name match (`@evil/lodash`) is worse still.
"""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

# Distancia maxima considerada. Acima de 2 o ruido cresce muito mais rapido que
# o sinal: nomes de 8+ caracteres tem dezenas de vizinhos legitimos a distancia 3.
_MAX_DISTANCE = 2

# Prefiltro por conjunto de caracteres: se dois nomes diferem em mais de
# 2*_MAX_DISTANCE caracteres distintos, a distancia de edicao NAO cabe no limite.
# E' exato -- nunca descarta um par que passaria --, so' evita rodar a DP.
_SYMDIFF_CUTOFF = 2 * _MAX_DISTANCE

_BIT_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_.@/+~"
_CHAR_BIT = {c: i for i, c in enumerate(_BIT_ALPHABET)}
_OTHER_BIT = 63

# Caches por ecossistema, preenchidos sob demanda.
_POPULAR: dict[str, list[str]] = {}
_POPULAR_SET: dict[str, set[str]] = {}
_POPULAR_BY_LEN: dict[str, dict[int, list[tuple[str, int]]]] = {}
_DENYLIST: dict[str, set[str]] = {}
_ALLOWLIST: dict[str, set[str]] = {}


def _ler_json(caminho: Path):
    """Le' JSON SEMPRE em utf-8.

    Sem o encoding explicito o Python no Windows abre em cp1252 e estoura com
    UnicodeDecodeError no primeiro caractere acentuado dos comentarios dos
    arquivos de dados -- que foi exatamente o que aconteceu ao montar este
    modulo.
    """
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _char_mask(nome: str) -> int:
    """Bitmask dos caracteres distintos presentes em `nome`."""
    mask = 0
    get = _CHAR_BIT.get
    for c in nome:
        mask |= 1 << get(c, _OTHER_BIT)
    return mask


def _popular(eco: str) -> list[str]:
    if eco not in _POPULAR:
        dados = _ler_json(_DATA / "popular" / f"{eco}.json")
        _POPULAR[eco] = [n.lower() for n in dados] if isinstance(dados, list) else []
    return _POPULAR[eco]


def _popular_set(eco: str) -> set[str]:
    if eco not in _POPULAR_SET:
        _POPULAR_SET[eco] = set(_popular(eco))
    return _POPULAR_SET[eco]


def _popular_por_tamanho(eco: str) -> dict[int, list[tuple[str, int]]]:
    """Indice {tamanho: [(nome, mask)]}.

    A distancia so' pode ser <= _MAX_DISTANCE se os tamanhos diferirem no
    maximo isso, entao percorrer os baldes vizinhos evita ~5 mil comparacoes
    por dependencia.
    """
    if eco not in _POPULAR_BY_LEN:
        baldes: dict[int, list[tuple[str, int]]] = {}
        for nome in _popular(eco):
            baldes.setdefault(len(nome), []).append((nome, _char_mask(nome)))
        _POPULAR_BY_LEN[eco] = baldes
    return _POPULAR_BY_LEN[eco]


_ESCOPOS: dict[str, set[str]] = {}


def _escopos_confiaveis(eco: str) -> set[str]:
    """Escopos cujo nome nu nao vale como sinal de squat.

    Cache por ecossistema: o arquivo e' lido uma vez por processo.
    """
    if eco not in _ESCOPOS:
        dados = _ler_json(_DATA / "escopos-confiaveis.json") or {}
        _ESCOPOS[eco] = {s.lower() for s in dados.get(eco, [])}
    return _ESCOPOS[eco]


def _lista(arquivo: str, cache: dict[str, set[str]], eco: str) -> set[str]:
    if eco not in cache:
        dados = _ler_json(_DATA / arquivo) or {}
        entrada = dados.get(eco) or []
        # A denylist e' lista; a allowlist e' {nome: metadados}. As duas viram
        # conjunto de nomes normalizados.
        nomes = entrada.keys() if isinstance(entrada, dict) else entrada
        cache[eco] = {str(n).lower() for n in nomes}
    return cache[eco]


def _distancia(a: str, b: str, cutoff: int) -> int:
    """Damerau-Levenshtein (alinhamento otimo) com saida antecipada.

    Devolve `cutoff` quando a distancia real passa do limite -- quem chama so'
    precisa saber que nao cabe, e parar cedo economiza a maior parte do custo.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) >= cutoff:
        return cutoff
    if la == 0:
        return min(lb, cutoff)
    if lb == 0:
        return min(la, cutoff)

    ante_ant = [0] * (lb + 1)
    ant = list(range(lb + 1))          # linha base d[0][j] = j
    atual = [0] * (lb + 1)
    for i in range(1, la + 1):
        atual[0] = i
        menor_da_linha = atual[0]
        for j in range(1, lb + 1):
            custo = 0 if a[i - 1] == b[j - 1] else 1
            atual[j] = min(ant[j] + 1,            # remocao
                           atual[j - 1] + 1,      # insercao
                           ant[j - 1] + custo)    # substituicao
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                atual[j] = min(atual[j], ante_ant[j - 2] + 1)   # transposicao
            if atual[j] < menor_da_linha:
                menor_da_linha = atual[j]
        if menor_da_linha >= cutoff:
            return cutoff
        # Rotaciona DEPOIS de preencher: a linha recem-calculada vira a anterior.
        atual, ant, ante_ant = [0] * (lb + 1), atual, ant
    return min(ant[lb], cutoff)


def _checar(eco: str, nome: str, versao: str) -> dict | None:
    populares = _popular(eco)
    if not populares:
        return None
    n = nome.lower()

    if n in _lista("denylist.json", _DENYLIST, eco):
        return {"ecosystem": eco, "name": nome, "version": versao,
                "nearest": n, "distance": 0, "severity": "high",
                "reason": "nome na denylist de confusaveis ja' verificados"}

    # E' o proprio pacote popular -- nada a dizer.
    if n in _popular_set(eco):
        return None
    # Projeto real que so' PARECE com um famoso (preact x react).
    if n in _lista("allowlist.json", _ALLOWLIST, eco):
        return None

    # `@escopo/nome`: o nome nu vale APENAS por igualdade exata.
    #
    # Squat de escopo e' publicar `@mau/lodash` para se passar por `lodash` -- o
    # nome nu bate EXATAMENTE com o popular. Comparar o nome nu por APROXIMACAO,
    # como se fazia aqui, acusa meio ecossistema: `@dnd-kit/core` fica a 1 edicao
    # de `cors`, `@chevrotain/types` a 1 de `type`, `@floating-ui/dom` a 1 de
    # `dot`. Nome generico de subpacote (core, types, dom, utils, node) e' a regra
    # em pacote com escopo, e nenhum deles esta' imitando ninguem.
    #
    # Medido em 21/08/2026 num projeto React: 80 dos 82 achados vinham daqui,
    # todos em HIGH. Relatorio nesse estado nao e' lido, e a checagem inteira
    # perde o valor -- que esta' em NAO gritar.
    if n.startswith("@") and "/" in n:
        escopo, nu = n.split("/", 1)
        # Escopo de organizacao conhecida: o nome nu igual ao popular e' a
        # CONVENCAO, nao ataque -- @types/lodash tipa o lodash. Ver
        # data/escopos-confiaveis.json.
        if escopo in _escopos_confiaveis(eco):
            return None
        if nu in _popular_set(eco):
            return {"ecosystem": eco, "name": nome, "version": versao,
                    "nearest": nu, "distance": 0, "severity": "high",
                    "reason": (f"o nome nu bate com o popular '{nu}': "
                               "formato de squat de escopo")}

    candidatos = [n]

    baldes = _popular_por_tamanho(eco)
    melhor: tuple[int, str] | None = None
    for cand in candidatos:
        mask = _char_mask(cand)
        for tam in range(len(cand) - _MAX_DISTANCE, len(cand) + _MAX_DISTANCE + 1):
            for pop, pop_mask in baldes.get(tam, ()):
                if cand == pop:
                    if melhor is None or melhor[0] > 0:
                        melhor = (0, pop)
                    continue
                if (mask ^ pop_mask).bit_count() > _SYMDIFF_CUTOFF:
                    continue
                d = _distancia(cand, pop, _MAX_DISTANCE + 1)
                if d <= _MAX_DISTANCE and (melhor is None or d < melhor[0]):
                    melhor = (d, pop)

    if melhor is None:
        return None
    distancia, vizinho = melhor
    if distancia == 0:
        sev, motivo = "high", (f"o nome nu bate com o popular '{vizinho}': "
                               "formato de squat de escopo")
    elif distancia == 1:
        sev, motivo = "high", (f"a 1 edicao de '{vizinho}'; pode ser pacote "
                               "legitimo, mas e' o formato classico de typosquat")
    else:
        sev, motivo = "medium", (f"a {distancia} edicoes de '{vizinho}'; "
                                 "confira se e' o pacote que voce queria")
    return {"ecosystem": eco, "name": nome, "version": versao,
            "nearest": vizinho, "distance": distancia,
            "severity": sev, "reason": motivo}


def escanear(deps) -> list[dict]:
    """Recebe `(ecossistema, nome, versao)` e devolve os achados, piores antes."""
    achados = [a for a in (_checar(e, n, v) for (e, n, v) in deps) if a]
    achados.sort(key=lambda a: (a["distance"], a["name"]))
    return achados


def ecossistemas_cobertos() -> list[str]:
    """Para que o relatorio possa dizer o que NAO foi coberto."""
    pasta = _DATA / "popular"
    return sorted(p.stem for p in pasta.glob("*.json")) if pasta.is_dir() else []


__all__ = ["escanear", "ecossistemas_cobertos"]
