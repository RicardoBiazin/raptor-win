"""
Checagens de SQL que precisam olhar MAIS DE UM comando ao mesmo tempo — coisa
que o Semgrep (por padrão, uma regra por trecho) não faz bem. Complementa as
regras `rules/raptorwin/supabase/*.yaml`.

Detecta:
  * Índices DUPLICADOS: dois `create index` na mesma tabela com a MESMA lista de
    colunas (mesma unicidade e mesmo `where`). O segundo só custa escrita e
    espaço. (Supabase: "Duplicate Index".)
  * Múltiplas policies PERMISSIVAS para a mesma (tabela, ação, papel): o Postgres
    avalia TODAS por linha e combina com OR — dá para consolidar numa só.
    (Supabase: "Multiple Permissive Policies".) Policies `as restrictive` não
    entram (elas combinam com AND, propósito diferente).

Saída: lista de dicts {rule, severity, path, line, message} — o mesmo formato de
`secrets_scan`, para entrar na mesma lista do relatório.

Heurística por regex, não um parser SQL completo: mira o DDL comum de índice e de
policy. Marca o padrão para revisão; não afirma bug de execução.
"""
from __future__ import annotations

import re
from pathlib import Path

# Ações concretas que uma policy pode cobrir; `all` cobre todas.
_ACOES = ("select", "insert", "update", "delete")

_RE_INDEX = re.compile(
    r"create\s+(?P<unique>unique\s+)?index\s+(?:concurrently\s+)?"
    r"(?:if\s+not\s+exists\s+)?(?P<name>[\w.\"]+)\s+on\s+(?P<table>[\w.\"]+)\s*"
    r"(?:using\s+\w+\s*)?\((?P<cols>[^)]*)\)(?P<rest>[^;]*)",
    re.IGNORECASE | re.DOTALL,
)
_RE_POLICY = re.compile(
    r"create\s+policy\s+(?P<name>[\w.\"]+)\s+on\s+(?P<table>[\w.\"]+)(?P<body>[^;]*)",
    re.IGNORECASE | re.DOTALL,
)
_RE_TO = re.compile(r"\bto\s+(?P<roles>[\w\s,\"]+?)(?=\busing\b|\bwith\b|$)", re.IGNORECASE | re.DOTALL)
_RE_FOR = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b", re.IGNORECASE)
_RE_WHERE = re.compile(r"\bwhere\b(?P<w>.*)", re.IGNORECASE | re.DOTALL)


def _linha(texto: str, pos: int) -> int:
    return texto.count("\n", 0, pos) + 1


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _cols_norm(cols: str) -> str:
    return ", ".join(_norm(c) for c in cols.split(","))


def _papeis_efetivos(roles_txt: str | None) -> set[str]:
    # Sem `to` a policy vale para PUBLIC. `public` expande para anon+authenticated
    # (os dois papéis de cliente que o advisor considera).
    if not roles_txt:
        return {"anon", "authenticated"}
    papeis = {_norm(r) for r in roles_txt.split(",") if r.strip()}
    if "public" in papeis:
        papeis.discard("public")
        papeis |= {"anon", "authenticated"}
    return papeis


def _acoes_de(cmd: str | None) -> set[str]:
    c = (cmd or "all").lower()
    return set(_ACOES) if c == "all" else {c}


def _arquivos_sql(alvos: list[Path], skip_dirs: set[str]) -> list[Path]:
    out: list[Path] = []
    for alvo in alvos:
        if alvo.is_file():
            if alvo.suffix.lower() == ".sql":
                out.append(alvo)
            continue
        for p in alvo.rglob("*.sql"):
            if any(part in skip_dirs for part in p.parts):
                continue
            out.append(p)
    return sorted(set(out))


def _achados_indices(texto: str, rel: str) -> list[dict]:
    achados: list[dict] = []
    vistos: dict[tuple, tuple[str, int]] = {}
    for m in _RE_INDEX.finditer(texto):
        where = _RE_WHERE.search(m.group("rest") or "")
        chave = (
            _norm(m.group("table")),
            _cols_norm(m.group("cols")),
            bool(m.group("unique")),
            _norm(where.group("w")) if where else "",
        )
        nome = _norm(m.group("name"))
        if chave in vistos:
            nome_orig, linha_orig = vistos[chave]
            achados.append({
                "rule": "sql.duplicate-index",
                "severity": "INFO",
                "context": "",
                "path": rel,
                "line": _linha(texto, m.start()),
                "message": (
                    f"Índice duplicado: `{nome}` tem as mesmas colunas de "
                    f"`{nome_orig}` (linha {linha_orig}) em `{chave[0]}`. Um índice "
                    f"idêntico só custa escrita e espaço — mantenha um e remova o outro."
                ),
            })
        else:
            vistos[chave] = (nome, _linha(texto, m.start()))
    return achados


def _achados_policies(texto: str, rel: str) -> list[dict]:
    # (tabela, ação, papel) -> lista de (nome, linha) de policies PERMISSIVAS.
    from collections import defaultdict
    grupos: dict[tuple, list[tuple[str, int]]] = defaultdict(list)
    for m in _RE_POLICY.finditer(texto):
        body = m.group("body") or ""
        if re.search(r"\bas\s+restrictive\b", body, re.IGNORECASE):
            continue  # restritiva combina com AND — não é "multiple permissive"
        tabela = _norm(m.group("table"))
        nome = _norm(m.group("name"))
        linha = _linha(texto, m.start())
        cmd = _RE_FOR.search(body)
        acoes = _acoes_de(cmd.group(1) if cmd else None)
        to = _RE_TO.search(body)
        papeis = _papeis_efetivos(to.group("roles") if to else None)
        for a in acoes:
            for p in papeis:
                grupos[(tabela, a, p)].append((nome, linha))

    achados: list[dict] = []
    reportado: set[tuple] = set()  # (tabela, frozenset(nomes)) — evita repetir por ação/papel
    for (tabela, acao, papel), lista in grupos.items():
        if len(lista) < 2:
            continue
        nomes = frozenset(n for n, _ in lista)
        chave = (tabela, nomes)
        if chave in reportado:
            continue
        reportado.add(chave)
        linha = max(ln for _, ln in lista)
        achados.append({
            "rule": "sql.multiple-permissive-policies",
            "severity": "INFO",
            "context": "",
            "path": rel,
            "line": linha,
            "message": (
                f"Múltiplas policies PERMISSIVAS em `{tabela}` para {acao}/{papel}: "
                f"{', '.join(sorted(nomes))}. O Postgres avalia todas por linha e "
                f"combina com OR — consolide numa policy só (ou use `as restrictive`)."
            ),
        })
    return achados


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    achados: list[dict] = []
    for arq in _arquivos_sql(alvos, skip_dirs):
        try:
            texto = arq.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = str(arq.relative_to(Path.cwd())).replace("\\", "/")
        except ValueError:
            rel = str(arq).replace("\\", "/")
        achados += _achados_indices(texto, rel)
        achados += _achados_policies(texto, rel)
    achados.sort(key=lambda a: (a["path"], a["line"]))
    return achados
