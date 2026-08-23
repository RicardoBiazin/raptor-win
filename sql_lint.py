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
  * REVOKE de EXECUTE que fecha `public`/`anon` e ESQUECE `authenticated`, sem
    nenhum GRANT deliberado para esse papel. Correlaciona comandos de ARQUIVOS
    diferentes — o create, o revoke e o grant da mesma função costumam morar em
    migrações separadas.
  * Função DEFINER que nenhum grant/revoke cita: no Supabase ela nasce
    executável por `anon`, porque a plataforma roda `alter default privileges
    ... grant execute on functions to anon, authenticated`. Fechar em bloco uma
    vez não sustenta — só `alter default privileges ... revoke` alcança o que
    vem depois.
  * `set search_path` presente mas SEM `pg_temp`: a regra do Semgrep só exige
    que o search_path exista, então `= public` passa limpo e continua
    sequestrável (o Postgres procura pg_temp PRIMEIRO para nomes de relação).
  * DEFINER que recebe o inquilino por PARÂMETRO sem conferir a sessão —
    leitura entre inquilinos, sem o RLS intervir.
  * Guarda condicionada a `auth.uid() is not null`: o caminho sem sessão não
    passa por verificação nenhuma.

NÃO implementado, e o motivo importa: "arquivo com guarda `raise exception` e
sem `begin;`/`commit;` explícito". A falha é real — colado no SQL Editor do
Supabase, que não envolve o arquivo numa transação, a guarda dispara e todos os
comandos anteriores ficam aplicados. Mas ela é propriedade do CANAL DE ENTREGA,
não do arquivo: um runner que faz `client.query(arquivo_inteiro)` manda uma
simple query multi-comando, que o Postgres envolve numa transação implícita, e
aí o mesmo arquivo está correto. Medido em dois repositórios reais: 16 achados
num que usa runner (todos falsos) contra 2 noutro que aplica à mão (os dois
verdadeiros). A posição da guarda no arquivo não separa os casos — nos dois ela
vem depois dos comandos mutantes. Sem discriminador legível no arquivo, a
checagem só treinaria a pessoa a ignorar achado.

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

# EXECUTE de função concedido/revogado. O alvo é `.+?` e não `[\w.]+` porque a
# lista de argumentos quebra linha entre o nome e o `from`/`to` — casar só até o
# fim da linha perderia justamente as assinaturas longas, que são as das funções
# que mais importam.
_RE_REVOKE_EXEC = re.compile(
    r"\brevoke\s+(?:all\s+privileges|all|execute)\s+on\s+function\s+"
    r"(?P<alvo>.+?)\s+from\s+(?P<papeis>[^;]+)",
    re.IGNORECASE | re.DOTALL,
)
_RE_GRANT_EXEC = re.compile(
    r"\bgrant\s+(?:all\s+privileges|all|execute)\s+on\s+function\s+"
    r"(?P<alvo>.+?)\s+to\s+(?P<papeis>[^;]+)",
    re.IGNORECASE | re.DOTALL,
)
# Nome de função literal: sem schema, sem aspas. Serve de filtro para descartar
# alvo dinâmico (`%s` de um `format()` dentro de bloco DO), cuja identidade não
# dá para saber por regex.
_RE_NOME_SIMPLES = re.compile(r"^[a-z_][a-z0-9_$]*$")


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


def _chave_funcao(alvo: str) -> tuple[str, str] | None:
    """`public.fn_x(uuid, text)` -> ('fn_x', 'uuid, text'). None se não for literal.

    O schema sai da chave de propósito: o mesmo repositório escreve ora
    `public.fn_x(...)`, ora `fn_x(...)`, e tratá-los como funções diferentes
    faria o GRANT de um lado não cancelar o REVOKE do outro — que é exatamente
    o falso positivo que esta checagem existe para não produzir.
    """
    alvo = alvo.strip()
    abre = alvo.find("(")
    nome_txt = alvo if abre < 0 else alvo[:abre]
    args = "" if abre < 0 else alvo[abre + 1:alvo.rfind(")")] if alvo.rfind(")") > abre else ""
    nome = _norm(nome_txt).split(".")[-1].strip('"')
    if not _RE_NOME_SIMPLES.match(nome):
        return None
    return nome, _norm(args)


def _papeis_listados(txt: str) -> set[str]:
    """Papéis de um `from`/`to`, ignorando o que não for identificador simples."""
    papeis = set()
    for parte in txt.split(","):
        p = _norm(parte).strip('"')
        if re.fullmatch(r"[a-z_][a-z0-9_]*", p):
            papeis.add(p)
    return papeis


def _coletar_execute(texto: str, rel: str, revogados: dict, concedidos: dict) -> None:
    """Acumula, POR FUNÇÃO, a união dos papéis revogados e concedidos.

    União, e não statement a statement: a correção de um revoke incompleto
    costuma ser um `revoke` NOVO numa migração posterior, com o repositório
    guardando os dois. Avaliando cada comando isolado, o repositório já
    corrigido continuaria acusando para sempre.
    """
    for m in _RE_REVOKE_EXEC.finditer(texto):
        chave = _chave_funcao(m.group("alvo"))
        if chave is None:
            continue
        papeis = _papeis_listados(m.group("papeis"))
        if not papeis:
            continue
        atual = revogados.setdefault(chave, {"papeis": set(), "path": rel, "line": 0})
        atual["papeis"] |= papeis
        # Fica com a ÚLTIMA ocorrência: é a linha onde o papel que falta seria
        # acrescentado, não a do comando histórico que já foi superado.
        atual["path"], atual["line"] = rel, _linha(texto, m.start())

    for m in _RE_GRANT_EXEC.finditer(texto):
        chave = _chave_funcao(m.group("alvo"))
        if chave is None:
            continue
        concedidos.setdefault(chave, set())
        concedidos[chave] |= _papeis_listados(m.group("papeis"))


def _achados_revoke_incompleto(revogados: dict, concedidos: dict) -> list[dict]:
    achados: list[dict] = []
    for (nome, args), info in revogados.items():
        papeis = info["papeis"]
        if not (papeis & {"public", "anon"}):
            continue          # não é uma tentativa de fechar o acesso de cliente
        if "authenticated" in papeis:
            continue          # fechou o papel que importa
        if "authenticated" in concedidos.get((nome, args), set()):
            continue          # acesso deliberado: é RPC de app, o padrão correto
        assinatura = f"{nome}({args})" if args else f"{nome}()"
        achados.append({
            "rule": "sql.supabase.revoke-incompleto",
            "severity": "HIGH",
            "context": "",
            "path": info["path"],
            "line": info["line"],
            "message": (
                f"`revoke execute on function {assinatura}` fecha "
                f"{', '.join(sorted(papeis & {'public', 'anon'}))} mas não "
                f"`authenticated`, e não há GRANT para esse papel em lugar nenhum. "
                f"No Supabase isso NÃO fecha o acesso: o projeto roda "
                f"`alter default privileges ... grant execute on functions to anon, "
                f"authenticated`, então cada função nasce com um grant PRÓPRIO para "
                f"`authenticated` — que `revoke ... from public` não desfaz. Qualquer "
                f"usuário logado continua chamando por /rest/v1/rpc/{nome}. Se a função "
                f"é SECURITY DEFINER e recebe o id do inquilino por argumento em vez de "
                f"deduzi-lo da sessão, isso é escrita entre inquilinos. Acrescente "
                f"`authenticated` à lista do revoke; se o acesso for intencional, "
                f"escreva o GRANT explícito para registrar a intenção."
            ),
        })
    return achados


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


# ---------------------------------------------------------------------------
# Parser de `create function` compartilhado pelas checagens de função.
#
# Um parser em vez de quatro regexes: as checagens de search_path, de EXECUTE e
# de inquilino-por-parâmetro precisam TODAS do mesmo recorte (nome, assinatura,
# cabeçalho, corpo), e o cabeçalho de uma função não pode ser confundido com o
# da vizinha. Balancear parênteses à mão é o que evita `numeric(10,2)` virar
# dois parâmetros e `default now()` truncar a assinatura.
# ---------------------------------------------------------------------------
_RE_CREATE_FN = re.compile(
    r"\bcreate\s+(?:or\s+replace\s+)?(?:function|procedure)\s+", re.IGNORECASE
)
_RE_TAG = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
_RE_NOME_QUALIF = re.compile(r'[\w."]+')

# Onde termina o valor de `set search_path`: no próximo atributo do cabeçalho,
# no início do corpo ou no fim do comando.
_RE_SEARCH_PATH = re.compile(
    r"\bset\s+search_path\s*(?:=|\bto\b)\s*(?P<val>.*?)"
    r"(?=\s*\b(?:as|language|security|stable|immutable|volatile|strict|leakproof|"
    r"parallel|cost|rows|window|support|set|returns|external|called|return)\b"
    r"|\s*\$|;|$)",
    re.IGNORECASE | re.DOTALL,
)

# Parâmetro cujo NOME tem forma de identificador de inquilino.
_RE_PARAM_TENANT = re.compile(
    r"^(?:[pv]_|_)?(?:org|orgs|organizacao|organization|tenant|company|empresa|"
    r"conta|account|workspace|unidade|filial|customer|cliente)(?:_?id)?$",
    re.IGNORECASE,
)
_TIPOS_ID = {"uuid", "bigint", "int", "int2", "int4", "int8", "integer",
             "smallint", "text", "varchar", "citext"}

# Qualquer coisa no corpo que amarre a execução a QUEM chamou. A presença de um
# destes é o que separa "recebe o inquilino por parâmetro" de "recebe o
# parâmetro e o confere contra a sessão".
_RE_SESSAO = re.compile(
    r"auth\.(?:uid|jwt|role)\s*\("
    r"|current_setting\s*\(\s*'request\.jwt"
    r"|\b(?:session_user|current_user)\b"
    r"|\b(?:my|meu|minha|current)_(?:org|orgs|tenant|empresa|conta|filial)\w*\s*\("
    r"|\bis_(?:admin|manager|gestor|member|membro|owner|dono|staff|platform)\w*\s*\(",
    re.IGNORECASE,
)

# Guarda cuja CONDIÇÃO exige sessão: sem uid, o `raise` nunca acontece.
_RE_GUARDA_NULL_UID = re.compile(
    r"\bif\b[^;]{0,240}?auth\.uid\s*\(\s*\)\s+is\s+not\s+null"
    r"[^;]{0,240}?\bthen\b.{0,400}?\braise\s+exception\b",
    re.IGNORECASE | re.DOTALL,
)

# Fecho em bloco. O primeiro só alcança o que JÁ existe; o segundo (default
# privileges) é o único que alcança o que vem depois.
_RE_REVOKE_BLOCO = re.compile(
    r"\brevoke\s+(?:all\s+privileges|all|execute)\s+on\s+all\s+functions\s+in\s+schema\b",
    re.IGNORECASE,
)
_RE_DEFAULT_PRIV_REVOKE = re.compile(
    r"\balter\s+default\s+privileges\b[^;]*?\brevoke\b[^;]*?\bexecute\b[^;]*?\bon\s+functions\b",
    re.IGNORECASE | re.DOTALL,
)
# Nome citado por QUALQUER grant/revoke de execute — só o nome, porque o create
# escreve `p_org uuid` e o grant escreve `uuid`: casar por assinatura nunca casa.
_RE_EXEC_ALVO = re.compile(
    r"\b(?:grant|revoke)\s+(?:all\s+privileges|all|execute)\s+on\s+function\s+"
    r"(?P<alvo>[\w.\"]+)",
    re.IGNORECASE,
)
_RE_CHAMADA = re.compile(r"\b([a-z_][a-z0-9_]*)\s*\(", re.IGNORECASE)


def _fecha_parenteses(texto: str, i: int) -> int:
    """`i` aponta para um `(`. Devolve o índice do `)` que o fecha, ou -1."""
    prof = 0
    n = len(texto)
    while i < n:
        c = texto[i]
        if c == "'":
            i = texto.find("'", i + 1)
            if i < 0:
                return -1
        elif c == '"':
            i = texto.find('"', i + 1)
            if i < 0:
                return -1
        elif c == "(":
            prof += 1
        elif c == ")":
            prof -= 1
            if prof == 0:
                return i
        i += 1
    return -1


def _dividir_args(args: str) -> list[str]:
    """Divide a assinatura na vírgula de TOPO — `numeric(10,2)` fica inteiro."""
    partes: list[str] = []
    prof = 0
    atual: list[str] = []
    for c in args:
        if c == "(":
            prof += 1
        elif c == ")":
            prof -= 1
        if c == "," and prof == 0:
            partes.append("".join(atual))
            atual = []
        else:
            atual.append(c)
    if atual:
        partes.append("".join(atual))
    return [p for p in (x.strip() for x in partes) if p]


def _funcoes(texto: str) -> list[dict]:
    """Recorta cada `create function`/`procedure`: nome, args, cabeçalho, corpo.

    `ini_corpo`/`fim_corpo` saem junto porque `_apagar_corpos_de_funcao` precisa
    apagar EXATAMENTE esses trechos — e nada além deles.
    """
    out: list[dict] = []
    for m in _RE_CREATE_FN.finditer(texto):
        mn = _RE_NOME_QUALIF.match(texto, m.end())
        if not mn:
            continue
        j = mn.end()
        while j < len(texto) and texto[j].isspace():
            j += 1
        if j >= len(texto) or texto[j] != "(":
            continue
        fim = _fecha_parenteses(texto, j)
        if fim < 0:
            continue
        args = texto[j + 1:fim]
        resto = texto[fim + 1:]
        mt = _RE_TAG.search(resto)
        # Uma tag depois de um `;` pertence a OUTRO comando — não é o corpo deste.
        if mt and ";" not in resto[:mt.start()]:
            tag = mt.group(0)
            ini_corpo = fim + 1 + mt.end()
            f2 = texto.find(tag, ini_corpo)
            fim_corpo = f2 if f2 >= 0 else len(texto)
            corpo = texto[ini_corpo:fim_corpo]
            header = resto[:mt.start()]
        else:
            ponto = resto.find(";")
            header = resto[:ponto] if ponto >= 0 else resto
            corpo = ""
            ini_corpo = fim_corpo = -1
        out.append({
            "nome": _norm(mn.group(0)).split(".")[-1].strip('"'),
            "args": args,
            "header": header,
            "corpo": corpo,
            "ini_corpo": ini_corpo,
            "fim_corpo": fim_corpo,
            "pos": m.start(),
            "linha": _linha(texto, m.start()),
            "definer": bool(re.search(r"\bsecurity\s+definer\b", header, re.IGNORECASE)),
            "trigger": bool(re.search(r"\breturns\s+trigger\b", header, re.IGNORECASE)),
        })
    return out


def _apagar(texto: str, faixas: list[tuple[int, int]]) -> str:
    """Troca as faixas por espaços PRESERVANDO comprimento e quebras de linha.

    Preservar o comprimento é o que mantém os números de linha certos depois de
    apagar.
    """
    out = list(texto)
    for ini, fim in faixas:
        if ini < 0:
            continue
        for k in range(max(0, ini), min(len(out), fim)):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _apagar_corpos_de_funcao(texto: str, funcs: list[dict]) -> str:
    """Só os corpos de `create function` — bloco `do $$ ... $$` fica INTACTO.

    A distinção importa: um `raise exception` dentro de uma função criada aqui é
    validação de execução, mas dentro de um `do $$ ... $$` é guarda de migração,
    que é exatamente o que a checagem de transação procura.
    """
    return _apagar(texto, [(f["ini_corpo"], f["fim_corpo"]) for f in funcs])


def _apagar_todo_dollar(texto: str) -> str:
    """Apaga TODA região dollar-quoted (corpo de função e bloco `do`).

    Usado pelas checagens de nível de comando: sem isso, um `grant` ou um
    `begin` ESCRITO DENTRO de um corpo contaria como comando de topo.
    """
    faixas: list[tuple[int, int]] = []
    i, n = 0, len(texto)
    while i < n:
        m = _RE_TAG.search(texto, i)
        if not m:
            break
        tag = m.group(0)
        fim = texto.find(tag, m.end())
        if fim < 0:
            break
        faixas.append((m.start(), fim + len(tag)))
        i = fim + len(tag)
    return _apagar(texto, faixas)


def _achados_search_path(texto: str, rel: str, funcs: list[dict]) -> list[dict]:
    """`set search_path` presente mas SEM `pg_temp` — a regra do Semgrep não pega.

    `raptor.supabase.function-search-path-mutable` só exige que EXISTA um
    `set search_path`, então `= public` passa limpo. E ainda é sequestrável:
    quando `pg_temp` não é nomeado na lista, o Postgres o procura PRIMEIRO para
    nomes de RELAÇÃO, então um `pg_temp.contatos` plantado assume o lugar da
    tabela real dentro do corpo DEFINER e a função o lê com os privilégios do
    dono.

    As duas checagens são complementares por construção — a do Semgrep exige o
    `set search_path` AUSENTE, esta exige que ele esteja PRESENTE — então nunca
    acusam a mesma função. Vale dizer porque é a primeira dúvida de quem revisa.
    """
    achados: list[dict] = []
    for f in funcs:
        if not f["definer"]:
            continue          # invoker roda com o path de quem chama, sem elevação
        m = _RE_SEARCH_PATH.search(f["header"])
        if not m:
            continue          # a ausência total é o caso da regra do Semgrep
        val = _norm(m.group("val"))
        itens = [x.strip().strip('"').strip("'") for x in val.split(",")]
        itens = [x for x in itens if x]
        # `= ''` (corpo todo qualificado) e só `pg_catalog` (objetos de sistema,
        # que ninguém planta em pg_temp) não abrem janela nenhuma.
        if not itens or set(itens) <= {"pg_catalog"}:
            continue
        assinatura = f"{f['nome']}()" if not f["args"].strip() else f"{f['nome']}(...)"
        if "pg_temp" not in itens:
            achados.append({
                "rule": "sql.search-path-missing-pg-temp",
                "severity": "WARNING",
                "context": "",
                "path": rel,
                "line": f["linha"],
                "message": (
                    f"`{assinatura}` é SECURITY DEFINER com `search_path = {val}` "
                    f"mas SEM `pg_temp`. Isso satisfaz o linter e continua "
                    f"sequestrável: quando `pg_temp` não está na lista, o Postgres "
                    f"o procura PRIMEIRO para nomes de RELAÇÃO, então um "
                    f"`pg_temp.<tabela>` plantado por quem chama assume o lugar da "
                    f"tabela real e a função o lê com os privilégios do dono. "
                    f"Corrija para `set search_path = {val}, pg_temp` (pg_temp por "
                    f"ÚLTIMO) ou `= ''` com tudo qualificado no corpo."
                ),
            })
        elif itens[-1] != "pg_temp":
            achados.append({
                "rule": "sql.search-path-missing-pg-temp",
                "severity": "INFO",
                "context": "",
                "path": rel,
                "line": f["linha"],
                "message": (
                    f"`{assinatura}`: `pg_temp` está no `search_path` mas NÃO por "
                    f"último (`{val}`). A ordem É a resolução de nomes — um objeto "
                    f"plantado em `pg_temp` ainda ganha dos schemas listados depois "
                    f"dele. Mova `pg_temp` para o fim da lista."
                ),
            })
    return achados


def _achados_tenant_param(texto: str, rel: str, funcs: list[dict]) -> list[dict]:
    """DEFINER que recebe o inquilino por PARÂMETRO e não confere a sessão.

    O parâmetro decide de quem são os dados, e quem chama escolhe o parâmetro:
    com o id de outro inquilino, lê os dados dele. Sendo DEFINER, o RLS não
    intervém.

    O freio de falso positivo é exigir as TRÊS coisas — DEFINER, parâmetro com
    forma de inquilino E ausência TOTAL de marcador de sessão no corpo. Uma
    função que recebe `p_org` e a confere contra `auth.uid()` não acusa, que é
    justamente o padrão correto.
    """
    achados: list[dict] = []
    for f in funcs:
        if not f["definer"] or f["trigger"] or not f["corpo"].strip():
            continue
        if _RE_SESSAO.search(f["corpo"]):
            continue
        suspeitos: list[str] = []
        for parte in _dividir_args(f["args"]):
            campos = parte.split()
            if campos and campos[0].lower() in ("in", "out", "inout", "variadic"):
                campos = campos[1:]
            if len(campos) < 2:
                continue
            nome_p = campos[0].strip('"')
            tipo_p = re.split(r"[\s(\[]", campos[1])[0].lower()
            if _RE_PARAM_TENANT.match(nome_p) and tipo_p in _TIPOS_ID:
                suspeitos.append(f"{nome_p} {tipo_p}")
        if not suspeitos:
            continue
        achados.append({
            "rule": "sql.security-definer-tenant-param",
            "severity": "ERROR",
            "context": "",
            "path": rel,
            "line": f["linha"],
            "message": (
                f"`{f['nome']}(...)` é SECURITY DEFINER e recebe o inquilino por "
                f"PARÂMETRO (`{'`, `'.join(suspeitos)}`), e o corpo não deriva nada "
                f"da sessão — nem `auth.uid()`, nem "
                f"`current_setting('request.jwt...')`, nem helper do tipo "
                f"`my_org()`/`is_admin()`. Quem tiver o id de OUTRO inquilino lê os "
                f"dados dele com os privilégios do dono, e o RLS não intervém "
                f"porque a função é DEFINER. Derive o inquilino da sessão dentro da "
                f"função (e valide o parâmetro contra ela), ou torne-a SECURITY "
                f"INVOKER e deixe o RLS filtrar."
            ),
        })
    return achados


def _achados_guarda_null_uid(texto: str, rel: str, funcs: list[dict]) -> list[dict]:
    """Guarda condicionada a `auth.uid() is not null`: o caminho sem sessão passa.

    O formato aparece quando a mesma função serve à tela e a uma rotina do cron:
    "se houver usuário, exija que seja admin". O efeito colateral é que o
    caminho SEM usuário — service_role, cron, chamada anônima — não passa por
    verificação nenhuma.
    """
    achados: list[dict] = []
    for f in funcs:
        if not f["definer"] or not f["corpo"].strip():
            continue
        if not _RE_GUARDA_NULL_UID.search(f["corpo"]):
            continue
        achados.append({
            "rule": "sql.security-definer-guard-null-uid",
            "severity": "WARNING",
            "context": "",
            "path": rel,
            "line": f["linha"],
            "message": (
                f"`{f['nome']}(...)`: a guarda está condicionada a "
                f"`auth.uid() is not null`, então o caminho SEM sessão não passa "
                f"por ela — a exceção nunca é levantada e a função executa sem "
                f"autorização nenhuma. Se a intenção é liberar um chamador de "
                f"sistema, teste-o explicitamente "
                f"(`current_setting('request.jwt.claims', true)::jsonb->>'role' = "
                f"'service_role'`) em vez de tratar \"sem uid\" como confiável."
            ),
        })
    return achados


def _coletar_funcoes_definer(texto: str, rel: str, ordem: int, funcs: list[dict],
                            definidas: dict, mencionados: set,
                            bloco: list, defaults: list, helpers: set) -> None:
    """Acumula o que a checagem de EXECUTE-nunca-fechado precisa, entre arquivos."""
    limpo = _apagar_todo_dollar(texto)
    for f in funcs:
        if not f["definer"] or f["trigger"]:
            continue          # gatilho não é chamável: o grant padrão não é vetor
        definidas.setdefault(f["nome"], {"path": rel, "line": f["linha"], "ordem": ordem})
    for m in _RE_EXEC_ALVO.finditer(limpo):
        nome = _norm(m.group("alvo")).split(".")[-1].strip('"')
        if _RE_NOME_SIMPLES.match(nome):
            mencionados.add(nome)
    if _RE_REVOKE_BLOCO.search(limpo):
        bloco.append(ordem)
    if _RE_DEFAULT_PRIV_REVOKE.search(limpo):
        defaults.append(ordem)
    # Funções chamadas de dentro de expressão de policy: é a carve-out que evita
    # que este aviso vire uma recomendação capaz de derrubar a produção.
    for m in _RE_POLICY.finditer(texto):
        corpo = m.group("body") or ""
        for c in _RE_CHAMADA.finditer(corpo):
            helpers.add(c.group(1).lower())


def _achados_execute_nunca_fechado(definidas: dict, mencionados: set,
                                   bloco: list, defaults: list,
                                   helpers: set) -> list[dict]:
    """DEFINER criada e nunca citada por grant/revoke nenhum — nasce aberta.

    No Supabase isso é mais grave que o padrão do Postgres: além do
    `EXECUTE TO PUBLIC` que todo `create function` concede, a plataforma roda
    `alter default privileges ... grant execute on functions to anon,
    authenticated`, então a função nasce com grant PRÓPRIO para `anon` — é RPC
    pública em `/rest/v1/rpc/<nome>` desde o primeiro deploy.

    Fechar em bloco UMA vez não sustenta: `revoke ... on all functions in
    schema` só alcança o que JÁ existe, então a migração seguinte cria a próxima
    função aberta de novo. Só `alter default privileges ... revoke` alcança o
    futuro — daí a assimetria de ordem abaixo, que é o que separa um
    repositório corrigido de um que se corrige e se reabre.
    """
    achados: list[dict] = []
    for nome, info in sorted(definidas.items(), key=lambda kv: (kv[1]["path"], kv[1]["line"])):
        if nome in mencionados:
            continue
        if any(o >= info["ordem"] for o in bloco):
            continue          # fecho em bloco POSTERIOR alcança esta função
        if any(o <= info["ordem"] for o in defaults):
            continue          # default privileges ANTERIOR já a fecha ao nascer
        if nome in helpers:
            achados.append({
                "rule": "sql.supabase.execute-nunca-fechado",
                "severity": "INFO",
                "context": "",
                "path": info["path"],
                "line": info["line"],
                "message": (
                    f"`{nome}(...)` é SECURITY DEFINER e nenhum `grant`/`revoke "
                    f"execute` a cita: no Supabase ela nasce executável por `anon` "
                    f"(a plataforma roda `alter default privileges ... grant "
                    f"execute on functions to anon, authenticated`). MAS ela é "
                    f"chamada de dentro de uma expressão de policy, e policies são "
                    f"avaliadas com os privilégios de QUEM CONSULTA: revogar de "
                    f"`authenticated` derruba toda query na tabela com \"permission "
                    f"denied for function {nome}\". O fecho correto aqui é `revoke "
                    f"execute on function {nome}(...) from public, anon;` MANTENDO "
                    f"`grant execute on function {nome}(...) to authenticated;` — "
                    f"nunca uma revogação em bloco."
                ),
            })
            continue
        achados.append({
            "rule": "sql.supabase.execute-nunca-fechado",
            "severity": "WARNING",
            "context": "",
            "path": info["path"],
            "line": info["line"],
            "message": (
                f"`{nome}(...)` é SECURITY DEFINER e nenhum `grant`/`revoke "
                f"execute` a cita em arquivo nenhum — ela nasce ABERTA. No "
                f"Supabase não é só o `EXECUTE TO PUBLIC` padrão do Postgres: a "
                f"plataforma roda `alter default privileges ... grant execute on "
                f"functions to anon, authenticated`, então ela é RPC pública em "
                f"`/rest/v1/rpc/{nome}` desde o primeiro deploy. Feche "
                f"explicitamente: `revoke execute on function {nome}(...) from "
                f"public, anon, authenticated;` e conceda só ao papel que precisa. "
                f"ATENÇÃO: helper DEFINER chamado dentro de expressão de policy "
                f"DEVE manter EXECUTE para `authenticated` — revogação em bloco "
                f"causa \"permission denied for function\" em produção. E fechar em "
                f"bloco numa migração NÃO protege as funções criadas nas migrações "
                f"seguintes: elas nascem abertas de novo."
            ),
        })
    return achados


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    # Duas fases: índice e policy se resolvem dentro de um arquivo, mas o
    # EXECUTE de uma função se decide entre migrações — o revoke numa, o grant
    # noutra. Só dá para julgar depois de ler todas.
    achados: list[dict] = []
    revogados: dict[tuple[str, str], dict] = {}
    concedidos: dict[tuple[str, str], set[str]] = {}
    # Estado de `execute-nunca-fechado`: a função nasce numa migração e é (ou
    # não) fechada em outra, então nada disso se decide num arquivo só.
    definidas: dict[str, dict] = {}
    mencionados: set[str] = set()
    bloco: list[int] = []
    defaults: list[int] = []
    helpers: set[str] = set()

    # Ordem de caminho ~ ordem de aplicação (migração é prefixada por
    # timestamp/número), e é dela que sai a assimetria entre o fecho em bloco e
    # o `alter default privileges`.
    for ordem, arq in enumerate(_arquivos_sql(alvos, skip_dirs)):
        try:
            texto = arq.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = str(arq.relative_to(Path.cwd())).replace("\\", "/")
        except ValueError:
            rel = str(arq).replace("\\", "/")
        funcs = _funcoes(texto)
        achados += _achados_indices(texto, rel)
        achados += _achados_policies(texto, rel)
        achados += _achados_search_path(texto, rel, funcs)
        achados += _achados_tenant_param(texto, rel, funcs)
        achados += _achados_guarda_null_uid(texto, rel, funcs)
        _coletar_execute(texto, rel, revogados, concedidos)
        _coletar_funcoes_definer(texto, rel, ordem, funcs, definidas,
                                 mencionados, bloco, defaults, helpers)

    achados += _achados_revoke_incompleto(revogados, concedidos)
    achados += _achados_execute_nunca_fechado(definidas, mencionados, bloco,
                                              defaults, helpers)
    achados.sort(key=lambda a: (a["path"], a["line"]))
    return achados
