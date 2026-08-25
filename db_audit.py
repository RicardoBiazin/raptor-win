"""
Auditoria SOMENTE-LEITURA do catálogo de um Postgres/Supabase ao vivo.

POR QUE existe, além das regras estáticas: um repositório de migrações não é o
banco. Medido numa auditoria real — as migrações estavam coerentes e ainda
assim, no banco, 21 funções eram executáveis por `anon`, 18 tinham `search_path`
sequestrável e uma extensão que a documentação manda relocar não era relocável.
Nada disso é derivável dos `.sql`: o que decide é `pg_proc.proacl`,
`pg_proc.proconfig` e `pg_extension.extrelocatable`.

SOMENTE LEITURA, em quatro camadas:
  1. Todo SQL é constante de módulo em `CONSULTAS` — não há SQL construído a
     partir de entrada do usuário, só a lista de schemas, validada identificador
     por identificador.
  2. `_exigir_somente_leitura` roda em TODA consulta, em todo backend: exige
     `select`/`with` no início, proíbe `;` (um comando só) e recusa uma denylist
     de verbos. Um teste afirma que cada valor de `CONSULTAS` passa e que um
     `update` é recusado — uma edição descuidada quebra a build, não a produção.
  3. Backend `psql`: `default_transaction_read_only=on` no ambiente do filho.
     A garantia passa a ser do SERVIDOR, não da nossa regex — e o preflight lê
     de volta `transaction_read_only` para a garantia ser MOSTRADA.
  4. Backend API: a garantia é do lado cliente (camadas 1 e 2). Está dito assim
     no README, sem enfeite: o token da Management API é de conta, não de banco.

Credencial NUNCA em argv (visível em `ps`/gerenciador de tarefas, e vai para o
histórico do shell). Só variável de ambiente. Nada de host, usuário, senha ou
token entra em achado, relatório ou mensagem de erro — `_sanitizar` limpa as
exceções, porque o `psql` escreve host e usuário no stderr e o `urllib` põe a
URL no `HTTPError`.

O seam de teste é `Consulta`: um callable que recebe SQL e devolve linhas. A CI
não tem banco, então os handlers `_achados_*` são puros e recebem linhas
gravadas.

Saída: lista de dicts {rule, severity, path, line, message, context} — o mesmo
formato de `secrets_scan` e `sql_lint`. `path` é o pseudo-caminho `db:<obj>` e
`line` é 0.

ATENÇÃO ao juntar no relatório: estes achados JÁ TRAZEM `context` e NÃO devem
passar por `classify_context()`. Medido: `db:test.foo()` e `db:seed.aplicar()`
casam `TOOLING_RE` e sairiam da conta de "exigem atenção" em silêncio, só por um
schema ou uma função se chamar `test`/`seed`. O prefixo também tem de ser `db:`
com duas letras: `d:` viraria letra de unidade no Windows e `os.path.relpath`
levantaria ValueError dentro do gerador de SARIF.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Mapping

# SQL -> linhas (lista de dicts). É o seam: a CI injeta linhas gravadas.
Consulta = Callable[[str], list]


class ErroBanco(Exception):
    """Falha de conexão, de credencial ou de consulta. Mensagem já sanitizada."""


# Schemas de sistema e da plataforma. Sem esta lista o relatório afoga em
# objetos que o usuário não pode corrigir — e um relatório assim ensina a
# ignorar relatório.
SCHEMAS_SISTEMA = frozenset({
    # catálogo do Postgres
    "pg_catalog", "information_schema", "pg_toast",
    # plataforma Supabase
    "auth", "storage", "realtime", "_realtime", "vault", "extensions",
    "graphql", "pgbouncer", "cron", "net", "supabase_functions",
    "supabase_migrations", "pgsodium", "pgsodium_masks", "pgtle",
    "_analytics", "_supavisor", "dbdev",
})
# Onde o PostgREST publica: um achado aqui é alcançável pela API, não teórico.
# `graphql_public` NÃO é excluído de propósito — é exposto.
SCHEMAS_EXPOSTOS = frozenset({"public", "graphql_public"})
# Extensões que dão alcance de REDE a partir do banco (SSRF de dentro do
# Postgres) ou execução. Reportadas UMA vez por extensão, não por função.
EXTENSOES_COM_ALCANCE = frozenset({
    "http", "pg_net", "dblink", "postgres_fdw", "file_fdw",
    "plpython3u", "plpythonu", "plsh", "plperlu", "pltclu",
})

# Papéis que a plataforma administra. Objeto de dono destes não é do usuário
# para corrigir, e reportá-lo é ruído garantido: medido, `graphql_public.graphql`
# (dono `supabase_admin`, executável por `anon` por DESENHO) aparecia em todo
# projeto Supabase sem que houvesse nada a fazer a respeito.
DONOS_PLATAFORMA = frozenset({
    "supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
    "supabase_realtime_admin", "supabase_functions_admin", "supabase_read_only_user",
    "pgbouncer", "pgsodium_keyholder", "pgsodium_keyiduser", "pgsodium_keymaker",
    "dashboard_user", "extensions_admin",
})

_RE_IDENT = re.compile(r"^[a-z_][a-z0-9_$]{0,62}$")
_RE_SO_LEITURA = re.compile(r"^\s*(?:select|with)\b", re.IGNORECASE)
_RE_PROIBIDO = re.compile(
    r"\b(?:insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|"
    r"call|do|set|reset|vacuum|analyze|refresh|reindex|lock|comment|merge|"
    r"import|notify|listen|unlisten|cluster|checkpoint|discard|prepare|execute|"
    r"security\s+label)\b",
    re.IGNORECASE,
)


def _sem_literais(sql: str) -> str:
    """Apaga literais de string, preservando o comprimento.

    Sem isto a denylist recusava as PRÓPRIAS consultas deste módulo:
    `has_function_privilege(..., 'execute')` e
    `has_table_privilege(..., 'insert, update, delete')` são somente-leitura, e
    os verbos ali são DADOS, não comandos. Pego no teste do guarda, que era
    exatamente o motivo de escrevê-lo.
    """
    out = list(sql or "")
    i, n, dentro = 0, len(out), False
    while i < n:
        if out[i] == "'":
            # `''` escapado dentro de literal continua sendo literal.
            dentro = not dentro
            out[i] = " "
        elif dentro:
            out[i] = " "
        i += 1
    return "".join(out)


def _exigir_somente_leitura(sql: str) -> None:
    """Recusa qualquer coisa que não seja UM `select`/`with`.

    Camada 2 das quatro. Existe para que uma edição futura descuidada em
    `CONSULTAS` quebre um teste em vez de escrever no banco de alguém.

    Um `;` no FIM é aceito (continua sendo um comando só); o que é recusado é um
    `;` no meio, que é o que permitiria empilhar um segundo comando.
    """
    if not _RE_SO_LEITURA.match(sql or ""):
        raise ErroBanco("consulta recusada: só `select`/`with` são permitidos")
    limpo = _sem_literais(sql)
    if ";" in limpo.strip().rstrip(";"):
        raise ErroBanco("consulta recusada: um comando por vez (`;` no meio)")
    proibido = _RE_PROIBIDO.search(limpo)
    if proibido:
        raise ErroBanco(f"consulta recusada: verbo de escrita `{proibido.group(0)}`")


def _ident(nome: str) -> str:
    """Valida um identificador e devolve o literal SQL. Barra injeção via flag."""
    n = (nome or "").strip().lower()
    if not _RE_IDENT.match(n):
        raise ErroBanco(f"nome de schema inválido: {nome!r}")
    return "'" + n + "'"


def _bool(v) -> bool:
    """`psql --csv` devolve `t`/`f` e a API devolve `true`/`false`.

    Normalizar aqui é o que mantém os dois backends dando o MESMO achado — foi
    a armadilha de portabilidade prevista no desenho.
    """
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("t", "true", "1", "y", "yes")


def _txt(v) -> str:
    return "" if v is None else str(v).strip()


# ---------------------------------------------------------------------------
# As consultas. Constantes, e nenhuma pode devolver NULL: `psql --csv` não
# distingue NULL de string vazia, então toda coluna anulável vai em
# `coalesce()` e toda pergunta "está ausente?" é respondida por uma coluna
# BOOLEANA explícita, nunca inferida de célula vazia.
# ---------------------------------------------------------------------------
_Q_PREFLIGHT = """
select current_setting('server_version') as versao,
       coalesce(current_setting('transaction_read_only', true), 'off') as somente_leitura,
       exists (select 1 from pg_roles where rolname = 'anon') as tem_anon,
       exists (select 1 from pg_roles where rolname = 'authenticated') as tem_auth
"""

# `acldefault('f', proowner)` é essencial: `proacl IS NULL` significa privilégio
# PADRÃO, e o padrão de função É `EXECUTE TO PUBLIC`. Ler NULL como "sem grants"
# perderia o caso mais comum de todos.
_Q_FUNCOES = """
select n.nspname as schema,
       p.proname as nome,
       coalesce(pg_get_function_identity_arguments(p.oid), '') as args,
       p.prosecdef as definer,
       coalesce(o.rolname, '?') as dono,
       coalesce(o.rolsuper, false) as dono_super,
       coalesce(o.rolbypassrls, false) as dono_bypassrls,
       {ANON_EXEC} as anon_exec,
       exists (select 1
                 from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                where a.grantee = 0
                  and a.privilege_type = 'EXECUTE') as public_exec,
       not exists (select 1 from unnest(coalesce(p.proconfig, '{{}}'::text[])) c
                    where c like 'search\\_path=%') as sp_ausente,
       coalesce((select substr(c, length('search_path=') + 1)
                   from unnest(coalesce(p.proconfig, '{{}}'::text[])) c
                  where c like 'search\\_path=%' limit 1), '') as sp_valor
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  left join pg_roles o on o.oid = p.proowner
 where p.prokind in ('f', 'p')
   and p.prorettype <> 'pg_catalog.trigger'::regtype
   and n.nspname <> all (array[{SCHEMAS}]::name[])
   and n.nspname not like 'pg\\_%'
   and not exists (select 1 from pg_depend d
                    where d.objid = p.oid and d.deptype = 'e')
   and coalesce(o.rolname, '') <> all (array[{DONOS_PLATAFORMA}]::name[])
"""

_Q_RELACOES = """
select n.nspname as schema,
       c.relname as tabela,
       c.relrowsecurity as rls,
       (select count(*) from pg_policy pol where pol.polrelid = c.oid)::int as n_policies,
       {ANON_SELECT} as anon_read,
       {ANON_WRITE} as anon_write,
       {AUTH_SELECT} as auth_read
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where c.relkind in ('r', 'p')
   and n.nspname <> all (array[{SCHEMAS}]::name[])
   and n.nspname not like 'pg\\_%'
   and not exists (select 1 from pg_depend d
                    where d.objid = c.oid and d.deptype = 'e')
"""

_Q_POLICIES = """
select schemaname as schema,
       tablename as tabela,
       policyname as policy,
       permissive as permissiva,
       coalesce(cmd, 'ALL') as cmd,
       coalesce(array_to_string(roles, ','), '') as papeis,
       coalesce(qual, '') as qual,
       coalesce(with_check, '') as with_check
  from pg_policies
 where schemaname <> all (array[{SCHEMAS}]::name[])
   and schemaname not like 'pg\\_%'
"""

_Q_EXTENSOES = """
select e.extname as nome,
       n.nspname as schema,
       coalesce(e.extversion, '') as versao,
       e.extrelocatable as relocavel,
       coalesce((select bool_or({ANON_EXEC_EXT})
                   from pg_depend d
                   join pg_proc p on p.oid = d.objid
                  where d.refobjid = e.oid and d.deptype = 'e'), false) as anon_exec_fn,
       coalesce((select bool_or(fn.nspname = any (array[{EXPOSTOS}]::name[]))
                   from pg_depend d
                   join pg_proc p on p.oid = d.objid
                   join pg_namespace fn on fn.oid = p.pronamespace
                  where d.refobjid = e.oid and d.deptype = 'e'), false) as fn_em_exposto
  from pg_extension e
  join pg_namespace n on n.oid = e.extnamespace
 where n.nspname = any (array[{EXPOSTOS}]::name[])
"""

CONSULTAS: dict[str, str] = {
    "preflight": _Q_PREFLIGHT,
    "funcoes": _Q_FUNCOES,
    "relacoes": _Q_RELACOES,
    "policies": _Q_POLICIES,
    "extensoes": _Q_EXTENSOES,
}


def montar(chave: str, *, schemas: frozenset, capacidades: dict) -> str:
    """Preenche os buracos de uma consulta. Só identificadores validados entram.

    `has_function_privilege('anon', ...)` levanta erro se o papel não existir, e
    o Postgres não garante curto-circuito no AND — então a existência do papel é
    decidida AQUI, pelo preflight, e não por um `case` dentro do SQL.
    """
    sql = CONSULTAS[chave]
    lista = ", ".join(_ident(s) for s in sorted(schemas)) or "''"
    expostos = ", ".join(_ident(s) for s in sorted(SCHEMAS_EXPOSTOS))
    tem_anon = capacidades.get("tem_anon", False)
    tem_auth = capacidades.get("tem_auth", False)
    sql = sql.replace("{SCHEMAS}", lista).replace("{EXPOSTOS}", expostos)
    sql = sql.replace("{ANON_EXEC}",
                      "has_function_privilege('anon', p.oid, 'execute')" if tem_anon else "false")
    sql = sql.replace("{ANON_SELECT}",
                      "has_table_privilege('anon', c.oid, 'select')" if tem_anon else "false")
    sql = sql.replace("{ANON_WRITE}",
                      "has_table_privilege('anon', c.oid, 'insert, update, delete')"
                      if tem_anon else "false")
    sql = sql.replace("{AUTH_SELECT}",
                      "has_table_privilege('authenticated', c.oid, 'select')" if tem_auth else "false")
    sql = sql.replace("{ANON_EXEC_EXT}",
                      "has_function_privilege('anon', p.oid, 'execute')" if tem_anon else "false")
    donos = ", ".join(_ident(d) for d in sorted(DONOS_PLATAFORMA))
    sql = sql.replace("{DONOS_PLATAFORMA}", donos)
    return sql.replace("{{", "{").replace("}}", "}")


# ---------------------------------------------------------------------------
# Handlers. Puros: recebem linhas, devolvem achados. Testáveis sem banco.
# ---------------------------------------------------------------------------
def _pseudo(schema: str, nome: str, args: str = "") -> str:
    # Duas sobrecargas viram dois achados, por isso a assinatura entra. Nunca
    # `|` nem `\n`: o Markdown põe isto numa célula de tabela.
    alvo = f"{schema}.{nome}" + (f"({args})" if args else "")
    return "db:" + alvo.replace("|", "/").replace("\n", " ")


def _ctx(schema: str) -> str:
    return ("db · catálogo · schema exposto" if schema in SCHEMAS_EXPOSTOS
            else "db · catálogo")


def _achados_funcoes(linhas: list) -> list[dict]:
    """Executável por anon/PUBLIC, search_path e dono privilegiado."""
    out: list[dict] = []
    for r in linhas or []:
        schema, nome = _txt(r.get("schema")), _txt(r.get("nome"))
        args = _txt(r.get("args"))
        exposto = schema in SCHEMAS_EXPOSTOS
        definer = _bool(r.get("definer"))
        alvo = _pseudo(schema, nome, args)
        ctx = _ctx(schema)
        assinatura = f"{schema}.{nome}({args})"

        if _bool(r.get("anon_exec")):
            out.append({
                "rule": "db.function-executable-by-anon",
                "severity": "HIGH" if exposto else "WARNING",
                "context": ctx, "path": alvo, "line": 0,
                "message": (
                    f"`{assinatura}` é executável pelo papel `anon`"
                    + (f" e está em `{schema}`, que o PostgREST publica: é RPC "
                       f"pública em `/rest/v1/rpc/{nome}`, chamável sem login "
                       f"com a chave anônima." if exposto else ".")
                    + (" A função é SECURITY DEFINER, então roda com os "
                       "privilégios do dono e o RLS não a filtra."
                       if definer else "")
                    + f" Feche: `revoke execute on function {assinatura} from "
                      f"anon;` (e de `public`, que `anon` herda)."
                ),
            })
        elif _bool(r.get("public_exec")):
            out.append({
                "rule": "db.function-executable-by-public",
                "severity": "HIGH" if exposto else "WARNING",
                "context": ctx, "path": alvo, "line": 0,
                "message": (
                    f"`{assinatura}` tem EXECUTE para PUBLIC (a entrada `=X/` da "
                    f"ACL), que todo papel herda — inclusive `anon`. Atenção: "
                    f"`proacl` nulo NÃO quer dizer \"sem grants\"; quer dizer "
                    f"privilégio PADRÃO, e o padrão de função é `EXECUTE TO "
                    f"PUBLIC`. Feche: `revoke execute on function {assinatura} "
                    f"from public;` e conceda só ao papel que precisa."
                ),
            })

        # `search_path` só interessa quando há elevação (DEFINER) ou alcance
        # anônimo. Sem esse recorte, todo INVOKER do banco vira uma linha do
        # relatório — é o que torna a saída do Advisor oficial ilegível.
        relevante = definer or _bool(r.get("anon_exec"))
        if relevante and _bool(r.get("sp_ausente")):
            out.append({
                "rule": "db.function-search-path-missing",
                "severity": "HIGH" if definer else "WARNING",
                "context": "db · catálogo (autoritativo)", "path": alvo, "line": 0,
                "message": (
                    f"`{assinatura}` não tem `search_path` fixo: nomes não "
                    f"qualificados no corpo são resolvidos pelo path de QUEM "
                    f"chama — sequestro de search_path com os privilégios do "
                    f"dono. Contraparte autoritativa de "
                    f"`raptor.supabase.function-search-path-mutable`: aqui é o "
                    f"catálogo, não o arquivo. Fixe com `alter function "
                    f"{assinatura} set search_path = '';`."
                ),
            })
        elif relevante:
            val = _txt(r.get("sp_valor"))
            itens = [x.strip().strip('"').strip("'") for x in val.split(",")]
            itens = [x for x in itens if x]
            # `= ''` e só `pg_catalog` não abrem janela: nada a plantar. É
            # "não é subconjunto de {pg_catalog}", e não superconjunto estrito —
            # `{"public"} > {"pg_catalog"}` é False, e a regra nunca disparava.
            if itens and not set(itens) <= {"pg_catalog"} and itens[-1] != "pg_temp":
                falta = "pg_temp" not in itens
                out.append({
                    "rule": "db.function-search-path-hijackable",
                    "severity": "HIGH" if definer and falta else "WARNING",
                    "context": ctx, "path": alvo, "line": 0,
                    "message": (
                        f"`{assinatura}` tem `search_path = {val}`, "
                        + ("sem `pg_temp`" if falta else "com `pg_temp` fora do fim")
                        + ". Quando `pg_temp` não é o último item, o Postgres o "
                          "procura ANTES dos schemas seguintes para nomes de "
                          "RELAÇÃO, então uma tabela temporária plantada por quem "
                          "chama assume o lugar da real dentro do corpo. Isto NÃO "
                          "aparece no linter do Supabase, que só verifica se o "
                          f"search_path existe. Corrija: `alter function "
                          f"{assinatura} set search_path = {val}, pg_temp;`."
                    ),
                })

        # DONO PRIVILEGIADO SÓ IMPORTA COM ALCANCE DE CLIENTE.
        #
        # Medido contra um Supabase hospedado real: sem este gate a regra deu 85
        # de 90 achados. O motivo é estrutural, não é ajuste fino — na
        # plataforma o papel `postgres` é dono de praticamente toda função E tem
        # `rolbypassrls = true`, então a regra dispararia em 100% das funções
        # DEFINER de 100% dos projetos. Isso é propriedade da PLATAFORMA, não do
        # código de quem é auditado: sinal zero, e um relatório assim treina a
        # pessoa a ignorar relatório.
        #
        # O que de fato é risco é a combinação: o corpo ignora o RLS E um papel
        # de cliente consegue chamar. Quando só `service_role`/`postgres`
        # alcançam, o arranjo é o desenho normal do Supabase.
        alcancavel = _bool(r.get("anon_exec")) or _bool(r.get("public_exec"))
        if definer and alcancavel and (_bool(r.get("dono_super"))
                                       or _bool(r.get("dono_bypassrls"))):
            motivo = ("superusuário" if _bool(r.get("dono_super")) else "BYPASSRLS")
            quem = "`anon`" if _bool(r.get("anon_exec")) else "PUBLIC"
            out.append({
                "rule": "db.security-definer-owned-by-superuser",
                "severity": "HIGH",
                "context": ctx, "path": alvo, "line": 0,
                "message": (
                    f"`{assinatura}` é SECURITY DEFINER, o dono "
                    f"(`{_txt(r.get('dono'))}`) é {motivo} — o corpo IGNORA o RLS "
                    f"por completo — E ela é alcançável por {quem}. As duas coisas "
                    f"juntas são o problema: um chamador sem privilégio nenhum "
                    f"executa código que passa por cima de todo filtro de linha. "
                    f"Feche o EXECUTE, ou recorte o corpo por sessão. (Nota: no "
                    f"Supabase hospedado `postgres` tem `rolsuper = false` e "
                    f"`rolbypassrls = true`, e é dono de quase tudo — por isso "
                    f"este achado exige o alcance de cliente para aparecer.)"
                ),
            })
    return out


def _achados_relacoes(linhas: list) -> list[dict]:
    """Tabela alcançável por papel cliente sem RLS, e RLS ligada sem policy."""
    out: list[dict] = []
    for r in linhas or []:
        schema, tabela = _txt(r.get("schema")), _txt(r.get("tabela"))
        alvo, ctx = _pseudo(schema, tabela), _ctx(schema)
        exposto = schema in SCHEMAS_EXPOSTOS
        rls = _bool(r.get("rls"))
        anon_r, anon_w = _bool(r.get("anon_read")), _bool(r.get("anon_write"))
        auth_r = _bool(r.get("auth_read"))

        if exposto and not rls and (anon_r or anon_w or auth_r):
            quem = ("`anon` (sem login)" if anon_r or anon_w else "`authenticated`")
            out.append({
                "rule": "db.table-without-rls-exposed",
                "severity": "CRITICAL" if anon_w else ("HIGH" if anon_r else "WARNING"),
                "context": ctx, "path": alvo, "line": 0,
                "message": (
                    f"`{schema}.{tabela}` está em schema publicado pelo PostgREST, "
                    f"SEM row level security, e {quem} tem privilégio de "
                    + ("ESCRITA" if anon_w else "leitura")
                    + f". Sem RLS não há filtro de linha: a tabela inteira é "
                      f"alcançável por `/rest/v1/{tabela}`. Ligue e escreva a "
                      f"policy: `alter table {schema}.{tabela} enable row level "
                      f"security;` — ligar SEM policy nenhuma devolve zero linhas "
                      f"(ver `db.rls-enabled-no-policy`), então as duas coisas vão "
                      f"na mesma migração."
                ),
            })

        if rls and int(r.get("n_policies") or 0) == 0:
            out.append({
                "rule": "db.rls-enabled-no-policy",
                "severity": "WARNING",
                "context": "db · catálogo · disponibilidade", "path": alvo, "line": 0,
                "message": (
                    f"`{schema}.{tabela}` tem RLS LIGADA e policy NENHUMA. Isto "
                    f"NÃO é vazamento — é indisponibilidade silenciosa: todo "
                    f"select de papel que não seja o dono (ou BYPASSRLS) devolve "
                    f"ZERO linhas, sem erro, e o sintoma é tela vazia. A correção "
                    f"é ESCREVER a policy que falta. Não \"corrija\" desligando o "
                    f"RLS: isso troca uma tela vazia por uma tabela aberta."
                ),
            })
    return out


_RE_TRUE = re.compile(r"^\s*\(?\s*true\s*\)?\s*$", re.IGNORECASE)
_ACOES_ESCRITA = {"ALL", "INSERT", "UPDATE", "DELETE"}
_PAPEIS_CLIENTE = {"anon", "authenticated", "public"}


def _achados_policies(linhas: list) -> list[dict]:
    """Policy `true` em ação de escrita, e permissivas duplicadas de SELECT."""
    out: list[dict] = []
    grupos: dict[tuple, list[str]] = {}
    for r in linhas or []:
        schema, tabela = _txt(r.get("schema")), _txt(r.get("tabela"))
        policy, cmd = _txt(r.get("policy")), _txt(r.get("cmd")).upper()
        papeis = {p.strip().lower() for p in _txt(r.get("papeis")).split(",") if p.strip()}
        cliente = papeis & _PAPEIS_CLIENTE
        permissiva = _txt(r.get("permissiva")).upper().startswith("PERM")
        alvo, ctx = _pseudo(schema, tabela), _ctx(schema)

        if permissiva and cmd in _ACOES_ESCRITA and cliente:
            check = _txt(r.get("with_check")) or _txt(r.get("qual"))
            if _RE_TRUE.match(check):
                out.append({
                    "rule": "db.policy-always-true-write",
                    "severity": "HIGH",
                    "context": ctx, "path": alvo, "line": 0,
                    "message": (
                        f"A policy `{policy}` de `{schema}.{tabela}` cobre "
                        f"{cmd} para {', '.join(sorted(cliente))} com expressão "
                        f"`true`: qualquer linha passa na verificação, então o "
                        f"papel escreve o que quiser — inclusive com `org_id` de "
                        f"outro inquilino. Recorte por sessão."
                    ),
                })
        if permissiva and cmd in ("SELECT", "ALL"):
            for p in cliente:
                grupos.setdefault((schema, tabela, p), []).append(policy)

    for (schema, tabela, papel), nomes in sorted(grupos.items()):
        if len(nomes) < 2:
            continue
        out.append({
            "rule": "db.multiple-permissive-policies",
            "severity": "INFO",
            "context": _ctx(schema), "path": _pseudo(schema, tabela), "line": 0,
            "message": (
                f"`{schema}.{tabela}` tem {len(nomes)} policies PERMISSIVAS "
                f"cobrindo SELECT para `{papel}`: {', '.join(sorted(nomes))}. O "
                f"Postgres avalia todas por linha e combina com OR. Uma policy "
                f"`FOR ALL` ao lado de uma `FOR SELECT` é a causa comum — dividir "
                f"o ALL em INSERT/UPDATE/DELETE resolve, mas só é equivalente se a "
                f"expressão de escrita for SUBCONJUNTO da de leitura; senão alguém "
                f"perde leitura em silêncio."
            ),
        })
    return out


def _achados_extensoes(linhas: list) -> list[dict]:
    """Extensão em schema exposto — e o ramo do `extrelocatable`.

    Este é o achado que justifica ler o catálogo em vez de repetir a
    documentação: `ALTER EXTENSION ... SET SCHEMA` FALHA numa extensão declarada
    `relocatable = false`, e recomendar a migração impossível é pior que ficar
    calado. Medido em produção: `pg_net` é exatamente esse caso.
    """
    out: list[dict] = []
    for r in linhas or []:
        nome, schema = _txt(r.get("nome")), _txt(r.get("schema"))
        relocavel = _bool(r.get("relocavel"))
        alvo, ctx = _pseudo(schema, nome), _ctx(schema)
        if relocavel:
            msg = (f"A extensão `{nome}` está instalada em `{schema}`, que o "
                   f"PostgREST publica. Ela É relocável: mova com `alter "
                   f"extension {nome} set schema extensions;`.")
            sev = "WARNING"
        else:
            msg = (f"A extensão `{nome}` está em `{schema}`, mas é declarada "
                   f"`relocatable = false`: `alter extension {nome} set schema "
                   f"extensions` VAI FALHAR com `0A000 ... does not support SET "
                   f"SCHEMA`. O único caminho seria drop/recreate, que derruba o "
                   f"estado da extensão e o que depende dela. Aceitar em "
                   f"`{schema}` é desfecho legítimo — confira apenas onde os "
                   f"objetos dela realmente vivem, porque o aviso costuma ser só "
                   f"a linha de registro em `pg_extension`.")
            sev = "INFO"
        out.append({
            "rule": "db.extension-in-public", "severity": sev,
            "context": ctx, "path": alvo, "line": 0, "message": msg,
        })
        # ALCANCE MEDIDO, não afirmado. A primeira versão reportava HIGH só por a
        # extensão estar registrada num schema exposto — mas os objetos dela
        # costumam viver noutro schema (medido: `pg_net` registra em `public` e
        # cria tudo em `net`), então o nome da regra prometia uma alcançabilidade
        # que ela não tinha verificado. Agora `anon_exec_fn` vem do catálogo.
        if nome.lower() in EXTENSOES_COM_ALCANCE and _bool(r.get("anon_exec_fn")):
            # Ter EXECUTE não é ser chamável pela API: o PostgREST só publica os
            # schemas expostos. A severidade acompanha essa diferença.
            exposto_fn = _bool(r.get("fn_em_exposto"))
            out.append({
                "rule": "db.extension-network-exec-por-anon",
                "severity": "HIGH" if exposto_fn else "WARNING",
                "context": ctx, "path": alvo, "line": 0,
                "message": (
                    f"A extensão `{nome}` dá alcance de REDE ou execução a partir "
                    f"do banco, e o papel `anon` TEM EXECUTE nas funções dela "
                    f"(medido no catálogo, não inferido). "
                    + ("As funções estão em schema publicado pelo PostgREST: um "
                       "anônimo pode chamá-las direto pela API — SSRF de dentro do "
                       "Postgres."
                       if exposto_fn else
                       "As funções NÃO estão em schema publicado, então o PostgREST "
                       "não as expõe diretamente — o grant sozinho não é chamável "
                       "de fora. O risco é indireto: qualquer função SECURITY "
                       "INVOKER em schema exposto que `anon` alcance e que passe "
                       "entrada dele para essas funções vira SSRF.")
                    + f" Feche o que não for usado: `revoke execute on all "
                      f"functions in schema <schema-da-extensão> from anon;`."
                ),
            })
    return out


def preflight(consultar: Consulta) -> dict:
    """Capacidades do banco. NADA daqui entra em relatório.

    `current_user`/`current_database()` não são coletados — removidos da
    consulta, e não coletados-e-filtrados depois.
    """
    linhas = consultar(CONSULTAS["preflight"])
    r = (linhas or [{}])[0]
    return {
        "versao": _txt(r.get("versao")),
        "somente_leitura": _txt(r.get("somente_leitura")).lower() in ("on", "t", "true"),
        "tem_anon": _bool(r.get("tem_anon")),
        "tem_auth": _bool(r.get("tem_auth")),
    }


def escanear(consultar: Consulta, *,
             schemas_excluidos: frozenset = SCHEMAS_SISTEMA,
             schemas_incluidos: frozenset | None = None,
             capacidades: dict | None = None) -> list[dict]:
    """Roda as consultas e devolve achados no formato do relatório.

    `schemas_incluidos` recorta o RESULTADO, e não o SQL: as consultas dizem
    "não é schema de sistema", que é uma exclusão — não há como enumerar por
    SQL "só estes" sem transformar a cláusula. Filtrar depois dá o mesmo
    resultado e mantém uma consulta só, constante.
    """
    cap = capacidades if capacidades is not None else preflight(consultar)
    if schemas_incluidos is not None:
        for s in schemas_incluidos:
            _ident(s)          # valida antes de qualquer coisa
    achados: list[dict] = []
    for chave, handler in (("funcoes", _achados_funcoes),
                           ("relacoes", _achados_relacoes),
                           ("policies", _achados_policies),
                           ("extensoes", _achados_extensoes)):
        sql = montar(chave, schemas=schemas_excluidos, capacidades=cap)
        _exigir_somente_leitura(sql)
        achados += handler(consultar(sql))
    if schemas_incluidos is not None:
        pedidos = {s.strip().lower() for s in schemas_incluidos}
        achados = [a for a in achados
                   if a["path"][3:].split(".", 1)[0] in pedidos]
    achados.sort(key=lambda a: (a["path"], a["rule"]))
    return achados


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
_API = "https://api.supabase.com/v1/projects/{ref}/database/query"
_RE_REF = re.compile(r"^[a-z0-9]{16,32}$")


def _sanitizar(texto: str, segredos: list) -> str:
    """Remove segredos de qualquer texto que possa ser impresso.

    Não é zelo excessivo: o `psql` escreve host e usuário no stderr e o
    `urllib` põe a URL inteira no `HTTPError`. Relatório vai para repositório.
    """
    t = str(texto)
    for s in segredos:
        if s and len(str(s)) >= 4:
            t = t.replace(str(s), "«oculto»")
    return t.splitlines()[0][:300] if t else ""


def _consulta_api(ref: str, token: str, timeout: int) -> Consulta:
    if not _RE_REF.match(ref or ""):
        raise ErroBanco("SUPABASE_PROJECT_REF inválido")
    url = _API.format(ref=ref)

    def consultar(sql: str) -> list:
        _exigir_somente_leitura(sql)
        corpo = json.dumps({"query": sql, "read_only": True}).encode("utf-8")
        req = urllib.request.Request(
            url, data=corpo, method="POST",
            # User-Agent EXPLÍCITO, e não é cosmético: o WAF da API responde 403
            # ao `Python-urllib/3.x` que o urllib manda por padrão. Sem esta
            # linha a auditoria falha em toda máquina, com um 403 que parece
            # problema de token. Medido contra a API real.
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json",
                     "User-Agent": "raptor-win"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                dados = json.loads(resp.read().decode("utf-8") or "[]")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ErroBanco(_sanitizar(e, [token])) from None
        if isinstance(dados, dict):
            if dados.get("message"):
                raise ErroBanco(_sanitizar(dados["message"], [token]))
            dados = dados.get("result", [])
        return dados if isinstance(dados, list) else []

    return consultar


def _consulta_psql(dsn: str, timeout: int) -> Consulta:
    psql = shutil.which("psql")
    if not psql:
        raise ErroBanco("psql não encontrado no PATH (instale o cliente do Postgres)")
    p = urllib.parse.urlparse(dsn)
    if not p.hostname:
        raise ErroBanco("RAPTOR_DB_URL sem host")
    senha = urllib.parse.unquote(p.password or "")
    env = dict(os.environ)
    env.update({
        "PGHOST": p.hostname,
        "PGPORT": str(p.port or 5432),
        "PGUSER": urllib.parse.unquote(p.username or ""),
        "PGDATABASE": (p.path or "/postgres").lstrip("/") or "postgres",
        # Camada 3: a garantia passa a ser do SERVIDOR. Mesmo que a regex do
        # cliente falhasse, o Postgres recusa a escrita.
        "PGOPTIONS": ("-c default_transaction_read_only=on "
                      "-c statement_timeout=15000 "
                      "-c idle_in_transaction_session_timeout=15000 "
                      "-c lock_timeout=3000"),
    })
    if senha:
        env["PGPASSWORD"] = senha
    # A DSN não vai na linha de comando: argv é visível a qualquer usuário da
    # máquina (`ps`, detalhes do gerenciador de tarefas).
    segredos = [senha, dsn]

    def consultar(sql: str) -> list:
        _exigir_somente_leitura(sql)
        try:
            r = subprocess.run(
                [psql, "-X", "-q", "-A", "--csv", "-v", "ON_ERROR_STOP=1", "-c", sql],
                env=env, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            raise ErroBanco(_sanitizar(e, segredos)) from None
        if r.returncode != 0:
            raise ErroBanco(_sanitizar(r.stderr or "psql falhou", segredos))
        linhas = [l for l in (r.stdout or "").splitlines() if l.strip()]
        if not linhas:
            return []
        import csv
        return list(csv.DictReader(linhas))

    return consultar


AJUDA_ENV = (
    "defina as variáveis de ambiente (NUNCA na linha de comando, que fica no "
    "histórico do shell e é visível a outros processos):\n"
    "  API  : SUPABASE_ACCESS_TOKEN + SUPABASE_PROJECT_REF\n"
    "  psql : RAPTOR_DB_URL (ex.: postgresql://raptor_ro:SENHA@host:5432/postgres)"
)


def abrir_backend(env: Mapping[str, str], preferencia: str = "auto",
                  timeout: int = 30, ref: str = "") -> tuple:
    """Devolve (consultar, nome_do_backend). Só lê credencial do ambiente."""
    token = env.get("SUPABASE_ACCESS_TOKEN", "")
    projeto = ref or env.get("SUPABASE_PROJECT_REF", "")
    dsn = env.get("RAPTOR_DB_URL", "")
    if preferencia in ("auto", "api") and token and projeto:
        return _consulta_api(projeto, token, timeout), "api"
    if preferencia in ("auto", "psql") and dsn:
        return _consulta_psql(dsn, timeout), "psql"
    if preferencia == "api":
        raise ErroBanco("backend api pede SUPABASE_ACCESS_TOKEN e SUPABASE_PROJECT_REF")
    if preferencia == "psql":
        raise ErroBanco("backend psql pede RAPTOR_DB_URL")
    raise ErroBanco("nenhuma credencial de banco no ambiente.\n" + AJUDA_ENV)
