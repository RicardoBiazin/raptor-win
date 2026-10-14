"""Varredura do que um visitante consegue ler num site publicado.

A pergunta: "com o navegador de qualquer pessoa, o que eu entrego?"

Olha só o que o navegador já baixa -- o HTML, os bundles JS, o source map se o
bundle o referencia -- e faz algumas leituras GET de caminhos sensíveis e de
tabelas do Supabase, usando a chave PÚBLICA que o próprio bundle carrega. Nada
é escrito, nada é autenticado, e nenhum valor de linha é impresso: só a
contagem e os nomes das colunas.

Uso só em sites seus. A varredura faz requisições reais e o alvo é explícito
(`--url`); não há descoberta de domínios.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from secrets_scan import REGRAS as REGRAS_SEGREDO

UA = "raptor-win-bundle-scan/1.0 (verificacao de site proprio)"
TIMEOUT = 20
MAX_BYTES = 8 * 1024 * 1024
MAX_SCRIPTS = 15
MAX_REQS = 200
MAX_TABELAS = 40

_RE_SCRIPT = re.compile(r"""<script[^>]*\bsrc=["']([^"']+)["']""", re.IGNORECASE)
_RE_SUPA_REF = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
_RE_PUBLISHABLE = re.compile(r"\bsb_publishable_[A-Za-z0-9_\-]{20,}")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_RE_TABELA = re.compile(r"\.from\(\s*[`\"']([a-z_][a-z0-9_]{1,60})[`\"']\s*\)")
_RE_SOURCEMAP = re.compile(r"sourceMappingURL=(\S+)")
# Schema fora do `public` declarado no cliente: `db: { schema: 'servico' }`
# ou `schema: 'servico'` em canal realtime. Sem ele, a sonda não alcança.
_RE_SCHEMA = re.compile(r"""\bschema\s*:\s*["'`]([a-z_][a-z0-9_]{1,40})["'`]""")
_RE_ENV_LINHA = re.compile(rb"(?m)^[A-Z][A-Z0-9_]{2,}=\S")


class Resp:
    __slots__ = ("status", "headers", "corpo", "url")

    def __init__(self, status: int, headers: dict, corpo: bytes, url: str):
        self.status, self.headers, self.corpo, self.url = status, headers, corpo, url


def buscar(url: str, headers: dict | None = None, timeout: int = TIMEOUT) -> Resp | None:
    """GET simples. Devolve None se não houver resposta (rede, DNS, timeout)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            corpo = r.read(MAX_BYTES)
            return Resp(r.status, {k.lower(): v for k, v in r.headers.items()}, corpo, r.geturl())
    except urllib.error.HTTPError as e:
        try:
            corpo = e.read(MAX_BYTES)
        except OSError:
            corpo = b""
        cab = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return Resp(e.code, cab, corpo, url)
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _eh_html(corpo: bytes) -> bool:
    inicio = corpo[:500].lower()
    return b"<!doctype html" in inicio or b"<html" in inicio


def _role_do_jwt(token: str) -> str | None:
    """Lê o claim `role` do payload. Não verifica assinatura: é só para classificar."""
    try:
        meio = token.split(".")[1]
        meio += "=" * (-len(meio) % 4)
        return json.loads(base64.urlsafe_b64decode(meio)).get("role")
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return None


# Caminhos que nunca deveriam ser servidos. Cada um tem um sinal de conteúdo:
# um SPA responde 200 com o index.html para QUALQUER caminho, então o status
# sozinho não prova nada.
def _sinal_env(c: bytes) -> bool:
    return not _eh_html(c) and bool(_RE_ENV_LINHA.search(c))


def _sinal_package(c: bytes) -> bool:
    if _eh_html(c):
        return False
    try:
        d = json.loads(c)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(d, dict) and ("dependencies" in d or "scripts" in d or "name" in d)


SONDAS = [
    (".env", "HIGH", "arquivo de ambiente com valores", _sinal_env),
    (".git/config", "HIGH", "configuração de repositório git",
     lambda c: b"[core]" in c and not _eh_html(c)),
    (".git/HEAD", "HIGH", "repositório git",
     lambda c: c.lstrip().startswith(b"ref:") and not _eh_html(c)),
    ("source.zip", "HIGH", "código-fonte compactado", lambda c: c[:4] == b"PK\x03\x04"),
    ("backup.zip", "HIGH", "backup compactado", lambda c: c[:4] == b"PK\x03\x04"),
    ("supabase/config.toml", "MEDIUM", "configuração do Supabase",
     lambda c: (b"project_id" in c or b"[api]" in c) and not _eh_html(c)),
    ("package.json", "MEDIUM", "manifesto do projeto", _sinal_package),
    (".DS_Store", "LOW", "metadados do macOS", lambda c: c[4:8] == b"Bud1"),
]


def _achado(rule: str, sev: str, url: str, msg: str) -> dict:
    return {"rule": rule, "severity": sev, "context": "", "path": url,
            "line": 0, "message": msg}


def _achados_cabecalhos(url: str, pag: Resp) -> list[dict]:
    achados = []
    csp = pag.headers.get("content-security-policy")
    if not csp:
        achados.append(_achado("bundle.sem-csp", "LOW", url,
                               "Página sem Content-Security-Policy. Sem ela, qualquer "
                               "script injetado roda com o acesso do site."))
    elif "frame-ancestors" not in csp and "x-frame-options" not in pag.headers:
        achados.append(_achado("bundle.sem-protecao-clickjacking", "LOW", url,
                               "Sem `frame-ancestors` na CSP nem X-Frame-Options: a página "
                               "pode ser embutida em outro site (clickjacking)."))
    if "strict-transport-security" not in pag.headers:
        achados.append(_achado("bundle.sem-hsts", "LOW", url,
                               "Sem Strict-Transport-Security: o primeiro acesso pode "
                               "ser feito em HTTP."))
    return achados


def _achados_texto(url: str, texto: str) -> tuple[list[dict], dict]:
    """Segredos e pistas num bundle. Devolve (achados, pistas para as sondas)."""
    achados: list[dict] = []
    for r in REGRAS_SEGREDO:
        if r.id == "jwt":
            continue  # tratado abaixo: só o service_role importa aqui
        m = r.re.search(texto)
        if m:
            achados.append(_achado(
                f"bundle.segredo-{r.id}", r.sev, url,
                f"{r.desc} no bundle público. O valor não é exibido. Se for chave "
                f"de uso público por desenho (ex.: Firebase, Maps), aceite no "
                f"baseline; se for credencial, rotacione e retire do build."))

    anon = None
    for m in _RE_JWT.finditer(texto):
        role = _role_do_jwt(m.group(0))
        if role == "service_role":
            achados.append(_achado(
                "bundle.jwt-service-role", "CRITICAL", url,
                "JWT com role=service_role no bundle público: ignora a RLS inteira. "
                "Rotacione a chave e retire-a do build."))
            break
        if role == "anon":
            anon = anon or m.group(0)

    m_pub = _RE_PUBLISHABLE.search(texto)
    pistas = {
        "refs": set(_RE_SUPA_REF.findall(texto)),
        "publishable": m_pub.group(0) if m_pub else None,
        "anon_jwt": anon,
        "tabelas": set(_RE_TABELA.findall(texto)),
        "schemas": set(_RE_SCHEMA.findall(texto)),
        "sourcemaps": _RE_SOURCEMAP.findall(texto),
    }
    return achados, pistas


def _achados_sourcemap(url_script: str, ref: str, bus) -> list[dict]:
    url_map = urljoin(url_script, ref)
    r = bus(url_map)
    if not r or r.status != 200 or _eh_html(r.corpo):
        return []
    try:
        d = json.loads(r.corpo)
    except (ValueError, UnicodeDecodeError):
        return []
    fontes = [s for s in d.get("sourcesContent", []) if s] if isinstance(d, dict) else []
    if not fontes:
        return []
    return [_achado("bundle.sourcemap-expoe-codigo", "HIGH", url_map,
                    f"Source map público com o código-fonte original ({len(fontes)} "
                    f"arquivo(s)). Quem o baixa lê a aplicação inteira. Desligue o "
                    f"sourcemap no build de produção.")]


def _sondar_tabelas(origem_ref: str, chave: str, tabelas: set, schemas: set, bus) -> list[dict]:
    """Leitura anon de cada tabela citada no bundle, em cada schema usado por ele.

    Só contagem e nomes de coluna. Schema que não seja `public` vai no header
    Accept-Profile, que é como o PostgREST escolhe o schema da leitura.
    """
    achados = []
    base = f"https://{origem_ref}.supabase.co/rest/v1"
    lista_schemas = ["public"] + sorted(s for s in schemas if s != "public")
    for schema in lista_schemas:
        cab = {"apikey": chave, "Authorization": f"Bearer {chave}", "Prefer": "count=exact"}
        if schema != "public":
            cab["Accept-Profile"] = schema
        for t in sorted(tabelas)[:MAX_TABELAS]:
            url = f"{base}/{t}?select=*&limit=1"
            r = bus(url, headers=cab)
            # 206 é o normal aqui: o PostgREST responde Partial Content quando o
            # `limit` corta a tabela, que é justamente o caso de ter linhas.
            if not r or r.status not in (200, 206):
                continue
            total = (r.headers.get("content-range") or "").split("/")[-1]
            if not total.isdigit() or int(total) == 0:
                continue
            try:
                linha = json.loads(r.corpo)[0]
                colunas = ", ".join(sorted(linha.keys()))
            except (ValueError, IndexError, AttributeError, TypeError):
                colunas = "?"
            nome = t if schema == "public" else f"{schema}.{t}"
            achados.append(_achado(
                "bundle.anon-le-tabela", "MEDIUM", f"{base}/{t}",
                f"Tabela `{nome}` é legível com a chave pública do site: {total} "
                f"linha(s). Colunas: {colunas}. Valores não exibidos. Se a leitura é "
                f"intencional, aceite no baseline; se não é, ligue RLS e restrinja a policy."))
    return achados


def escanear_urls(urls: list[str], buscar_fn=buscar) -> list[dict]:
    """Varre cada URL de página. `buscar_fn` permite testar sem rede.

    O teto de requisições vale POR URL: um site grande não pode gastar o
    orçamento dos seguintes. Estourar o teto ou o de tabelas vira aviso no
    relatório, nunca corte silencioso.
    """
    achados: list[dict] = []
    contagem = [0]

    def bus(url: str, headers: dict | None = None):
        contagem[0] += 1
        if contagem[0] > MAX_REQS:
            return None
        return buscar_fn(url, headers=headers)

    for url in urls:
        if urlparse(url).scheme not in ("http", "https") or not urlparse(url).netloc:
            achados.append(_achado("bundle.url-invalida", "INFO", url,
                                   "URL ignorada: precisa ser http(s)://dominio/caminho."))
            continue
        contagem[0] = 0
        pag = bus(url)
        if pag is None:  # falha de rede transitória (timeout, reset): uma nova tentativa
            pag = bus(url)
        if pag is None or pag.status >= 400:
            achados.append(_achado("bundle.inacessivel", "INFO", url,
                                   "Página não respondeu com sucesso; nada foi verificado."))
            continue
        achados += _achados_cabecalhos(url, pag)

        texto_pag = pag.corpo.decode("utf-8", "replace")
        scripts = []
        for src in _RE_SCRIPT.findall(texto_pag):
            absoluto = urljoin(url, src)
            if absoluto not in scripts:
                scripts.append(absoluto)

        refs, tabelas, schemas = set(), set(), set()
        publishable = anon_jwt = None
        for src in scripts[:MAX_SCRIPTS]:
            r = bus(src)
            if not r or r.status != 200:
                continue
            texto = r.corpo.decode("utf-8", "replace")
            ach, pistas = _achados_texto(src, texto)
            achados += ach
            refs |= pistas["refs"]
            tabelas |= pistas["tabelas"]
            schemas |= pistas["schemas"]
            publishable = publishable or pistas["publishable"]
            anon_jwt = anon_jwt or pistas["anon_jwt"]
            for ref in pistas["sourcemaps"][:1]:
                achados += _achados_sourcemap(src, ref, bus)

        origem = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for caminho, sev, desc, sinal in SONDAS:
            r = bus(f"{origem}/{caminho}")
            if r and r.status == 200 and sinal(r.corpo):
                achados.append(_achado(
                    f"bundle.exposto-{caminho.replace('/', '-').strip('.')}", sev,
                    f"{origem}/{caminho}",
                    f"Caminho público que deveria ser privado: {desc}. Quem acessa lê o "
                    f"conteúdo. Retire do build e confira o que já foi publicado."))

        chave = publishable or anon_jwt
        if chave:
            for ref in sorted(refs)[:3]:
                achados += _sondar_tabelas(ref, chave, tabelas, schemas, bus)
        if len(tabelas) > MAX_TABELAS:
            achados.append(_achado(
                "bundle.limite-de-tabelas", "INFO", url,
                f"O bundle cita {len(tabelas)} tabelas; só as {MAX_TABELAS} primeiras "
                f"(em ordem alfabética) foram sondadas."))
        if contagem[0] > MAX_REQS:
            achados.append(_achado(
                "bundle.limite-de-requisicoes", "INFO", url,
                f"Teto de {MAX_REQS} requisições atingido nesta página: parte dos "
                f"caminhos e tabelas NÃO foi verificada."))
    return achados
