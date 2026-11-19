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

import exploracao
import headers_lint
import retire
from secrets_scan import REGRAS as REGRAS_SEGREDO

UA = "raptor-win-bundle-scan/1.0 (verificacao de site proprio)"
TIMEOUT = 20
MAX_BYTES = 8 * 1024 * 1024
MAX_SCRIPTS = 15
# Chunks carregados sob demanda (rota de SPA Vite/Rollup): a maior parte do
# código de tela mora neles, não no <script> do HTML.
MAX_CHUNKS = 80
MAX_SOURCEMAPS = 15
MAX_REQS = 200
MAX_TABELAS = 40

_RE_SCRIPT = re.compile(r"""<script[^>]*\bsrc=["']([^"']+)["']""", re.IGNORECASE)
_RE_LINK = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_RE_HREF = re.compile(r"""\bhref=["']([^"']+)["']""", re.IGNORECASE)
_RE_MODULEPRELOAD = re.compile(r"""\brel=["']?[^"'>]*\bmodulepreload\b""", re.IGNORECASE)
# Caminho literal de chunk JS dentro de um bundle: `import("./Tela-ab12.js")` e a
# lista de dependências do `__vitePreload` (`"assets/Tela-ab12.js"`). Exige `./`,
# `../` ou uma barra, para não confundir com nome de pacote ("chart.js"). Nome
# montado em runtime (webpack: "static/js/"+id+".chunk.js") não é alcançado.
_RE_CHUNK = re.compile(
    r"""["'`]((?:\.{1,2}/)[\w\-./@~]+\.m?js|/?[\w\-.@~]+/[\w\-./@~]*\.m?js)["'`]""")
_RE_FIREBASE_DB = re.compile(
    r"""databaseURL["']?\s*:\s*["'](https://[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)?"""
    r"""\.(?:firebaseio\.com|firebasedatabase\.app))/?["']""", re.I)
# Estado inicial do SSR (Next/Nuxt): o servidor serializa para o HTML o que a
# tela recebeu, e o que sobra de campo nessa serialização chega a qualquer visitante.
_RE_ESTADO_SSR = re.compile(
    r"""<script[^>]*\bid=["']__NEXT_DATA__["'][^>]*>(.*?)</script>"""
    r"""|window\.__NUXT__\s*=\s*(.*?)</script>""", re.S | re.I)
_RE_CHAVE_SENSIVEL = re.compile(
    r"""["'](password|passwd|senha|password_?hash|secret|api_?key|access_?token|refresh_?token|"""
    r"""private_?key|ssn|cpf)["']\s*:""", re.I)
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


_RE_HTPASSWD = re.compile(rb"(?m)^[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$5\$|\$6\$)")


def _sinal_dump(c: bytes) -> bool:
    """Dump de banco pelo CONTEÚDO: cabeçalho do pg_dump/mysqldump, ou CREATE TABLE + INSERT."""
    if _eh_html(c):
        return False
    return (b"-- PostgreSQL database dump" in c[:4096] or b"-- MySQL dump" in c[:4096]
            or b"-- MariaDB dump" in c[:4096]
            or (b"CREATE TABLE" in c and b"INSERT INTO" in c))


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
    (".env.local", "HIGH", "arquivo de ambiente local com valores", _sinal_env),
    (".env.bak", "HIGH", "cópia de backup do arquivo de ambiente com valores", _sinal_env),
    (".env.old", "HIGH", "cópia antiga do arquivo de ambiente com valores", _sinal_env),
    (".env.save", "HIGH", "cópia salva do arquivo de ambiente com valores", _sinal_env),
    (".htpasswd", "HIGH", "arquivo de senhas do servidor web",
     lambda c: not _eh_html(c) and bool(_RE_HTPASSWD.search(c))),
    ("backup.sql", "HIGH", "dump do banco de dados", _sinal_dump),
    ("dump.sql", "HIGH", "dump do banco de dados", _sinal_dump),
    ("database.sql", "HIGH", "dump do banco de dados", _sinal_dump),
    (".env.production", "HIGH", "arquivo de ambiente de produção com valores", _sinal_env),
    (".git-credentials", "HIGH", "credenciais do git (usuário e token em URL)",
     lambda c: not _eh_html(c) and b"https://" in c and b"@" in c),
    (".svn/wc.db", "HIGH", "cópia de trabalho do Subversion",
     lambda c: c.startswith(b"SQLite format 3\0")),
    (".npmrc", "HIGH", "configuração do npm com token",
     lambda c: not _eh_html(c) and b"_authToken" in c),
    (".vscode/sftp.json", "HIGH", "config de SFTP do editor com host e senha",
     lambda c: not _eh_html(c) and b'"host"' in c and b'"password"' in c),
    ("sftp-config.json", "HIGH", "config de SFTP do editor com host e senha",
     lambda c: not _eh_html(c) and b'"host"' in c and b'"password"' in c),
    # Servidor de desenvolvimento do Vite exposto como se fosse produção.
    ("@vite/client", "MEDIUM", "servidor de desenvolvimento do Vite (código-fonte sem build)",
     lambda c: not _eh_html(c) and b"import.meta.hot" in c),
]

# Cabeçalhos que anunciam produto e VERSÃO. Só acusa com número de versão: o
# nome sozinho ("Netlify", "cloudflare") não ajuda quem procura exploit pronto.
_CAB_VERSAO = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
               "x-generator")
_RE_TEM_VERSAO = re.compile(r"\d+\.\d+")
_RE_META_GERADOR = re.compile(
    r"""<meta\b[^>]*\bname=["']generator["'][^>]*\bcontent=["']([^"']+)["']"""
    r"""|<meta\b[^>]*\bcontent=["']([^"']+)["'][^>]*\bname=["']generator["']""", re.I)


# Achados que a varredura OBSERVOU no site no ar (conteúdo conferido, cabeçalho
# recebido, leitura anon que devolveu linhas, JWT decodificado): são fato, não
# padrão. Segredo por regex continua indício: pode ser chave pública por desenho.
_CONFIRMADOS = ("bundle.exposto-", "bundle.anon-le-tabela", "bundle.sourcemap-expoe-codigo",
                "bundle.jwt-service-role", "bundle.sem-csp", "bundle.sem-hsts",
                "bundle.sem-protecao-clickjacking")


def _achado(rule: str, sev: str, url: str, msg: str, evidencia: bool = False) -> dict:
    a = {"rule": rule, "severity": sev, "context": "", "path": url,
         "line": 0, "message": msg}
    if evidencia or rule.startswith(_CONFIRMADOS):
        a["evidencia"] = "confirmado"
    return a


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
    # O VALOR de cada cabeçalho recebido, com as mesmas checagens que o
    # headers_lint faz no netlify.toml/_headers: aqui é o que o site entrega de
    # fato, não o que o arquivo promete. Clickjacking já foi visto acima.
    for nome, valor in pag.headers.items():
        for a in headers_lint._achados_valor(nome, valor, url, 0):
            if a["rule"] != "headers.csp-sem-frame-ancestors":
                a["evidencia"] = "confirmado"
                achados.append(a)
    for nome in _CAB_VERSAO:
        valor = pag.headers.get(nome)
        if valor and _RE_TEM_VERSAO.search(valor):
            achados.append(_achado(
                "bundle.versao-exposta", "LOW", url,
                f"Cabeçalho `{nome}: {valor}` anuncia produto e versão: quem procura "
                f"exploit pronto para essa versão começa por aqui. Remova ou tire o número.",
                evidencia=True))
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
        "firebase": set(_RE_FIREBASE_DB.findall(texto)),
    }
    return achados, pistas


def _url_chunk(ref: str, url_script: str, origem: str) -> str:
    """`./x.js` é relativo ao módulo que importa; `assets/x.js` (deps do
    __vitePreload) é relativo à base do site."""
    if ref.startswith(("./", "../")):
        return urljoin(url_script, ref)
    return origem + (ref if ref.startswith("/") else "/" + ref)


def _preloads(html: str, url: str) -> list[str]:
    return [urljoin(url, m.group(1)) for tag in _RE_LINK.findall(html)
            if _RE_MODULEPRELOAD.search(tag) and (m := _RE_HREF.search(tag))]


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


def _sondar_firebase(db: str, bus) -> list[dict]:
    """Realtime Database aberto: `?shallow=true` devolve só os NOMES dos nós de topo.

    Nunca baixa valor nenhum: com `shallow`, o Firebase responde `{"users": true}`.
    401 ("Permission denied") é o resultado bom e não vira achado.
    """
    r = bus(f"{db}/.json?shallow=true")
    if not r or r.status != 200:
        return []
    try:
        dados = json.loads(r.corpo)
    except (ValueError, UnicodeDecodeError):
        return []
    if not isinstance(dados, dict) or not dados:
        return []  # `null` = banco vazio (ou nó inexistente): nada lido, nada exposto
    nos = sorted(dados)
    amostra = ", ".join(nos[:10]) + (" …" if len(nos) > 10 else "")
    return [_achado(
        "bundle.firebase-leitura-anonima", "HIGH", db,
        f"Realtime Database do Firebase legível SEM login: {len(nos)} nó(s) de topo "
        f"({amostra}). Valores não lidos. A URL está no JavaScript do site, então qualquer "
        f"pessoa baixa o banco por `{db}/.json`. Feche as regras (`\".read\": false`) e "
        f"exija `auth != null` e dono por `auth.uid`.", evidencia=True)]


def _achados_estado_ssr(url: str, html: str) -> list[dict]:
    """`__NEXT_DATA__` / `__NUXT__`: segredos e campos que não deveriam ir ao navegador."""
    achados = []
    for m in _RE_ESTADO_SSR.finditer(html):
        bloco = m.group(1) or m.group(2) or ""
        ach, _ = _achados_texto(url, bloco)
        achados += ach
        chave = _RE_CHAVE_SENSIVEL.search(bloco)
        if chave:
            achados.append(_achado(
                "bundle.estado-ssr-campo-sensivel", "MEDIUM", url,
                f"O estado inicial da página (`__NEXT_DATA__`/`__NUXT__`) carrega um campo "
                f"`{chave.group(1)}`. O servidor serializa para o HTML tudo o que a tela recebeu, "
                f"então o campo chega a qualquer visitante, mesmo sem aparecer na tela. "
                f"Selecione só as colunas que a tela usa."))
    return achados


_COOKIES_DO_SUPABASE = re.compile(r"^sb-[a-z0-9\-]+-auth-token(\.\d+)?$", re.I)


def _achados_cookies(url: str, pag) -> list[dict]:
    """Atributos do `Set-Cookie` da página: só o que ela mesma já devolveu."""
    achados = []
    # `Resp.headers` junta cabeçalhos repetidos pela última ocorrência; quando houver
    # mais de um cookie só o último é visto. Melhor um falso negativo que inventar.
    bruto = pag.headers.get("set-cookie")
    if not bruto:
        return achados
    nome = bruto.split("=", 1)[0].strip()
    atributos = [a.strip().lower() for a in bruto.split(";")[1:]]
    https = url.lower().startswith("https://")
    faltam = []
    if https and "secure" not in atributos:
        faltam.append("Secure")
    if "httponly" not in atributos and not _COOKIES_DO_SUPABASE.match(nome):
        faltam.append("HttpOnly")
    if not any(a.startswith("samesite") for a in atributos):
        faltam.append("SameSite")
    if faltam:
        achados.append(_achado(
            "bundle.cookie-sem-atributo", "LOW", url,
            f"O cookie `{nome}` vem sem {', '.join(faltam)}. Sem Secure ele viaja em HTTP; "
            f"sem HttpOnly um script injetado o lê; sem SameSite o navegador o envia em "
            f"requisições de outros sites.", evidencia=True))
    return achados


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
        achados += _achados_cookies(url, pag)

        texto_pag = pag.corpo.decode("utf-8", "replace")
        m_ger = _RE_META_GERADOR.search(texto_pag)
        gerador = m_ger and (m_ger.group(1) or m_ger.group(2))
        if gerador and _RE_TEM_VERSAO.search(gerador):
            achados.append(_achado(
                "bundle.versao-exposta", "LOW", url,
                f'`<meta name="generator" content="{gerador}">` anuncia produto e versão '
                f"(comum em WordPress/Joomla/Drupal). Remova a meta tag.", evidencia=True))
        achados += _achados_estado_ssr(url, texto_pag)
        scripts = []
        for src in _RE_SCRIPT.findall(texto_pag):
            absoluto = urljoin(url, src)
            if absoluto not in scripts:
                scripts.append(absoluto)
        for src in scripts:
            aviso = retire.backdoor(src)
            if aviso:
                achados.append(_achado(
                    "bundle.script-de-host-comprometido", "HIGH", src,
                    f"A página carrega script de um host sabidamente comprometido "
                    f"(base Retire.js): {aviso} Troque pela cópia de um CDN confiável ou "
                    f"sirva o arquivo do próprio site.", evidencia=True))

        origem = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        host = urlparse(url).netloc
        fila = scripts[:MAX_SCRIPTS]
        vistos = set(scripts)
        extras = cortados = mapas = 0

        def enfileirar(c: str) -> None:
            nonlocal extras, cortados
            # Só chunks do próprio site: CDN de terceiro não é o código do alvo.
            if urlparse(c).netloc != host or c in vistos:
                return
            vistos.add(c)
            if extras < MAX_CHUNKS:
                fila.append(c)
                extras += 1
            else:
                cortados += 1

        for c in _preloads(texto_pag, url):
            enfileirar(c)

        refs, tabelas, schemas = set(), set(), set()
        publishable = anon_jwt = None
        firebase_dbs: set[str] = set()
        libs_vistas: set[tuple[str, str]] = set()
        libs_achados: list[dict] = []
        libs_detalhes: dict[str, dict] = {}
        i = 0
        while i < len(fila):
            src = fila[i]
            i += 1
            r = bus(src)
            # SPA devolve o index.html com 200 para chunk inexistente: não é JS.
            if not r or r.status != 200 or _eh_html(r.corpo):
                continue
            texto = r.corpo.decode("utf-8", "replace")
            ach, pistas = _achados_texto(src, texto)
            achados += ach
            refs |= pistas["refs"]
            tabelas |= pistas["tabelas"]
            schemas |= pistas["schemas"]
            firebase_dbs |= pistas["firebase"]
            publishable = publishable or pistas["publishable"]
            anon_jwt = anon_jwt or pistas["anon_jwt"]
            # Source map também pode vir pelo cabeçalho, sem comentário no arquivo.
            cab_mapa = r.headers.get("sourcemap") or r.headers.get("x-sourcemap")
            for ref in ([cab_mapa] if cab_mapa else []) + pistas["sourcemaps"][:1]:
                if mapas < MAX_SOURCEMAPS:
                    mapas += 1
                    achados += _achados_sourcemap(src, ref, bus)
            if urlparse(src).netloc == host:
                for ref in _RE_CHUNK.findall(texto):
                    enfileirar(_url_chunk(ref, src, origem))
            for lib, versao in retire.detectar(src, texto).items():
                if (lib, versao) in libs_vistas:
                    continue
                libs_vistas.add((lib, versao))
                vulns = retire.vulnerabilidades(lib, versao)
                if not vulns:
                    continue
                sev, cves, cwes = retire.resumo_vulns(vulns)
                resumos = "; ".join(dict.fromkeys(
                    ((v.get("identifiers") or {}).get("summary") or "").strip()
                    for v in vulns if (v.get("identifiers") or {}).get("summary")))
                lista = ", ".join(cves[:5]) + (" …" if len(cves) > 5 else "")
                chave_lib = f"retire:{lib}@{versao}"
                a = _achado(
                    "bundle.lib-vulneravel", sev, src,
                    f"{lib} {versao} servido pelo site tem {len(vulns)} vulnerabilidade(s) "
                    f"conhecida(s) (base Retire.js)" + (f": {lista}" if cves else "")
                    + (f". {resumos[:300]}" if resumos else "")
                    + ". Atualize a biblioteca e publique de novo.", evidencia=True)
                a["cwe"] = cwes
                a["osv_id"] = chave_lib
                libs_detalhes[chave_lib] = {"aliases": cves}
                libs_achados.append(a)

        if libs_achados:
            # Mesma marcação do SCA: CVE explorada em ataque real sobe de severidade.
            exploracao.anotar(libs_achados, libs_detalhes)
            achados += libs_achados
        if cortados:
            achados.append(_achado(
                "bundle.limite-de-chunks", "INFO", url,
                f"O site carrega mais de {MAX_CHUNKS} chunks JS sob demanda; "
                f"{cortados} NÃO foram lidos (segredos e tabelas neles ficam de fora)."))

        for caminho, sev, desc, sinal in SONDAS:
            r = bus(f"{origem}/{caminho}")
            if r and r.status == 200 and sinal(r.corpo):
                achados.append(_achado(
                    f"bundle.exposto-{caminho.replace('/', '-').strip('.')}", sev,
                    f"{origem}/{caminho}",
                    f"Caminho público que deveria ser privado: {desc}. Quem acessa lê o "
                    f"conteúdo. Retire do build e confira o que já foi publicado."))

        for db in sorted(firebase_dbs)[:3]:
            achados += _sondar_firebase(db, bus)

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
