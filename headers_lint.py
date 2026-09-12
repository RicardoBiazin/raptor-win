"""Cabeçalhos de segurança de site estático — a metade que o helmet não cobre.

O `helmet` resolve isto em Express com uma linha. Só que um app Vite/React
publicado na Netlify ou na Vercel **não tem Express**: não há middleware onde
pendurar cabeçalho nenhum. Quem os define é o arquivo de configuração do host —
`netlify.toml`, `_headers` ou `vercel.json` — e é exatamente aí que ninguém
olha, porque não é código e não quebra o build quando está errado ou ausente.

Este módulo lê os três formatos, une o que eles declaram para a rota curinga e
compara com o conjunto que o helmet aplica por padrão. Duas classes de achado:

  * o cabeçalho não existe (nada protege a página);
  * o cabeçalho existe com valor que não protege — que é pior, porque passa
    em qualquer conferência que só verifique presença.

E uma terceira, mais silenciosa que as duas: `_headers` fora do diretório de
publicação. O arquivo existe, está versionado, o conteúdo está correto, e o
Vite nunca o copia para `dist/`. Não há erro em lugar nenhum; o site
simplesmente sobe sem cabeçalho. Ver `_achados_headers_fora_do_publish`.

Nada aqui faz rede: é leitura de arquivo do repositório, como o `sql_lint`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# O que se espera encontrar
# ---------------------------------------------------------------------------

# Cabeçalhos que o helmet v8 aplica por padrão em `app.use(helmet())`, com a
# severidade da AUSÊNCIA de cada um. Não é a lista inteira do helmet: ficam de
# fora os que só fazem sentido atrás de um servidor de aplicação
# (`X-Powered-By`, `Origin-Agent-Cluster`) e os que a Netlify recusa definir.
#
# `Permissions-Policy` não vem do helmet — ele não o implementa — mas entra
# porque desliga câmera, microfone e geolocalização de uma vez, e o custo de
# escrevê-lo é uma linha.
ESPERADOS: dict[str, tuple[str, str]] = {
    "content-security-policy": ("HIGH",
        "sem CSP, qualquer script injetado na página executa: é a única defesa "
        "que sobra quando um XSS passa pela sanitização"),
    "strict-transport-security": ("HIGH",
        "sem HSTS, a primeira visita ainda pode ser interceptada em HTTP e "
        "rebaixada antes de chegar ao redirecionamento"),
    "x-content-type-options": ("MEDIUM",
        "sem `nosniff`, o navegador pode interpretar um upload como script"),
    "referrer-policy": ("MEDIUM",
        "sem política de referrer, o caminho completo da página — com o que "
        "houver na URL — vaza para todo domínio de terceiro que a página chama"),
    "x-frame-options": ("MEDIUM",
        "sem proteção de enquadramento, a página pode ser embutida em iframe "
        "de terceiro (clickjacking)"),
    "cross-origin-opener-policy": ("LOW",
        "sem COOP, uma janela aberta por terceiro continua com referência a "
        "esta (`window.opener`) e compartilha o mesmo grupo de contexto"),
    "permissions-policy": ("LOW",
        "sem Permissions-Policy, câmera, microfone e geolocalização seguem "
        "disponíveis para qualquer script da página"),
}

# HSTS abaixo disto não vale muito: o mínimo para entrar na lista de preload dos
# navegadores é um ano, e 180 dias é o piso que o securityheaders.com cobra.
HSTS_MINIMO = 15552000          # 180 dias em segundos


# ---------------------------------------------------------------------------
# Leitura dos três formatos
# ---------------------------------------------------------------------------

def _ler_headers_texto(texto: str) -> list[tuple[str, dict[str, tuple[str, int]]]]:
    """Formato `_headers` da Netlify: rota na coluna 0, cabeçalhos indentados.

        /*
          X-Frame-Options: DENY
          Content-Security-Policy: default-src 'self'

    Nome de cabeçalho é insensível a maiúsculas (a norma HTTP diz isso), então
    a chave é normalizada — senão `content-security-policy` escrito assim, que
    é válido e a Netlify aceita, passaria por ausente.
    """
    blocos: list[tuple[str, dict[str, tuple[str, int]]]] = []
    rota = ""
    atual: dict[str, tuple[str, int]] = {}
    for n, raw in enumerate(texto.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            if rota:
                blocos.append((rota, atual))
            rota, atual = raw.strip(), {}
            continue
        if not rota or ":" not in raw:
            continue
        nome, _, valor = raw.strip().partition(":")
        atual[nome.strip().lower()] = (valor.strip(), n)
    if rota:
        blocos.append((rota, atual))
    return blocos


# `for = "/*"` abre um bloco; `Nome = "valor"` dentro de `[headers.values]` é um
# cabeçalho. Leio linha a linha em vez de usar `tomllib` porque ele só existe no
# Python 3.11+ e o resto do raptor-win roda a partir do 3.10 — subir o piso da
# ferramenta inteira por causa de um bloco TOML de cinco linhas seria mau negócio.
_TOML_SECAO = re.compile(r"^\s*\[+([^\]]+)\]+\s*$")
_TOML_PAR = re.compile(r"""^\s*["']?([A-Za-z0-9_-]+)["']?\s*=\s*(.+?)\s*$""")


def _ler_netlify_toml(texto: str) -> tuple[list, str]:
    """Devolve (blocos de cabeçalho, diretório de publicação).

    O `publish` importa tanto quanto os cabeçalhos: é ele que diz para onde o
    `_headers` precisa ir para valer alguma coisa.
    """
    blocos: list[tuple[str, dict[str, tuple[str, int]]]] = []
    publish = ""
    secao = ""
    rota = ""
    atual: dict[str, tuple[str, int]] = {}
    for n, raw in enumerate(texto.splitlines(), start=1):
        linha = raw.split("#", 1)[0] if not raw.strip().startswith("#") else ""
        if not linha.strip():
            continue
        m = _TOML_SECAO.match(linha)
        if m:
            nova = m.group(1).strip()
            # Sair de um bloco [[headers]] fecha o que estava aberto.
            if rota and not nova.startswith("headers."):
                blocos.append((rota, atual))
                rota, atual = "", {}
            secao = nova
            continue
        m = _TOML_PAR.match(linha)
        if not m:
            continue
        chave, valor = m.group(1), m.group(2).strip().strip("\"'")
        if secao == "build" and chave == "publish":
            publish = valor
        elif secao == "headers" and chave == "for":
            if rota:
                blocos.append((rota, atual))
            rota, atual = valor, {}
        elif secao == "headers.values" and rota:
            atual[chave.lower()] = (valor, n)
    if rota:
        blocos.append((rota, atual))
    return blocos, publish


def _ler_vercel_json(texto: str) -> list[tuple[str, dict[str, tuple[str, int]]]]:
    try:
        dados = json.loads(texto)
    except Exception:
        return []
    blocos = []
    for entrada in (dados.get("headers") or []):
        if not isinstance(entrada, dict):
            continue
        rota = str(entrada.get("source") or "")
        vals: dict[str, tuple[str, int]] = {}
        for h in (entrada.get("headers") or []):
            if isinstance(h, dict) and h.get("key"):
                vals[str(h["key"]).lower()] = (str(h.get("value", "")), 1)
        if rota:
            blocos.append((rota, vals))
    return blocos


def _e_curinga(rota: str) -> bool:
    """Rota que cobre o site inteiro.

    Só os blocos curinga contam para a checagem de ausência: um CSP declarado
    apenas em `/admin/*` não protege a página inicial, e somá-lo ao conjunto
    daria um "tem CSP" falso.
    """
    return rota.strip() in ("/*", "/(.*)", "/.*", "/**", "/:path*", "/")


# ---------------------------------------------------------------------------
# Valores que não protegem
# ---------------------------------------------------------------------------

def _achados_valor(nome: str, valor: str, rel: str, linha: int) -> list[dict]:
    """Cabeçalho presente cujo valor não entrega a proteção que o nome promete.

    Esta metade importa mais que a checagem de ausência: um `Content-Security-
    Policy: default-src *` passa em qualquer conferência que só olhe se o
    cabeçalho existe, e não impede absolutamente nada.
    """
    v = valor.strip()
    vl = v.lower()
    out: list[dict] = []

    def achado(regra: str, sev: str, msg: str) -> None:
        out.append({"rule": regra, "severity": sev, "context": "",
                    "path": rel, "line": linha, "message": msg})

    if nome == "content-security-policy":
        if re.search(r"default-src[^;]*\*(?!\.)", vl) or re.search(r"script-src[^;]*\s\*", vl):
            achado("headers.csp-curinga", "HIGH",
                   "CSP com `*` em default-src/script-src permite script de "
                   "qualquer origem: o cabeçalho está lá, mas não restringe nada.")
        if "'unsafe-inline'" in vl and "script-src" in vl:
            # Só acuso em script-src. Em style-src o 'unsafe-inline' é quase
            # inevitável com Tailwind e afins, e acusá-lo faria o relatório
            # gritar em todo projeto React — exatamente o que tira a atenção do
            # achado que importa.
            trecho = vl.split("script-src", 1)[1].split(";", 1)[0]
            if "'unsafe-inline'" in trecho:
                achado("headers.csp-unsafe-inline", "HIGH",
                       "`script-src 'unsafe-inline'` devolve ao atacante a "
                       "execução de script inline — é o que a CSP existe para tirar.")
        if "'unsafe-eval'" in vl:
            achado("headers.csp-unsafe-eval", "HIGH",
                   "`'unsafe-eval'` reabre `eval()` e `new Function()` para "
                   "string vinda de fora.")
        if re.search(r"connect-src[^;]*\s\*", vl):
            achado("headers.csp-connect-curinga", "MEDIUM",
                   "`connect-src *` deixa a página falar com qualquer host — "
                   "é o caminho de exfiltração que a CSP fecharia. Com Supabase, "
                   "liste `https://<ref>.supabase.co` E `wss://<ref>.supabase.co` "
                   "(o Realtime precisa do wss) em vez do curinga.")
        if "object-src" not in vl:
            achado("headers.csp-sem-object-src", "MEDIUM",
                   "sem `object-src 'none'`, `<object>`/`<embed>` continuam "
                   "disponíveis como sink de execução.")
        if "frame-ancestors" not in vl:
            achado("headers.csp-sem-frame-ancestors", "LOW",
                   "sem `frame-ancestors`, o controle de enquadramento depende "
                   "só do X-Frame-Options, que navegador novo já ignora.")

    elif nome == "strict-transport-security":
        m = re.search(r"max-age\s*=\s*(\d+)", vl)
        if not m:
            achado("headers.hsts-sem-max-age", "HIGH",
                   "HSTS sem `max-age` não é aplicado por navegador nenhum.")
        else:
            idade = int(m.group(1))
            if idade == 0:
                achado("headers.hsts-desligado", "HIGH",
                       "`max-age=0` DESLIGA o HSTS — e apaga o que o navegador "
                       "já tinha guardado deste domínio.")
            elif idade < HSTS_MINIMO:
                achado("headers.hsts-curto", "MEDIUM",
                       f"`max-age={idade}` é curto demais ({idade // 86400} dias). "
                       f"Use 31536000 (um ano), que é o mínimo do preload.")
        if "includesubdomains" not in vl:
            achado("headers.hsts-sem-subdominio", "LOW",
                   "sem `includeSubDomains`, um subdomínio em HTTP continua "
                   "servindo de ponto de entrada.")

    elif nome == "x-frame-options":
        if vl not in ("deny", "sameorigin"):
            achado("headers.xfo-invalido", "MEDIUM",
                   f"`{v}` não é valor válido de X-Frame-Options (só DENY e "
                   "SAMEORIGIN são). Valor inválido é ignorado pelo navegador, "
                   "e o resultado é o mesmo de não ter o cabeçalho.")

    elif nome == "x-content-type-options":
        if vl != "nosniff":
            achado("headers.nosniff-invalido", "MEDIUM",
                   f"o único valor válido é `nosniff`; `{v}` é ignorado.")

    elif nome == "referrer-policy":
        if vl in ("unsafe-url", "no-referrer-when-downgrade"):
            achado("headers.referrer-vazante", "MEDIUM",
                   f"`{v}` envia a URL completa para terceiros — incluindo o "
                   "que estiver no caminho e na query.")

    elif nome == "x-xss-protection":
        if vl.startswith("1"):
            achado("headers.xss-auditor-legado", "LOW",
                   "`X-XSS-Protection: 1` liga o auditor legado, que já foi "
                   "usado para CRIAR XSS em navegador antigo. O helmet manda "
                   "`0` de propósito; remova o cabeçalho ou zere-o.")

    elif nome == "access-control-allow-origin":
        if v == "*":
            achado("headers.cors-aberto", "MEDIUM",
                   "`Access-Control-Allow-Origin: *` libera leitura da resposta "
                   "para qualquer origem.")

    elif nome == "content-security-policy-report-only":
        achado("headers.csp-so-relatorio", "MEDIUM",
               "CSP em modo Report-Only NÃO bloqueia nada — só avisa. Se esta "
               "é a única CSP do site, a proteção não está ativa.")

    return out


# ---------------------------------------------------------------------------
# O achado silencioso
# ---------------------------------------------------------------------------

# Diretórios cujo conteúdo o Vite (e o CRA, e o Astro) copiam inteiro para a
# pasta de build. Um `_headers` aqui dentro chega ao deploy; fora daqui, não.
COPIADOS_NO_BUILD = ("public", "static")

# Diretorios de SAIDA de build. Um `_headers` aqui dentro e' copia gerada, nao
# arquivo de fonte: ele chegou ali justamente porque o build funcionou. Medido
# no Sunset, que publica dois sites (`dist` e `dist-demo`) e por isso tem tres
# copias do mesmo `_headers` -- acusar as geradas seria acusar o acerto.
# Casa por PREFIXO porque a variante por ambiente (`dist-demo`, `dist-staging`)
# e' comum e nao da' para enumerar.
PREFIXOS_DE_BUILD = ("dist", "build", "out", ".next", ".svelte-kit", ".output")


def _e_saida_de_build(partes: tuple[str, ...], publish: str) -> bool:
    if not partes:
        return False
    p0 = partes[0]
    if publish and p0 == publish.strip("/"):
        return True
    return any(p0 == x or p0.startswith(x + "-") for x in PREFIXOS_DE_BUILD)


def _achados_headers_fora_do_publish(arq: Path, raiz: Path, publish: str) -> list[dict]:
    """`_headers` que o build nunca vai copiar.

    A Netlify só lê o `_headers` que estiver DENTRO do diretório publicado
    (`dist/`, para Vite). Um `_headers` na raiz do repositório é versionado,
    revisado, aprovado em PR — e some no build. Não há erro, não há aviso, e o
    site sobe sem cabeçalho nenhum enquanto o repositório mostra o contrário.

    É o pior formato de falha que existe para uma ferramenta destas: parece
    configurado. Por isso o achado é HIGH mesmo com o conteúdo do arquivo
    perfeito — o conteúdo é justamente o que faz ninguém desconfiar.
    """
    try:
        partes = arq.relative_to(raiz).parts
    except ValueError:
        return []
    if _e_saida_de_build(partes, publish):
        return []                              # copia gerada pelo build
    if len(partes) > 1 and partes[0] in COPIADOS_NO_BUILD:
        return []                              # fonte no lugar certo
    if len(partes) > 1 and partes[-2] in COPIADOS_NO_BUILD:
        return []                              # monorepo: `web/public/_headers`
    destino = (publish or "dist").strip("/")
    return [{
        "rule": "headers.arquivo-fora-do-publish",
        "severity": "HIGH", "context": "",
        "path": str(arq).replace("\\", "/"), "line": 1,
        "message": (
            f"`_headers` fora do diretório publicado: a Netlify só lê o que "
            f"estiver dentro de `{destino}/`, e o build não copia este arquivo "
            f"para lá. Ele está versionado e parece configurado, mas o site sobe "
            f"sem estes cabeçalhos. Mova para `public/` (o Vite copia o conteúdo "
            f"de `public/` para `{destino}/`)."),
    }]


# ---------------------------------------------------------------------------
# Varredura
# ---------------------------------------------------------------------------

_CONFIGS_VITE = ("vite.config.ts", "vite.config.js", "vite.config.mjs",
                 "vite.config.mts")


def _e_site_estatico(raiz: Path, skip_dirs: set[str]) -> bool:
    """Projeto que publica página, e portanto deveria mandar cabeçalho.

    Sem esta porta, a checagem de ausência acusaria biblioteca, script e
    qualquer repositório que não serve HTML para navegador nenhum.

    O `index.html` NÃO é procurado só na raiz: em monorepo ele fica no pacote
    do app. Medido no omnichannel, que tem `netlify.toml` na raiz e o app em
    `web/` -- olhar só a raiz dava "não é site estático" e engolia em silêncio
    um projeto publicado com três cabeçalhos.
    """
    if (raiz / "index.html").exists():
        return True
    for cfg in _CONFIGS_VITE:
        for achado in raiz.rglob(cfg):
            if any(x in skip_dirs for x in achado.parts):
                continue
            if (achado.parent / "index.html").exists():
                return True
    return False


def _relativo(p: Path) -> str:
    try:
        return str(p.relative_to(Path.cwd())).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    achados: list[dict] = []
    for alvo in alvos:
        raiz = alvo if alvo.is_dir() else alvo.parent
        if not raiz.is_dir():
            continue
        publish = ""
        blocos: list[tuple[str, dict[str, tuple[str, int]], str]] = []
        arquivos_headers: list[Path] = []

        for arq in sorted(raiz.rglob("*")):
            if any(x in skip_dirs for x in arq.parts) or not arq.is_file():
                continue
            nome = arq.name
            if nome not in ("netlify.toml", "_headers", "vercel.json"):
                continue
            # Saída de build fica de fora da LEITURA, não só do julgamento.
            # `dist/_headers` é cópia gerada, e uma cópia velha mente nos dois
            # sentidos: some do relatório o achado que existe na fonte (a união
            # veria o CSP do build anterior e diria "tem CSP"), e apontaria a
            # correção para um arquivo que o próximo build sobrescreve.
            try:
                if _e_saida_de_build(arq.relative_to(raiz).parts, ""):
                    continue
            except ValueError:
                pass
            try:
                texto = arq.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = _relativo(arq)
            if nome == "netlify.toml":
                bs, pub = _ler_netlify_toml(texto)
                publish = publish or pub
            elif nome == "_headers":
                arquivos_headers.append(arq)
                bs = _ler_headers_texto(texto)
            else:
                bs = _ler_vercel_json(texto)
            for rota, vals in bs:
                blocos.append((rota, vals, rel))

        for arq in arquivos_headers:
            achados += _achados_headers_fora_do_publish(arq, raiz, publish)

        # Valor inseguro vale em QUALQUER rota: um `unsafe-eval` declarado só
        # para `/admin/*` continua sendo unsafe-eval em /admin.
        for rota, vals, rel in blocos:
            for nome, (valor, linha) in vals.items():
                achados += _achados_valor(nome, valor, rel, linha)

        # Ausência, só pelo que cobre o site inteiro. Ver `_e_curinga`.
        cobertos: set[str] = set()
        csp_curinga = ""
        for rota, vals, _rel in blocos:
            if _e_curinga(rota):
                cobertos |= set(vals)
                if "content-security-policy" in vals:
                    csp_curinga = vals["content-security-policy"][0].lower()
        if not _e_site_estatico(raiz, skip_dirs):
            continue
        # O achado de ausência precisa apontar para ALGUM arquivo. Se já existe
        # configuração de cabeçalho, aponto para ela (é onde a linha que falta
        # deve ser escrita). Se não existe nenhuma, aponto para onde o arquivo
        # deveria ser criado.
        fonte = next((rel for _r, _v, rel in blocos),
                     _relativo(raiz / "public" / "_headers"))
        for nome, (sev, porque) in ESPERADOS.items():
            if nome in cobertos:
                continue
            # `frame-ancestors` na CSP substitui o X-Frame-Options, e é a forma
            # que os navegadores novos respeitam. Cobrar os dois seria cobrar
            # duas vezes a mesma proteção.
            if nome == "x-frame-options" and "frame-ancestors" in csp_curinga:
                continue
            achados.append({
                "rule": f"headers.ausente.{nome}",
                "severity": sev, "context": "",
                "path": fonte, "line": 1,
                "message": (f"`{nome}` não é enviado em nenhuma rota curinga: "
                            f"{porque}."),
            })
    return sorted(achados, key=lambda a: (a["path"], a["line"], a["rule"]))
