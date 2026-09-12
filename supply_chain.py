"""Sinais de cadeia de suprimentos lidos do lockfile — a parte do Socket que
não precisa de chave, de servidor, nem de baixar o pacote.

O `--sca` responde "esta dependência tem CVE conhecido?". Esta checagem responde
outra coisa: **o que esta dependência faz na hora de instalar, e de onde ela
veio**. São perguntas diferentes, e a segunda é a que sobra quando o pacote é
malicioso e recém-publicado — aí não há CVE nenhum a encontrar.

O Socket faz isso analisando o tarball publicado no servidor deles. Nada disso
é reproduzível aqui, e tentar seria mentir sobre o alcance. Mas três dos sinais
que eles reportam já estão **escritos no lockfile que o raptor-win lê**, e esses
saem de graça:

  * `hasInstallScript` — código de terceiro que executa no `npm install`, na
    máquina de quem desenvolve e no CI, onde está o token do repositório;
  * `resolved` apontando para fora do registro — tarball, git ou host próprio;
  * `integrity` ausente num pacote que veio por HTTP — nada verifica o que
    chegou.

Calibração antes de código, como no resto da ferramenta: medi `hasInstallScript`
em quatro projetos reais e o resultado foi `fsevents` nos quatro e `deno` num
deles. Todos benignos. Sem a allowlist de `data/install-scripts-conhecidos.json`
esta checagem nasceria como 100% de falso positivo — e seria desligada na
primeira execução, levando junto a atenção que o achado de verdade precisaria.

Sem rede: é leitura do lockfile, como o `sql_lint` é leitura do SQL.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

# Hosts de registro público. O que vier de fora daqui não passou pela
# publicação normal do ecossistema.
_REGISTROS_CONHECIDOS = (
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com",
    "files.pythonhosted.org", "pypi.org",
)

_ALLOWLIST: dict[str, dict] = {}


def _allowlist(eco: str) -> dict:
    if eco not in _ALLOWLIST:
        try:
            dados = json.loads(
                (_DATA / "install-scripts-conhecidos.json").read_text(encoding="utf-8"))
            _ALLOWLIST[eco] = dados.get(eco) or {}
        except Exception:
            # Degrada em SILÊNCIO para o lado seguro: sem a lista, não acuso
            # nada. O contrário -- acusar tudo porque o arquivo sumiu -- é o
            # comportamento que faz a ferramenta gritar justamente quando algo
            # nela quebrou.
            _ALLOWLIST[eco] = {}
    return _ALLOWLIST[eco]


def _nome_do_caminho(chave: str) -> str:
    """`node_modules/a/node_modules/@scope/b` -> `@scope/b`."""
    return chave.split("node_modules/")[-1]


def _host(url: str) -> str:
    m = re.match(r"^[a-z+]+://([^/]+)", url.strip(), re.I)
    if not m:
        return ""
    return (m.group(1).split("@")[-1].split(":")[0]).lower()


def _e_interno(resolved: str) -> bool:
    """Link de workspace num monorepo: `packages/core`, `web`, `file:../x`.

    Não é procedência suspeita — é o próprio repositório. Medido no
    omnichannel, onde `packages/core` e `web` apareciam como "host fora do
    registro" numa primeira versão desta checagem.
    """
    r = resolved.strip()
    if not r:
        return True
    if r.startswith(("file:", "link:", "workspace:", "portal:")):
        return True
    return "://" not in r          # caminho relativo, não URL


def _achados_do_package_lock(caminho: Path, rel: str) -> list[dict]:
    try:
        dados = json.loads(caminho.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    pacotes = dados.get("packages")
    if not isinstance(pacotes, dict):
        return []
    conhecidos = _allowlist("npm")
    achados: list[dict] = []
    for chave, meta in pacotes.items():
        meta = meta or {}
        if not chave:                       # a entrada "" é o próprio projeto
            continue
        nome = _nome_do_caminho(chave)
        resolved = str(meta.get("resolved") or "")

        if meta.get("hasInstallScript") and nome.lower() not in conhecidos:
            achados.append({
                "rule": "supply.script-de-instalacao",
                "severity": "MEDIUM", "context": "",
                "path": rel, "line": 1,
                "message": (
                    f"`{nome}` executa script na instalação. Esse código roda "
                    f"com as suas permissões no `npm install` — na máquina de "
                    f"quem desenvolve e no CI, onde está o token do "
                    f"repositório — e roda ANTES de qualquer teste ou revisão. "
                    f"Se o script é esperado (binário nativo, download de "
                    f"toolchain), acrescente o pacote a "
                    f"`data/install-scripts-conhecidos.json` com o motivo."),
            })

        if resolved and not _e_interno(resolved):
            host = _host(resolved)
            if host and not any(host.endswith(r) for r in _REGISTROS_CONHECIDOS):
                achados.append({
                    "rule": "supply.fora-do-registro",
                    "severity": "HIGH", "context": "",
                    "path": rel, "line": 1,
                    "message": (
                        f"`{nome}` não vem do registro público: foi resolvido "
                        f"em `{host}`. Esse conteúdo não passou pela publicação "
                        f"normal do ecossistema, não aparece em auditoria de "
                        f"registro, e pode mudar sem que a versão mude. "
                        f"Confirme que o host é seu."),
                })
            elif not meta.get("integrity") and resolved.startswith("http"):
                achados.append({
                    "rule": "supply.sem-integrity",
                    "severity": "MEDIUM", "context": "",
                    "path": rel, "line": 1,
                    "message": (
                        f"`{nome}` não tem `integrity` no lockfile: nada "
                        f"verifica que o tarball baixado é o mesmo que foi "
                        f"revisado. O lockfile deixa de ser garantia e passa a "
                        f"ser só um registro do que foi baixado uma vez."),
                })
    return achados


_INDEX_URL = re.compile(r"^\s*--(?:extra-)?index-url\s+(\S+)", re.M)


def _achados_do_requirements(caminho: Path, rel: str) -> list[dict]:
    """`--index-url` / `--extra-index-url` num requirements.

    É o vetor de confusão de dependência na forma mais direta: com
    `--extra-index-url`, o pip consulta os DOIS índices e, historicamente, fica
    com a versão mais alta — então quem publicar `1.0.0.post1` do seu pacote
    interno no PyPI público ganha a disputa sem precisar de acesso nenhum.
    """
    try:
        texto = caminho.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    achados = []
    for m in _INDEX_URL.finditer(texto):
        linha = texto[:m.start()].count("\n") + 1
        achados.append({
            "rule": "supply.index-url-extra",
            "severity": "MEDIUM", "context": "",
            "path": rel, "line": linha,
            "message": (
                f"índice de pacotes alternativo declarado (`{m.group(1)}`). O "
                f"pip consulta os dois índices e fica com a versão mais alta, "
                f"então quem publicar um número maior do seu pacote interno no "
                f"PyPI público vence a disputa. Prefira `--index-url` único "
                f"apontando para um proxy que espelhe os dois."),
        })
    return achados


_LOCKS_NPM = ("package-lock.json", "npm-shrinkwrap.json")


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    achados: list[dict] = []
    vistos: set[tuple] = set()
    for alvo in alvos:
        raiz = alvo if alvo.is_dir() else alvo.parent
        if not raiz.is_dir():
            continue
        for arq in sorted(raiz.rglob("*")):
            if any(x in skip_dirs for x in arq.parts) or not arq.is_file():
                continue
            nome = arq.name
            try:
                rel = str(arq.relative_to(Path.cwd())).replace("\\", "/")
            except ValueError:
                rel = str(arq).replace("\\", "/")
            if nome in _LOCKS_NPM:
                novos = _achados_do_package_lock(arq, rel)
            elif nome.startswith("requirements") and nome.endswith(".txt"):
                novos = _achados_do_requirements(arq, rel)
            else:
                continue
            for a in novos:
                # Um pacote transitivo aparece em várias posições da árvore; o
                # relatório precisa dele UMA vez.
                chave = (a["rule"], a["path"], a["message"])
                if chave not in vistos:
                    vistos.add(chave)
                    achados.append(a)
    return sorted(achados, key=lambda a: (a["path"], a["rule"], a["message"]))
