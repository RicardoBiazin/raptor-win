"""
Riscos aceitos — o que transforma `--fail-on` em algo utilizável.

O PROBLEMA QUE ISTO RESOLVE. Todo projeto real acumula achados que já
foram analisados e conscientemente aceitos: a vulnerabilidade está no
servidor de desenvolvimento e não no pacote de produção; o aviso é de um
modo que o app não usa; a correção exige uma troca de versão maior que
está planejada para depois. Enquanto eles voltam a aparecer em toda
varredura, duas coisas acontecem, e as duas são ruins:

  · `--fail-on HIGH` reprova todo build, então ninguém liga o portão;
  · o relatório fica com ruído fixo, e ruído fixo treina a equipe a não
    ler o relatório — inclusive quando aparece coisa nova.

A saída usual é documentar num SECURITY.md à mão. Só que documento não é
verificado por nada: ele descreve o que se decidiu, não o que a ferramenta
faz, e as duas coisas divergem em silêncio.

O QUE ESTE ARQUIVO ACRESCENTA À IDEIA DE BASELINE. Um baseline comum é
uma lista de coisas a ignorar — e ignorar para sempre é como um risco
aceito vira risco esquecido. Aqui:

  · `motivo` é OBRIGATÓRIO. Sem justificativa não é aceite, é ocultação.
  · `ate` é uma DATA DE VALIDADE. Passou, o achado volta a reprovar e a
    ferramenta diz que o prazo venceu. "Adiado até a próxima atualização
    do toolchain" deixa de ser para sempre.
  · Entrada que não casa com nada é reportada. O achado foi corrigido e a
    dispensa ficou para trás — remover mantém o arquivo honesto.

Formato TOML porque este arquivo é lido e revisado por gente em pull
request. `tomllib` é biblioteca padrão desde o Python 3.11, então isso não
custa nenhuma dependência nova.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:      # Python 3.10 ou anterior
    tomllib = None               # type: ignore[assignment]

NOME_PADRAO = ".raptor-baseline.toml"

MODELO = '''# Riscos aceitos — conferidos pelo raptor-win, não só documentados.
#
# Cada entrada dispensa um achado da contagem do --fail-on. `motivo` é
# obrigatório e `ate` é uma data de validade: quando ela passa, o achado
# volta a reprovar. É o que impede "aceito por enquanto" de virar
# "aceito para sempre".

# [[aceito]]
# regra  = "GHSA-qwww-vcr4-c8h2"      # id da regra, CVE/GHSA, ou parte dele
# caminho = "package-lock.json"       # opcional: limita a um arquivo
# motivo = "RSC Mode CSRF: este é um SPA com HashRouter, sem RSC e sem route actions."
# ate    = 2026-11-01                 # opcional, mas recomendado
# por    = "ricardo"
'''


class ErroBaseline(Exception):
    pass


def _hoje() -> _dt.date:
    return _dt.date.today()


def carregar(caminho: Path) -> list[dict]:
    if tomllib is None:
        raise ErroBaseline(
            "ler o baseline exige Python 3.11+ (tomllib). Atualize o Python "
            "ou rode sem --baseline.")
    try:
        dados = tomllib.loads(caminho.read_text(encoding="utf-8"))
    except Exception as e:
        raise ErroBaseline(f"{caminho}: TOML inválido — {e}") from e

    entradas = dados.get("aceito") or []
    if not isinstance(entradas, list):
        raise ErroBaseline(f"{caminho}: `aceito` precisa ser uma lista de [[aceito]].")

    saida: list[dict] = []
    for i, e in enumerate(entradas, 1):
        regra = str(e.get("regra", "")).strip()
        motivo = str(e.get("motivo", "")).strip()
        if not regra:
            raise ErroBaseline(f"{caminho}: entrada #{i} sem `regra`.")
        # Sem motivo não é aceite de risco, é o risco escondido debaixo do
        # tapete. Falhar aqui é o que mantém o arquivo revisável.
        if len(motivo) < 10:
            raise ErroBaseline(
                f"{caminho}: entrada #{i} ({regra}) precisa de um `motivo` que "
                f"explique por que o achado não é explorável aqui.")

        ate = e.get("ate")
        if ate is not None and not isinstance(ate, _dt.date):
            raise ErroBaseline(
                f"{caminho}: entrada #{i} ({regra}): `ate` deve ser uma data "
                f"TOML sem aspas, ex.: ate = 2026-11-01")

        saida.append({
            "regra": regra,
            "caminho": str(e.get("caminho", "")).strip().replace("\\", "/"),
            "motivo": motivo,
            "ate": ate,
            "por": str(e.get("por", "")).strip(),
        })
    return saida


def _casa(entrada: dict, achado: dict) -> bool:
    # Subcadeia, e não igualdade: o id do Semgrep é longo e cheio de
    # prefixos ("python.lang.security.audit.xyz"), e o CVE aparece no
    # texto do achado do SCA. Exigir o id exato tornaria o arquivo
    # impossível de escrever à mão.
    alvo = f"{achado.get('rule', '')} {achado.get('message', '')}".lower()
    if entrada["regra"].lower() not in alvo:
        return False
    if entrada["caminho"]:
        cam = achado.get("path", "").replace("\\", "/")
        if entrada["caminho"] not in cam:
            return False
    return True


def aplicar(achados: list[dict], entradas: list[dict]) -> tuple[list[dict], dict]:
    """Separa o que foi aceito do que continua valendo.

    Devolve (achados_que_continuam, resumo). Um achado aceito NÃO some do
    relatório — ele só deixa de contar para o --fail-on, e aparece marcado.
    Sumir seria a mesma cegueira que o baseline existe para evitar.
    """
    hoje = _hoje()
    vencidas: list[dict] = []
    usadas: set[int] = set()
    restantes: list[dict] = []

    for a in achados:
        aceito_por = None
        for idx, e in enumerate(entradas):
            if not _casa(e, a):
                continue
            usadas.add(idx)
            if e["ate"] is not None and e["ate"] < hoje:
                if e not in vencidas:
                    vencidas.append(e)
                continue          # vencida não dispensa mais
            aceito_por = e
            break

        if aceito_por:
            a = dict(a)
            a["aceito"] = aceito_por
            ctx = a.get("context", "")
            a["context"] = (ctx + " · " if ctx else "") + "risco aceito"
        restantes.append(a)

    orfas = [e for i, e in enumerate(entradas) if i not in usadas]
    resumo = {
        "aceitos": sum(1 for a in restantes if a.get("aceito")),
        "vencidas": vencidas,
        "orfas": orfas,
        "total_entradas": len(entradas),
    }
    return restantes, resumo


def render(resumo: dict) -> None:
    if not resumo["total_entradas"]:
        return
    print()
    print("=" * 62)
    print(" raptor-win — riscos aceitos")
    print("=" * 62)
    print(f" {resumo['aceitos']} achado(s) dispensados por "
          f"{resumo['total_entradas']} entrada(s) do baseline")

    for e in resumo["vencidas"]:
        print(f" ⚠ VENCEU em {e['ate']}: {e['regra']}")
        print(f"   {e['motivo']}")
        print("   O prazo passou — o achado volta a contar. Reavalie e "
              "renove a data, ou corrija.")

    for e in resumo["orfas"]:
        print(f" · entrada sem achado correspondente: {e['regra']}")
        print("   Provavelmente já foi corrigido. Remova a entrada para o "
              "arquivo continuar honesto.")


def prox_de_aceitar(achados: list[dict]) -> str:
    """Modelo TOML para os achados ainda não dispensados.

    Impresso para o usuário COLAR e preencher — de propósito não é
    gravado direto no arquivo. Um comando que aceita tudo de uma vez é um
    carimbo automático, e aí o baseline deixa de significar "alguém olhou".
    """
    linhas = [MODELO.rstrip(), ""]
    vistos: set[str] = set()
    for a in achados:
        if a.get("aceito"):
            continue
        r = a.get("rule", "")
        if r in vistos:
            continue
        vistos.add(r)
        linhas += [
            "[[aceito]]",
            f'regra  = "{r}"',
            f'caminho = "{a.get("path", "")}"',
            'motivo = "PREENCHA: por que este achado não é explorável aqui"',
            f"ate    = {_hoje().replace(year=_hoje().year + 1)}",
            "",
        ]
    return "\n".join(linhas)
