"""Relatório executivo do raptor-win: nota 0–100, prompt de correção, HTML e checklist.

Só stdlib. Não importa raptor_win (quem chama é o raptor_win), para não criar ciclo.
Tudo aqui é opt-in: sem --executivo / --html nada disto aparece na saída.

Regra sensível: achado de segredo ou de dado pessoal NUNCA leva o valor para o
prompt, o HTML ou o trecho de código. A mensagem dessas regras pode conter um
pedaço do valor (ver secrets_scan.py), por isso não é reproduzida.
"""

from __future__ import annotations

import base64
import html
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from secrets_scan import ATRIBUICAO_RE, REGRAS

# Peso de desconto por achado real (que exige atenção). Teto: 100 pontos.
PESO = {"CRITICAL": 25, "ERROR": 10, "HIGH": 10,
        "WARNING": 3, "MEDIUM": 3, "UNKNOWN": 3,
        "INFO": 0.5, "LOW": 0.5}
ORDEM_SEV = ["CRITICAL", "ERROR", "HIGH", "WARNING", "UNKNOWN", "MEDIUM", "INFO", "LOW"]

LOGO_MAX_BYTES = 2 * 1024 * 1024
LOGO_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".webp": "image/webp", ".svg": "image/svg+xml"}

OWASP = {
    "A01": "Controle de acesso quebrado",
    "A02": "Falhas criptográficas",
    "A03": "Injeção",
    "A04": "Design inseguro",
    "A05": "Configuração incorreta",
    "A06": "Componentes vulneráveis ou desatualizados",
    "A07": "Falhas de identificação e autenticação",
    "A08": "Falhas de integridade de software e dados",
    "A09": "Falhas de registro e monitoramento de segurança",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# CWE -> categoria OWASP Top 10 (2021). Achado sem CWE cai no prefixo da regra.
CWE_OWASP = {
    "CWE-22": "A01", "CWE-201": "A05", "CWE-250": "A01", "CWE-284": "A01",
    "CWE-732": "A01", "CWE-668": "A01", "CWE-1220": "A01",
    "CWE-78": "A03", "CWE-79": "A03", "CWE-89": "A03", "CWE-94": "A03",
    "CWE-643": "A03", "CWE-1427": "A03",
    "CWE-327": "A02", "CWE-328": "A02", "CWE-295": "A02",
    "CWE-209": "A05", "CWE-942": "A05",
    "CWE-636": "A04", "CWE-770": "A04", "CWE-1050": "A04",
    "CWE-287": "A07", "CWE-306": "A07", "CWE-308": "A07", "CWE-522": "A07",
    "CWE-540": "A07", "CWE-798": "A07",
    "CWE-348": "A08", "CWE-426": "A08", "CWE-470": "A08", "CWE-494": "A08",
    "CWE-502": "A08", "CWE-829": "A08",
    "CWE-532": "A09",
    "CWE-918": "A10",
}
# Prefixo da regra -> categoria, para achados sem CWE (segredo, SCA, banco, cabeçalhos).
PREFIXO_OWASP = [
    ("supply.", "A06"),
    ("secrets.", "A07"),
    ("db.", "A01"),
    ("sql.", "A01"),
    ("headers.", "A05"),
]

_RE_LGPD = re.compile(r"privacidade\.dado-pessoal|dado-pessoal-em-demo")
_RE_PREFIXO = {p: re.compile(rf"(^|\.){re.escape(p)}") for p, _ in PREFIXO_OWASP}
# NOME=valor sem aspas (formato de .env). ATRIBUICAO_RE do secrets_scan exige aspas.
_RE_ATRIB_SOLTA = re.compile(
    r"(?i)\w*(password|passwd|senha|secret|token|api[_\-]?key|private[_\-]?key|credential)\w*"
    r"\s*[:=]\s*[^\s(\"']{8,}(?![\w.(])")


def _tem_valor_sensivel(texto: str) -> bool:
    """O texto contém algo que parece segredo? Usa as mesmas regras do --secrets.

    Vale para a linha de código e para a mensagem: a mensagem de um pack do
    Semgrep (ex.: aws-access-key) pode repetir o valor. Por isso o teste é pelo
    conteúdo, não pelo nome da regra.
    """
    if not texto:
        return False
    if any(regra.re.search(texto) for regra in REGRAS):
        return True
    return bool(ATRIBUICAO_RE.search(texto) or _RE_ATRIB_SOLTA.search(texto))


# Identificadores trocados por marcador no prompt de correção (que vai para um
# assistente de terceiro): a linha continua útil para corrigir, mas o e-mail, o
# IP e o projeto Supabase de quem roda o scan não saem da máquina.
_MASCARAS = [
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "{email}"),
    (re.compile(r"\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b"), "{ip}"),
    (re.compile(r"\b[a-z0-9]{20}(?=\.supabase\.(?:co|in)\b)"), "{projeto}"),
]


def mascarar(texto: str) -> str:
    for rx, marcador in _MASCARAS:
        texto = rx.sub(marcador, texto)
    return texto


def _curta(rule: str) -> str:
    return rule.split(".")[-1] if "." in rule else rule


def e_sensivel(f: dict) -> bool:
    """Achado que pode carregar valor de segredo ou dado pessoal.

    Três critérios, qualquer um basta: regra de segredo ou LGPD pelo nome, ou
    mensagem com cara de segredo pelo conteúdo. Não há critério por nome só,
    porque os packs do Semgrep têm nomes próprios (aws-access-key, stripe-key).
    """
    rule = f.get("rule", "")
    return (rule.startswith("secrets.") or bool(_RE_LGPD.search(rule))
            or _tem_valor_sensivel(f.get("message", "")))


def _caminho_normal(path: str, raiz: Path | None) -> str:
    """Caminho absoluto e normalizado. O Semgrep devolve absoluto; o --secrets, relativo."""
    p = Path(path)
    if not p.is_absolute() and raiz is not None:
        p = raiz / p
    try:
        return str(p.resolve()).lower()
    except OSError:
        return str(p).lower()


def _chave_do_problema(f: dict, raiz: Path | None = None) -> tuple:
    """Uma linha de código é um problema só, mesmo com duas regras disparando nela.

    Sem linha (banco, cabeçalhos, pacotes), a identidade é o achado inteiro:
    não se pode fundir achados diferentes só porque são do mesmo arquivo.
    """
    caminho = _caminho_normal(f.get("path", ""), raiz)
    if f.get("line"):
        return (caminho, f["line"])
    return (caminho, f.get("rule", ""), f.get("message", ""))


def calcular_nota(reais: list[dict], raiz: Path | None = None) -> int:
    """Nota 0–100 sobre os achados reais (já filtrados por exigem_atencao e não aceitos).

    Parte de 100. Cada PROBLEMA desconta PESO da severidade mais alta entre os
    achados que o compõem: duas regras na mesma linha (ex.: chave Stripe) contam
    uma vez. Arredonda para baixo: a nota nunca fica acima do que os achados
    permitem. Os números de "achados" continuam sendo por regra, sem fundir.
    """
    maior: dict[tuple, float] = {}
    for f in reais:
        peso = PESO.get(f.get("severity", ""), 0.5)
        chave = _chave_do_problema(f, raiz)
        maior[chave] = max(maior.get(chave, 0.0), peso)
    return math.floor(max(0.0, 100 - sum(maior.values())))


def resumo(reais: list[dict], nota: int, quantos: int = 5) -> dict:
    por_sev = Counter(f.get("severity", "?") for f in reais)
    ordenados = sorted(reais, key=lambda f: (-PESO.get(f.get("severity", ""), 0.5),
                                              f.get("path", ""), f.get("line", 0)))
    return {"nota": nota, "por_sev": por_sev, "total": len(reais), "principais": ordenados[:quantos]}


def trecho(raiz: Path, path: str, line: int) -> str | None:
    """Uma linha do código-fonte afetado. None se não for arquivo local legível."""
    if not line or line <= 0:
        return None
    candidatos = [Path(path)] if Path(path).is_absolute() else [raiz / path, Path(path)]
    for p in candidatos:
        try:
            if p.is_file() and p.stat().st_size <= 2_000_000:
                linhas = p.read_text(encoding="utf-8", errors="replace").splitlines()
                if 1 <= line <= len(linhas):
                    linha = linhas[line - 1].strip()[:200]
                    # Linha com cara de credencial não sai do repositório, nem no prompt.
                    return None if _tem_valor_sensivel(linha) else linha
                return None
        except OSError:
            return None
    return None


def prompt_correcao(f: dict, trecho_codigo: str | None = None) -> str:
    """Texto para colar num assistente de código. Sem valor sensível, nunca."""
    local = mascarar(f"{f['path']}:{f['line']}" if f.get("line") else f.get("path", ""))
    cwe = ", ".join(f.get("cwe") or []) or "não informado"
    linhas = [f"Corrija o achado `{_curta(f['rule'])}` em `{local}` "
              f"(severidade {f.get('severity', '?')}; CWE: {cwe}).", ""]
    if e_sensivel(f):
        linhas += [
            "O achado envolve um valor sensível. O valor NÃO aparece neste texto, de propósito.",
            "Remova-o do código e do histórico do repositório, troque a credencial ou o dado "
            "no provedor e use variável de ambiente ou o cofre de segredos do projeto.",
        ]
        return "\n".join(linhas)
    if f.get("message"):
        linhas += ["Descrição da regra:", mascarar(f["message"]), ""]
    if trecho_codigo:
        linhas += ["Linha afetada:", "```", mascarar(trecho_codigo), "```", ""]
    linhas += ["Corrija a causa, sem mudar o comportamento esperado do código.",
               "Acrescente um teste que falha antes da correção e passa depois."]
    return "\n".join(linhas)


def categoria_owasp(f: dict) -> str | None:
    # Dependência com CVE conhecida é A06 pela origem, qualquer que seja o CWE
    # da falha dentro dela (uma XSS numa lib não é A03 do projeto). Vem antes do
    # CWE de propósito; e o rule id do OSV (GHSA-/PYSEC-) não tem prefixo.
    if f.get("osv_id") or str(f.get("context", "")).startswith("SCA"):
        return "A06"
    for cwe in f.get("cwe") or []:
        if cwe in CWE_OWASP:
            return CWE_OWASP[cwe]
    rule = f.get("rule", "")
    for prefixo, cat in PREFIXO_OWASP:
        if _RE_PREFIXO[prefixo].search(rule):
            return cat
    return None


def checklist(achados: list[dict]) -> dict:
    """Indícios por categoria OWASP e por item LGPD. Não é avaliação de conformidade."""
    owasp = {cod: {"titulo": titulo, "achados": 0, "regras": set()} for cod, titulo in OWASP.items()}
    lgpd = {"achados": 0, "regras": set()}
    for f in achados:
        cat = categoria_owasp(f)
        if cat:
            owasp[cat]["achados"] += 1
            owasp[cat]["regras"].add(_curta(f["rule"]))
        if _RE_LGPD.search(f.get("rule", "")):
            lgpd["achados"] += 1
            lgpd["regras"].add(_curta(f["rule"]))
    for item in owasp.values():
        item["regras"] = sorted(item["regras"])
    lgpd["regras"] = sorted(lgpd["regras"])
    return {"owasp": owasp, "lgpd": lgpd}


def logo_data_uri(caminho: Path) -> str:
    """Logo embutida como data: URI. Levanta ValueError se o arquivo não servir."""
    ext = caminho.suffix.lower()
    if ext not in LOGO_MIME:
        raise ValueError(f"logo: formato não aceito ({ext or 'sem extensão'}). Use PNG, JPG, WEBP ou SVG.")
    if not caminho.is_file():
        raise ValueError(f"logo não encontrada: {caminho}")
    if caminho.stat().st_size > LOGO_MAX_BYTES:
        raise ValueError("logo maior que 2 MB.")
    dados = base64.b64encode(caminho.read_bytes()).decode("ascii")
    return f"data:{LOGO_MIME[ext]};base64,{dados}"


def _e(valor) -> str:
    return html.escape(str(valor), quote=True)


def _prompts(reais: list[dict], raiz: Path) -> dict[int, str]:
    """Prompt por índice do achado. Lê cada arquivo uma vez."""
    cache: dict[str, str | None] = {}
    saida = {}
    for i, f in enumerate(reais):
        cod = None
        if not e_sensivel(f) and f.get("line"):
            chave = f"{f['path']}:{f['line']}"
            if chave not in cache:
                cache[chave] = trecho(raiz, f["path"], f["line"])
            cod = cache[chave]
        saida[i] = prompt_correcao(f, cod)
    return saida


def bloco_executivo_md(reais: list[dict], nota: int, res: dict, raiz: Path) -> str:
    """Seção executiva para o Markdown (vai depois da tabela de achados)."""
    linhas = [
        "## Resumo executivo",
        "",
        f"- **Nota de segurança:** {nota}/100 (cálculo em `relatorio.calcular_nota`; cada linha "
        "afetada desconta pela severidade mais alta: 25 (crítico), 10 (alto), 3 (médio) ou 0,5 (baixo/info)).",
        f"- **Achados que exigem atenção:** {res['total']}",
        "",
        "### Principais",
    ]
    if not res["principais"]:
        linhas.append("Nenhum achado que exija atenção.")
    for f in res["principais"]:
        linhas.append(f"- **{f['severity']}** `{_curta(f['rule'])}` em `{f['path']}:{f['line']}`")
    linhas += ["", "### Checklist de indícios", "",
               "Indícios encontrados nesta varredura, não avaliação de conformidade.", "",
               "| Categoria OWASP Top 10 (2021) | Achados | Regras |", "|---|---|---|"]
    ck = checklist(reais)
    for cod, item in ck["owasp"].items():
        linhas.append(f"| {cod} {item['titulo']} | {item['achados']} | "
                      f"{', '.join(item['regras']) or '—'} |")
    linhas += ["", f"**LGPD (dado pessoal):** {ck['lgpd']['achados']} indício(s)"
               + (f" — {', '.join(ck['lgpd']['regras'])}" if ck["lgpd"]["regras"] else "."), "",
               "### Prompts de correção", ""]
    prompts = _prompts(reais, raiz)
    for i, f in enumerate(reais):
        linhas += [f"#### {i + 1}. `{_curta(f['rule'])}` ({f['severity']})", "", "```text",
                   prompts[i], "```", ""]
    return "\n".join(linhas)


_CSS = """
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#1b1f24;background:#f6f7f9}
header{background:#fff;border-bottom:1px solid #d7dce2;padding:18px 28px;display:flex;gap:18px;align-items:center}
header img{max-height:56px}
main{max-width:1100px;margin:0 auto;padding:22px}
h1{font-size:22px;margin:0}h2{font-size:18px;margin-top:30px}h3{font-size:15px}
.cartao{background:#fff;border:1px solid #d7dce2;border-radius:10px;padding:16px 20px;margin-top:14px}
.nota{font-size:48px;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e6e9ee;vertical-align:top}
pre{background:#0f1216;color:#e6e9ee;padding:12px;border-radius:8px;white-space:pre-wrap;word-break:break-word;font-size:13px}
.sev-CRITICAL{color:#8b1e1e;font-weight:700}.sev-HIGH,.sev-ERROR{color:#b3261e}.sev-WARNING,.sev-MEDIUM{color:#8a5a00}
.aviso{color:#5b6470;font-size:13px}
"""


def html_relatorio(reais: list[dict], res: dict, nota: int, raiz: Path, alvo: str,
                   logo: str | None = None) -> str:
    """Relatório HTML autocontido. Todo texto que vem de fora passa por html.escape."""
    ck = checklist(reais)
    prompts = _prompts(reais, raiz)
    cabeca_logo = f'<img src="{_e(logo)}" alt="">' if logo else ""
    partes = [
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta name=\"robots\" content=\"noindex\">",
        "<title>Relatório de segurança</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<header>{cabeca_logo}<div><h1>Relatório de segurança</h1>"
        f"<div class=\"aviso\">Alvo: {_e(alvo)} · gerado em "
        f"{datetime.now().strftime('%d/%m/%Y %H:%M')}</div></div></header><main>",
        f"<div class=\"cartao\"><div class=\"nota\">{nota}/100</div>"
        f"<div>Achados que exigem atenção: <b>{res['total']}</b></div>",
        "<div class=\"aviso\">Nota: parte de 100; cada linha afetada desconta pela severidade mais alta "
        "(crítico 25, alto 10, médio 3, baixo/info 0,5). Arredondada para baixo.</div></div>",
        "<h2>Por severidade</h2><div class=\"cartao\"><table><tr><th>Severidade</th><th>Achados</th></tr>",
    ]
    for sev in ORDEM_SEV:
        if res["por_sev"].get(sev):
            partes.append(f"<tr><td class=\"sev-{_e(sev)}\">{_e(sev)}</td><td>{res['por_sev'][sev]}</td></tr>")
    partes += ["</table></div>", "<h2>Principais</h2><div class=\"cartao\">"]
    if not res["principais"]:
        partes.append("<p>Nenhum achado que exija atenção.</p>")
    for f in res["principais"]:
        partes.append(f"<p><span class=\"sev-{_e(f['severity'])}\">{_e(f['severity'])}</span> "
                      f"<code>{_e(_curta(f['rule']))}</code> em <code>{_e(f['path'])}:{_e(f['line'])}</code></p>")
    partes += ["</div>", "<h2>Checklist de indícios</h2><div class=\"cartao\">",
               "<p class=\"aviso\">Indícios encontrados nesta varredura, não avaliação de conformidade.</p>",
               "<table><tr><th>Categoria OWASP Top 10 (2021)</th><th>Achados</th><th>Regras</th></tr>"]
    for cod, item in ck["owasp"].items():
        partes.append(f"<tr><td>{_e(cod)} {_e(item['titulo'])}</td><td>{item['achados']}</td>"
                      f"<td>{_e(', '.join(item['regras']) or '—')}</td></tr>")
    partes.append("</table>")
    partes.append(f"<p><b>LGPD (dado pessoal):</b> {ck['lgpd']['achados']} indício(s)"
                  + (f" — {_e(', '.join(ck['lgpd']['regras']))}" if ck["lgpd"]["regras"] else "") + "</p></div>")
    partes.append("<h2>Achados e prompts de correção</h2>")
    for i, f in enumerate(reais):
        partes.append(
            f"<div class=\"cartao\"><h3><span class=\"sev-{_e(f['severity'])}\">{_e(f['severity'])}</span> "
            f"{_e(_curta(f['rule']))}</h3>"
            f"<p><code>{_e(f['path'])}:{_e(f['line'])}</code>"
            + (f" · CWE: {_e(', '.join(f['cwe']))}" if f.get("cwe") else "") + "</p>")
        if not e_sensivel(f) and f.get("message"):
            partes.append(f"<p>{_e(f['message'])}</p>")
        partes.append(f"<pre>{_e(prompts[i])}</pre></div>")
    partes.append("<p class=\"aviso\">Gerado por análise estática, somente leitura. "
                  "Revise cada achado antes de agir: a ferramenta aponta indícios, não prova.</p>")
    partes.append("</main></body></html>")
    return "".join(partes)
