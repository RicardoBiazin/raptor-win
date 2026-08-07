"""
Varredura de credenciais — a terceira perna do raptor-win.

O SAST acha padrões perigosos no código; o SCA acha dependências com CVE.
Nenhum dos dois acha uma **senha escrita no repositório**, que é o
acidente mais comum e o de reversão mais cara: uma vez comitado, o
segredo fica no histórico para sempre, e a única correção de verdade é
rotacionar a credencial.

DUAS COISAS SÃO PROCURADAS, e a segunda é a que quase ninguém faz:

  1. Padrões de credencial no conteúdo dos arquivos.

  2. ARQUIVOS QUE GUARDAM SEGREDO E NÃO ESTÃO IGNORADOS PELO GIT.
     Um `.env` fora do `.gitignore` ainda não vazou — mas vai vazar no
     próximo `git add -A`, e aí é tarde. Esta verificação é determinística
     (pergunta ao próprio git), então não gera falso-positivo, e pega o
     caso antes de virar incidente.

Sobre precisão: a alternativa preguiçosa é medir entropia e acusar toda
cadeia aleatória. Isso enche o relatório de ruído — hash de lockfile,
id de build, chave pública — e um relatório ruidoso é um relatório que
ninguém lê. Aqui são padrões nomeados, com prefixo conhecido, mais uma
regra estreita para atribuição de literal longo a variável de nome
sugestivo.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

# Extensões que nunca contêm segredo escrito à mão e enchem o relatório.
BIN_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".ogg", ".m4a", ".wav",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".map",
}

# Arquivos gerados: um "segredo" aqui é hash de integridade, não credencial.
GERADOS_RE = re.compile(
    r"(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|"
    r"Pipfile\.lock|Cargo\.lock|composer\.lock|.*\.min\.(js|css))$", re.I)

# Arquivos cujo NOME anuncia que guardam credencial.
SEGREDO_NO_NOME_RE = re.compile(
    r"(^|[\\/])(\.env(\..+)?|.*\.pem|.*\.key|.*\.pfx|.*\.p12|"
    r"id_rsa|id_ed25519|.*\.keystore|credentials(\.json)?|"
    r"service[-_]?account.*\.json)$", re.I)

# Exemplos e modelos são feitos para ser versionados.
MODELO_RE = re.compile(r"(\.example$|\.sample$|\.template$|\.dist$)", re.I)

# Arquivo de ambiente, qualquer sufixo: .env, .env.demo, .env.local, .env.ci…
ENV_RE = re.compile(r"(^|[\\/])\.env(\..+)?$", re.I)

# Valores que parecem credencial mas são espaço reservado.
PLACEHOLDER_RE = re.compile(
    r"^(x{3,}|\.{3,}|senha|sua[-_]?senha|your[-_].*|my[-_].*|change[-_]?me|"
    r"placeholder|example|exemplo|dummy|test|teste|foo|bar|todo|tbd|"
    r"<.*>|\[.*\]|\{\{.*\}\}|\$\{.*\}|%.*%|null|none|undefined)$", re.I)


class Regra:
    def __init__(self, id_: str, sev: str, desc: str, padrao: str, grupo: int = 0):
        self.id, self.sev, self.desc = id_, sev, desc
        self.re = re.compile(padrao)
        self.grupo = grupo


# Prefixos publicados pelos próprios provedores. Precisão alta porque o
# formato é deles, não uma heurística nossa.
REGRAS = [
    Regra("chave-privada", "CRITICAL",
          "Chave privada (PEM) escrita no repositório",
          r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    Regra("aws-access-key", "CRITICAL",
          "Chave de acesso da AWS",
          r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    Regra("github-token", "CRITICAL",
          "Token do GitHub",
          r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"),
    Regra("supabase-secret", "CRITICAL",
          "Chave SECRETA do Supabase (service_role)",
          r"\bsb_secret_[A-Za-z0-9_\-]{15,}"),
    Regra("openai-key", "CRITICAL", "Chave da OpenAI", r"\bsk-[A-Za-z0-9]{32,}"),
    Regra("groq-key", "CRITICAL", "Chave da Groq", r"\bgsk_[A-Za-z0-9]{40,}"),
    Regra("nvidia-key", "CRITICAL", "Chave da NVIDIA", r"\bnvapi-[A-Za-z0-9_\-]{40,}"),
    Regra("slack-token", "CRITICAL", "Token do Slack", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
    Regra("google-api-key", "HIGH", "Chave de API do Google", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    Regra("stripe-key", "CRITICAL", "Chave secreta do Stripe", r"\b(sk|rk)_live_[A-Za-z0-9]{20,}"),

    # Senha DENTRO de string de conexão. O grupo 1 evita reportar a URL
    # inteira no console — o host não é segredo, a senha é.
    Regra("conexao-com-senha", "CRITICAL",
          "String de conexão com senha embutida",
          r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
          r"[^:/\s]+:([^@/\s]{4,})@", 1),

    # JWT. Chave `anon` do Supabase também casa aqui — e é PÚBLICA por
    # projeto, daí MEDIUM: vale olhar, não vale acordar ninguém.
    Regra("jwt", "MEDIUM",
          "JWT no código (confira se não é uma chave de serviço)",
          r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]

# Atribuição de literal longo a variável de nome sugestivo. É a regra que
# pega o segredo de um provedor que ninguém previu — e a que mais precisa
# de freio, por isso exige nome sugestivo E valor longo E não-placeholder.
ATRIBUICAO_RE = re.compile(
    r"""(?ix)
    \b(
        (?:api|secret|private|auth|access|refresh|session|encryption|signing)
        [_\-]?(?:key|token|secret)
      | password | passwd | senha | client[_\-]?secret
      | token | secret | credential
    )
    \s* [:=] \s* ['"]([^'"\s]{16,})['"]
    """)


def _linha_de(texto: str, pos: int) -> int:
    return texto.count("\n", 0, pos) + 1


def _ler(arquivo: Path) -> str | None:
    try:
        return arquivo.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return None


def _env_tem_credencial(texto: str) -> bool:
    """Algum valor deste arquivo de ambiente parece credencial?

    Existe para calibrar a severidade do aviso de `.env` versionado, sem
    desligá-lo. A convenção de nome de modelo não é uma só: além de
    `.env.example`, projetos usam `.env.demo`, `.env.local`, `.env.ci` — e
    julgar pelo nome erra nos dois sentidos, deixando passar um `.env.prod`
    cheio de chave real e acusando um `.env.demo` que só tem `MARCA=PDV Demo`.

    O aviso preventivo continua, porque a razão dele é o FUTURO ("vai vazar no
    próximo `git add -A`"). Mas um arquivo que hoje não tem segredo nenhum não
    pode competir em severidade com uma chave de verdade exposta.
    """
    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        valor = linha.split("=", 1)[1].strip().strip("\"'")
        if not valor or PLACEHOLDER_RE.match(valor):
            continue
        if any(r.re.search(valor) for r in REGRAS):
            return True
        # Sem prefixo conhecido: entropia é o que separa credencial de
        # configuração. "PDV Demo", "logo-pdv.svg", "1" não são segredo;
        # cadeia longa misturando maiúscula e dígito, provavelmente sim.
        if len(valor) >= 20 and any(c.isdigit() for c in valor) \
                and any(c.isupper() for c in valor) and " " not in valor:
            return True
    return False


def _ignorado_pelo_git(raiz: Path, arquivo: Path) -> bool | None:
    """O git ignora este arquivo? None quando não há git para perguntar."""
    try:
        p = subprocess.run(
            ["git", "-C", str(raiz), "check-ignore", "-q", str(arquivo)],
            capture_output=True, timeout=10)
        return p.returncode == 0
    except Exception:
        return None


def _e_repo_git(raiz: Path) -> bool:
    try:
        p = subprocess.run(["git", "-C", str(raiz), "rev-parse", "--git-dir"],
                           capture_output=True, timeout=10)
        return p.returncode == 0
    except Exception:
        return False


def _arquivos(alvos: list[Path], skip_dirs: set[str]) -> list[Path]:
    out: list[Path] = []
    for alvo in alvos:
        if alvo.is_file():
            out.append(alvo)
            continue
        for p in alvo.rglob("*"):
            if not p.is_file():
                continue
            if any(parte in skip_dirs for parte in p.parts):
                continue
            if p.suffix.lower() in BIN_EXT:
                continue
            try:
                if p.stat().st_size > 2_000_000:   # 2 MB: não é arquivo escrito à mão
                    continue
            except OSError:
                continue
            out.append(p)
    return out


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    """Devolve achados no mesmo formato de `collect()`, para fluírem pelo
    console, Markdown, SARIF e --fail-on sem tratamento especial."""
    achados: list[dict] = []
    raiz = alvos[0] if alvos[0].is_dir() else alvos[0].parent
    tem_git = _e_repo_git(raiz)

    for arq in _arquivos(alvos, skip_dirs):
        try:
            rel = str(arq.relative_to(raiz))
        except ValueError:
            rel = str(arq)
        rel_norm = rel.replace("\\", "/")

        modelo = bool(MODELO_RE.search(rel_norm))

        # Arquivo de ambiente versionado, mas sem nenhum valor que pareça
        # credencial: o aviso continua (preventivo), com severidade honesta.
        # Ver _env_tem_credencial().
        env_sem_segredo = False
        if not modelo and ENV_RE.search(rel_norm):
            texto_env = _ler(arq)
            if texto_env is not None and not _env_tem_credencial(texto_env):
                env_sem_segredo = True

        # --- 1. arquivo de segredo desprotegido -------------------------
        if SEGREDO_NO_NOME_RE.search(rel_norm) and not modelo:
            if tem_git and _ignorado_pelo_git(raiz, arq) is False:
                achados.append({
                    "rule": "secrets.arquivo-nao-ignorado",
                    "severity": "INFO" if env_sem_segredo else "HIGH",
                    "path": rel_norm,
                    "line": 0,
                    "message": (
                        "Arquivo de ambiente versionado. Hoje não há credencial "
                        "nele, então não houve vazamento — mas se um segredo for "
                        "escrito aqui, entra no histórico no próximo commit. "
                        "Se é modelo, o nome `.env.example` deixa isso explícito."
                        if env_sem_segredo else
                        "Arquivo de credenciais NÃO está no .gitignore. Ainda não "
                        "vazou, mas vai no próximo `git add -A` — e o que entra no "
                        "histórico só se corrige rotacionando a credencial."),
                    "context": "sem credencial no conteúdo" if env_sem_segredo else "",
                })

        # Conteúdo de arquivo de segredo já ignorado não é achado: ele
        # existe para guardar credencial, e o git não vai levá-lo.
        if SEGREDO_NO_NOME_RE.search(rel_norm) and tem_git and \
                _ignorado_pelo_git(raiz, arq) is True:
            continue

        if GERADOS_RE.search(rel_norm):
            continue

        try:
            texto = arq.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue   # binário disfarçado ou ilegível

        # --- 2. padrões de credencial -----------------------------------
        vistos: set[tuple] = set()
        for regra in REGRAS:
            for m in regra.re.finditer(texto):
                valor = m.group(regra.grupo) if regra.grupo else m.group(0)
                if PLACEHOLDER_RE.match(valor.strip()):
                    continue
                linha = _linha_de(texto, m.start())
                chave = (regra.id, linha)
                if chave in vistos:
                    continue
                vistos.add(chave)
                achados.append({
                    "rule": f"secrets.{regra.id}",
                    "severity": "INFO" if modelo else regra.sev,
                    "path": rel_norm,
                    "line": linha,
                    "message": regra.desc + (" (arquivo de exemplo)" if modelo else ""),
                    "context": "arquivo de exemplo" if modelo else "",
                })

        for m in ATRIBUICAO_RE.finditer(texto):
            valor = m.group(2)
            if PLACEHOLDER_RE.match(valor.strip()):
                continue
            # Nome de variável, caminho ou URL não são credencial.
            if valor.startswith(("http://", "https://", "/", "./", "../")) or " " in valor:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", valor):
                continue
            # PALAVRAS EM MINÚSCULA NÃO SÃO CREDENCIAL. `service-role-key`,
            # `fake-api-key`, `my-test-token` — texto descritivo em teste.
            # Foi o único falso-positivo desta regra em dois repositórios
            # reais. Credencial de verdade tem entropia: mistura maiúscula
            # com dígito. Abaixo de 32 caracteres exijo os dois; acima
            # disso o comprimento já basta, porque hex longo é minúsculo e
            # é credencial de verdade.
            if len(valor) < 32 and not (any(c.isdigit() for c in valor)
                                        and any(c.isupper() for c in valor)):
                continue
            linha = _linha_de(texto, m.start())
            if any(a["line"] == linha and a["path"] == rel_norm for a in achados):
                continue   # já reportado por uma regra de prefixo, que é mais específica
            achados.append({
                "rule": "secrets.literal-suspeito",
                "severity": "INFO" if modelo else "HIGH",
                "path": rel_norm,
                "line": linha,
                "message": (f"Literal longo atribuído a `{m.group(1)}` — "
                            f"confira se não é uma credencial de verdade"
                            + (" (arquivo de exemplo)" if modelo else "")),
                "context": "arquivo de exemplo" if modelo else "",
            })

    achados.sort(key=lambda a: (a["path"], a["line"]))
    return achados
