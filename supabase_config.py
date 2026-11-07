"""Lista de redirecionamento do Supabase Auth larga demais (`supabase/config.toml`).

O link mágico e o retorno do OAuth levam o token na URL de destino. Se a lista
de destinos permitidos aceita `https://*.netlify.app/**`, qualquer pessoa sobe
um site grátis na Netlify e passa a receber o token de quem clicar no link
(o PayloadsAllTheThings, na página de OAuth: "nunca libere domínios inteiros").

O `config.toml` é a configuração do ambiente LOCAL; a de produção fica no
painel (Authentication → URL Configuration). Por isso o achado é indício: ele
mostra o hábito, e o painel precisa ser conferido.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

# Plataformas onde qualquer um cria subdomínio de graça.
_COMPARTILHADOS = ("netlify.app", "vercel.app", "pages.dev", "github.io", "onrender.com",
                   "herokuapp.com", "web.app", "firebaseapp.com", "surge.sh", "workers.dev",
                   "fly.dev", "railway.app", "glitch.me", "ngrok.io", "ngrok-free.app")
_LOCAL = re.compile(r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(/|$)", re.I)


def _problema(url: str) -> tuple[str, str, str] | None:
    u = url.strip()
    host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/", 1)[0].lower()
    if host in ("*", "**", "") or u in ("*", "**"):
        return ("supabase.auth-redirect-qualquer-destino", "HIGH",
                f"`{u}` aceita QUALQUER destino: o token do link mágico/OAuth pode ser "
                f"mandado para um site do atacante.")
    if "*" in host:
        base = host.split("*", 1)[1].lstrip(".-")
        if any(base == d or base.endswith("." + d) for d in _COMPARTILHADOS):
            return ("supabase.auth-redirect-dominio-compartilhado", "HIGH",
                    f"`{u}` libera todos os subdomínios de {base}, onde qualquer um cria um "
                    f"site de graça e passa a receber o token de login. Liste o endereço "
                    f"exato do seu site (e dos previews, um a um, se precisar).")
        return ("supabase.auth-redirect-curinga", "MEDIUM",
                f"`{u}` libera um curinga de subdomínio. Só é seguro se todo subdomínio "
                f"de {base} for seu e nenhum aceitar conteúdo de terceiros.")
    if u.lower().startswith("http://") and not _LOCAL.match(u):
        return ("supabase.auth-redirect-http", "MEDIUM",
                f"`{u}` é HTTP: o token viaja em texto aberto até o destino.")
    return None


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    achados = []
    for alvo in alvos:
        raiz = alvo if alvo.is_dir() else alvo.parent
        for arq in sorted(raiz.rglob("config.toml")):
            if arq.parent.name != "supabase" or any(x in skip_dirs for x in arq.parts):
                continue
            try:
                texto = arq.read_text(encoding="utf-8")
                auth = tomllib.loads(texto).get("auth") or {}
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                continue
            urls = [auth.get("site_url") or ""] + list(auth.get("additional_redirect_urls") or [])
            try:
                rel = str(arq.relative_to(Path.cwd())).replace("\\", "/")
            except ValueError:
                rel = str(arq).replace("\\", "/")
            linhas = texto.splitlines()
            for u in urls:
                if not isinstance(u, str) or not u:
                    continue
                p = _problema(u)
                if not p:
                    continue
                regra, sev, msg = p
                linha = next((i + 1 for i, l in enumerate(linhas) if u in l), 1)
                achados.append({
                    "rule": regra, "severity": sev, "path": rel, "line": linha, "context": "",
                    "cwe": ["CWE-601"],
                    "message": msg + " Este arquivo vale para o ambiente local; confira a "
                               "mesma lista no painel (Authentication → URL Configuration), "
                               "que é a de produção."})
    return achados
