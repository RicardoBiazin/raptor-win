"""v1.23: relatório honesto, metas de verificação, dump de banco, Firebase, MCP,
cookies e estado SSR. Sem rede: respostas HTTP dubladas; Semgrep de verdade só
para as regras YAML."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import binarios  # noqa: E402
import bundle_scan  # noqa: E402
import raptor_win  # noqa: E402
import relatorio  # noqa: E402
import supply_chain  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
PAG = "https://site.exemplo.com.br/"
CSP_OK = {"content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
          "strict-transport-security": "max-age=31536000; includeSubDomains"}


def achado(rule, sev="HIGH", path="a.ts", line=3, msg="m"):
    return {"rule": rule, "severity": sev, "path": path, "line": line, "message": msg,
            "context": "", "cwe": []}


def varrer(rotas: dict, html: str = '<script src="/assets/index.js"></script>', cab=None):
    def falso(url, headers=None):
        if url == PAG:
            return bundle_scan.Resp(200, dict(cab if cab is not None else CSP_OK), html.encode(), url)
        if url in rotas:
            st, h, corpo = rotas[url]
            return bundle_scan.Resp(st, h, corpo.encode() if isinstance(corpo, str) else corpo, url)
        return bundle_scan.Resp(404, {}, b"not found", url)
    with mock.patch.object(bundle_scan.exploracao, "anotar", lambda *a, **k: {}):
        return bundle_scan.escanear_urls([PAG], buscar_fn=falso)


def regras(achados):
    return {a["rule"] for a in achados}


class RelatorioHonestoTests(unittest.TestCase):
    def test_categoria_sem_alcance_nao_diz_apenas_zero(self):
        md = relatorio.bloco_executivo_md([], 100, relatorio.resumo([], 100), Path("."))
        self.assertIn("| A01 Controle de acesso quebrado | 0 (não prova ausência) |", md)
        self.assertIn("| A06 Componentes vulneráveis ou desatualizados | 0 |", md)
        self.assertIn("### Não verificável por análise estática", md)
        self.assertIn("rate limit", md)
        self.assertIn("| A01 | Com o usuário A, peça o ID", md)

    def test_html_tem_a_mesma_secao(self):
        html = relatorio.html_relatorio([], relatorio.resumo([], 100), 100, Path("."), "alvo")
        self.assertIn("Não verificável por análise estática", html)
        self.assertIn("(não prova ausência)", html)
        self.assertIn("Teste à mão", html)

    def test_categoria_com_achado_mostra_so_o_numero(self):
        f = dict(achado("db.anon", "HIGH"), cwe=["CWE-284"])
        ck = relatorio.checklist([f])
        self.assertEqual(ck["owasp"]["A01"]["achados"], 1)
        self.assertEqual(ck["owasp"]["A01"]["limite"], relatorio.NAO_VERIFICAVEL["A01"])
        md = relatorio.bloco_executivo_md([f], 90, relatorio.resumo([f], 90), Path("."))
        self.assertIn("| A01 Controle de acesso quebrado | 1 |", md)


class MetaDeVerificacaoTests(unittest.TestCase):
    def test_cada_familia_tem_sua_meta(self):
        casos = {
            "bundle.anon-le-tabela": "chave pública",
            "raptorwin.supabase.rls-anon-select": "chave pública",
            "raptorwin.cors.reflete-origin": "Access-Control-Allow-Origin",
            "headers.csp-curinga": "curl -sI",
            "GHSA-2gwj-7jmv-h26r": "--sca",
            "bundle.sourcemap-expoe-codigo": ".js.map",
            "raptorwin.erro.erro-de-banco-para-o-cliente": "mensagem genérica",
            "supply.binario-versionado": "git ls-files",
        }
        for rule, trecho in casos.items():
            meta = relatorio.meta_verificacao(achado(rule))
            self.assertTrue(meta and trecho in meta, (rule, meta))

    def test_prompt_traz_a_meta_e_segredo_continua_sem_valor(self):
        texto = relatorio.prompt_correcao(achado("bundle.anon-le-tabela", msg="tabela legível"))
        self.assertIn("Meta de verificação", texto)
        self.assertIn("Acrescente um teste", texto)
        seg = relatorio.prompt_correcao(achado("secrets.chave-aws", msg="AKIA" + "X" * 16))
        self.assertIn("REVOGADA", seg)
        self.assertNotIn("AKIAXXXX", seg)

    def test_regra_desconhecida_fica_sem_meta(self):
        self.assertIsNone(relatorio.meta_verificacao(achado("regra-solta")))
        self.assertNotIn("Meta de verificação", relatorio.prompt_correcao(achado("regra-solta")))


class DumpDeBancoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.d)], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _add(self, nome, dados: bytes):
        p = self.d / nome
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(dados)
        subprocess.run(["git", "-C", str(self.d), "add", nome], check=True)

    def test_dump_com_dados_e_acusado_so_esquema_e_seed_nao(self):
        cab = b"--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n"
        self._add("backup/producao.sql", cab + b"CREATE TABLE clientes (id int);\n"
                  b"COPY public.clientes (id) FROM stdin;\n1\n\\.\n")
        self._add("supabase/migrations/0001_baseline.sql",
                  cab + b"CREATE TABLE clientes (id int);\nALTER TABLE ONLY clientes ADD PRIMARY KEY (id);\n")
        self._add("supabase/seed.sql", b"INSERT INTO clientes (id) VALUES (1);\n")
        self._add("mysql.sql", b"-- MySQL dump 10.13\nCREATE TABLE a (x int);\nINSERT INTO a VALUES (1);\n")
        self._add("custom.dump", b"PGDMP\x01\x0e\x00" + b"\0" * 50)
        achados = binarios.escanear([self.d], set())
        por = {Path(a["path"]).name: a for a in achados if a["rule"] == "secrets.dump-de-banco-versionado"}
        self.assertEqual(set(por), {"producao.sql", "mysql.sql", "custom.dump"})
        self.assertEqual(por["producao.sql"]["severity"], "HIGH")
        self.assertIn("LGPD", por["producao.sql"]["message"])

    def test_vai_para_o_indicio_lgpd(self):
        self.assertTrue(relatorio._RE_LGPD.search("secrets.dump-de-banco-versionado"))


class SondasNovasTests(unittest.TestCase):
    def test_dump_env_bak_e_htpasswd_pelo_conteudo(self):
        base = "https://site.exemplo.com.br/"
        dump = "-- PostgreSQL database dump\nCREATE TABLE a (x int);\n"
        achados = varrer({
            base + "backup.sql": (200, {}, dump),
            base + ".env.bak": (200, {}, "SUPABASE_URL=https://x.supabase.co\nAPI_KEY=abc123\n"),
            base + ".htpasswd": (200, {}, "admin:$apr1$abcd$xxxxxxxxxxxxxxxxxxxxxx\n"),
        }, html="<html></html>")
        self.assertTrue({"bundle.exposto-backup.sql", "bundle.exposto-env.bak",
                         "bundle.exposto-htpasswd"} <= regras(achados))

    def test_spa_devolvendo_html_nao_acusa(self):
        shell = "<!doctype html><html><body>CREATE TABLE INSERT INTO</body></html>"
        base = "https://site.exemplo.com.br/"
        achados = varrer({base + p: (200, {}, shell)
                          for p in ("backup.sql", "dump.sql", ".env.bak", ".htpasswd")},
                         html="<html></html>")
        self.assertFalse([r for r in regras(achados) if r.startswith("bundle.exposto-")])


class FirebaseUrlTests(unittest.TestCase):
    JS = 'const cfg={apiKey:"x",databaseURL:"https://meu-app-default-rtdb.firebaseio.com"};'
    JSON_URL = "https://meu-app-default-rtdb.firebaseio.com/.json?shallow=true"
    BASE = "https://site.exemplo.com.br/assets/index.js"

    def _rodar(self, resposta):
        pedidos = []

        def falso(url, headers=None):
            pedidos.append(url)
            if url == PAG:
                return bundle_scan.Resp(200, dict(CSP_OK), b'<script src="/assets/index.js"></script>', url)
            if url == self.BASE:
                return bundle_scan.Resp(200, {}, self.JS.encode(), url)
            if url == self.JSON_URL:
                return resposta(url)
            return bundle_scan.Resp(404, {}, b"", url)
        with mock.patch.object(bundle_scan.exploracao, "anotar", lambda *a, **k: {}):
            return bundle_scan.escanear_urls([PAG], buscar_fn=falso), pedidos

    def test_banco_aberto_e_confirmado_sem_ler_valores(self):
        achados, pedidos = self._rodar(
            lambda u: bundle_scan.Resp(200, {}, b'{"clientes": true, "pedidos": true}', u))
        a = [x for x in achados if x["rule"] == "bundle.firebase-leitura-anonima"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["evidencia"], "confirmado")
        self.assertIn("2 nó(s)", a[0]["message"])
        self.assertIn(self.JSON_URL, pedidos)
        self.assertFalse([p for p in pedidos if "firebaseio" in p and "shallow=true" not in p])

    def test_permissao_negada_e_banco_vazio_nao_acusam(self):
        for resp in (lambda u: bundle_scan.Resp(401, {}, b'{"error":"Permission denied"}', u),
                     lambda u: bundle_scan.Resp(200, {}, b"null", u)):
            achados, _ = self._rodar(resp)
            self.assertNotIn("bundle.firebase-leitura-anonima", regras(achados))


class CookiesESsrTests(unittest.TestCase):
    def test_cookie_sem_atributos(self):
        achados = varrer({}, html="<html></html>",
                         cab=dict(CSP_OK, **{"set-cookie": "sessao=abc123; Path=/"}))
        a = [x for x in achados if x["rule"] == "bundle.cookie-sem-atributo"]
        self.assertEqual(len(a), 1)
        self.assertIn("Secure, HttpOnly, SameSite", a[0]["message"])

    def test_cookie_ok_e_cookie_do_supabase_nao_acusam(self):
        ok = "sessao=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        supa = "sb-abcdefghijklmnopqrst-auth-token=base64; Path=/; Secure; SameSite=Lax"
        for c in (ok, supa):
            achados = varrer({}, html="<html></html>", cab=dict(CSP_OK, **{"set-cookie": c}))
            self.assertNotIn("bundle.cookie-sem-atributo", regras(achados), c)

    def test_estado_ssr_com_campo_sensivel(self):
        html = ('<html><script id="__NEXT_DATA__" type="application/json">'
                '{"props":{"user":{"email":"a@b.c","password_hash":"x"}}}</script></html>')
        achados = varrer({}, html=html)
        self.assertIn("bundle.estado-ssr-campo-sensivel", regras(achados))

    def test_estado_ssr_limpo_nao_acusa(self):
        html = ('<html><script id="__NEXT_DATA__" type="application/json">'
                '{"props":{"titulo":"Olá"}}</script></html>')
        self.assertNotIn("bundle.estado-ssr-campo-sensivel", regras(varrer({}, html=html)))


class McpTests(unittest.TestCase):
    def _escanear(self, nome_arquivo, conteudo, pasta=None):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / pasta if pasta else Path(d)
            base.mkdir(parents=True, exist_ok=True)
            (base / nome_arquivo).write_text(json.dumps(conteudo), encoding="utf-8")
            return supply_chain.escanear([Path(d)], set())

    def test_npx_sem_versao_e_http_sao_acusados(self):
        achados = self._escanear(".mcp.json", {"mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
            "fixo": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory@1.2.3"]},
            "ultimo": {"command": "npx", "args": ["-y", "chrome-devtools-mcp@latest"]},
            "remoto": {"url": "http://mcp.exemplo.com/sse"},
            "local": {"url": "http://localhost:8080/sse"},
            "py": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
        sem = [a for a in achados if a["rule"] == "supply.mcp-sem-versao-fixa"]
        self.assertEqual(len(sem), 3)
        self.assertEqual([a["rule"] for a in achados if a["rule"] == "supply.mcp-http"], ["supply.mcp-http"])
        self.assertFalse([a for a in sem if "server-memory" in a["message"]])

    def test_so_nos_arquivos_de_mcp(self):
        achados = self._escanear("mcp.json", {"servers": {"x": {"command": "npx", "args": ["pkg"]}}},
                                 pasta=".cursor")
        self.assertTrue(achados)
        self.assertFalse(self._escanear("outro.json", {"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}}))

    def test_typosquat_no_pacote_do_mcp(self):
        achados = self._escanear(".mcp.json", {"mcpServers": {
            "x": {"command": "npx", "args": ["-y", "expres@4.18.2"]}}})
        self.assertIn("typosquat", regras(achados))


class RegrasYamlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.semgrep = raptor_win.find_semgrep()
        if not cls.semgrep:
            raise unittest.SkipTest("semgrep não encontrado")

    def _rodar(self, pasta_regra: str, arquivos: dict) -> set:
        d = Path(tempfile.mkdtemp())
        for nome, conteudo in arquivos.items():
            (d / nome).parent.mkdir(parents=True, exist_ok=True)
            (d / nome).write_text(conteudo, encoding="utf-8")
        env = os.environ.copy()
        env["PATH"] = str(Path(self.semgrep).parent) + os.pathsep + env.get("PATH", "")
        out = subprocess.run(
            [self.semgrep, "--config", str(RAIZ / "rules" / "raptorwin" / pasta_regra), "--json",
             "--metrics=off", "--quiet", str(d)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=180)
        dados = json.loads(out.stdout)
        self.assertEqual(dados.get("errors"), [], "regra não compila")
        return {(r["check_id"].rsplit(".", 1)[-1], Path(r["path"]).name) for r in dados["results"]}

    def test_stripe_webhook_sem_assinatura(self):
        achados = self._rodar("pagamento", {
            "a/index.ts": 'const ev = await req.json();\nif (ev.type === "checkout.session.completed") liberar(ev);\n',
            "b/index.ts": ('const ev = await stripe.webhooks.constructEventAsync(await req.text(), sig, s);\n'
                           'if (ev.type === "checkout.session.completed") liberar(ev);\n'),
            "c/views.py": 'ev = json.loads(request.body)\nif ev["type"] == "invoice.paid":\n    liberar(ev)\n',
            "d/outro.ts": 'const x = 1;\n'})
        nomes = {(r, a) for r, a in achados}
        self.assertEqual(nomes, {("stripe-webhook-sem-assinatura", "index.ts"),
                                 ("stripe-webhook-sem-assinatura", "views.py")})
        self.assertEqual(len(achados), 2)

    def test_regras_do_firebase(self):
        achados = self._rodar("firebase", {
            "firestore.rules": ('service cloud.firestore { match /databases/{d}/documents {\n'
                                '  match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 12, 1); }\n'
                                '  match /p/{i} { allow read: if true; allow write: if true; }\n'
                                '  match /{document=**} { allow read, write: if request.auth != null; }\n}}\n'),
            "database.rules.json": '{"rules": {".read": true}}',
            "storage.rules": 'service firebase.storage { match /b/{b}/o { match /{allPaths=**} { allow read, write: if request.auth.uid == "x"; } } }\n'})
        regras_ = {r for r, _ in achados}
        self.assertEqual(regras_, {"escrita-aberta", "leitura-aberta", "modo-de-teste",
                                   "qualquer-logado-le-tudo", "realtime-db-aberto"})
        self.assertNotIn(("escrita-aberta", "storage.rules"), achados)


if __name__ == "__main__":
    unittest.main()
