"""Retire.js, cabeçalhos ao vivo, versão exposta, binários versionados e segredos novos.
Sem rede: as respostas HTTP são dubladas e o KEV/EPSS é desligado."""

import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import binarios  # noqa: E402
import bundle_scan  # noqa: E402
import retire  # noqa: E402
import secrets_scan  # noqa: E402

PAG = "https://site.exemplo.com.br/"
CSP_OK = {"content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
          "strict-transport-security": "max-age=31536000; includeSubDomains"}


def varrer(rotas: dict, html: str = '<script src="/assets/index.js"></script>', cab=None):
    def falso(url, headers=None):
        if url == PAG:
            return bundle_scan.Resp(200, cab if cab is not None else dict(CSP_OK), html.encode(), url)
        if url in rotas:
            st, h, corpo = rotas[url]
            return bundle_scan.Resp(st, h, corpo.encode() if isinstance(corpo, str) else corpo, url)
        return bundle_scan.Resp(404, {}, b"not found", url)
    with mock.patch.object(bundle_scan.exploracao, "anotar", lambda *a, **k: {}):
        return bundle_scan.escanear_urls([PAG], buscar_fn=falso)


def regras(achados):
    return {a["rule"] for a in achados}


class RetireTests(unittest.TestCase):
    def test_base_carrega(self):
        self.assertTrue(retire.disponivel())

    def test_comparar_versoes(self):
        self.assertEqual(retire.comparar("1.6.2", "1.6.3"), -1)
        self.assertEqual(retire.comparar("3.5.0", "3.4.99"), 1)
        self.assertEqual(retire.comparar("1.0.0-beta", "1.0.0"), -1)
        self.assertEqual(retire.comparar("2.0.0", "2.0.0"), 0)

    def test_jquery_antigo_pelo_banner(self):
        libs = retire.detectar("https://x/js/app.js", "/*! jQuery v1.8.3 jquery.com | jquery.org/license */")
        self.assertEqual(libs.get("jquery"), "1.8.3")
        self.assertTrue(retire.vulnerabilidades("jquery", "1.8.3"))
        self.assertFalse(retire.vulnerabilidades("jquery", "99.0.0"))

    def test_jquery_pela_url_de_cdn(self):
        libs = retire.detectar("https://code.jquery.com/jquery-1.11.0.min.js", "")
        self.assertEqual(libs.get("jquery"), "1.11.0")

    def test_backdoor_polyfill(self):
        self.assertTrue(retire.backdoor("https://cdn.polyfill.io/v3/polyfill.min.js"))
        self.assertIsNone(retire.backdoor("https://cdnjs.cloudflare.com/x.js"))

    def test_bundle_acusa_lib_vulneravel_servida(self):
        js = "/*! jQuery v1.8.3 jquery.com | jquery.org/license */ var a=1;"
        achados = varrer({"https://site.exemplo.com.br/assets/index.js": (200, {}, js)})
        lib = [a for a in achados if a["rule"] == "bundle.lib-vulneravel"]
        self.assertEqual(len(lib), 1)
        self.assertEqual(lib[0]["evidencia"], "confirmado")
        self.assertIn("jquery 1.8.3", lib[0]["message"])
        self.assertIn("CVE-", lib[0]["message"])

    def test_bundle_acusa_script_de_host_comprometido_sem_buscar(self):
        html = '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
        achados = varrer({}, html=html)
        self.assertIn("bundle.script-de-host-comprometido", regras(achados))


class CabecalhoAoVivoTests(unittest.TestCase):
    def test_valor_ruim_do_cabecalho_recebido_e_confirmado(self):
        cab = dict(CSP_OK, **{"content-security-policy":
                              "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'"})
        achados = varrer({}, html="<html></html>", cab=cab)
        ev = [a for a in achados if a["rule"] == "headers.csp-unsafe-eval"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["evidencia"], "confirmado")
        self.assertNotIn("headers.csp-sem-frame-ancestors", regras(achados))

    def test_versao_no_server_e_no_generator(self):
        cab = dict(CSP_OK, server="nginx/1.18.0 (Ubuntu)")
        html = '<html><meta name="generator" content="WordPress 6.2.1"></html>'
        achados = varrer({}, html=html, cab=cab)
        msgs = [a["message"] for a in achados if a["rule"] == "bundle.versao-exposta"]
        self.assertEqual(len(msgs), 2)

    def test_server_sem_numero_nao_e_acusado(self):
        achados = varrer({}, html="<html></html>", cab=dict(CSP_OK, server="Netlify"))
        self.assertNotIn("bundle.versao-exposta", regras(achados))

    def test_source_map_pelo_cabecalho(self):
        mapa = '{"version":3,"sources":["a.ts"],"sourcesContent":["const x = 1"]}'
        achados = varrer({
            "https://site.exemplo.com.br/assets/index.js": (200, {"sourcemap": "index.js.map"}, "var a=1;"),
            "https://site.exemplo.com.br/assets/index.js.map": (200, {}, mapa)})
        self.assertIn("bundle.sourcemap-expoe-codigo", regras(achados))

    def test_npmrc_com_token_exposto(self):
        achados = varrer({"https://site.exemplo.com.br/.npmrc":
                          (200, {}, "//registry.npmjs.org/:_authToken=abc")}, html="<html></html>")
        self.assertIn("bundle.exposto-npmrc", regras(achados))


class BinariosTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.d)], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _pe(extra: bytes = b"") -> bytes:
        cab = bytearray(512)
        cab[0:2] = b"MZ"
        struct.pack_into("<I", cab, 0x3C, 0x80)
        cab[0x80:0x84] = b"PE\0\0"
        return bytes(cab) + extra

    def _add(self, nome: str, dados: bytes):
        p = self.d / nome
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(dados)
        subprocess.run(["git", "-C", str(self.d), "add", nome], check=True)

    def test_classifica_por_bytes(self):
        self._add("tools/app.exe", self._pe())
        self._add("tools/upx.exe", self._pe(b"UPX0\0\0\0\0UPX1"))
        self._add("dist/setup.exe", self._pe(b"\0" * 64 + b"Inno Setup Setup Data (6.2.0)"))
        self._add("gradle/wrapper/gradle-wrapper.jar", b"PK\x03\x04" + b"\0" * 40)
        self._add("dados.zip", b"PK\x03\x04" + b"\0" * 40)
        self._add("planilha.xlsx", b"PK\x03\x04" + b"\0" * 40)
        self._add("disfarcado.txt", b"\x7fELF" + b"\0" * 60)
        (self.d / "nao-versionado.exe").write_bytes(self._pe())
        sev = {Path(a["path"]).name: (a["rule"], a["severity"])
               for a in binarios.escanear([self.d], set())}
        self.assertEqual(sev["app.exe"], ("supply.binario-versionado", "MEDIUM"))
        self.assertEqual(sev["upx.exe"], ("supply.executavel-empacotado", "HIGH"))
        self.assertEqual(sev["setup.exe"], ("supply.executavel-empacotado", "HIGH"))
        self.assertEqual(sev["gradle-wrapper.jar"][1], "INFO")
        self.assertEqual(sev["dados.zip"], ("supply.compactado-versionado", "LOW"))
        self.assertEqual(sev["disfarcado.txt"][0], "supply.binario-versionado")
        self.assertNotIn("planilha.xlsx", sev)
        self.assertNotIn("nao-versionado.exe", sev)

    def test_pasta_sem_git_nao_acusa(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.exe").write_bytes(self._pe())
            self.assertEqual(binarios.escanear([Path(d)], set()), [])


class SegredosNovosTests(unittest.TestCase):
    def _ids(self, texto):
        return {r.id for r in secrets_scan.REGRAS if r.re.search(texto)}

    def test_formatos_novos_de_chave(self):
        # Montadas por concatenação: o próprio scanner do repositório não pode acusar o teste.
        casos = {
            "openai-key": "sk-" + "proj-" + "Ab3_dE" * 10,
            "anthropic-key": "sk-" + "ant-api03-" + "xY9-" * 20,
            "npm-token": "npm" + "_" + "a1B2c3D4e5" * 3 + "F6g7H8",
            "gitlab-token": "glpat" + "-" + "Zx9_" * 6,
            "slack-webhook": "https://hooks.slack.com/" + "services/" + "T0A1B2C3D/B0A1B2C3D/" + "x" * 24,
        }
        for regra, texto in casos.items():
            self.assertIn(regra, self._ids(texto), regra)

    def test_atribuicao_com_prefixo(self):
        m = secrets_scan.ATRIBUICAO_RE.search('OPENAI_API_KEY="' + "Zq8w" * 6 + '"')
        self.assertTrue(m)

    def test_arquivos_de_credencial_por_nome(self):
        for nome in (".git-credentials", "infra/terraform.tfstate", ".pgpass", "x/.vscode/sftp.json",
                     "cofre.kdbx", "prod.tfvars"):
            self.assertTrue(secrets_scan.SEGREDO_NO_NOME_RE.search(nome), nome)
        self.assertFalse(secrets_scan.SEGREDO_NO_NOME_RE.search(".npmrc"))


if __name__ == "__main__":
    unittest.main()


class SupabaseConfigTests(unittest.TestCase):
    def test_redirect_largo_e_acusado(self):
        import supabase_config
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "supabase"
            p.mkdir()
            (p / "config.toml").write_text(
                '[auth]\nsite_url = "http://localhost:5173"\n'
                'additional_redirect_urls = ["https://*.netlify.app/**", "https://app.exemplo.com.br",'
                ' "http://app.exemplo.com.br/cb", "**"]\n', encoding="utf-8")
            regras_ = {a["rule"] for a in supabase_config.escanear([Path(d)], set())}
        self.assertEqual(regras_, {"supabase.auth-redirect-dominio-compartilhado",
                                   "supabase.auth-redirect-http",
                                   "supabase.auth-redirect-qualquer-destino"})


class RegraJwtTests(unittest.TestCase):
    """Roda o Semgrep de verdade: regra que não compila tem de falhar aqui."""

    def test_decodificacao_manual_so_no_servidor(self):
        import json as _json
        import raptor_win
        semgrep = raptor_win.find_semgrep()
        if not semgrep:
            self.skipTest("semgrep não encontrado")
        d = Path(tempfile.mkdtemp())
        ts = ('const t = req.headers.get("Authorization")!.slice(7);\n'
              'const p = JSON.parse(atob(t.split(".")[1]));\n'
              'jwt.verify(t, key, { ignoreExpiration: true });\n')
        for sub in ("supabase/functions/f/index.ts", "src/tela.ts"):
            (d / sub).parent.mkdir(parents=True, exist_ok=True)
            (d / sub).write_text(ts, encoding="utf-8")
        env = os.environ.copy()
        env["PATH"] = str(Path(semgrep).parent) + os.pathsep + env.get("PATH", "")
        regra = Path(raptor_win.__file__).parent / "rules/raptorwin/autenticacao/jwt-sem-verificar.yaml"
        out = subprocess.run([semgrep, "--config", str(regra), "--json", "--metrics=off", "--quiet",
                              str(d)], capture_output=True, text=True, encoding="utf-8", env=env,
                             timeout=180)
        dados = _json.loads(out.stdout)
        self.assertEqual(dados.get("errors"), [])
        achados = {(r["check_id"].rsplit(".", 1)[-1], Path(r["path"]).parts[-2])
                   for r in dados["results"]}
        self.assertIn(("jwt-decodificado-sem-verificar", "f"), achados)
        self.assertNotIn(("jwt-decodificado-sem-verificar", "src"), achados)
        self.assertIn(("jwt-ignora-expiracao", "src"), achados)
