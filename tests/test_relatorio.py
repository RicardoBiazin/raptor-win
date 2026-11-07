"""Relatório executivo: nota, sensibilidade, prompts, OWASP/LGPD, HTML e logo.

Os testes de unidade não rodam o Semgrep. O de integração roda e é pulado se
o Semgrep não estiver disponível.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

import relatorio  # noqa: E402

# Chave de exemplo oficial da AWS, montada em pedaços: o próprio raptor-win
# acusaria um literal inteiro no repositório (ver job "Sem falso-positivo").
CHAVE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def achado(sev="HIGH", path="app.py", line=1, rule="x", msg="m", cwe=None):
    return {"severity": sev, "path": path, "line": line, "rule": rule, "message": msg,
            "context": "", "cwe": cwe or []}


class NotaTests(unittest.TestCase):
    def test_sem_achados_e_100(self):
        self.assertEqual(relatorio.calcular_nota([]), 100)

    def test_pesos(self):
        self.assertEqual(relatorio.calcular_nota([achado("CRITICAL", "a", 1)]), 75)
        self.assertEqual(relatorio.calcular_nota([achado("HIGH", "a", 1), achado("WARNING", "a", 2)]), 87)
        self.assertEqual(relatorio.calcular_nota([achado("INFO", "a", 1)]), 99)

    def test_mesma_linha_conta_uma_vez(self):
        # Chave Stripe disparou duas regras na mesma linha: uma penalidade, a mais grave.
        reais = [achado("CRITICAL", "a", 1, "stripe-key"), achado("ERROR", "a", 1, "detected-stripe")]
        self.assertEqual(relatorio.calcular_nota(reais), 75)

    def test_sem_linha_nao_funde_achados_diferentes(self):
        reais = [achado("CRITICAL", "db", 0, "db.x", "tabela A"), achado("CRITICAL", "db", 0, "db.x", "tabela B")]
        self.assertEqual(relatorio.calcular_nota(reais), 50)

    def test_caminho_relativo_e_absoluto_sao_a_mesma_linha(self):
        # secrets_scan devolve relativo ("app.py"); o Semgrep devolve absoluto. Mesma linha.
        with tempfile.TemporaryDirectory() as d:
            raiz = Path(d)
            absoluto = str(raiz / "app.py")
            reais = [achado("CRITICAL", "app.py", 21, "aws-access-key"),
                     achado("HIGH", absoluto, 21, "regex")]
            self.assertEqual(relatorio.calcular_nota(reais, raiz), 75)

    def test_piso_zero(self):
        self.assertEqual(relatorio.calcular_nota([achado("CRITICAL", f"p{i}", 1) for i in range(9)]), 0)


class SensibilidadeTests(unittest.TestCase):
    def test_valor_de_aws_na_mensagem_e_sensivel(self):
        f = achado("CRITICAL", "app.py", 3, "aws-access-key", f"chave {CHAVE_AWS} exposta")
        self.assertTrue(relatorio.e_sensivel(f))
        self.assertNotIn(CHAVE_AWS, relatorio.prompt_correcao(f))

    def test_regra_de_segredo_nao_leva_valor_nem_trecho(self):
        f = achado("HIGH", ".env", 2, "secrets.literal-suspeito", "Literal longo atribuído a `X`")
        texto = relatorio.prompt_correcao(f, trecho_codigo=f"STRIPE={CHAVE_AWS}")
        self.assertNotIn(CHAVE_AWS, texto)
        self.assertIn("NÃO aparece", texto)

    def test_trecho_com_credencial_nao_sai(self):
        with tempfile.TemporaryDirectory() as d:
            arq = Path(d) / "app.py"
            arq.write_text(f"x = 1\nK = '{CHAVE_AWS}'\n", encoding="utf-8")
            self.assertIsNone(relatorio.trecho(Path(d), "app.py", 2))
            self.assertEqual(relatorio.trecho(Path(d), "app.py", 1), "x = 1")

    def test_env_sem_aspas_e_detectado(self):
        self.assertTrue(relatorio._tem_valor_sensivel("DATABASE_PASSWORD=Qw3rTy9ZxCvBnM7LkJhGfDs2"))
        self.assertFalse(relatorio._tem_valor_sensivel("DEBUG=true"))

    def test_lgpd_por_nome_e_sensivel(self):
        self.assertTrue(relatorio.e_sensivel(achado("WARNING", "x", 1, "raptorwin.privacidade.dado-pessoal-em-log")))


class PromptTests(unittest.TestCase):
    def test_sast_traz_linha_cwe_e_instrucao(self):
        f = achado("ERROR", "app.py", 8, "subprocess-shell-true", "shell=True é perigoso", cwe=["CWE-78"])
        texto = relatorio.prompt_correcao(f, trecho_codigo='subprocess.call(x, shell=True)')
        self.assertIn("app.py:8", texto)
        self.assertIn("CWE-78", texto)
        self.assertIn("subprocess.call(x, shell=True)", texto)
        self.assertIn("Acrescente um teste", texto)

    def test_identificadores_viram_marcador(self):
        """O prompt vai para um assistente de terceiro: e-mail, IP e projeto
        Supabase saem como marcador, e o resto da linha continua útil."""
        f = achado("ERROR", "app.ts", 3, "ssrf", "fetch para 10.0.0.12")
        linha = ('fetch("https://abcdefghijklmnopqrst.supabase.co/x?to=ana.souza@empresa.com.br'
                 '&ip=192.168.10.1&local=127.0.0.1")')
        texto = relatorio.prompt_correcao(f, trecho_codigo=linha)
        for vazado in ("abcdefghijklmnopqrst", "ana.souza@empresa.com.br", "192.168.10.1", "10.0.0.12"):
            self.assertNotIn(vazado, texto)
        self.assertIn("https://{projeto}.supabase.co/x?to={email}&ip={ip}&local=127.0.0.1", texto)
        self.assertIn("fetch para {ip}", texto)

    def test_versao_nao_vira_ip(self):
        self.assertEqual(relatorio.mascarar("semgrep==1.182.1 e lib 2.0"), "semgrep==1.182.1 e lib 2.0")


class OwaspTests(unittest.TestCase):
    def test_cwe_tem_prioridade(self):
        self.assertEqual(relatorio.categoria_owasp(achado(cwe=["CWE-89"])), "A03")
        self.assertEqual(relatorio.categoria_owasp(achado(cwe=["CWE-918"])), "A10")

    def test_prefixo_quando_nao_ha_cwe(self):
        self.assertEqual(relatorio.categoria_owasp(achado(rule="supply.sem-integrity")), "A06")
        self.assertEqual(relatorio.categoria_owasp(achado(rule="secrets.literal-suspeito")), "A07")
        self.assertEqual(relatorio.categoria_owasp(achado(rule="headers.ausente.csp")), "A05")
        self.assertIsNone(relatorio.categoria_owasp(achado(rule="regra-solta")))

    def test_checklist_conta_e_marca_lgpd(self):
        ck = relatorio.checklist([
            achado(cwe=["CWE-89"], rule="a.sqli"),
            achado(rule="raptorwin.privacidade.dado-pessoal-em-log"),
        ])
        self.assertEqual(ck["owasp"]["A03"]["achados"], 1)
        self.assertEqual(ck["owasp"]["A03"]["regras"], ["sqli"])
        self.assertEqual(ck["lgpd"]["achados"], 1)


class HtmlTests(unittest.TestCase):
    def test_escapa_texto_de_fora(self):
        f = achado("HIGH", "<img src=x onerror=alert(1)>.py", 1, "r", "<script>alert(1)</script>")
        res = relatorio.resumo([f], 90)
        html = relatorio.html_relatorio([f], res, 90, Path("."), "alvo <b>")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("alvo &lt;b&gt;", html)
        self.assertIn("90/100", html)

    def test_logo_valida(self):
        with tempfile.TemporaryDirectory() as d:
            png = Path(d) / "logo.png"
            png.write_bytes(b"\x89PNG\r\n\x1a\n")
            self.assertTrue(relatorio.logo_data_uri(png).startswith("data:image/png;base64,"))
            exe = Path(d) / "x.exe"
            exe.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                relatorio.logo_data_uri(exe)
            grande = Path(d) / "g.png"
            grande.write_bytes(b"0" * (relatorio.LOGO_MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                relatorio.logo_data_uri(grande)


@unittest.skipUnless(shutil.which("semgrep") or (RAIZ / ".venv" / "Scripts" / "semgrep.exe").exists()
                     or (RAIZ / ".venv" / "bin" / "semgrep").exists(), "semgrep indisponível")
class IntegracaoTests(unittest.TestCase):
    def _alvo(self, d: Path) -> Path:
        (d / "app.py").write_text("import subprocess\n\n\ndef rodar(c):\n"
                                  "    subprocess.call(c, shell=True)\n", encoding="utf-8")
        return d

    def test_sem_opcoes_novas_nao_muda_a_saida(self):
        with tempfile.TemporaryDirectory() as d:
            alvo = self._alvo(Path(d))
            r = subprocess.run([sys.executable, str(RAIZ / "raptor_win.py"), str(alvo)],
                               capture_output=True, text=True, encoding="utf-8", timeout=600)
            self.assertNotIn("Nota de segurança", r.stdout)

    def test_executivo_gera_nota_md_e_html(self):
        with tempfile.TemporaryDirectory() as d:
            alvo = self._alvo(Path(d))
            md, htm = Path(d) / "r.md", Path(d) / "r.html"
            r = subprocess.run([sys.executable, str(RAIZ / "raptor_win.py"), str(alvo), "--executivo",
                                "--md", str(md), "--html", str(htm)],
                               capture_output=True, text=True, encoding="utf-8", timeout=600)
            self.assertIn("Nota de segurança:", r.stdout)
            self.assertIn("## Resumo executivo", md.read_text(encoding="utf-8"))
            self.assertIn("Relatório de segurança", htm.read_text(encoding="utf-8"))

    def test_logo_sem_html_e_erro(self):
        r = subprocess.run([sys.executable, str(RAIZ / "raptor_win.py"), str(RAIZ / "sample_vuln"),
                            "--logo", "x.png"], capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--logo precisa de --html", r.stderr)


if __name__ == "__main__":
    unittest.main()
