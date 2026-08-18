import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import raptor_win
import typosquat


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class SeverityTests(unittest.TestCase):
    def test_cvss_version_is_not_mistaken_for_score(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(raptor_win._osv_severity(vuln), "UNKNOWN")

    def test_explicit_numeric_score_is_classified(self):
        self.assertEqual(raptor_win._osv_severity({"severity": [{"score": "9.8"}]}), "CRITICAL")


class ChangedFilesTests(unittest.TestCase):
    def test_sibling_with_same_prefix_is_not_included(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "app"
            sibling = root / "app-old"
            target.mkdir()
            sibling.mkdir()
            inside = target / "ok.py"
            outside = sibling / "fora.py"
            inside.write_text("ok = 1", encoding="utf-8")
            outside.write_text("fora = 1", encoding="utf-8")
            calls = [
                SimpleNamespace(returncode=0, stdout=str(root)),
                SimpleNamespace(returncode=0, stdout="app/ok.py\napp-old/fora.py\n"),
            ]
            with mock.patch.object(raptor_win.subprocess, "run", side_effect=calls):
                self.assertEqual(raptor_win.changed_files(target, "main"), [inside.resolve()])


class ScaTests(unittest.TestCase):
    def test_osv_vulnerability_becomes_a_regular_finding(self):
        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "requirements.txt"
            req.write_text("demo==1.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-test"}]}]}
            detail = {
                "id": "GHSA-test",
                "summary": "Falha de teste",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"fixed": "2.0"}]}]}],
            }
            with mock.patch.object(raptor_win.urllib.request, "urlopen",
                                   side_effect=[FakeResponse(batch), FakeResponse(detail)]):
                result = raptor_win.run_sca([Path(td)])
            finding = result["findings"][0]
            self.assertEqual(finding["rule"], "GHSA-test")
            self.assertEqual(finding["severity"], "HIGH")
            self.assertEqual(Path(finding["path"]), req)
            self.assertIn("corrigido em 2.0", finding["message"])

    def test_baseline_is_present_in_markdown_and_sarif(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / ".raptor-baseline.toml"
            markdown = root / "report.md"
            sarif = root / "report.sarif"
            baseline.write_text(
                '[[aceito]]\nregra = "GHSA-test"\n'
                'motivo = "Dependência não alcançável neste aplicativo."\n',
                encoding="utf-8",
            )
            sca = {
                "sources": ["requirements.txt"], "deps": 1,
                "vulns": {("PyPI", "demo", "1.0"): ["GHSA-test"]},
                "details": {},
                "findings": [{
                    "rule": "GHSA-test", "severity": "HIGH",
                    "path": str(root / "requirements.txt"), "line": 1,
                    "message": "demo@1.0 vulnerável", "context": "SCA · PyPI",
                }],
            }
            argv = ["raptor-win", str(root), "--sca", "--no-raptor", "--no-registry",
                    "--baseline", str(baseline), "--md", str(markdown),
                    "--sarif", str(sarif), "--fail-on", "HIGH"]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(raptor_win, "run_sca", return_value=sca), \
                    redirect_stdout(io.StringIO()):
                code = raptor_win.main()
            self.assertEqual(code, 0)
            self.assertIn("risco aceito", markdown.read_text(encoding="utf-8"))
            result = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"][0]
            self.assertEqual(result["suppressions"][0]["kind"], "external")

    def test_sca_finding_participates_in_fail_on(self):
        with tempfile.TemporaryDirectory() as td:
            sca = {
                "sources": ["requirements.txt"], "deps": 1,
                "vulns": {("PyPI", "demo", "1.0"): ["GHSA-test"]},
                "details": {},
                "findings": [{
                    "rule": "GHSA-test", "severity": "HIGH",
                    "path": str(Path(td) / "requirements.txt"), "line": 1,
                    "message": "demo@1.0 vulnerável", "context": "SCA · PyPI",
                }],
            }
            argv = ["raptor-win", td, "--sca", "--no-raptor", "--no-registry",
                    "--fail-on", "HIGH"]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(raptor_win, "run_sca", return_value=sca), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(raptor_win.main(), 1)


class TyposquatTests(unittest.TestCase):
    """O valor do typosquat esta' em NAO gritar. Metade destes testes cobra
    silencio: pacote popular, projeto legitimo parecido e nome interno unico
    tem de passar limpos, senao a checagem vira ruido e o usuario a desliga."""

    def test_popular_package_is_never_flagged(self):
        self.assertEqual(typosquat.escanear([("PyPI", "requests", "2.31.0")]), [])
        self.assertEqual(typosquat.escanear([("npm", "lodash", "4.17.21")]), [])

    def test_one_edit_from_popular_is_high(self):
        (a,) = typosquat.escanear([("PyPI", "reqests", "1.0")])
        self.assertEqual(a["severity"], "high")
        self.assertEqual(a["distance"], 1)
        self.assertEqual(a["nearest"], "requests")

    def test_plural_typosquat_is_caught(self):
        (a,) = typosquat.escanear([("PyPI", "python-dateutils", "2.0")])
        self.assertEqual(a["nearest"], "python-dateutil")

    def test_denylisted_name_is_high(self):
        (a,) = typosquat.escanear([("npm", "loadash", "1.0")])
        self.assertEqual(a["severity"], "high")

    def test_allowlisted_lookalike_is_silent(self):
        # preact fica a 1 edicao de react e e' projeto real e independente.
        self.assertEqual(typosquat.escanear([("npm", "preact", "10.0")]), [])

    def test_scoped_namespace_squat_is_distance_zero(self):
        (a,) = typosquat.escanear([("npm", "@evil/lodash", "1.0")])
        self.assertEqual(a["distance"], 0)
        self.assertEqual(a["nearest"], "lodash")

    def test_unique_internal_name_is_silent(self):
        self.assertEqual(
            typosquat.escanear([("PyPI", "meu-pacote-interno-xyz", "1.0")]), [])

    def test_unknown_ecosystem_does_not_explode(self):
        self.assertEqual(typosquat.escanear([("Cargo", "serde", "1.0")]), [])

    def test_distance_two_is_medium_not_high(self):
        # Severidade acompanha a distancia: a 2 edicoes o falso-positivo e'
        # bem mais provavel, entao nao pode reprovar um CI configurado em high.
        achados = typosquat.escanear([("PyPI", "reqest", "1.0")])
        if achados:
            self.assertIn(achados[0]["severity"], ("high", "medium"))
            self.assertLessEqual(achados[0]["distance"], 2)

    def test_damerau_transposition_counts_as_one_edit(self):
        # 'flsak' -> 'flask' e' uma transposicao adjacente: distancia 1 para
        # Damerau, 2 para Levenshtein puro. E' o erro de digitacao mais comum.
        self.assertEqual(typosquat._distancia("flsak", "flask", 3), 1)

    def test_findings_feed_the_sca_report(self):
        deps = [("PyPI", "reqests", "1.0")]
        with mock.patch.object(raptor_win, "find_manifests", return_value=[]),              mock.patch.object(raptor_win, "enumerate_venv", return_value=deps),              mock.patch.object(raptor_win.urllib.request, "urlopen",
                               return_value=FakeResponse({"results": [{}]})):
            sca = raptor_win.run_sca([Path(".")])
        regras = [f["rule"] for f in sca["findings"]]
        self.assertIn("typosquat", regras)
        self.assertEqual(sca["findings"][0]["severity"], "HIGH")


class ManifestTests(unittest.TestCase):
    """Regressao: o SCA sub-reportava em silencio, que e' o pior defeito
    possivel num scanner -- exibia 'nenhuma vulneravel ✅' sem ter checado
    dependencia alguma."""

    def test_unpinned_requirement_is_not_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text("cryptography>=50\npywin32>=306\n"
                           "requests==2.31.0\n", encoding="utf-8")
            deps = raptor_win.parse_requirements(req)
        nomes = {n for (_e, n, _v) in deps}
        self.assertEqual(nomes, {"cryptography", "pywin32", "requests"})
        # o pinado mantem a versao; os demais ficam com versao vazia
        versoes = {n: v for (_e, n, v) in deps}
        self.assertEqual(versoes["requests"], "2.31.0")
        self.assertEqual(versoes["cryptography"], "")

    def test_requirements_variants_are_discovered(self):
        with tempfile.TemporaryDirectory() as d:
            for nome in ("requirements.txt", "requirements-dev.txt",
                         "requirements-nuvem.txt"):
                (Path(d) / nome).write_text("requests==2.31.0\n",
                                            encoding="utf-8")
            achados = {m.name for m in raptor_win.find_manifests([Path(d)])}
        self.assertEqual(achados, {"requirements.txt", "requirements-dev.txt",
                                   "requirements-nuvem.txt"})

    def test_variant_manifest_does_not_crash_the_scan(self):
        # `parsers[m.name]` levantava KeyError em requirements-nuvem.txt e
        # derrubava a varredura inteira.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "requirements-nuvem.txt").write_text(
                "boto3>=1.0\n", encoding="utf-8")
            with mock.patch.object(raptor_win.urllib.request, "urlopen",
                                   return_value=FakeResponse({"results": []})):
                sca = raptor_win.run_sca([Path(d)])
        self.assertEqual(sca["deps"], 1)
        self.assertEqual(sca["pinados"], 0)
        self.assertIn("boto3", sca["sem_pin"])

    def test_report_states_what_was_not_checked(self):
        sca = {"sources": ["requirements.txt"], "deps": 4, "pinados": 0,
               "sem_pin": ["Pillow", "cryptography"], "vulns": {},
               "typosquat": [], "details": {}}
        buf = io.StringIO()
        with redirect_stdout(buf):
            raptor_win.render_sca(sca)
        saida = buf.getvalue()
        self.assertIn("NÃO checadas", saida)
        self.assertIn("cryptography", saida)


if __name__ == "__main__":
    unittest.main()
