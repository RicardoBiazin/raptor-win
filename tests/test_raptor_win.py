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


if __name__ == "__main__":
    unittest.main()
