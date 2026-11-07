"""KEV/EPSS e evidência (confirmado x indício) — sem rede: as consultas são dubladas."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bundle_scan  # noqa: E402
import exploracao  # noqa: E402
import raptor_win  # noqa: E402

KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}


def fonte(kev=KEV, epss=None, falha=()):
    """Dublê de `buscar`: responde KEV e EPSS; URLs em `falha` levantam erro."""
    chamadas = []

    def buscar(url, timeout=30):
        chamadas.append(url)
        if any(url.startswith(f) for f in falha):
            raise OSError("sem rede")
        if url.startswith(exploracao.EPSS_URL):
            cves = url[len(exploracao.EPSS_URL):].split(",")
            return {"data": [{"cve": c, "epss": str(v[0]), "percentile": str(v[1])}
                             for c, v in (epss or {}).items() if c in cves]}
        return kev
    buscar.chamadas = chamadas
    return buscar


def achado_osv(vid="GHSA-jfh8-c2jp-5v3q", sev="MEDIUM"):
    return {"rule": vid, "severity": sev, "path": "pom.xml", "line": 1,
            "message": "log4j-core@2.14.1: RCE", "context": "SCA · Maven",
            "osv_id": vid, "evidencia": "confirmado"}


class KevTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pasta = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cve_vem_dos_aliases(self):
        """O id do OSV costuma ser GHSA/PYSEC; o CVE está em `aliases`."""
        self.assertEqual(exploracao.cves_de("GHSA-x", {"aliases": ["CVE-2021-44228", "PYSEC-1"]}),
                         ["CVE-2021-44228"])
        self.assertEqual(exploracao.cves_de("CVE-2020-1234", {}), ["CVE-2020-1234"])

    def test_kev_sobe_para_high_e_diz_desde_quando(self):
        f = achado_osv()
        det = {f["osv_id"]: {"aliases": ["CVE-2021-44228"]}}
        estado = exploracao.anotar([f], det, buscar=fonte(epss={"CVE-2021-44228": (0.97, 0.999)}),
                                   pasta=self.pasta)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["severidade_osv"], "MEDIUM")
        self.assertEqual(f["kev"], "2021-12-10")
        self.assertIn("CISA KEV desde 2021-12-10", f["message"])
        self.assertAlmostEqual(f["epss"], 0.97)
        self.assertIn("EPSS 97.0%", f["message"])
        self.assertEqual(estado["kev"], [f["osv_id"]])

    def test_critical_continua_critical(self):
        f = achado_osv(sev="CRITICAL")
        exploracao.anotar([f], {f["osv_id"]: {"aliases": ["CVE-2021-44228"]}},
                          buscar=fonte(), pasta=self.pasta)
        self.assertEqual(f["severity"], "CRITICAL")

    def test_fora_do_kev_nao_muda_severidade(self):
        f = achado_osv(vid="CVE-2020-0001")
        exploracao.anotar([f], {}, buscar=fonte(epss={"CVE-2020-0001": (0.01, 0.2)}),
                          pasta=self.pasta)
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertNotIn("kev", f)
        self.assertIn("EPSS 1.0%", f["message"])

    def test_sem_cve_nao_consulta_nada(self):
        buscar = fonte()
        f = achado_osv(vid="GHSA-sem-cve")
        estado = exploracao.anotar([f], {}, buscar=buscar, pasta=self.pasta)
        self.assertEqual(buscar.chamadas, [])
        self.assertIsNone(exploracao.linha_relatorio(estado))

    def test_cache_do_dia_evita_download(self):
        (self.pasta / "kev.json").write_text(json.dumps(KEV), encoding="utf-8")
        buscar = fonte()
        indice, origem = exploracao.carregar_kev(buscar, self.pasta)
        self.assertIn("CVE-2021-44228", indice)
        self.assertEqual(origem, "cache de hoje")
        self.assertEqual(buscar.chamadas, [])

    def test_sem_rede_usa_cache_velho_e_diz_a_data(self):
        arq = self.pasta / "kev.json"
        arq.write_text(json.dumps(KEV), encoding="utf-8")
        velho = time.time() - 3 * 86400
        os.utime(arq, (velho, velho))
        indice, origem = exploracao.carregar_kev(fonte(falha=("https://",)), self.pasta)
        self.assertIn("CVE-2021-44228", indice)
        self.assertIn("sem rede", origem)

    def test_sem_rede_e_sem_cache_o_relatorio_diz_que_nao_checou(self):
        """Ausência de marca KEV não pode parecer "nenhuma explorada"."""
        f = achado_osv(vid="CVE-2021-44228")
        estado = exploracao.anotar([f], {}, buscar=fonte(falha=("https://",)), pasta=self.pasta)
        linha = exploracao.linha_relatorio(estado)
        self.assertIn("NÃO consultado", linha)
        self.assertIn("EPSS NÃO consultado", linha)
        self.assertEqual(f["severity"], "MEDIUM")

    def test_espelho_quando_a_cisa_falha(self):
        buscar = fonte(falha=(exploracao.KEV_URLS[0],))
        indice, origem = exploracao.carregar_kev(buscar, self.pasta)
        self.assertIn("CVE-2021-44228", indice)
        self.assertEqual(origem, "baixado agora")
        self.assertTrue((self.pasta / "kev.json").exists())

    def test_json_estranho_nao_vira_cache(self):
        indice, origem = exploracao.carregar_kev(fonte(kev={"erro": "x"}), self.pasta)
        self.assertIsNone(indice)
        self.assertFalse((self.pasta / "kev.json").exists())


class EvidenciaTests(unittest.TestCase):
    def test_bundle_observado_e_confirmado_regex_e_indicio(self):
        self.assertEqual(bundle_scan._achado("bundle.anon-le-tabela", "MEDIUM", "u", "m")
                         .get("evidencia"), "confirmado")
        self.assertEqual(bundle_scan._achado("bundle.exposto-env", "HIGH", "u", "m")
                         .get("evidencia"), "confirmado")
        self.assertNotIn("evidencia", bundle_scan._achado("bundle.segredo-aws", "HIGH", "u", "m"))
        self.assertNotIn("evidencia", bundle_scan._achado("bundle.limite-de-chunks", "INFO", "u", "m"))

    def test_markdown_e_sarif_mostram_a_evidencia(self):
        fs = [dict(achado_osv(), kev="2021-12-10", epss=0.97),
              {"rule": "python.x", "severity": "HIGH", "path": "a.py", "line": 3,
               "message": "m", "context": ""}]
        md = raptor_win.render_markdown(fs, "alvo", 1, 1)
        self.assertIn("| Sev | Evidência |", md)
        self.assertIn("| MEDIUM | confirmado |", md)
        self.assertIn("| HIGH | indício |", md)
        res = raptor_win.to_sarif(fs)["runs"][0]["results"]
        self.assertEqual(res[0]["properties"], {"evidencia": "confirmado", "kev": "2021-12-10",
                                                "epss": 0.97})
        self.assertEqual(res[1]["properties"], {"evidencia": "indicio"})


if __name__ == "__main__":
    unittest.main()
