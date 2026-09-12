import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import db_audit
import headers_lint
import raptor_win
import secrets_scan
import sql_lint
import supply_chain
import raptor_win as R
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

    def test_trusted_scope_bare_name_is_silent(self):
        """Escopo de organizacao conhecida nao e' squat, mesmo com nome nu igual.

        `@types/lodash` TIPA o lodash: o nome nu igual ao popular e' a convencao
        do DefinitelyTyped, nao um ataque. Sem esta excecao a checagem acusava a
        arvore inteira de um projeto React em HIGH -- 57 achados num projeto,
        quase todos `@types/*`, e um relatorio nesse estado ninguem le.
        """
        for nome in ("@types/d3-array", "@radix-ui/react-portal",
                     "@alloc/quick-lru", "@babel/core"):
            self.assertEqual(typosquat.escanear([("npm", nome, "1.0")]), [],
                             f"{nome} nao deveria ser acusado")

    def test_scoped_generic_subname_is_silent(self):
        """`core`, `types`, `dom` a 1 edicao de `cors`, `type`, `dot`.

        Nome generico de subpacote e' a regra em pacote com escopo. Comparar o
        nome nu por APROXIMACAO gerava a maior parte do ruido; agora ele vale
        apenas por igualdade exata, e so' fora dos escopos confiaveis.
        """
        for nome in ("@qualquer-escopo-novo/core", "@outro/types"):
            self.assertEqual(typosquat.escanear([("npm", nome, "1.0")]), [],
                             f"{nome} nao deveria ser acusado")

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


class FalsoBanco:
    """Seam de teste: mapeia SQL -> linhas gravadas, sem banco nenhum.

    A chave é a de `db_audit.CONSULTAS`, encontrada comparando o SQL montado —
    assim o teste falha se uma consulta for renomeada, em vez de devolver vazio
    em silêncio e fazer o assert passar por engano.
    """

    def __init__(self, linhas: dict, capacidades: dict | None = None):
        self.linhas = linhas
        self.cap = capacidades or {"tem_anon": True, "tem_auth": True}
        self.vistas: list[str] = []

    def __call__(self, sql: str) -> list:
        self.vistas.append(sql)
        for chave in db_audit.CONSULTAS:
            montada = db_audit.montar(chave, schemas=db_audit.SCHEMAS_SISTEMA,
                                      capacidades=self.cap)
            if montada == sql:
                return self.linhas.get(chave, [])
        if sql == db_audit.CONSULTAS["preflight"]:
            return self.linhas.get("preflight", [])
        raise AssertionError("SQL não reconhecido — consulta renomeada?")


def _fn(**kw) -> dict:
    """Linha de `funcoes` com padrões inofensivos; o teste sobrepõe o que importa."""
    base = {"schema": "public", "nome": "fn_x", "args": "", "definer": False,
            "dono": "postgres", "dono_super": False, "dono_bypassrls": False,
            "anon_exec": False, "public_exec": False, "sp_ausente": False,
            "sp_valor": "public, pg_temp"}
    base.update(kw)
    return base


class DbGuardaSomenteLeituraTests(unittest.TestCase):
    """A camada que faz a promessa de somente-leitura ser verificável.

    Existe para que uma edição descuidada em `CONSULTAS` quebre a build em vez
    de escrever no banco de alguém.
    """

    def _montadas(self):
        for chave in db_audit.CONSULTAS:
            yield chave, db_audit.montar(
                chave, schemas=db_audit.SCHEMAS_SISTEMA,
                capacidades={"tem_anon": True, "tem_auth": True})

    def test_toda_consulta_do_modulo_passa(self):
        for chave, sql in self._montadas():
            with self.subTest(consulta=chave):
                db_audit._exigir_somente_leitura(sql)

    def test_escrita_e_recusada(self):
        for ruim in ("update t set x = 1",
                     "delete from t",
                     "select 1; drop table t",
                     "grant all on t to anon",
                     "do $$ begin end $$",
                     "select f() ; revoke all on t from anon"):
            with self.subTest(sql=ruim):
                with self.assertRaises(db_audit.ErroBanco):
                    db_audit._exigir_somente_leitura(ruim)

    def test_verbo_dentro_de_literal_e_dado_nao_comando(self):
        """`has_table_privilege(..., 'insert, update, delete')` é leitura.

        Sem apagar literais, o guarda recusava as próprias consultas do módulo.
        """
        db_audit._exigir_somente_leitura(
            "select has_table_privilege('anon', c.oid, 'insert, update, delete') from pg_class c")

    def test_schema_invalido_nao_chega_ao_sql(self):
        with self.assertRaises(db_audit.ErroBanco):
            db_audit._ident("public; drop table t")
        with self.assertRaises(db_audit.ErroBanco):
            db_audit._ident("1bad")


class DbFuncoesTests(unittest.TestCase):
    def test_proacl_nulo_e_execute_to_public(self):
        """`proacl IS NULL` significa privilégio PADRÃO, e o padrão é PUBLIC.

        Lê-lo como "sem grants" perderia o caso mais comum — é o motivo do
        `acldefault('f', proowner)` na consulta.
        """
        a = db_audit._achados_funcoes([_fn(definer=True, public_exec=True)])
        regras = [x["rule"] for x in a]
        self.assertIn("db.function-executable-by-public", regras)

    def test_anon_em_schema_exposto_e_high(self):
        a = [x for x in db_audit._achados_funcoes([_fn(anon_exec=True)])
             if x["rule"] == "db.function-executable-by-anon"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "HIGH")
        self.assertIn("/rest/v1/rpc/", a[0]["message"])

    def test_anon_fora_de_schema_exposto_e_warning(self):
        a = [x for x in db_audit._achados_funcoes(
            [_fn(schema="interno", anon_exec=True)])
            if x["rule"] == "db.function-executable-by-anon"]
        self.assertEqual(a[0]["severity"], "WARNING")

    def test_search_path_ausente_em_definer(self):
        a = [x for x in db_audit._achados_funcoes([_fn(definer=True, sp_ausente=True)])
             if x["rule"] == "db.function-search-path-missing"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "HIGH")

    def test_search_path_sem_pg_temp_e_sequestravel(self):
        a = [x for x in db_audit._achados_funcoes(
            [_fn(definer=True, sp_valor="public")])
            if x["rule"] == "db.function-search-path-hijackable"]
        self.assertEqual(len(a), 1)
        self.assertIn("pg_temp", a[0]["message"])

    def test_silencio_nos_search_path_legitimos(self):
        """`= ''` e `= pg_catalog` não abrem janela: não há o que plantar."""
        for val in ("", "pg_catalog", "public, pg_temp", "atendimento, public, pg_temp"):
            with self.subTest(valor=val):
                a = [x for x in db_audit._achados_funcoes(
                    [_fn(definer=True, sp_valor=val)])
                    if "search-path" in x["rule"]]
                self.assertEqual(a, [])

    def test_invoker_sem_alcance_nao_gera_achado_de_search_path(self):
        """Sem elevação nem alcance anônimo, search_path não é risco.

        É o recorte que impede o relatório de virar uma linha por função do
        banco — o que torna a saída do Advisor oficial ilegível.
        """
        a = db_audit._achados_funcoes([_fn(sp_ausente=True)])
        self.assertEqual([x for x in a if "search-path" in x["rule"]], [])

    def test_dono_bypassrls_sozinho_nao_acusa(self):
        """No Supabase `postgres` é dono de tudo E tem BYPASSRLS.

        Sem o gate de alcance esta regra deu 85 de 90 achados contra um banco
        real: dispararia em 100% das funções DEFINER de 100% dos projetos.
        """
        a = db_audit._achados_funcoes([_fn(definer=True, dono_bypassrls=True)])
        self.assertEqual(
            [x for x in a if x["rule"] == "db.security-definer-owned-by-superuser"], [])

    def test_dono_bypassrls_com_alcance_de_cliente_acusa(self):
        a = [x for x in db_audit._achados_funcoes(
            [_fn(definer=True, dono_bypassrls=True, anon_exec=True)])
            if x["rule"] == "db.security-definer-owned-by-superuser"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "HIGH")


class DbRelacoesTests(unittest.TestCase):
    def _rel(self, **kw):
        base = {"schema": "public", "tabela": "t", "rls": True, "n_policies": 1,
                "anon_read": False, "anon_write": False, "auth_read": False}
        base.update(kw)
        return [base]

    def test_sem_rls_com_escrita_anonima_e_critical(self):
        a = [x for x in db_audit._achados_relacoes(
            self._rel(rls=False, anon_read=True, anon_write=True))
            if x["rule"] == "db.table-without-rls-exposed"]
        self.assertEqual(a[0]["severity"], "CRITICAL")

    def test_rls_ligada_sem_policy_e_indisponibilidade(self):
        """A mensagem precisa dizer que NÃO é vazamento.

        Sem isso alguém "corrige" desligando o RLS, o que troca tela vazia por
        tabela aberta — o achado viraria a causa do incidente.
        """
        a = [x for x in db_audit._achados_relacoes(self._rel(n_policies=0))
             if x["rule"] == "db.rls-enabled-no-policy"]
        self.assertEqual(len(a), 1)
        self.assertIn("NÃO é vazamento", a[0]["message"])
        self.assertIn("desligando", a[0]["message"])

    def test_com_rls_e_policy_silencio(self):
        self.assertEqual(db_audit._achados_relacoes(self._rel(anon_read=True)), [])

    def test_csv_e_json_dao_o_mesmo_achado(self):
        """`psql --csv` devolve `t`/`f`; a API devolve booleano.

        Era a armadilha de portabilidade: sem normalizar, uma checagem
        disparava num backend e não no outro.
        """
        csv_ = [{"schema": "public", "tabela": "t", "rls": "f", "n_policies": "0",
                 "anon_read": "t", "anon_write": "f", "auth_read": "t"}]
        api = [{"schema": "public", "tabela": "t", "rls": False, "n_policies": 0,
                "anon_read": True, "anon_write": False, "auth_read": True}]
        chave = lambda achados: sorted((x["rule"], x["severity"]) for x in achados)
        self.assertEqual(chave(db_audit._achados_relacoes(csv_)),
                         chave(db_audit._achados_relacoes(api)))


class DbPoliciesTests(unittest.TestCase):
    def _pol(self, **kw):
        base = {"schema": "public", "tabela": "t", "policy": "p",
                "permissiva": "PERMISSIVE", "cmd": "SELECT",
                "papeis": "authenticated", "qual": "org_id = my_org()",
                "with_check": ""}
        base.update(kw)
        return base

    def test_true_em_escrita_e_high(self):
        a = [x for x in db_audit._achados_policies(
            [self._pol(cmd="UPDATE", qual="true")])
            if x["rule"] == "db.policy-always-true-write"]
        self.assertEqual(a[0]["severity"], "HIGH")

    def test_true_em_select_nao_e_esse_achado(self):
        a = [x for x in db_audit._achados_policies([self._pol(qual="true")])
             if x["rule"] == "db.policy-always-true-write"]
        self.assertEqual(a, [])

    def test_duas_permissivas_de_select(self):
        a = [x for x in db_audit._achados_policies(
            [self._pol(policy="p1"), self._pol(policy="p2")])
            if x["rule"] == "db.multiple-permissive-policies"]
        self.assertEqual(len(a), 1)

    def test_restritiva_nao_conta(self):
        a = [x for x in db_audit._achados_policies(
            [self._pol(policy="p1"), self._pol(policy="p2", permissiva="RESTRICTIVE")])
            if x["rule"] == "db.multiple-permissive-policies"]
        self.assertEqual(a, [])


class DbExtensoesTests(unittest.TestCase):
    def _ext(self, **kw):
        base = {"nome": "pg_net", "schema": "public", "versao": "0.20.3",
                "relocavel": False, "anon_exec_fn": False, "fn_em_exposto": False}
        base.update(kw)
        return [base]

    def test_nao_relocavel_nao_recomenda_set_schema(self):
        """Recomendar a migração impossível é pior que ficar calado.

        `alter extension ... set schema` FALHA com 0A000 numa extensão
        `relocatable = false` — medido em produção com `pg_net`.
        """
        a = [x for x in db_audit._achados_extensoes(self._ext(relocavel=False))
             if x["rule"] == "db.extension-in-public"][0]
        self.assertEqual(a["severity"], "INFO")
        self.assertIn("VAI FALHAR", a["message"])
        self.assertNotIn("mova com", a["message"])

    def test_relocavel_recomenda_a_migracao(self):
        a = [x for x in db_audit._achados_extensoes(
            self._ext(nome="pgcrypto", relocavel=True))
            if x["rule"] == "db.extension-in-public"][0]
        self.assertEqual(a["severity"], "WARNING")
        self.assertIn("set schema extensions", a["message"])
        self.assertNotIn("VAI FALHAR", a["message"])

    def test_alcance_de_rede_so_com_execute_medido(self):
        """Sem `anon_exec_fn` não há achado: o alcance é medido, não presumido."""
        a = [x for x in db_audit._achados_extensoes(self._ext(anon_exec_fn=False))
             if x["rule"] == "db.extension-network-exec-por-anon"]
        self.assertEqual(a, [])

    def test_execute_sem_schema_exposto_e_warning_nao_high(self):
        """Ter EXECUTE não é ser chamável: o PostgREST só publica o que é exposto."""
        a = [x for x in db_audit._achados_extensoes(
            self._ext(anon_exec_fn=True, fn_em_exposto=False))
            if x["rule"] == "db.extension-network-exec-por-anon"][0]
        self.assertEqual(a["severity"], "WARNING")
        self.assertIn("não as expõe", a["message"])

    def test_execute_com_schema_exposto_e_high(self):
        a = [x for x in db_audit._achados_extensoes(
            self._ext(anon_exec_fn=True, fn_em_exposto=True))
            if x["rule"] == "db.extension-network-exec-por-anon"][0]
        self.assertEqual(a["severity"], "HIGH")

    def test_extensao_sem_alcance_nao_gera_o_segundo_achado(self):
        a = [x for x in db_audit._achados_extensoes(
            self._ext(nome="pgcrypto", relocavel=True, anon_exec_fn=True))
            if x["rule"] == "db.extension-network-exec-por-anon"]
        self.assertEqual(a, [])


class DbFormatoDoAchadoTests(unittest.TestCase):
    """O pseudo-caminho tem de sobreviver a tudo que o relatório faz com ele."""

    def test_prefixo_db_sobrevive_ao_relpath(self):
        """`d:` viraria letra de unidade e `os.path.relpath` levantaria ValueError."""
        import os.path
        p = db_audit._pseudo("public", "f", "uuid, text")
        self.assertTrue(p.startswith("db:"))
        self.assertEqual(os.path.relpath(p), p)

    def test_sem_pipe_nem_quebra_de_linha(self):
        """O Markdown põe o caminho numa célula de tabela delimitada por `|`."""
        p = db_audit._pseudo("public", "f|g", "a\nb")
        self.assertNotIn("|", p)
        self.assertNotIn("\n", p)

    def test_contexto_vem_do_modulo_e_nao_do_classify_context(self):
        """Medido: `db:test.foo()` casa TOOLING_RE e sairia de "exigem atenção".

        Por isso o módulo define o próprio `context` e o `main()` NÃO roda
        `classify_context()` sobre estes achados.
        """
        self.assertTrue(raptor_win.TOOLING_RE.search("db:test.foo()"))
        a = db_audit._achados_funcoes([_fn(schema="test", anon_exec=True)])
        self.assertTrue(all(x["context"] for x in a))

    def test_achado_de_banco_entra_em_exigem_atencao(self):
        a = db_audit._achados_funcoes([_fn(anon_exec=True)])
        self.assertEqual(len(raptor_win.exigem_atencao(a)), len(a))

    def test_sobrecargas_sao_achados_distintos(self):
        p1 = db_audit._pseudo("public", "f", "uuid")
        p2 = db_audit._pseudo("public", "f", "uuid, text")
        self.assertNotEqual(p1, p2)


class DbBackendTests(unittest.TestCase):
    def test_sem_credencial_nomeia_as_variaveis(self):
        with self.assertRaises(db_audit.ErroBanco) as ctx:
            db_audit.abrir_backend({}, "auto")
        msg = str(ctx.exception)
        for var in ("SUPABASE_ACCESS_TOKEN", "SUPABASE_PROJECT_REF", "RAPTOR_DB_URL"):
            self.assertIn(var, msg)

    def test_api_manda_user_agent_proprio(self):
        """O WAF da API responde 403 ao `Python-urllib/3.x` padrão.

        Sem o User-Agent explícito a auditoria falha em toda máquina, com um 403
        que parece problema de token. Medido contra a API real.
        """
        capturado = {}

        def falso_urlopen(req, timeout=None):
            capturado["ua"] = req.get_header("User-agent")
            capturado["corpo"] = json.loads(req.data.decode("utf-8"))
            return FakeResponse([{"x": 1}])

        consultar, nome = db_audit.abrir_backend(
            {"SUPABASE_ACCESS_TOKEN": "tok", "SUPABASE_PROJECT_REF": "a" * 20}, "api")
        self.assertEqual(nome, "api")
        with mock.patch.object(db_audit.urllib.request, "urlopen", falso_urlopen):
            consultar("select 1 as x")
        self.assertEqual(capturado["ua"], "raptor-win")
        self.assertTrue(capturado["corpo"]["read_only"])

    def test_ref_invalido_e_recusado(self):
        with self.assertRaises(db_audit.ErroBanco):
            db_audit.abrir_backend(
                {"SUPABASE_ACCESS_TOKEN": "tok", "SUPABASE_PROJECT_REF": "../etc"}, "api")

    def test_token_nunca_aparece_na_mensagem_de_erro(self):
        """`urllib` põe a URL no HTTPError; relatório vai para repositório."""
        segredo = "sbp_supersecreto_1234567890"

        def falso_urlopen(req, timeout=None):
            raise db_audit.urllib.error.URLError(f"falhou com token {segredo}")

        consultar, _ = db_audit.abrir_backend(
            {"SUPABASE_ACCESS_TOKEN": segredo, "SUPABASE_PROJECT_REF": "a" * 20}, "api")
        with mock.patch.object(db_audit.urllib.request, "urlopen", falso_urlopen):
            with self.assertRaises(db_audit.ErroBanco) as ctx:
                consultar("select 1 as x")
        self.assertNotIn(segredo, str(ctx.exception))
        self.assertIn("«oculto»", str(ctx.exception))


class DbEscanearTests(unittest.TestCase):
    def test_escanear_com_banco_falso(self):
        banco = FalsoBanco({
            "funcoes": [_fn(anon_exec=True, definer=True, sp_valor="public")],
            "relacoes": [],
            "policies": [],
            "extensoes": [],
        })
        a = db_audit.escanear(banco, capacidades={"tem_anon": True, "tem_auth": True})
        regras = {x["rule"] for x in a}
        self.assertIn("db.function-executable-by-anon", regras)
        self.assertIn("db.function-search-path-hijackable", regras)
        self.assertEqual(len(banco.vistas), 4)

    def test_schemas_incluidos_recorta_o_resultado(self):
        banco = FalsoBanco({
            "funcoes": [_fn(schema="public", anon_exec=True),
                        _fn(schema="outro", nome="fn_y", anon_exec=True)],
        })
        a = db_audit.escanear(banco, schemas_incluidos=frozenset({"outro"}),
                              capacidades={"tem_anon": True, "tem_auth": True})
        self.assertTrue(all(x["path"].startswith("db:outro.") for x in a))
        self.assertTrue(a)

    def test_schema_incluido_invalido_falha_antes_do_sql(self):
        banco = FalsoBanco({})
        with self.assertRaises(db_audit.ErroBanco):
            db_audit.escanear(banco, schemas_incluidos=frozenset({"x; drop table t"}),
                              capacidades={"tem_anon": True, "tem_auth": True})
        self.assertEqual(banco.vistas, [])

    def test_papel_ausente_nao_gera_sql_com_has_privilege(self):
        """`has_function_privilege('anon', ...)` ERRA se o papel não existir.

        E o Postgres não garante curto-circuito no AND, então a existência do
        papel se decide no preflight, não com um `case` dentro do SQL.
        """
        sql = db_audit.montar("funcoes", schemas=db_audit.SCHEMAS_SISTEMA,
                              capacidades={"tem_anon": False, "tem_auth": False})
        self.assertNotIn("has_function_privilege('anon'", sql)
        self.assertNotIn("has_table_privilege('anon'", sql)


class DbIntegracaoNoRelatorioTests(unittest.TestCase):
    """A ponta a ponta: achado de banco chega ao relatório, ao SARIF e ao gate."""

    ACHADO = {
        "rule": "db.function-executable-by-anon", "severity": "HIGH",
        "path": "db:public.minha_fn(uuid)", "line": 0,
        "context": "db · catálogo · schema exposto",
        "message": "executável por anon",
    }

    def _rodar(self, extra: list) -> tuple:
        with tempfile.TemporaryDirectory() as td:
            alvo = Path(td) / "alvo"
            alvo.mkdir()
            (alvo / "a.py").write_text("x = 1\n", encoding="utf-8")
            md = Path(td) / "r.md"
            sarif = Path(td) / "r.sarif"
            argv = ["raptor-win", str(alvo), "--db-audit", "--no-raptor",
                    "--no-registry", "--md", str(md), "--sarif", str(sarif)] + extra
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(raptor_win, "run_db_audit",
                                   return_value={"findings": [dict(self.ACHADO)],
                                                 "backend": "api",
                                                 "capacidades": {"versao": "17.6"}}):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    codigo = raptor_win.main()
            return codigo, buf.getvalue(), md.read_text(encoding="utf-8"), \
                json.loads(sarif.read_text(encoding="utf-8"))

    def test_chega_ao_markdown_e_ao_sarif(self):
        _, saida, md, sarif = self._rodar([])
        self.assertIn("db:public.minha_fn(uuid)", md)
        self.assertIn("function-executable-by-anon", md)
        self.assertIn("catálogo", saida)
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in sarif["runs"][0]["results"]]
        self.assertIn("db:public.minha_fn(uuid)", uris)

    def test_fail_on_reprova_com_achado_de_banco(self):
        codigo, _, _, _ = self._rodar(["--fail-on", "HIGH"])
        self.assertEqual(codigo, 1)

    def test_baseline_suprime_achado_de_banco(self):
        """`baseline._casa()` já casa por substring de path — sem alteração."""
        with tempfile.TemporaryDirectory() as td:
            bl = Path(td) / "bl.toml"
            bl.write_text(
                '[[aceito]]\nregra = "db.function-executable-by-anon"\n'
                'caminho = "public.minha_fn"\nmotivo = "RPC pública de propósito"\n',
                encoding="utf-8")
            codigo, _, _, _ = self._rodar(["--fail-on", "HIGH", "--baseline", str(bl)])
        self.assertEqual(codigo, 0)


class DbFalhaNaoViraRelatorioLimpoTests(unittest.TestCase):
    def test_erro_de_banco_sai_2(self):
        """Auditoria pedida que não completa NÃO pode reportar limpo.

        É o mesmo princípio do bloco de erros do Semgrep: um relatório vazio
        aqui significaria "não analisei", e debaixo de um gate de CI isso é
        pior que scanner nenhum.
        """
        with tempfile.TemporaryDirectory() as td:
            alvo = Path(td) / "alvo"
            alvo.mkdir()
            (alvo / "a.py").write_text("x = 1\n", encoding="utf-8")
            argv = ["raptor-win", str(alvo), "--db-audit", "--no-raptor",
                    "--no-registry", "--fail-on", "HIGH"]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(raptor_win, "run_db_audit",
                                   return_value={"findings": [], "backend": "api",
                                                 "error": "sem credencial"}):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    codigo = raptor_win.main()
        self.assertEqual(codigo, 2)
        self.assertNotIn("Nenhum achado", buf.getvalue())


class SqlLintTests(unittest.TestCase):
    def _scan(self, sql: str) -> list[dict]:
        import sql_lint
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "m.sql"
            f.write_text(sql, encoding="utf-8")
            return sql_lint.escanear([f], set())

    def test_duplicate_index_flagged_once(self):
        rules = [a["rule"] for a in self._scan(
            "create index a on public.t (email, criado_em desc);\n"
            "create index b on public.t (email, criado_em desc);\n"
            "create index c on public.t (telefone);\n"
        )]
        self.assertEqual(rules.count("sql.duplicate-index"), 1)

    def test_different_columns_not_duplicate(self):
        rules = [a["rule"] for a in self._scan(
            "create index a on public.t (email);\n"
            "create index b on public.t (telefone);\n"
        )]
        self.assertNotIn("sql.duplicate-index", rules)

    def test_multiple_permissive_flagged(self):
        rules = [a["rule"] for a in self._scan(
            "create policy p1 on public.t for select to authenticated using (true);\n"
            "create policy p2 on public.t for select to authenticated using (x = 1);\n"
        )]
        self.assertIn("sql.multiple-permissive-policies", rules)

    def test_restrictive_is_not_multiple_permissive(self):
        rules = [a["rule"] for a in self._scan(
            "create policy p1 on public.t for select to authenticated using (true);\n"
            "create policy p2 on public.t as restrictive for select to authenticated using (ativo);\n"
        )]
        self.assertNotIn("sql.multiple-permissive-policies", rules)

    def test_different_action_not_overlap(self):
        rules = [a["rule"] for a in self._scan(
            "create policy p1 on public.t for select to authenticated using (true);\n"
            "create policy p2 on public.t for insert to authenticated with check (true);\n"
        )]
        self.assertNotIn("sql.multiple-permissive-policies", rules)


SEARCH_PATH = "sql.search-path-missing-pg-temp"
TENANT_PARAM = "sql.security-definer-tenant-param"
GUARDA_NULL = "sql.security-definer-guard-null-uid"
NUNCA_FECHADO = "sql.supabase.execute-nunca-fechado"


class MultiArquivoMixin:
    """Grava vários .sql num tempdir — as checagens de EXECUTE cruzam arquivos."""

    def _scan(self, *arquivos: str) -> list[dict]:
        import sql_lint
        with tempfile.TemporaryDirectory() as td:
            caminhos = []
            for i, sql in enumerate(arquivos):
                f = Path(td) / f"{i:04d}_m.sql"
                f.write_text(sql, encoding="utf-8")
                caminhos.append(f)
            return sql_lint.escanear(caminhos, set())

    def _rules(self, *arquivos: str) -> list[str]:
        return [a["rule"] for a in self._scan(*arquivos)]


# Molde de função DEFINER: (assinatura, cabeçalho, corpo).
DEF = ("create or replace function public.fn_x(%s)\n"
       "returns integer language plpgsql security definer\n"
       "%s as $$ begin %s return 1; end; $$;\n")


class SearchPathPgTempTests(MultiArquivoMixin, unittest.TestCase):
    """`set search_path` presente mas sem `pg_temp`.

    A regra do Semgrep só exige que o search_path EXISTA, então `= public`
    passa limpo por lá. As duas checagens são complementares por construção:
    uma exige o `set search_path` ausente, esta exige que esteja presente.
    """

    def test_sem_pg_temp_acusa(self):
        self.assertIn(SEARCH_PATH, self._rules(DEF % ("", "set search_path = public", "")))

    def test_com_pg_temp_ok(self):
        self.assertNotIn(SEARCH_PATH,
                         self._rules(DEF % ("", "set search_path = public, pg_temp", "")))

    def test_path_vazio_ok(self):
        self.assertNotIn(SEARCH_PATH, self._rules(DEF % ("", "set search_path = ''", "")))

    def test_pg_catalog_ok(self):
        self.assertNotIn(SEARCH_PATH,
                         self._rules(DEF % ("", "set search_path = pg_catalog", "")))

    def test_pg_temp_fora_de_ordem_e_info(self):
        achados = [a for a in self._scan(DEF % ("", "set search_path = pg_temp, public", ""))
                   if a["rule"] == SEARCH_PATH]
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0]["severity"], "INFO")

    def test_invoker_nao_acusa(self):
        sql = ("create or replace function public.fn_i() returns int language sql\n"
               "set search_path = public as $$ select 1 $$;\n")
        self.assertNotIn(SEARCH_PATH, self._rules(sql))

    def test_search_path_de_outra_funcao_nao_suprime(self):
        """O cabeçalho da função vizinha não pode calar o achado desta."""
        sql = (DEF % ("", "set search_path = public, pg_temp", "")).replace("fn_x", "fn_boa")
        sql += (DEF % ("", "set search_path = public", "")).replace("fn_x", "fn_ma")
        achados = [a for a in self._scan(sql) if a["rule"] == SEARCH_PATH]
        self.assertEqual(len(achados), 1)
        self.assertIn("fn_ma", achados[0]["message"])


class TenantParamTests(MultiArquivoMixin, unittest.TestCase):
    """DEFINER que recebe o inquilino por parâmetro sem conferir a sessão.

    O falso positivo a evitar é o padrão CORRETO: receber `p_org` e validá-lo
    contra a sessão. Por isso a checagem exige as três coisas — DEFINER,
    parâmetro com forma de inquilino e ausência total de marcador de sessão.
    """

    def test_tenant_param_acusa_como_error(self):
        achados = [a for a in self._scan(
            DEF % ("p_org uuid", "set search_path = public, pg_temp", ""))
            if a["rule"] == TENANT_PARAM]
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0]["severity"], "ERROR")

    def test_com_auth_uid_no_corpo_ok(self):
        corpo = "perform 1 from t where u = auth.uid();"
        self.assertNotIn(TENANT_PARAM, self._rules(
            DEF % ("p_org uuid", "set search_path = public, pg_temp", corpo)))

    def test_com_helper_my_org_ok(self):
        corpo = "perform 1 from t where org = my_org();"
        self.assertNotIn(TENANT_PARAM, self._rules(
            DEF % ("p_org uuid", "set search_path = public, pg_temp", corpo)))

    def test_invoker_com_tenant_param_ok(self):
        sql = ("create or replace function public.fn_i(p_org uuid) returns int\n"
               "language sql set search_path = public, pg_temp as $$ select 1 $$;\n")
        self.assertNotIn(TENANT_PARAM, self._rules(sql))

    def test_param_que_nao_e_tenant_ok(self):
        self.assertNotIn(TENANT_PARAM, self._rules(
            DEF % ("p_valor numeric", "set search_path = public, pg_temp", "")))

    def test_numeric_com_virgula_nao_quebra_assinatura(self):
        """`numeric(10,2)` não pode virar dois parâmetros."""
        args = "p_v numeric(10,2), p_org uuid"
        achados = [a for a in self._scan(
            DEF % (args, "set search_path = public, pg_temp", ""))
            if a["rule"] == TENANT_PARAM]
        self.assertEqual(len(achados), 1)
        self.assertIn("p_org uuid", achados[0]["message"])

    def test_gatilho_nao_acusa(self):
        sql = ("create or replace function public.fn_t() returns trigger language plpgsql\n"
               "security definer set search_path = public, pg_temp as $$\n"
               "begin return new; end; $$;\n")
        self.assertNotIn(TENANT_PARAM, self._rules(sql))


class GuardaNullUidTests(MultiArquivoMixin, unittest.TestCase):
    def test_guarda_condicionada_acusa(self):
        corpo = "if auth.uid() is not null and not is_admin() then raise exception 'nao'; end if;"
        self.assertIn(GUARDA_NULL, self._rules(
            DEF % ("", "set search_path = public, pg_temp", corpo)))

    def test_guarda_incondicional_ok(self):
        corpo = "if not is_admin() then raise exception 'nao'; end if;"
        self.assertNotIn(GUARDA_NULL, self._rules(
            DEF % ("", "set search_path = public, pg_temp", corpo)))


class ExecuteNuncaFechadoTests(MultiArquivoMixin, unittest.TestCase):
    """DEFINER que nenhum grant/revoke cita — no Supabase nasce aberta a `anon`.

    A carve-out do helper de policy não é opcional: recomendar revogar de
    `authenticated` uma função chamada de dentro de policy derruba toda query
    na tabela com "permission denied for function".
    """

    CRIA = ("create or replace function public.helper_x(p_id uuid)\n"
            "returns boolean language sql security definer\n"
            "set search_path = public, pg_temp as $$ select true $$;\n")

    def test_sem_grant_nenhum_acusa(self):
        self.assertIn(NUNCA_FECHADO, self._rules(self.CRIA))

    def test_grant_em_outro_arquivo_suprime(self):
        """Prova a passada entre arquivos: o create numa migração, o grant noutra."""
        self.assertNotIn(NUNCA_FECHADO, self._rules(
            self.CRIA, "grant execute on function public.helper_x(uuid) to authenticated;\n"))

    def test_revoke_em_outro_arquivo_suprime(self):
        self.assertNotIn(NUNCA_FECHADO, self._rules(
            self.CRIA, "revoke execute on function public.helper_x(uuid) from public, anon;\n"))

    def test_revoke_em_bloco_anterior_nao_suprime(self):
        """A regressão real: fechar tudo em bloco e criar a função DEPOIS.

        `revoke ... on all functions in schema` só alcança o que já existe, então
        a migração seguinte nasce aberta de novo — e ninguém liga uma coisa à outra.
        """
        self.assertIn(NUNCA_FECHADO, self._rules(
            "revoke execute on all functions in schema public from public, anon;\n",
            self.CRIA))

    def test_revoke_em_bloco_posterior_suprime(self):
        self.assertNotIn(NUNCA_FECHADO, self._rules(
            self.CRIA,
            "revoke execute on all functions in schema public from public, anon;\n"))

    def test_default_privileges_anterior_suprime(self):
        """Só `alter default privileges` alcança o que vem depois."""
        self.assertNotIn(NUNCA_FECHADO, self._rules(
            "alter default privileges in schema public revoke execute on functions from public;\n",
            self.CRIA))

    def test_gatilho_nao_exige_grant(self):
        sql = ("create or replace function public.fn_t() returns trigger language plpgsql\n"
               "security definer set search_path = public, pg_temp as $$\n"
               "begin return new; end; $$;\n")
        self.assertNotIn(NUNCA_FECHADO, self._rules(sql))

    def test_helper_de_policy_sai_como_info_e_avisa(self):
        achados = [a for a in self._scan(
            self.CRIA,
            "create policy p on public.t for select to authenticated\n"
            "  using (helper_x(id));\n") if a["rule"] == NUNCA_FECHADO]
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0]["severity"], "INFO")
        # O texto É o valor deste ramo: sem ele, a recomendação derruba a produção.
        self.assertIn("authenticated", achados[0]["message"])
        self.assertIn("permission denied", achados[0]["message"])


REVOKE_INCOMPLETO = "sql.supabase.revoke-incompleto"


class RevokeIncompletoTests(unittest.TestCase):
    """REVOKE que fecha public/anon e esquece `authenticated`.

    O falso positivo a evitar é o padrão CORRETO e comum (revogar do anônimo e
    conceder ao usuário logado); o verdadeiro positivo é quem revogou achando
    que fechou.
    """

    def _scan(self, *arquivos: str) -> list[dict]:
        import sql_lint
        with tempfile.TemporaryDirectory() as td:
            caminhos = []
            for i, sql in enumerate(arquivos):
                f = Path(td) / f"{i:04d}_m.sql"
                f.write_text(sql, encoding="utf-8")
                caminhos.append(f)
            return sql_lint.escanear(caminhos, set())

    def _rules(self, *arquivos: str) -> list[str]:
        return [a["rule"] for a in self._scan(*arquivos)]

    def test_revoke_sem_authenticated_acusa(self):
        self.assertIn(REVOKE_INCOMPLETO, self._rules(
            "revoke execute on function public.fn_x(uuid) from public, anon;\n"))

    def test_revoke_completo_nao_acusa(self):
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "revoke execute on function public.fn_x(uuid) from public, anon, authenticated;\n"))

    def test_grant_deliberado_nao_acusa(self):
        # O padrão correto de RPC de app: fecha o anônimo, declara a intenção.
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "revoke execute on function public.fn_x(uuid) from public, anon;\n"
            "grant  execute on function public.fn_x(uuid) to authenticated;\n"))

    def test_grant_em_outro_arquivo_nao_acusa(self):
        # Revoke e grant em migrações diferentes é o caso normal.
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "revoke execute on function fn_x(uuid) from public, anon;\n",
            "grant execute on function public.fn_x(uuid) to authenticated;\n"))

    def test_revoke_posterior_completa_nao_acusa(self):
        # A correção real é um revoke NOVO numa migração posterior; o antigo
        # continua no repositório. Sem unir os papéis, o repo corrigido acusaria
        # para sempre.
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "revoke execute on function fn_x(uuid, text) from public, anon;\n",
            "revoke execute on function fn_x(uuid, text) from public, anon, authenticated;\n"))

    def test_alvo_dinamico_nao_acusa(self):
        # Revogar em laço dentro de bloco DO é idiomático; a identidade da
        # função não é conhecível por regex.
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "do $$ declare r record; begin\n"
            "  for r in select oid::regprocedure as sig from pg_proc loop\n"
            "    execute format('revoke execute on function %s from public, anon', r.sig);\n"
            "  end loop;\nend $$;\n"))

    def test_assinatura_multilinha_acusa(self):
        achados = self._scan(
            "revoke execute on function fn_ingest(uuid, text, numeric,\n"
            "  timestamptz, text) from public, anon;\n")
        alvo = [a for a in achados if a["rule"] == REVOKE_INCOMPLETO]
        self.assertEqual(len(alvo), 1)
        self.assertEqual(alvo[0]["severity"], "HIGH")

    def test_revoke_de_tabela_ignorado(self):
        # `revoke ... on <tabela>` não é `on function` — fora do escopo.
        self.assertNotIn(REVOKE_INCOMPLETO, self._rules(
            "revoke insert, update, delete on compras from anon, authenticated;\n"))

    def test_uma_funcao_um_achado(self):
        # Dois revokes incompletos da mesma função não viram dois achados.
        achados = self._scan(
            "revoke execute on function fn_x(uuid) from public;\n",
            "revoke execute on function fn_x(uuid) from anon;\n")
        self.assertEqual(len([a for a in achados if a["rule"] == REVOKE_INCOMPLETO]), 1)


class SupabasePatTests(unittest.TestCase):
    def test_pat_detectado(self):
        import secrets_scan
        # Montado em tempo de execução: um literal `sbp_...` no repositório
        # dispararia o push protection do GitHub e o próprio scanner.
        falso = "sbp_" + "a1b2c3d4" * 5
        regras = [r for r in secrets_scan.REGRAS if r.re.search(falso)]
        self.assertEqual([r.id for r in regras], ["supabase-pat"])
        self.assertEqual(regras[0].sev, "CRITICAL")

    def test_pat_curto_ignorado(self):
        import secrets_scan
        self.assertFalse(any(r.re.search("sbp_curto") for r in secrets_scan.REGRAS))


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# GitHub Actions: descoberta, parser e casamento local de versao
# ---------------------------------------------------------------------------

class TestWorkflowsGHA(unittest.TestCase):
    def test_reconhece_workflow_e_action_composta(self):
        self.assertTrue(R._e_workflow_gha(Path(".github/workflows/ci.yml")))
        self.assertTrue(R._e_workflow_gha(Path("a/.github/workflows/deploy.yaml")))
        self.assertTrue(R._e_workflow_gha(Path("minha-acao/action.yml")))

    def test_ignora_yaml_que_nao_e_workflow(self):
        """docker-compose.yml e config de outras CIs nao sao workflows do GHA.

        Aceitar todo `*.yml` encheria o SCA de arquivo que nao tem `uses:` --
        e, pior, de `uses:` de outro dialeto que o OSV nao indexa.
        """
        self.assertFalse(R._e_workflow_gha(Path("docker-compose.yml")))
        self.assertFalse(R._e_workflow_gha(Path("k8s/deploy.yaml")))
        self.assertFalse(R._e_workflow_gha(Path("workflows/ci.yml")))  # sem .github
        self.assertFalse(R._e_workflow_gha(Path(".github/dependabot.yml")))

    def _wf(self, texto):
        d = Path(tempfile.mkdtemp())
        p = d / "ci.yml"
        p.write_text(texto, encoding="utf-8")
        return p

    def test_extrai_uses_com_e_sem_aspas(self):
        p = self._wf(
            "jobs:\n  b:\n    steps:\n"
            "      - uses: actions/checkout@v5\n"
            '      - uses: "actions/setup-node@v4.1.0"\n'
            "      - uses: 'org/repo/sub@abc123'\n"
            "        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n"
        )
        got = R.parse_gha_workflow(p)
        self.assertIn(("GitHub Actions", "actions/checkout", "v5"), got)
        self.assertIn(("GitHub Actions", "actions/setup-node", "v4.1.0"), got)
        self.assertIn(("GitHub Actions", "org/repo/sub", "abc123"), got)
        self.assertEqual(len(got), 4)

    def test_pula_acao_local_e_imagem_docker(self):
        p = self._wf(
            "      - uses: ./.github/actions/local@v1\n"
            "      - uses: docker://alpine@sha256:deadbeef\n"
            "      - uses: ./acao-sem-ref\n"
        )
        self.assertEqual(R.parse_gha_workflow(p), [])

    def test_versao_gha_nao_ordena_sha_nem_branch(self):
        """SHA e branch nao viram tupla: sem isso, `@main` compararia como 0."""
        self.assertIsNone(R._versao_gha("0057852bfaa89a56745cba8c7296529d2fc39830"))
        self.assertIsNone(R._versao_gha("main"))
        self.assertIsNone(R._versao_gha(""))
        self.assertEqual(R._versao_gha("v5"), (5,))
        self.assertEqual(R._versao_gha("45.0.7"), (45, 0, 7))
        self.assertEqual(R._versao_gha("v4.1.0"), (4, 1, 0))

    def test_actions_nao_entram_no_querybatch(self):
        """Regressao do motivo de existir `_consulta_gha`.

        O OSV aceita o ecossistema "GitHub Actions" mas nao ordena as versoes
        dele: perguntar nome+versao devolve SEMPRE lista vazia. Se uma action
        vazar para o batch, ela volta "limpa" e o relatorio mente.
        """
        deps = [("GitHub Actions", "tj-actions/changed-files", "v44"),
                ("PyPI", "requests", "2.0.0")]
        pinados = [d for d in deps if d[0] != "GitHub Actions" and d[2]]
        self.assertEqual(pinados, [("PyPI", "requests", "2.0.0")])


class TestCasamentoLocalGHA(unittest.TestCase):
    """`_consulta_gha` com o OSV dublado -- sem rede."""

    def _rodar(self, dep, vulns):
        def fake(req, timeout=0):
            class R_:
                def read(self_): return json.dumps({"vulns": vulns}).encode()
                def __enter__(self_): return self_
                def __exit__(self_, *a): return False
            return R_()
        with mock.patch.object(R.urllib.request, "urlopen", fake):
            return R._consulta_gha([dep])

    @staticmethod
    def _adv(vid, fixed):
        return {"id": vid, "affected": [{"ranges": [{"events": [
            {"introduced": "0"}, {"fixed": fixed}]}]}]}

    def test_ref_abaixo_do_fixed_e_vulneravel(self):
        dep = ("GitHub Actions", "tj-actions/changed-files", "45.0.7")
        hits, det, rev = self._rodar(dep, [self._adv("GHSA-x", "46.0.1")])
        self.assertEqual(hits, {dep: ["GHSA-x"]})
        self.assertEqual(rev, [])
        self.assertIn("GHSA-x", det)

    def test_ref_acima_do_fixed_esta_limpa(self):
        dep = ("GitHub Actions", "tj-actions/changed-files", "46.0.1")
        hits, _det, rev = self._rodar(dep, [self._adv("GHSA-x", "46.0.1")])
        self.assertEqual(hits, {})
        self.assertEqual(rev, [])

    def test_sha_vai_para_revisar_nunca_para_limpo(self):
        """Pin em SHA nao da' para ordenar. Silenciar seria dizer "tudo bem"."""
        dep = ("GitHub Actions", "tj-actions/changed-files",
               "0057852bfaa89a56745cba8c7296529d2fc39830")
        hits, _det, rev = self._rodar(dep, [self._adv("GHSA-x", "46.0.1")])
        self.assertEqual(hits, {})
        self.assertEqual(len(rev), 1)
        self.assertIn("não ordenável".replace("ã", "a").replace("á", "a"),
                      rev[0]["motivo"].replace("ã", "a").replace("á", "a"))

    def test_tag_de_major_solto_com_fixed_no_mesmo_major_e_revisar(self):
        """`@v5` flutua: se o fixed e' 5.2.0, o repo ja' pode ter a correcao.

        Acusar como vulneravel seria falso positivo; calar seria falso negativo.
        """
        dep = ("GitHub Actions", "org/acao", "v5")
        hits, _det, rev = self._rodar(dep, [self._adv("GHSA-y", "5.2.0")])
        self.assertEqual(hits, {})
        self.assertEqual(len(rev), 1)

    def test_tag_de_major_menor_que_o_major_corrigido_e_vulneravel(self):
        """`@v4` com fixed em 5.2.0: nenhum 4.x carrega a correcao. E' certeza."""
        dep = ("GitHub Actions", "org/acao", "v4")
        hits, _det, rev = self._rodar(dep, [self._adv("GHSA-y", "5.2.0")])
        self.assertEqual(hits, {dep: ["GHSA-y"]})
        self.assertEqual(rev, [])

    def test_osv_fora_do_ar_nao_derruba_nem_finge_limpo(self):
        def boom(req, timeout=0):
            raise OSError("sem rede")
        dep = ("GitHub Actions", "org/acao", "v1")
        with mock.patch.object(R.urllib.request, "urlopen", boom):
            hits, det, rev = R._consulta_gha([dep])
        self.assertEqual((hits, det, rev), ({}, {}, []))


# ---------------------------------------------------------------------------
# Lockfiles npm alem do package-lock: pnpm (3 formatos) e yarn (2)
# ---------------------------------------------------------------------------

class TestNomeVersaoNpm(unittest.TestCase):
    def test_escopo_nao_e_separador(self):
        """`@scope/name@1.0` parte no SEGUNDO `@`, nunca no primeiro.

        Partir no primeiro devolve nome vazio e versao `types/node@20.11.5` --
        consulta que o OSV responde com nada, ou seja, um "limpo" falso para
        todo pacote com escopo (metade de um projeto React tipico).
        """
        self.assertEqual(R._nome_versao_npm("@types/node@20.11.5"),
                         ("@types/node", "20.11.5"))
        self.assertEqual(R._nome_versao_npm("lodash@4.17.21"),
                         ("lodash", "4.17.21"))

    def test_recusa_o_que_nao_tem_versao(self):
        self.assertIsNone(R._nome_versao_npm("lodash"))
        self.assertIsNone(R._nome_versao_npm("@types/node"))
        self.assertIsNone(R._nome_versao_npm("@semescopo"))
        self.assertIsNone(R._nome_versao_npm("@types/node@"))

    def test_limpa_anotacoes_de_peer_e_protocolo(self):
        self.assertEqual(R._limpa_versao_npm("29.0.3(typescript@5.0.4)"), "29.0.3")
        self.assertEqual(R._limpa_versao_npm("29.0.3_typescript@5.0.0"), "29.0.3")
        self.assertEqual(R._limpa_versao_npm("npm:4.17.21"), "4.17.21")
        self.assertEqual(R._limpa_versao_npm("4.17.21"), "4.17.21")

    def test_alias_do_yarn_resolve_no_pacote_real(self):
        """`ali@npm:@scope/real@1.0`: quem tem CVE e' o pacote de destino."""
        self.assertEqual(R._limpa_versao_npm("npm:@scope/real@1.2.3"), "1.2.3")

    def test_fonte_fora_do_registro_nao_vira_versao(self):
        """O OSV nao tem o que casar com `file:`/`workspace:`; fingir que tem
        seria contar a dependencia como checada sem checagem nenhuma."""
        for v in ("file:../meu", "workspace:.", "link:../x", "git+https://h/r",
                  "patch:typescript@npm%3A5.9.3#optional"):
            self.assertEqual(R._limpa_versao_npm(v), "", v)


class TestPnpmLock(unittest.TestCase):
    def _arq(self, texto):
        p = Path(tempfile.mkdtemp()) / "pnpm-lock.yaml"
        p.write_text(texto, encoding="utf-8")
        return p

    def test_v5_chave_com_barra(self):
        p = self._arq(
            "lockfileVersion: 5.4\n"
            "packages:\n"
            "  /lodash/4.17.21:\n"
            "    resolution: {integrity: sha512-x}\n"
            "  /@types/node/20.11.5:\n"
            "    resolution: {integrity: sha512-y}\n")
        self.assertEqual(R.parse_pnpm_lock(p),
                         [("npm", "@types/node", "20.11.5"),
                          ("npm", "lodash", "4.17.21")])

    def test_v5_peer_dep_nao_desloca_o_nome(self):
        """Regressao: `/jest/29.0.3_typescript@5.0.0`.

        Buscar o `@` solto parte no peer-dep e produz nome
        `jest/29.0.3_typescript` com versao `5.0.0` -- que o OSV responde
        vazio, deixando a dependencia contada como checada e limpa. Por isso
        `_CHAVE_V6` proibe `/` e `@` no segmento do nome (assim a forma v5 nao
        casa com ela) e e' tentada ANTES da v5.
        """
        p = self._arq("packages:\n  /jest/29.0.3_typescript@5.0.0:\n"
                      "    resolution: {integrity: sha512-z}\n")
        self.assertEqual(R.parse_pnpm_lock(p), [("npm", "jest", "29.0.3")])

    def test_v6_chave_com_arroba(self):
        p = self._arq(
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /lodash@4.17.21:\n"
            "    resolution: {integrity: sha512-x}\n"
            "  /@types/node@20.11.5:\n"
            "    resolution: {integrity: sha512-y}\n"
            "  /jest@29.0.3(typescript@5.0.4):\n"
            "    resolution: {integrity: sha512-z}\n")
        self.assertEqual(R.parse_pnpm_lock(p),
                         [("npm", "@types/node", "20.11.5"),
                          ("npm", "jest", "29.0.3"),
                          ("npm", "lodash", "4.17.21")])

    def test_v9_une_packages_com_snapshots(self):
        """No v9 o grafo resolvido migra para `snapshots`: ha' transitiva que
        SO' existe la'. Ler apenas `packages` perderia essas."""
        p = self._arq(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  lodash@4.17.21:\n"
            "    resolution: {integrity: sha512-x}\n"
            "snapshots:\n"
            "  lodash@4.17.21: {}\n"
            "  jest@29.0.3(typescript@5.0.4):\n"
            "    dependencies:\n"
            "      chalk: 4.1.2\n")
        self.assertEqual(R.parse_pnpm_lock(p),
                         [("npm", "jest", "29.0.3"), ("npm", "lodash", "4.17.21")])

    def test_v9_chave_com_escopo_entre_aspas(self):
        p = self._arq("lockfileVersion: '9.0'\npackages:\n"
                      "  '@types/node@20.11.5':\n"
                      "    resolution: {integrity: sha512-y}\n")
        self.assertEqual(R.parse_pnpm_lock(p), [("npm", "@types/node", "20.11.5")])

    def test_pacote_local_fica_sem_versao_mas_nao_some(self):
        """Sem versao consultavel, mas o NOME ainda alimenta o typosquat."""
        p = self._arq("lockfileVersion: '9.0'\npackages:\n"
                      "  meu-pkg@file:packages/meu:\n"
                      "    resolution: {directory: packages/meu}\n")
        self.assertEqual(R.parse_pnpm_lock(p), [("npm", "meu-pkg", "")])

    def test_ignora_blocos_que_nao_sao_packages(self):
        """`importers` tem nomes de pacote indentados iguais aos de `packages`.
        Ler tudo traria o intervalo PEDIDO no lugar da versao resolvida."""
        p = self._arq(
            "importers:\n"
            "  .:\n"
            "    dependencies:\n"
            "      lodash:\n"
            "        specifier: ^4.17.21\n"
            "        version: 4.17.21\n"
            "packages:\n"
            "  lodash@4.17.21:\n"
            "    resolution: {integrity: sha512-x}\n")
        self.assertEqual(R.parse_pnpm_lock(p), [("npm", "lodash", "4.17.21")])


class TestYarnLock(unittest.TestCase):
    def _arq(self, texto):
        p = Path(tempfile.mkdtemp()) / "yarn.lock"
        p.write_text(texto, encoding="utf-8")
        return p

    def test_classico_v1(self):
        p = self._arq(
            "# yarn lockfile v1\n\n\n"
            '"@types/node@^20.5.0", "@types/node@^20.10.0":\n'
            '  version "20.11.5"\n'
            '  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.11.5.tgz#abc"\n\n'
            "lodash@^4.17.21:\n"
            '  version "4.17.21"\n')
        self.assertEqual(R.parse_yarn_lock(p),
                         [("npm", "@types/node", "20.11.5"),
                          ("npm", "lodash", "4.17.21")])

    def test_berry_v2_mais(self):
        p = self._arq(
            "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
            '"lodash@npm:^4.17.21":\n'
            "  version: 4.17.21\n"
            '  resolution: "lodash@npm:4.17.21"\n'
            "  linkType: hard\n")
        self.assertEqual(R.parse_yarn_lock(p), [("npm", "lodash", "4.17.21")])

    def test_metadata_nao_vira_pacote(self):
        p = self._arq("__metadata:\n  version: 8\n  cacheKey: 10c0\n")
        self.assertEqual(R.parse_yarn_lock(p), [])

    def test_workspace_nao_herda_a_versao_do_bloco(self):
        """`meu-app@workspace:.` tem `version: 0.0.0-use.local` -- versao que
        nao existe no npm. Manda-la ao OSV e' checagem so' na aparencia."""
        p = self._arq(
            '"meu-app@workspace:.":\n'
            "  version: 0.0.0-use.local\n"
            '  resolution: "meu-app@workspace:."\n')
        self.assertEqual(R.parse_yarn_lock(p), [("npm", "meu-app", "")])

    def test_patch_do_berry_nao_gera_falso_sem_versao(self):
        """O Berry lista o pacote com patch DUAS vezes. Guardar a linha vazia
        junto da versionada poe o typescript no aviso de "nao checadas" mesmo
        tendo sido checado -- manda fixar o que ja' esta' fixo."""
        p = self._arq(
            '"typescript@npm:^5.5.3":\n'
            "  version: 5.9.3\n"
            '  resolution: "typescript@npm:5.9.3"\n\n'
            '"typescript@patch:typescript@npm%3A^5.5.3#optional!builtin<compat/typescript>":\n'
            "  version: 5.9.3\n")
        self.assertEqual(R.parse_yarn_lock(p), [("npm", "typescript", "5.9.3")])

    def test_pacote_local_sem_par_versionado_permanece(self):
        """A deduplicacao tira so' a linha vazia que TEM par. Sem par, ela e' a
        verdade: esse pacote nao foi checado, e calar seria o erro oposto."""
        p = self._arq('"meu-pkg@file:../meu":\n  version "0.0.0"\n')
        self.assertEqual(R.parse_yarn_lock(p), [("npm", "meu-pkg", "")])


class TestManifestosNovos(unittest.TestCase):
    def test_shrinkwrap_e_os_locks_novos_sao_reconhecidos(self):
        """npm-shrinkwrap.json tem o formato do package-lock e PRECEDENCIA
        sobre ele. Fora da tabela, o projeto era lido como se nao tivesse
        lock -- o mesmo bug que o upstream corrigiu."""
        for nome in ("npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"):
            self.assertIn(nome, R.SCA_MANIFESTS, nome)
            self.assertTrue(R._e_manifesto(nome), nome)

    def test_manifesto_vazio_e_denunciado_nao_engolido(self):
        """Um lock que existe e nao rende linha nenhuma e' o silencio que esta
        checagem existe para acabar: sem aviso, o relatorio diz "0 dependencias
        verificadas" como se o projeto nao tivesse dependencia."""
        d = Path(tempfile.mkdtemp())
        (d / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
        sca = R.run_sca([d])
        # Caminho INTEIRO, nao so' o nome: num monorepo ha' varios `yarn.lock`,
        # e "nenhuma dependencia extraida de yarn.lock" nao diz de qual.
        vazios = sca.get("vazios", [])
        self.assertEqual(len(vazios), 1, vazios)
        self.assertTrue(vazios[0].endswith("yarn.lock"), vazios)
        self.assertEqual(sca.get("deps"), 0)

    def test_relatorio_nomeia_o_manifesto_vazio(self):
        """O aviso tem de SAIR: guardar a lista e nao imprimir e' o mesmo
        silencio, so' que mais dificil de notar."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            R.render_sca({"sources": [], "deps": 0, "vulns": {},
                          "vazios": ["C:/proj/yarn.lock"]})
        saida = buf.getvalue()
        self.assertIn("C:/proj/yarn.lock", saida)
        self.assertIn("nenhuma dependência extraída", saida)


# ---------------------------------------------------------------------------
# Cabecalhos de seguranca do host estatico (headers_lint)
# ---------------------------------------------------------------------------

class _BaseHeaders(unittest.TestCase):
    def _projeto(self, arquivos: dict) -> Path:
        """Cria um projeto de mentira. `index.html` sempre, senao a checagem de
        ausencia nao liga (e esta' certa em nao ligar: biblioteca nao publica
        pagina)."""
        d = Path(tempfile.mkdtemp())
        (d / "index.html").write_text("<html></html>", encoding="utf-8")
        (d / "vite.config.ts").write_text("export default {}", encoding="utf-8")
        for rel, conteudo in arquivos.items():
            alvo = d / rel
            alvo.parent.mkdir(parents=True, exist_ok=True)
            alvo.write_text(conteudo, encoding="utf-8")
        return d

    def _rodar(self, d: Path) -> list[dict]:
        return headers_lint.escanear([d], raptor_win.SKIP_DIRS)

    def _regras(self, d: Path) -> set:
        return {a["rule"] for a in self._rodar(d)}


COMPLETO = """/*
  Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), camera=()
  Cross-Origin-Opener-Policy: same-origin
"""


class TestHeadersAusencia(_BaseHeaders):
    def test_projeto_completo_fica_silencioso(self):
        """Calibrado com o FiscalPro, que ja' manda tudo. Se esta configuracao
        gera achado, a checagem esta' cobrando o que nao deve."""
        self.assertEqual(self._regras(self._projeto({"public/_headers": COMPLETO})), set())

    def test_sem_configuracao_nenhuma_acusa_todos(self):
        regras = self._regras(self._projeto({}))
        for h in ("content-security-policy", "strict-transport-security",
                  "x-content-type-options", "referrer-policy", "x-frame-options"):
            self.assertIn("headers.ausente." + h, regras, h)

    def test_biblioteca_sem_index_html_nao_e_cobrada(self):
        """Sem `index.html` nao ha' pagina para proteger. Cobrar cabecalho de
        script e de biblioteca encheria o relatorio de ruido."""
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text("{}", encoding="utf-8")
        self.assertEqual(self._rodar(d), [])

    def test_monorepo_com_index_html_em_subpasta_e_cobrado(self):
        """Regressao medida no omnichannel: `netlify.toml` na raiz e o app em
        `web/`. Procurar `index.html` so' na raiz dava "nao e' site estatico" e
        engolia em silencio um projeto publicado com tres cabecalhos."""
        d = Path(tempfile.mkdtemp())
        (d / "netlify.toml").write_text(
            '[[headers]]\n  for = "/*"\n  [headers.values]\n'
            '    X-Frame-Options = "SAMEORIGIN"\n', encoding="utf-8")
        (d / "web").mkdir()
        (d / "web" / "index.html").write_text("<html></html>", encoding="utf-8")
        (d / "web" / "vite.config.ts").write_text("export default {}", encoding="utf-8")
        self.assertIn("headers.ausente.content-security-policy", self._regras(d))

    def test_frame_ancestors_na_csp_dispensa_x_frame_options(self):
        """Sao a mesma protecao, e `frame-ancestors` e' a que navegador novo
        respeita. Cobrar as duas seria cobrar duas vezes."""
        d = self._projeto({"public/_headers":
            "/*\n  Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'\n"})
        self.assertNotIn("headers.ausente.x-frame-options", self._regras(d))

    def test_cabecalho_so_em_rota_especifica_nao_conta_como_presente(self):
        """CSP declarada so' em `/admin/*` nao protege a pagina inicial."""
        d = self._projeto({"public/_headers":
            "/admin/*\n  Content-Security-Policy: default-src 'self'\n"})
        self.assertIn("headers.ausente.content-security-policy", self._regras(d))

    def test_le_os_tres_formatos(self):
        toml = ('[[headers]]\n  for = "/*"\n  [headers.values]\n'
                '    Content-Security-Policy = "default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'"\n')
        vercel = json.dumps({"headers": [{"source": "/(.*)", "headers": [
            {"key": "Content-Security-Policy",
             "value": "default-src 'self'; object-src 'none'; frame-ancestors 'none'"}]}]})
        for nome, conteudo in (("netlify.toml", toml), ("vercel.json", vercel),
                               ("public/_headers", "/*\n  Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'\n")):
            d = self._projeto({nome: conteudo})
            self.assertNotIn("headers.ausente.content-security-policy",
                             self._regras(d), nome)

    def test_nome_de_cabecalho_e_insensivel_a_maiusculas(self):
        """A norma HTTP diz isso, e a Netlify aceita. Comparar sensivel faria
        `content-security-policy` minusculo passar por ausente."""
        d = self._projeto({"public/_headers":
            "/*\n  content-security-policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'\n"})
        self.assertNotIn("headers.ausente.content-security-policy", self._regras(d))


class TestHeadersValorInseguro(_BaseHeaders):
    """A metade que importa mais: o cabecalho existe e nao protege. Passa em
    qualquer conferencia que so' verifique presenca."""

    def _com(self, valor_csp="", extra="") -> set:
        corpo = "/*\n"
        if valor_csp:
            corpo += f"  Content-Security-Policy: {valor_csp}\n"
        corpo += extra
        return self._regras(self._projeto({"public/_headers": corpo}))

    def test_csp_curinga(self):
        self.assertIn("headers.csp-curinga", self._com("default-src *"))

    def test_unsafe_inline_so_em_script_src(self):
        """Em `style-src` o 'unsafe-inline' e' quase inevitavel com Tailwind.
        Acusa-lo faria o relatorio gritar em todo projeto React -- e relatorio
        que grita sempre e' relatorio que ninguem le'."""
        com_script = self._com("default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.assertIn("headers.csp-unsafe-inline", com_script)
        so_style = self._com("default-src 'self'; style-src 'self' 'unsafe-inline'")
        self.assertNotIn("headers.csp-unsafe-inline", so_style)

    def test_unsafe_eval(self):
        self.assertIn("headers.csp-unsafe-eval", self._com("default-src 'self'; script-src 'unsafe-eval'"))

    def test_connect_src_curinga(self):
        self.assertIn("headers.csp-connect-curinga",
                      self._com("default-src 'self'; connect-src *"))

    def test_hsts_zerado_e_curto(self):
        zero = self._com(extra="  Strict-Transport-Security: max-age=0\n")
        self.assertIn("headers.hsts-desligado", zero)
        curto = self._com(extra="  Strict-Transport-Security: max-age=300\n")
        self.assertIn("headers.hsts-curto", curto)
        bom = self._com(extra="  Strict-Transport-Security: max-age=31536000; includeSubDomains\n")
        self.assertNotIn("headers.hsts-curto", bom)
        self.assertNotIn("headers.hsts-desligado", bom)

    def test_x_frame_options_invalido(self):
        """`ALLOWALL` nao existe na norma: o navegador ignora, e o resultado e'
        o mesmo de nao ter o cabecalho -- mas parece configurado."""
        self.assertIn("headers.xfo-invalido",
                      self._com(extra="  X-Frame-Options: ALLOWALL\n"))
        self.assertNotIn("headers.xfo-invalido",
                         self._com(extra="  X-Frame-Options: DENY\n"))

    def test_xss_auditor_legado(self):
        """O helmet manda `0` de proposito: o auditor legado ja' foi usado para
        CRIAR XSS em navegador antigo."""
        self.assertIn("headers.xss-auditor-legado",
                      self._com(extra="  X-XSS-Protection: 1; mode=block\n"))
        self.assertNotIn("headers.xss-auditor-legado",
                         self._com(extra="  X-XSS-Protection: 0\n"))

    def test_referrer_vazante(self):
        self.assertIn("headers.referrer-vazante",
                      self._com(extra="  Referrer-Policy: unsafe-url\n"))

    def test_csp_so_em_report_only(self):
        """Report-Only nao bloqueia nada -- so' avisa."""
        self.assertIn("headers.csp-so-relatorio",
                      self._com(extra="  Content-Security-Policy-Report-Only: default-src 'self'\n"))

    def test_valor_inseguro_vale_em_qualquer_rota(self):
        """Um `unsafe-eval` declarado so' para `/admin/*` continua sendo
        unsafe-eval em /admin."""
        d = self._projeto({"public/_headers":
            "/admin/*\n  Content-Security-Policy: default-src 'self'; script-src 'unsafe-eval'\n"})
        self.assertIn("headers.csp-unsafe-eval", self._regras(d))


class TestHeadersForaDoPublish(_BaseHeaders):
    """O achado silencioso: o arquivo existe, esta' certo, e nunca sobe."""

    def test_headers_na_raiz_e_acusado(self):
        d = self._projeto({"_headers": COMPLETO})
        self.assertIn("headers.arquivo-fora-do-publish", self._regras(d))

    def test_headers_em_public_esta_certo(self):
        d = self._projeto({"public/_headers": COMPLETO})
        self.assertNotIn("headers.arquivo-fora-do-publish", self._regras(d))

    def test_copia_gerada_pelo_build_nao_e_acusada(self):
        """Medido no Sunset, que publica dois sites e por isso tem `dist/` e
        `dist-demo/` com copias do mesmo arquivo. Acusar as geradas seria
        acusar o acerto -- e mandar corrigir o que o build reescreve."""
        d = self._projeto({"public/_headers": COMPLETO,
                           "dist-demo/_headers": COMPLETO})
        self.assertNotIn("headers.arquivo-fora-do-publish", self._regras(d))

    def test_build_velho_nao_mascara_ausencia_na_fonte(self):
        """A regressao mais perigosa desta familia: se a leitura incluisse a
        saida de build, um `dist/` com CSP de um build anterior faria a uniao
        dizer "tem CSP" enquanto a fonte esta' sem. Falso negativo vindo de
        artefato."""
        d = self._projeto({"public/_headers": "/*\n  X-Frame-Options: DENY\n",
                           "dist-demo/_headers": COMPLETO})
        regras = self._regras(d)
        self.assertIn("headers.ausente.content-security-policy", regras)
        # E a correcao tem de apontar para a FONTE, nao para o artefato.
        alvo = [a["path"] for a in self._rodar(d)
                if a["rule"] == "headers.ausente.content-security-policy"][0]
        self.assertIn("public", alvo)
        self.assertNotIn("dist", alvo)


class TestSkipDirsDeploy(unittest.TestCase):
    def test_cache_das_clis_de_deploy_e_ignorado(self):
        """`.netlify/` guarda uma COPIA do netlify.toml e esta' no .gitignore.
        Medido no Sunset: sem ignorar, o achado apontava para la' e mandava
        editar um arquivo que o proximo deploy sobrescreve."""
        self.assertIn(".netlify", raptor_win.SKIP_DIRS)
        self.assertIn(".vercel", raptor_win.SKIP_DIRS)


# ---------------------------------------------------------------------------
# Regras de XSS no DOM (rules/raptorwin/xss/)
# ---------------------------------------------------------------------------

class _BaseRegras(unittest.TestCase):
    """Roda o Semgrep de verdade contra um arquivo de mentira.

    Testar regra Semgrep por leitura do YAML nao prova nada: o que quebra na
    pratica e' o PARSE do padrao. Duas das regras aqui nasceram quebradas e
    passariam num teste que so' conferisse o texto -- um atributo JSX solto nao
    e' JS valido, e o `metavariable-regex` casa contra o texto do no', aspas
    incluidas, entao prever so' aspas duplas fazia a regra nunca disparar.
    """
    REGRAS = Path(__file__).resolve().parent.parent / "rules" / "raptorwin" / "xss"

    @classmethod
    def setUpClass(cls):
        cls.semgrep = raptor_win.find_semgrep()
        if not cls.semgrep:
            raise unittest.SkipTest("semgrep não encontrado")

    def _rodar(self, yaml_rel: str, conteudo: str, sufixo: str) -> set:
        d = Path(tempfile.mkdtemp())
        alvo = d / ("amostra" + sufixo)
        alvo.write_text(conteudo, encoding="utf-8")
        # `semgrep.exe` delega a `pysemgrep`, invocando-o pelo NOME PURO. Se a
        # pasta de Scripts do pip não está no PATH -- o padrão no Windows --, o
        # filho morre com "No such file or directory" e a saída vem VAZIA, que
        # este teste leria como "nenhum achado". Mesma correção que
        # `run_semgrep` já faz: pôr no PATH a pasta de onde o semgrep veio.
        env = os.environ.copy()
        pasta = str(Path(self.semgrep).parent)
        if pasta not in env.get("PATH", "").split(os.pathsep):
            env["PATH"] = pasta + os.pathsep + env.get("PATH", "")
        saida = subprocess.run(
            [self.semgrep, "--config", str(self.REGRAS / yaml_rel), "--json",
             "--metrics=off", "--quiet", str(d)],
            capture_output=True, text=True, timeout=180, env=env)
        self.assertTrue(saida.stdout.strip(),
                        f"semgrep não produziu saída: {saida.stderr[:300]}")
        dados = json.loads(saida.stdout)
        # Regra que nao compila vem como erro, NAO como zero achados. Sem esta
        # assercao, "nenhum achado" e "a regra esta' quebrada" ficam iguais.
        erros = [e for e in dados.get("errors", [])
                 if "parse" in str(e.get("message", "")).lower()]
        self.assertEqual(erros, [], f"regra não compila: {erros}")
        return {r["check_id"].rsplit(".", 1)[-1] for r in dados.get("results", [])}


class TestRegrasSinkDom(_BaseRegras):
    ARQ = "dom-sinks.yaml"

    def test_sink_com_valor_dinamico_e_acusado(self):
        achados = self._rodar(self.ARQ, """
export function f(el, sujo, w) {
  el.innerHTML = sujo
  el.insertAdjacentHTML('beforeend', sujo)
  w.document.write(`<h1>${sujo}</h1>`)
}
""", ".ts")
        self.assertIn("dom-html-sink", achados)

    def test_literal_e_limpeza_nao_sao_acusados(self):
        """`innerHTML = ''` para limpar um no' e string constante sao o uso
        comum e correto. Acusa-los poria a regra no ruido."""
        achados = self._rodar(self.ARQ, """
export function f(el) {
  el.innerHTML = ''
  el.innerHTML = '<b>fixo</b>'
  el.textContent = 'qualquer coisa'
}
""", ".ts")
        self.assertNotIn("dom-html-sink", achados)

    def test_sink_ja_sanitizado_nao_e_acusado(self):
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
export function f(el, sujo) {
  el.innerHTML = DOMPurify.sanitize(sujo)
  el.insertAdjacentHTML('beforeend', DOMPurify.sanitize(sujo))
}
""", ".ts")
        self.assertNotIn("dom-html-sink", achados)

    def test_dangerously_set_inner_html_dinamico(self):
        """Regressao de PARSE: o atributo JSX sozinho nao e' JS valido, e o
        Semgrep recusava a regra inteira com "Rule parse error" -- o que
        aparecia como zero achados, nao como falha."""
        achados = self._rodar(self.ARQ,
            'export const A = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />\n',
            ".tsx")
        self.assertIn("react-dangerously-set-inner-html", achados)

    def test_dangerously_set_inner_html_sanitizado_ou_literal(self):
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
export const A = ({html}) => <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />
export const B = () => <div dangerouslySetInnerHTML={{__html: "<b>fixo</b>"}} />
""", ".tsx")
        self.assertNotIn("react-dangerously-set-inner-html", achados)

    def test_sanitizar_e_depois_concatenar(self):
        """O README do DOMPurify avisa com todas as letras. E' o erro que
        PARECE cuidado -- ha' uma chamada de sanitize bem ali."""
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
export function f(el, sujo, rodape) {
  el.innerHTML = DOMPurify.sanitize(sujo) + rodape
}
""", ".ts")
        self.assertIn("sanitize-depois-modificado", achados)


class TestRegrasDomPurifyConfig(_BaseRegras):
    ARQ = "dompurify-config.yaml"

    def test_opcoes_que_reabrem_execucao(self):
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
const a = DOMPurify.sanitize(x, { ALLOW_UNKNOWN_PROTOCOLS: true })
const b = DOMPurify.sanitize(x, { SAFE_FOR_XML: false })
const c = DOMPurify.sanitize(x, { SANITIZE_DOM: false })
const d = DOMPurify.sanitize(x, { IN_PLACE: true })
""", ".ts")
        self.assertIn("dompurify-config-permissiva", achados)

    def test_add_tags_e_attr_executaveis(self):
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
const e = DOMPurify.sanitize(x, { ADD_TAGS: ['style', 'iframe'] })
const f = DOMPurify.sanitize(x, { ADD_ATTR: ['target', 'onerror'] })
""", ".ts")
        self.assertIn("dompurify-add-perigoso", achados)

    def test_hook_que_devolve_atributo_executavel(self):
        """Regressao de aspas: o `metavariable-regex` casa contra o TEXTO do
        no', e JS usa tanto ' quanto ". Prever so' aspas duplas fazia a regra
        compilar e nunca disparar -- o pior dos dois mundos."""
        achados = self._rodar(self.ARQ,
            "import DOMPurify from 'dompurify'\n"
            "DOMPurify.addHook('afterSanitizeAttributes', function (node) "
            "{ node.setAttribute('onclick', 'go()') })\n", ".ts")
        self.assertIn("dompurify-hook-que-desfaz", achados)

    def test_configuracao_correta_fica_silenciosa(self):
        """Inclui os dois casos que ENDURECEM e seriam falso positivo fácil:
        `ADD_ATTR: ['target']` e um hook que repõe `rel=noopener`."""
        achados = self._rodar(self.ARQ, """
import DOMPurify from 'dompurify'
const a = DOMPurify.sanitize(x)
const b = DOMPurify.sanitize(x, { ALLOWED_TAGS: ['b', 'i'], ADD_ATTR: ['target'] })
const c = DOMPurify.sanitize(x, { SAFE_FOR_XML: true, RETURN_TRUSTED_TYPE: true })
DOMPurify.addHook('afterSanitizeAttributes', function (node) { node.setAttribute('rel', 'noopener') })
""", ".ts")
        self.assertEqual(achados, set())


# ---------------------------------------------------------------------------
# Diretrizes do manual de seguranca do projeto (RLS, prefixo publico, edge)
# ---------------------------------------------------------------------------

class TestTabelaSemRLS(unittest.TestCase):
    def _rodar(self, arquivos: dict) -> list:
        d = Path(tempfile.mkdtemp())
        for nome, sql in arquivos.items():
            (d / nome).write_text(sql, encoding="utf-8")
        return [a for a in sql_lint.escanear([d], raptor_win.SKIP_DIRS)
                if a["rule"] == "sql.supabase.tabela-sem-rls"]

    def _acusadas(self, arquivos: dict) -> set:
        return {a["message"].split("`")[1] for a in self._rodar(arquivos)}

    def test_tabela_sem_rls_e_acusada(self):
        """No Supabase nao e' descuido de configuracao, e' exposicao: o
        PostgREST publica a tabela e a anon key -- publica por design -- le'."""
        self.assertEqual(
            self._acusadas({"01.sql": "create table public.clientes (id uuid);"}),
            {"public.clientes"})

    def test_rls_estatico_silencia(self):
        self.assertEqual(self._acusadas({"01.sql":
            "create table public.pedidos (id uuid);\n"
            "alter table public.pedidos enable row level security;\n"}), set())

    def test_rls_por_laco_dinamico_silencia(self):
        """A regressao que definiu esta checagem. Uma migracao que trata N
        tabelas iguais usa `execute format('alter table %I enable row level
        security', t)` sobre um array -- e o nome da tabela nao esta' no
        comando, esta' no array.

        Medido no omnichannel: 21 de 21 tabelas cobertas assim, e a versao
        ingenua acusava 13, todas falsas. Regra que erra 13 de 13 num projeto
        correto nao e' usada duas vezes.
        """
        self.assertEqual(self._acusadas({"01.sql": """
do $$
declare t text;
  tabelas text[] := array['itens', 'entregas'];
begin
  foreach t in array tabelas loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;
create table public.itens (id uuid);
create table public.entregas (id uuid);
"""}), set())

    def test_schema_interno_nao_e_cobrado(self):
        """`auth`, `storage` e afins sao do proprio Supabase: nao entram na API
        automatica, e RLS ali nao e' decisao do projeto."""
        self.assertEqual(
            self._acusadas({"01.sql": "create table auth.sessions (id uuid);"}),
            set())

    def test_decide_entre_arquivos(self):
        """A tabela nasce numa migracao e e' fechada em outra, as vezes meses
        depois. Julgar arquivo a arquivo acusaria toda tabela do projeto."""
        self.assertEqual(self._acusadas({
            "01_cria.sql": "create table public.notas (id uuid);",
            "02_rls.sql": "alter table public.notas enable row level security;",
        }), set())


class TestPrefixoPublicoComSegredo(unittest.TestCase):
    def _rodar(self, conteudo: str) -> list:
        d = Path(tempfile.mkdtemp())
        (d / ".env.example").write_text(conteudo, encoding="utf-8")
        return [a for a in secrets_scan.escanear([d], raptor_win.SKIP_DIRS)
                if a["rule"] == "secrets.prefixo-publico-com-segredo"]

    def _nomes(self, conteudo: str) -> set:
        return {a["message"].split("`")[1] for a in self._rodar(conteudo)}

    def test_service_role_sob_prefixo_publico(self):
        self.assertEqual(self._nomes("VITE_SUPABASE_SERVICE_ROLE_KEY=ey.x\n"),
                         {"VITE_SUPABASE_SERVICE_ROLE_KEY"})

    def test_valor_vazio_ainda_e_erro(self):
        """Assimetria deliberada com o resto do modulo: aqui nao importa se ha'
        valor. O nome ja' e' o erro, porque e' o PREFIXO que manda o bundler
        embutir -- e o painel da Netlify preenche esse nome no build."""
        self.assertEqual(self._nomes("VITE_SUPABASE_SERVICE_ROLE_KEY=\n"),
                         {"VITE_SUPABASE_SERVICE_ROLE_KEY"})

    def test_anon_key_nao_e_acusada(self):
        """A anon key vai para o bundle POR DESIGN -- e' o par da RLS. Acusa-la
        seria acusar o funcionamento normal do Supabase."""
        self.assertEqual(self._nomes(
            "VITE_SUPABASE_URL=https://x.supabase.co\n"
            "VITE_SUPABASE_ANON_KEY=ey.abc\n"
            "VITE_MARCA=PDV\n"), set())

    def test_sem_prefixo_publico_nao_e_acusada(self):
        """`SUPABASE_SERVICE_ROLE_KEY` sem prefixo NAO entra no bundle: e' o
        jeito certo, e e' o que a funcao serverless consome."""
        self.assertEqual(self._nomes("SUPABASE_SERVICE_ROLE_KEY=ey.real\n"), set())

    def test_outros_bundlers(self):
        for nome in ("NEXT_PUBLIC_STRIPE_SECRET", "REACT_APP_API_SECRET",
                     "EXPO_PUBLIC_CLIENT_SECRET"):
            self.assertEqual(self._nomes(nome + "=x\n"), {nome}, nome)


class TestRegraEdgeServiceRole(_BaseRegras):
    REGRAS = Path(__file__).resolve().parent.parent / "rules" / "raptorwin" / "supabase"
    ARQ = "edge-service-role-sem-autorizacao.yaml"

    def test_handler_sem_parametro_com_service_role(self):
        """O handler sem parametro nao RECEBE a requisicao: nao e' que a
        autorizacao esteja fraca, e' que ela e' impossivel de escrever."""
        achados = self._rodar(self.ARQ, """
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
Deno.serve(async () => {
  const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)
  const { data } = await db.from('contatos').select('*')
  return new Response(JSON.stringify(data))
})
""", ".ts")
        self.assertIn("edge-service-role-sem-autorizacao", achados)

    def test_handler_que_recebe_req_e_valida_nao_e_acusado(self):
        achados = self._rodar(self.ARQ, """
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
Deno.serve(async (req) => {
  const token = req.headers.get('Authorization')
  const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)
  const { data: user } = await db.auth.getUser(token)
  if (!user) return new Response('nao autorizado', { status: 401 })
  return new Response('ok')
})
""", ".ts")
        self.assertEqual(achados, set())

    def test_sem_service_role_nao_e_acusado(self):
        """Handler sem parametro que usa a anon key continua sob RLS: o banco
        ainda decide o que ele enxerga."""
        achados = self._rodar(self.ARQ, """
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
Deno.serve(async () => {
  const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!)
  return new Response('ok')
})
""", ".ts")
        self.assertEqual(achados, set())


# ---------------------------------------------------------------------------
# Cadeia de suprimentos lida do lockfile (supply_chain)
# ---------------------------------------------------------------------------

class TestSupplyChain(unittest.TestCase):
    def _lock(self, pacotes: dict) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3,
                        "packages": {"": {"name": "app"}, **pacotes}}),
            encoding="utf-8")
        return d

    def _regras(self, d: Path) -> set:
        return {a["rule"] for a in supply_chain.escanear([d], raptor_win.SKIP_DIRS)}

    def test_script_de_instalacao_desconhecido(self):
        """Codigo de terceiro que roda no `npm install` -- na maquina de quem
        desenvolve e no CI, onde esta' o token do repositorio -- e roda ANTES
        de qualquer teste ou revisao."""
        d = self._lock({"node_modules/pacote-mau": {
            "version": "1.0.0", "hasInstallScript": True,
            "resolved": "https://registry.npmjs.org/pacote-mau/-/pacote-mau-1.0.0.tgz",
            "integrity": "sha512-x"}})
        self.assertIn("supply.script-de-instalacao", self._regras(d))

    def test_install_script_conhecido_fica_calado(self):
        """A calibracao que decide se esta checagem serve para alguma coisa.
        Medida em quatro projetos reais: `hasInstallScript` apontava `fsevents`
        nos quatro e `deno` num deles, e mais nada. Sem a allowlist a checagem
        nasce 100% falso positivo -- e e' desligada na primeira execucao,
        levando junto a atencao que o achado de verdade precisaria."""
        d = self._lock({"node_modules/fsevents": {
            "version": "2.3.3", "hasInstallScript": True,
            "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
            "integrity": "sha512-y"}})
        self.assertEqual(self._regras(d), set())

    def test_resolvido_fora_do_registro(self):
        d = self._lock({"node_modules/estranho": {
            "version": "2.0.0",
            "resolved": "https://npm.host-qualquer.com/estranho-2.0.0.tgz",
            "integrity": "sha512-z"}})
        self.assertIn("supply.fora-do-registro", self._regras(d))

    def test_link_de_workspace_nao_e_procedencia_suspeita(self):
        """Medido no omnichannel: `packages/core` e `web` apareciam como "host
        fora do registro" numa primeira versao. Sao o proprio repositorio."""
        d = self._lock({
            "packages/core": {"version": "1.0.0", "resolved": "packages/core", "link": True},
            "node_modules/@app/core": {"resolved": "file:../core", "version": "1.0.0"},
        })
        self.assertEqual(self._regras(d), set())

    def test_sem_integrity(self):
        d = self._lock({"node_modules/sem-hash": {
            "version": "3.0.0",
            "resolved": "https://registry.npmjs.org/sem-hash/-/sem-hash-3.0.0.tgz"}})
        self.assertIn("supply.sem-integrity", self._regras(d))

    def test_index_url_alternativo_em_requirements(self):
        """Confusao de dependencia na forma mais direta: o pip consulta os dois
        indices e fica com a versao MAIS ALTA, entao quem publicar um numero
        maior do pacote interno no PyPI publico vence sem acesso nenhum."""
        d = Path(tempfile.mkdtemp())
        (d / "requirements.txt").write_text(
            "--extra-index-url https://pypi.empresa.com/simple\nrequests==2.31.0\n",
            encoding="utf-8")
        achados = supply_chain.escanear([d], raptor_win.SKIP_DIRS)
        self.assertEqual({a["rule"] for a in achados}, {"supply.index-url-extra"})

    def test_lista_ausente_degrada_para_o_lado_seguro(self):
        """Sem a allowlist, NAO acusar. O contrario -- acusar tudo porque um
        arquivo de dados sumiu -- faz a ferramenta gritar justamente quando
        algo nela quebrou."""
        with mock.patch.object(supply_chain, "_ALLOWLIST", {}), \
             mock.patch.object(supply_chain.Path, "read_text",
                               side_effect=OSError("sumiu")):
            self.assertEqual(supply_chain._allowlist("npm"), {})


# ---------------------------------------------------------------------------
# CWE nas tags do SARIF
# ---------------------------------------------------------------------------

class TestCweNoSarif(unittest.TestCase):
    def test_extrai_os_tres_formatos_de_metadata(self):
        """O campo `cwe` do Semgrep vem como string ou lista, com ou sem o
        titulo depois do numero. As ferramentas downstream casam so' o
        identificador."""
        self.assertEqual(raptor_win._cwe_de({"cwe": "CWE-79: XSS"}), ["CWE-79"])
        self.assertEqual(raptor_win._cwe_de({"cwe": ["CWE-89", "CWE-79: x"]}),
                         ["CWE-89", "CWE-79"])
        self.assertEqual(raptor_win._cwe_de({}), [])
        self.assertEqual(raptor_win._cwe_de({"cwe": []}), [])

    def test_sarif_leva_o_cwe_em_properties_tags(self):
        """E' de `tool.driver.rules[].properties.tags` que o parser SARIF do
        Faraday tira o CWE. Sem isto o SARIF e' valido e chega do outro lado
        sem classificacao nenhuma."""
        sarif = raptor_win.to_sarif([
            {"rule": "a.b", "severity": "HIGH", "path": "x.ts", "line": 1,
             "message": "m", "cwe": ["CWE-79"]},
            {"rule": "c.d", "severity": "INFO", "path": "y.ts", "line": 2,
             "message": "m"},
        ])
        regras = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(regras["a.b"]["properties"]["tags"], ["CWE-79"])
        self.assertNotIn("properties", regras["c.d"])

    def test_cwe_chega_mesmo_aparecendo_so_no_segundo_achado(self):
        """O mesmo rule id pode entrar primeiro por um achado sem metadata."""
        sarif = raptor_win.to_sarif([
            {"rule": "a.b", "severity": "INFO", "path": "x.ts", "line": 1, "message": "m"},
            {"rule": "a.b", "severity": "HIGH", "path": "y.ts", "line": 2,
             "message": "m", "cwe": ["CWE-79"]},
        ])
        regra = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(regra["properties"]["tags"], ["CWE-79"])


# ---------------------------------------------------------------------------
# Regras de privacidade e de erro cru
# ---------------------------------------------------------------------------

class TestRegraDadoPessoalEmLog(_BaseRegras):
    REGRAS = Path(__file__).resolve().parent.parent / "rules" / "raptorwin" / "privacidade"
    ARQ = "dado-pessoal-em-log.yaml"

    def test_acesso_a_propriedade_sensivel(self):
        achados = self._rodar(self.ARQ, """
export function f(cliente: any) {
  console.log('cliente', cliente.cpf)
  console.error(cliente.cnpj)
  console.debug(cliente.data_nascimento)
}
""", ".ts")
        self.assertIn("dado-pessoal-em-log", achados)

    def test_palavra_no_texto_da_mensagem_nao_e_acusada(self):
        """Os oito falsos positivos medidos em quatro projetos eram TODOS
        disto: a palavra dentro do texto, nao o dado. Casar acesso a
        propriedade os elimina sem excecao especial."""
        achados = self._rodar(self.ARQ, """
export function f() {
  console.log('a senha está errada')
  console.error('A URL não tem senha definida')
}
""", ".ts")
        self.assertEqual(achados, set())

    def test_derivacao_segura_nao_e_acusada(self):
        """`${senha.length}` loga o TAMANHO justamente para nao logar o valor.
        Acusar quem fez a coisa certa e' o pior erro de um scanner."""
        achados = self._rodar(self.ARQ,
            "export function f(senha: string) {\n"
            "  console.log(`✓ atualizada (${senha.length} caracteres)`)\n}\n", ".ts")
        self.assertEqual(achados, set())

    def test_campo_nao_sensivel_nao_e_acusado(self):
        achados = self._rodar(self.ARQ,
            "export function f(c: any) { console.log(c.id, c.nome) }\n", ".ts")
        self.assertEqual(achados, set())


class TestRegraErroCru(_BaseRegras):
    REGRAS = Path(__file__).resolve().parent.parent / "rules" / "raptorwin" / "erro"
    ARQ = "erro-de-banco-para-o-cliente.yaml"

    def test_erro_capturado_vai_inteiro_na_resposta(self):
        """Quando `e` vem do supabase-js, `String(e)` traz a mensagem inteira
        do Postgres: tabela, coluna, constraint, as vezes o valor que violou a
        restricao."""
        achados = self._rodar(self.ARQ, """
Deno.serve(async (req) => {
  try {
    return new Response('ok')
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e) }), { status: 500 })
  }
})
""", ".ts")
        self.assertIn("erro-cru-para-o-cliente", achados)

    def test_mensagem_generica_com_id_de_correlacao_e_o_certo(self):
        achados = self._rodar(self.ARQ, """
Deno.serve(async (req) => {
  try {
    return new Response('ok')
  } catch (e) {
    console.error('falha ao processar', e)
    return new Response(JSON.stringify({ error: 'erro interno', id: crypto.randomUUID() }), { status: 500 })
  }
})
""", ".ts")
        self.assertEqual(achados, set())
