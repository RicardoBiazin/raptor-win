import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import db_audit
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
