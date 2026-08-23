-- Fixture de teste do raptor-win (NÃO é banco real; nomes genéricos).
-- Padrões de segurança/performance em Postgres/Supabase. Os casos marcados
-- "(ok)" são a forma correta e NÃO devem gerar achado.

-- ── RLS: SELECT liberado ao papel anônimo ─────────────────────────────────
-- RLS filtra LINHA, nunca COLUNA: uma policy de SELECT para `anon` entrega
-- todas as colunas das linhas que casam (estoque, custo, códigos, PII).

-- Caso 1: tabela inteira aberta ao anônimo (using (true)).
create policy t1_select on public.tabela_um
  for select to anon, authenticated using (true);

-- Caso 2: filtrada por linha, mas ainda todas as colunas das linhas ativas.
create policy t2_select_anon on public.tabela_dois
  for select to anon using (ativo = true);

-- ── VIEW SECURITY DEFINER ─────────────────────────────────────────────────
-- Roda com os privilégios do dono e ignora o RLS de quem consulta.
create view public.view_exemplo with (security_invoker = false) as
  select id, nome, preco from public.tabela_dois where ativo;

-- View correta (ok): security_invoker = true.
create view public.view_ok with (security_invoker = true) as
  select id, nome, preco from public.tabela_dois where ativo;

-- ── Função SECURITY DEFINER sem search_path fixo ──────────────────────────
create or replace function public.fn_touch()
returns trigger language plpgsql security definer as $$
begin new.updated_at := now(); return new; end; $$;

-- Função SECURITY DEFINER COM search_path (ok).
create or replace function public.fn_touch_ok()
returns trigger language plpgsql security definer
set search_path = public, pg_temp as $$
begin new.updated_at := now(); return new; end; $$;

-- ── EXECUTE de função exposto a anon/PUBLIC (vira RPC pública) ─────────────
grant execute on function public.fn_admin(uuid) to anon;
grant execute on function public.fn_setup() to public;

-- Grant só a authenticated (ok).
grant execute on function public.fn_do_usuario() to authenticated;

-- ── REVOKE que esquece `authenticated` ────────────────────────────────────
-- O Supabase roda `alter default privileges ... grant execute on functions to
-- anon, authenticated`, então cada função nasce com um grant PRÓPRIO para
-- `authenticated`. Revogar de `public` não desfaz esse grant — a função segue
-- chamável por qualquer usuário logado.
revoke execute on function public.fn_interna(uuid) from public, anon;

-- Assinatura em várias linhas: o caso que mais escapa, porque é o das funções
-- com muitos argumentos.
revoke execute on function public.fn_ingestao(uuid, text, numeric,
  timestamptz, text) from public, anon;

-- Revoke completo (ok): fecha os três papéis de cliente.
revoke execute on function public.fn_interna_ok(uuid) from public, anon, authenticated;

-- Revoke parcial + GRANT deliberado (ok): é o padrão correto de RPC que a tela
-- chama — fecha o anônimo e declara a intenção para o usuário logado.
revoke execute on function public.fn_do_app(uuid) from public, anon;
grant execute on function public.fn_do_app(uuid) to authenticated;

-- ── RLS init plan (performance): auth.uid() reavaliado por linha ───────────
create policy p_meu on public.tabela_tres
  for select to authenticated using (user_id = auth.uid());

-- Forma cacheável (ok): auth.uid() dentro de um subselect.
create policy p_ok on public.tabela_tres_ok
  for select to authenticated using (user_id = (select auth.uid()));

-- ── Índice duplicado (mesma tabela + mesmas colunas) ──────────────────────
create index idx_a on public.tabela_quatro (email, criado_em desc);
create index idx_b on public.tabela_quatro (email, criado_em desc);
-- Índice diferente (ok).
create index idx_c on public.tabela_quatro (telefone);

-- ── Múltiplas policies PERMISSIVAS (mesma tabela/ação/papel) ───────────────
create policy m1 on public.tabela_cinco for select to authenticated using (true);
create policy m2 on public.tabela_cinco for select to authenticated using (dono = (select auth.uid()));
-- Uma permissiva + uma RESTRICTIVE (ok): não é "multiple permissive".
create policy r1 on public.tabela_seis for select to authenticated using (true);
create policy r2 on public.tabela_seis as restrictive for select to authenticated using (ativo);

-- ── search_path fixo mas SEM pg_temp ──────────────────────────────────────
-- `= public` satisfaz a regra do Semgrep (que só exige que o search_path
-- EXISTA) e ainda é sequestrável: sem `pg_temp` na lista, o Postgres o procura
-- PRIMEIRO para nomes de RELAÇÃO, então `from contatos` pode virar
-- `pg_temp.contatos` plantada por quem chama.
create or replace function public.fn_conta_contatos()
returns integer language plpgsql security definer
set search_path = public as $$
declare n integer; begin select count(*) into n from contatos; return n; end; $$;
revoke execute on function public.fn_conta_contatos() from public, anon, authenticated;

-- pg_temp presente mas NÃO por último: ainda perde a resolução de nome.
create or replace function public.fn_ordem_ruim()
returns integer language sql security definer
set search_path = pg_temp, public as $$ select 1 $$;
revoke execute on function public.fn_ordem_ruim() from public, anon, authenticated;

-- Formas corretas (ok): pg_temp por último, e corpo todo qualificado.
create or replace function public.fn_conta_ok()
returns integer language plpgsql security definer
set search_path = public, pg_temp as $$
declare n integer; begin select count(*) into n from public.contatos; return n; end; $$;
revoke execute on function public.fn_conta_ok() from public, anon, authenticated;

create or replace function public.fn_qualificada_ok()
returns integer language sql security definer
set search_path = '' as $$ select count(*)::int from public.contatos $$;
revoke execute on function public.fn_qualificada_ok() from public, anon, authenticated;

-- ── DEFINER que nenhum grant/revoke cita: nasce executável por anon ───────
create or replace function public.fn_relatorio_geral(p_de date, p_ate date)
returns table (dia date, total numeric) language sql security definer
set search_path = public, pg_temp as $$
  select data::date, sum(valor) from public.pedidos
  where data between p_de and p_ate group by 1 $$;

-- Fechada explicitamente (ok): revoke de public/anon + grant ao papel devido.
create or replace function public.fn_relatorio_ok(p_de date, p_ate date)
returns table (dia date, total numeric) language sql security definer
set search_path = public, pg_temp as $$
  select data::date, sum(valor) from public.pedidos
  where data between p_de and p_ate group by 1 $$;
revoke execute on function public.fn_relatorio_ok(date, date) from public, anon;
grant execute on function public.fn_relatorio_ok(date, date) to authenticated;

-- ── DEFINER com o inquilino vindo por PARÂMETRO (leitura entre inquilinos) ─
-- Quem chama escolhe o parâmetro: com o id de outro inquilino, lê os dados
-- dele. Sendo DEFINER, o RLS não intervém.
create or replace function public.anexo_permitido(p_org uuid, p_mime text)
returns boolean language sql security definer
set search_path = public, pg_temp as $$
  select exists (select 1 from public.mimes_permitidos
                 where org_id = p_org and mime = p_mime) $$;
revoke execute on function public.anexo_permitido(uuid, text) from public, anon, authenticated;

-- Mesma função derivando o inquilino da SESSÃO (ok): o parâmetro não decide.
create or replace function public.anexo_permitido_ok(p_mime text)
returns boolean language sql security definer
set search_path = public, pg_temp as $$
  select exists (
    select 1 from public.mimes_permitidos m
    join public.membros mb on mb.org_id = m.org_id
    where mb.user_id = (select auth.uid()) and m.mime = p_mime) $$;
revoke execute on function public.anexo_permitido_ok(text) from public, anon;
grant execute on function public.anexo_permitido_ok(text) to authenticated;

-- Recebe o inquilino por parâmetro MAS confere contra a sessão (ok).
create or replace function public.total_do_org(p_org uuid)
returns numeric language sql security definer
set search_path = public, pg_temp as $$
  select sum(valor) from public.pedidos
   where org_id = p_org and p_org = (select public.my_org()) $$;
revoke execute on function public.total_do_org(uuid) from public, anon;
grant execute on function public.total_do_org(uuid) to authenticated;

-- ── Guarda que só roda quando há sessão (o caminho anônimo passa livre) ────
create or replace function public.fn_expurgar(p_meses integer)
returns void language plpgsql security definer
set search_path = public, pg_temp as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    raise exception 'sem permissao';
  end if;
  delete from public.registros where criado_em < now() - make_interval(months => p_meses);
end; $$;
revoke execute on function public.fn_expurgar(integer) from public, anon, authenticated;

-- Guarda incondicional (ok): não há caminho que a contorne.
create or replace function public.fn_expurgar_ok(p_meses integer)
returns void language plpgsql security definer
set search_path = public, pg_temp as $$
begin
  if not public.is_admin() then
    raise exception 'sem permissao';
  end if;
  delete from public.registros where criado_em < now() - make_interval(months => p_meses);
end; $$;
revoke execute on function public.fn_expurgar_ok(integer) from public, anon, authenticated;
