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
