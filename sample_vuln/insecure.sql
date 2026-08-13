-- Fixture de teste do raptor-win (NÃO é banco real).
-- Row Level Security (Postgres/Supabase): uma policy de SELECT liberada para o
-- papel `anon` expõe TODAS AS COLUNAS das linhas que casam — RLS filtra linha,
-- nunca coluna. Um menu público que só precisa de nome/preço acaba entregando
-- também estoque, custo e códigos internos a qualquer visitante.

-- Caso 1: tabela inteira aberta ao anônimo (using (true)).
create policy mesas_select on public.mesas
  for select to anon, authenticated using (true);

-- Caso 2: filtrada por linha, mas ainda todas as colunas das linhas ativas.
create policy cardapio_select_anon on public.itens_cardapio
  for select to anon using (ativo = true);
