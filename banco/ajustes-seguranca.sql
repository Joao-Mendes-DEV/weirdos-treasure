-- =====================================================================
-- Weirdo's Treasure — ajustes de segurança do banco
-- Rodar UMA vez no SQL Editor do Supabase (tudo ou nada).
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 1) Sessões de login guardadas no banco (antes ficavam na memória)
-- ---------------------------------------------------------------------
create table if not exists public.sessions (
    sid        text primary key,
    sess       jsonb not null,
    expires_at timestamptz not null
);

create index if not exists idx_sessions_expires_at
    on public.sessions (expires_at);

alter table public.sessions enable row level security;

-- ---------------------------------------------------------------------
-- 2) Regras novas nas tabelas
-- ---------------------------------------------------------------------

-- Status de devolução de pontos
alter table public.transactions drop constraint transactions_status_check;
alter table public.transactions add constraint transactions_status_check
    check (status = any (array[
        'pending', 'completed', 'failed', 'reconciliation_required',
        'refund_pending', 'refunded'
    ]));

-- No máximo 1.000 tickets por compra
alter table public.transactions add constraint transactions_tickets_purchased_max
    check (tickets_purchased <= 1000);

-- Encerramento sempre depois do início
alter table public.giveaways add constraint giveaways_dates_check
    check (ends_at > starts_at);

-- Multiplicador de inscritos entre 1 e 10 (mesmo limite do painel)
alter table public.system_settings add constraint system_settings_subscriber_multiplier_max
    check (subscriber_multiplier <= 10);

-- ---------------------------------------------------------------------
-- 3) Índices de desempenho
-- ---------------------------------------------------------------------
create index if not exists idx_tickets_transaction
    on public.tickets (transaction_id);

create index if not exists idx_giveaway_draws_awaiting_deadline
    on public.giveaway_draws (response_deadline_at)
    where status = 'awaiting_response';

create index if not exists idx_audit_logs_action_transaction
    on public.audit_logs (action, (details->>'transaction_id'));

-- ---------------------------------------------------------------------
-- 4) Sorteio: revelação em 14 segundos (mesmo tempo do giro da Arena)
--    Única mudança: INTERVAL '10 seconds' -> INTERVAL '14 seconds'
-- ---------------------------------------------------------------------
create or replace function public.finalize_giveaway_draw(
    p_giveaway_id uuid,
    p_admin_twitch_id text,
    p_winner_twitch_id text,
    p_winner_ticket_number bigint,
    p_total_tickets integer,
    p_total_participants integer,
    p_total_weighted_entries integer,
    p_subscriber_count integer
)
returns integer
language plpgsql
set search_path to 'public'
as $function$
declare
    v_status text;
    v_round integer;
    v_latest_status text;
    v_reveal_at timestamptz;
    v_now timestamptz;
begin
    v_now := now();

    select status, current_round
    into v_status, v_round
    from public.giveaways
    where id = p_giveaway_id
    for update;

    if not found or v_status <> 'closed' then
        raise exception 'Sorteio inexistente ou não está encerrado.';
    end if;

    select status
    into v_latest_status
    from public.giveaway_draws
    where giveaway_id = p_giveaway_id
    order by round_number desc
    limit 1;

    if v_latest_status = 'awaiting_response' then
        raise exception 'A rodada anterior ainda está aguardando resposta.';
    end if;

    if v_latest_status is not null
       and v_latest_status not in ('confirmed', 'expired') then
        raise exception 'Não é possível iniciar uma nova rodada.';
    end if;

    if exists (
        select 1
        from public.giveaway_draws
        where giveaway_id = p_giveaway_id
          and winner_twitch_id = p_winner_twitch_id
    ) then
        raise exception 'Este participante já venceu uma rodada.';
    end if;

    if not exists (
        select 1
        from public.tickets
        where giveaway_id = p_giveaway_id
          and ticket_number = p_winner_ticket_number
          and twitch_id = p_winner_twitch_id
    ) then
        raise exception 'Ticket vencedor inválido.';
    end if;

    v_round := v_round + 1;
    v_reveal_at := v_now + interval '14 seconds';

    insert into public.giveaway_draws (
        giveaway_id, round_number, winner_twitch_id,
        winning_ticket_number, total_tickets_at_draw,
        total_participants_at_draw, total_weighted_entries_at_draw,
        subscriber_count_at_draw, status, drawn_at, response_deadline_at
    ) values (
        p_giveaway_id, v_round, p_winner_twitch_id,
        p_winner_ticket_number, p_total_tickets, p_total_participants,
        p_total_weighted_entries, p_subscriber_count,
        'awaiting_response', v_now, v_reveal_at + interval '40 seconds'
    );

    insert into public.draw_results (
        giveaway_id, round_number, winner_twitch_id,
        winner_ticket_number, total_tickets, total_participants,
        total_weighted_entries, subscriber_count, drawn_at, reveal_at
    ) values (
        p_giveaway_id, v_round, p_winner_twitch_id,
        p_winner_ticket_number, p_total_tickets, p_total_participants,
        p_total_weighted_entries, p_subscriber_count, v_now, v_reveal_at
    );

    update public.giveaways
    set
        current_round = v_round,
        draw_in_progress = true,
        draw_started_at = v_now,
        draw_reveal_at = v_reveal_at,
        total_tickets_at_draw = p_total_tickets,
        total_participants_at_draw = p_total_participants,
        total_weighted_entries_at_draw = p_total_weighted_entries,
        subscriber_count_at_draw = p_subscriber_count
    where id = p_giveaway_id;

    insert into public.audit_logs (
        twitch_id, action, details
    ) values (
        p_admin_twitch_id,
        'giveaway_draw_round_created',
        jsonb_build_object(
            'giveaway_id', p_giveaway_id,
            'round_number', v_round,
            'winner_twitch_id', p_winner_twitch_id,
            'winner_ticket_number', p_winner_ticket_number
        )
    );

    return v_round;
end;
$function$;

-- ---------------------------------------------------------------------
-- 5) Devolução de pontos (compra que não pôde emitir tickets)
-- ---------------------------------------------------------------------

-- Passo 1: reserva a devolução (impede devolver duas vezes). Retorna os pontos.
create or replace function public.start_ticket_purchase_refund(
    p_transaction_id uuid,
    p_admin_twitch_id text
)
returns bigint
language plpgsql
set search_path to 'public'
as $function$
declare
    v_transaction public.transactions%rowtype;
    v_emitted bigint;
begin
    if p_admin_twitch_id is null or btrim(p_admin_twitch_id) = '' then
        raise exception 'Identificação do administrador inválida.';
    end if;

    select *
    into v_transaction
    from public.transactions
    where id = p_transaction_id
    for update;

    if not found then
        raise exception 'Transação não encontrada.';
    end if;

    -- Pendente recente pode ainda estar em processamento
    if not (
        v_transaction.status = 'reconciliation_required'
        or (
            v_transaction.status = 'pending'
            and v_transaction.created_at < now() - interval '15 minutes'
        )
    ) then
        raise exception 'Status da transação não permite devolução.';
    end if;

    select count(*)
    into v_emitted
    from public.tickets
    where transaction_id = p_transaction_id;

    if v_emitted > 0 then
        raise exception 'Esta compra já tem tickets emitidos. Use a regularização.';
    end if;

    update public.transactions
    set status = 'refund_pending'
    where id = p_transaction_id;

    insert into public.audit_logs (twitch_id, action, details)
    values (
        p_admin_twitch_id,
        'ticket_purchase_refund_started',
        jsonb_build_object(
            'transaction_id', p_transaction_id,
            'customer_twitch_id', v_transaction.twitch_id,
            'giveaway_id', v_transaction.giveaway_id,
            'points_to_refund', v_transaction.points_spent,
            'previous_status', v_transaction.status
        )
    );

    return v_transaction.points_spent;
end;
$function$;

-- Passo 2: confirma que os pontos voltaram ao usuário
create or replace function public.complete_ticket_purchase_refund(
    p_transaction_id uuid,
    p_admin_twitch_id text
)
returns void
language plpgsql
set search_path to 'public'
as $function$
declare
    v_transaction public.transactions%rowtype;
begin
    if p_admin_twitch_id is null or btrim(p_admin_twitch_id) = '' then
        raise exception 'Identificação do administrador inválida.';
    end if;

    select *
    into v_transaction
    from public.transactions
    where id = p_transaction_id
    for update;

    if not found then
        raise exception 'Transação não encontrada.';
    end if;

    if v_transaction.status <> 'refund_pending' then
        raise exception 'A transação não está com devolução em andamento.';
    end if;

    update public.transactions
    set status = 'refunded'
    where id = p_transaction_id;

    insert into public.audit_logs (twitch_id, action, details)
    values (
        p_admin_twitch_id,
        'ticket_purchase_refunded',
        jsonb_build_object(
            'transaction_id', p_transaction_id,
            'customer_twitch_id', v_transaction.twitch_id,
            'giveaway_id', v_transaction.giveaway_id,
            'points_refunded', v_transaction.points_spent
        )
    );
end;
$function$;

-- ---------------------------------------------------------------------
-- 6) Permissões: só o servidor (service_role) acessa tabelas e funções.
--    O RLS já bloqueia as chaves públicas; isto é uma segunda camada.
-- ---------------------------------------------------------------------
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on all functions in schema public to service_role;

-- Objetos criados no futuro também nascem fechados
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

commit;
