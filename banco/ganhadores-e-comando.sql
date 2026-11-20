-- =====================================================================
-- GANHADORES NO SORTEIO NORMAL, FINALIZAR MANUALMENTE E PALAVRA DO CHAT
-- Rode este arquivo inteiro no SQL Editor do Supabase ANTES de publicar
-- a versão do site que usa estes recursos.
--
-- O que muda:
--  1) giveaways ganha "finished_at": quando preenchido, o sorteio está
--     finalizado e não aceita mais giros (botão "Finalizar sorteio").
--  2) giveaways ganha "chat_command": a palavra que inscreve no sorteio
--     pelo chat (vazio = !euquero, como antes).
--  3) finalize_giveaway_draw passa a respeitar o número de ganhadores
--     também no sorteio normal (por tickets) e recusa sorteio finalizado.
--  4) Sorteios já encerrados que tiveram vencedor confirmado ficam
--     finalizados, com a quantidade de ganhadores igual aos confirmados.
-- =====================================================================

begin;

-- 1) e 2) Novas colunas
alter table public.giveaways
    add column if not exists finished_at timestamptz;

alter table public.giveaways
    add column if not exists chat_command text;

alter table public.giveaways drop constraint if exists giveaways_chat_command_check;
alter table public.giveaways add constraint giveaways_chat_command_check
    check (chat_command is null or chat_command ~ '^\S{2,30}$');

-- 3) Rodada do sorteio (igual à versão de sorteio-chat.sql, com as
--    regras de ganhadores e de finalizado valendo para os dois tipos)
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
    v_kind text;
    v_winners_count integer;
    v_finished_at timestamptz;
    v_latest_status text;
    v_reveal_at timestamptz;
    v_now timestamptz;
begin
    v_now := now();

    select status, current_round, kind, winners_count, finished_at
    into v_status, v_round, v_kind, v_winners_count, v_finished_at
    from public.giveaways
    where id = p_giveaway_id
    for update;

    if not found or v_status <> 'closed' then
        raise exception 'Sorteio inexistente ou não está encerrado.';
    end if;

    if v_finished_at is not null then
        raise exception 'Este sorteio já foi finalizado.';
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

    if (
        select count(*)
        from public.giveaway_draws
        where giveaway_id = p_giveaway_id
          and status = 'confirmed'
    ) >= v_winners_count then
        raise exception 'Todos os ganhadores deste sorteio já foram confirmados.';
    end if;

    if v_kind = 'chat' then
        if not exists (
            select 1
            from public.chat_giveaway_entries
            where giveaway_id = p_giveaway_id
              and entry_number = p_winner_ticket_number
              and twitch_id = p_winner_twitch_id
        ) then
            raise exception 'Inscrição vencedora inválida.';
        end if;
    elsif not exists (
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

revoke all on function public.finalize_giveaway_draw(uuid, text, text, bigint, integer, integer, integer, integer) from public, anon, authenticated;
grant execute on function public.finalize_giveaway_draw(uuid, text, text, bigint, integer, integer, integer, integer) to service_role;

-- 4) Sorteios antigos: quem já teve vencedor confirmado fica finalizado,
--    e a quantidade de ganhadores passa a ser a de confirmados
--    (ex.: um sorteio normal com 5 confirmados fica "5 de 5").
with confirmed as (
    select giveaway_id, count(*)::integer as total
    from public.giveaway_draws
    where status = 'confirmed'
    group by giveaway_id
)
update public.giveaways g
set
    winners_count = least(50, greatest(g.winners_count, c.total)),
    finished_at = coalesce(g.finished_at, now())
from confirmed c
where c.giveaway_id = g.id
  and g.status = 'closed'
  and g.draw_in_progress = false;

commit;

-- Conferência: deve listar as duas colunas novas
select column_name, data_type
from information_schema.columns
where table_schema = 'public' and table_name = 'giveaways'
  and column_name in ('finished_at', 'chat_command');
