-- =====================================================================
-- MINIGAME: UMA PARTIDA POR DIA (em vez de a cada 20 horas)
-- Rode este arquivo inteiro no SQL Editor do Supabase ANTES de publicar
-- a versão do site que usa o limite por dia.
--
-- O que muda:
--  Nova função start_daily_word_game_today: só deixa iniciar se o usuário
--  ainda não começou nenhuma partida no dia de hoje (horário de Brasília).
--  Quem jogou às 23:50 pode jogar de novo a partir de 00:00.
--
-- A função antiga (start_daily_word_game) continua existindo, para a versão
-- atual do site não quebrar durante a troca. Depois de publicar, ela pode
-- ser apagada com:
--   drop function if exists public.start_daily_word_game(text, text, integer);
-- =====================================================================

begin;

create or replace function public.start_daily_word_game_today(
    p_twitch_id text,
    p_word text
)
returns uuid
language plpgsql
set search_path to 'public'
as $function$
declare
    v_id uuid;
    v_today_start timestamptz;
begin
    if p_twitch_id is null or btrim(p_twitch_id) = '' then
        raise exception 'Usuário inválido.';
    end if;

    perform pg_advisory_xact_lock(hashtext('daily_word_game:' || p_twitch_id));

    -- Meia-noite de hoje no horário de Brasília
    v_today_start := date_trunc('day', now() at time zone 'America/Sao_Paulo')
                     at time zone 'America/Sao_Paulo';

    if exists (
        select 1
        from public.daily_word_games
        where twitch_id = p_twitch_id
          and started_at >= v_today_start
    ) then
        raise exception 'COOLDOWN';
    end if;

    -- Partida antiga que ficou aberta é encerrada sem pontos
    update public.daily_word_games
    set status = 'abandoned', finished_at = now()
    where twitch_id = p_twitch_id
      and status = 'playing';

    insert into public.daily_word_games (twitch_id, word)
    values (p_twitch_id, p_word)
    returning id into v_id;

    return v_id;
end;
$function$;

-- Só o servidor (service_role) acessa
revoke execute on function public.start_daily_word_game_today(text, text) from public, anon, authenticated;
grant execute on function public.start_daily_word_game_today(text, text) to service_role;

commit;
