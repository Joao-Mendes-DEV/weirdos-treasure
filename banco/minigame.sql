-- =====================================================================
-- Minigame diário: tabela das partidas e função de início.
-- Rodar UMA vez no SQL Editor do Supabase (tudo ou nada).
-- Não afeta nada que já existe no site.
-- =====================================================================

begin;

create table if not exists public.daily_word_games (
    id               uuid primary key default gen_random_uuid(),
    twitch_id        text not null references public.users(twitch_id),
    word             text not null check (word ~ '^[a-z]{5}$'),
    status           text not null default 'playing'
                     check (status in ('playing', 'won', 'lost', 'abandoned')),
    attempts         integer not null default 0 check (attempts between 0 and 6),
    guesses          jsonb not null default '[]'::jsonb,
    points_awarded   integer not null default 0 check (points_awarded between 0 and 180),
    -- Crédito no StreamElements: none (sem prêmio), pending, credited, failed
    credit_status    text not null default 'none'
                     check (credit_status in ('none', 'pending', 'credited', 'failed')),
    credit_attempts  integer not null default 0,
    started_at       timestamptz not null default now(),
    finished_at      timestamptz,
    credited_at      timestamptz
);

-- Última partida de cada usuário (usada para o intervalo de 20 horas)
create index if not exists idx_daily_word_games_user_started
    on public.daily_word_games (twitch_id, started_at desc);

-- No máximo uma partida em andamento por usuário
create unique index if not exists idx_daily_word_games_one_playing
    on public.daily_word_games (twitch_id)
    where status = 'playing';

-- Créditos que falharam e serão tentados de novo
create index if not exists idx_daily_word_games_credit_failed
    on public.daily_word_games (credit_status)
    where credit_status = 'failed';

alter table public.daily_word_games enable row level security;

-- Inicia uma partida respeitando o intervalo entre partidas.
-- Trava por usuário: dois cliques ao mesmo tempo não criam duas partidas.
create or replace function public.start_daily_word_game(
    p_twitch_id text,
    p_word text,
    p_cooldown_hours integer
)
returns uuid
language plpgsql
set search_path to 'public'
as $function$
declare
    v_id uuid;
begin
    if p_twitch_id is null or btrim(p_twitch_id) = '' then
        raise exception 'Usuário inválido.';
    end if;

    if p_cooldown_hours is null or p_cooldown_hours < 1 then
        raise exception 'Intervalo inválido.';
    end if;

    perform pg_advisory_xact_lock(hashtext('daily_word_game:' || p_twitch_id));

    if exists (
        select 1
        from public.daily_word_games
        where twitch_id = p_twitch_id
          and started_at > now() - make_interval(hours => p_cooldown_hours)
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
revoke all on public.daily_word_games from anon, authenticated;
revoke execute on function public.start_daily_word_game(text, text, integer) from public, anon, authenticated;
grant execute on function public.start_daily_word_game(text, text, integer) to service_role;

commit;
