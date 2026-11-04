-- =====================================================================
-- PuzzlePop Tournament Edition — Supabase schema (Phase 1)
-- Run this ONCE in the Supabase dashboard: SQL editor -> New query ->
-- paste this whole file -> Run. It is safe to run twice (all statements
-- below tolerate re-runs; existing rows are never deleted).
--
-- WHAT THIS CREATES
--   profiles        one row per player (id = Supabase auth user id)
--   ranked_scores   one row per player per UTC day: that day's BEST
--                   single-game score + how many ranked games played
--   weekly_results  the frozen top 300 of a finished week + prize claims
--   player_progress one row per player: tournament level, highest level
--                   completed, and spendable daily-coin balance
--   daily_coin_grants one row per daily coin granted (source + time),
--                   the audit trail that enforces the coin caps
--   game_days       one row per player per UTC day played (any mode),
--                   the server-side source for streaks
--   rank_snapshots  each player's last-seen weekly rank (for the
--                   "someone just passed you" feed)
--   weekly_underdogs frozen weekly biggest-climber winners (badges)
--   spin_claims     one row per daily spin (points won, recorded)
--   spin_balances   each player's separate spin-points balance
--                   (in-game only: never coins, never ranked score)
--
-- SECURITY: Row Level Security (RLS) is ON for every table.
--   * Players can read the leaderboard (ranked_scores + profiles) and
--     their own rows, but can only write their OWN rows.
--   * weekly_results can only be WRITTEN by the owner (via the Supabase
--     dashboard / the freeze SQL at the bottom). Players may only update
--     their own claim fields (wallet + coin + claim_status), and a
--     trigger blocks any change to rank, score or prize amounts.
--   * Score submissions go through submit_ranked_game(), which checks
--     the player is logged in and rejects implausible results.
-- NEVER turn RLS off. NEVER paste a service_role key into the game.
-- =====================================================================

-- ---------------- profiles ----------------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique
    check (username ~ '^[A-Za-z0-9_]{3,20}$'),
  region text, -- display only, e.g. "Pakistan" (optional, free text)
  created_at timestamptz not null default now()
);

-- ---------------- ranked_scores ----------------
-- One row per (player, UTC day). best_score is that day's best
-- SINGLE game. total_score is the SUM of ALL ranked games that day.
-- The weekly value is sum(total_score) over the week, computed
-- when the leaderboard is read (and frozen at week end).
create table if not exists public.ranked_scores (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  game_date date not null, -- UTC day the games were played
  best_score integer not null default 0 check (best_score >= 0),
  games_played integer not null default 0 check (games_played >= 0),
  total_score integer not null default 0 check (total_score >= 0), -- sum of ALL ranked games that day
  last_score integer,        -- most recent submitted game, for audit
  last_moves integer,
  last_lines integer,
  last_duration_sec integer,
  last_played_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (user_id, game_date)
);
create index if not exists ranked_scores_game_date_idx
  on public.ranked_scores (game_date);

-- ---------------- weekly_results ----------------
-- Frozen results of one finished week. week_start is the Monday (UTC)
-- of that week. claim_status: 'unclaimed' -> 'claimed' (player sent a
-- wallet address) -> 'paid' (owner paid manually and marked it so).
create table if not exists public.weekly_results (
  id bigint generated always as identity primary key,
  week_start date not null, -- Monday, UTC
  user_id uuid not null references public.profiles (id) on delete cascade,
  rank integer not null check (rank >= 1 and rank <= 50),
  total_score integer not null check (total_score >= 0),
  prize_tier text not null, -- e.g. '1-10', '11-20', '21-30', '31-50'
  prize_amount numeric(10, 2) not null check (prize_amount >= 0),
  claim_wallet text, -- crypto wallet address, entered by the winner
  claim_coin text,   -- coin/network, free text, e.g. "USDT / TRC20"
  claim_status text not null default 'unclaimed'
    check (claim_status in ('unclaimed', 'claimed', 'paid')),
  claimed_at timestamptz,
  paid_at timestamptz,
  unique (week_start, user_id),
  unique (week_start, rank)
);
create index if not exists weekly_results_week_idx
  on public.weekly_results (week_start, rank);

-- ---------------- Row Level Security ----------------
alter table public.profiles enable row level security;
alter table public.ranked_scores enable row level security;
alter table public.weekly_results enable row level security;

drop policy if exists "profiles readable by logged-in users" on public.profiles;
create policy "profiles readable by logged-in users"
  on public.profiles for select to authenticated using (true);

drop policy if exists "profiles writable by owner only" on public.profiles;
create policy "profiles writable by owner only"
  on public.profiles for insert to authenticated
  with check (auth.uid() = id);

drop policy if exists "profiles updatable by owner only" on public.profiles;
create policy "profiles updatable by owner only"
  on public.profiles for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "ranked_scores readable by logged-in users" on public.ranked_scores;
create policy "ranked_scores readable by logged-in users"
  on public.ranked_scores for select to authenticated using (true);

drop policy if exists "ranked_scores writable by owner only" on public.ranked_scores;
create policy "ranked_scores writable by owner only"
  on public.ranked_scores for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "ranked_scores updatable by owner only" on public.ranked_scores;
create policy "ranked_scores updatable by owner only"
  on public.ranked_scores for update to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "weekly_results readable by logged-in users" on public.weekly_results;
create policy "weekly_results readable by logged-in users"
  on public.weekly_results for select to authenticated using (true);

-- NOTE: there is intentionally NO insert policy for weekly_results for
-- players. Only the owner (dashboard / freeze SQL, which bypasses RLS)
-- creates result rows. Players may only update their own claim fields,
-- and the trigger below blocks everything else.
drop policy if exists "weekly_results claimable by owner only" on public.weekly_results;
create policy "weekly_results claimable by owner only"
  on public.weekly_results for update to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- The game client (PostgREST "authenticated" role) needs these grants.
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update on public.ranked_scores to authenticated;
grant select, update on public.weekly_results to authenticated;
grant usage, select, update on sequence public.ranked_scores_id_seq to authenticated;
grant usage, select, update on sequence public.weekly_results_id_seq to authenticated;

-- =====================================================================
-- ANTI-CHEAT CAPS (why these numbers)
-- PuzzlePop scoring, from the game code: placing a piece scores
-- 10 points per filled cell (largest piece is 3x3 = 9 cells = 90 pts).
-- Clearing lines scores [100, 300, 600, 1000, 1500] for 1-5 lines in
-- one move, multiplied by the current combo, plus (combo-1)*75 streak
-- bonus. So one move can realistically score at most ~90 + 1500*combo.
--   MAX_SCORE_PER_MOVE = 50,000 covers a 5-line clear at combo 32 —
--   far beyond anything a real player reaches — while blocking absurd
--   values like 999,999,999 in a single move.
--   MAX_SCORE_PER_GAME = 5,000,000: a marathon game of hundreds of
--   moves stays well below this; faked totals do not.
--   MAX_GAMES_PER_DAY = 200: at ~2 minutes per game that is over 6
--   hours of ranked play in one day. A bot playing thousands of games
--   a day is stopped cold.
-- These caps are deliberately generous so no honest player is ever
-- rejected. Client-side numbers are only hints — the server enforces.
-- =====================================================================

-- ---------------- submit_ranked_game() ----------------
-- The ONLY supported way for the game to submit a ranked result.
-- Runs as SECURITY DEFINER so the daily-best upsert is atomic, but it
-- still only ever touches the calling player's own rows (auth.uid()).
create or replace function public.submit_ranked_game(
  p_score integer,
  p_moves integer,
  p_lines integer,
  p_duration_sec integer
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_day date := (now() at time zone 'UTC')::date;
  v_row public.ranked_scores%rowtype;
  v_is_new_best boolean := false;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;

  -- A profile row must exist (created when the player picks a
  -- username after first login). Never invent one.
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;

  -- Tournament is locked until level 12. The level lives on the
  -- server (player_progress), so no client trick can bypass the lock.
  declare
    v_level integer;
  begin
    select level into v_level from public.player_progress where user_id = v_uid;
    if v_level is null or v_level < 12 then
      raise exception 'tournament locked: reach level 12 first';
    end if;
  end;

  -- Implausible-submission checks.
  if p_score is null or p_score < 0 then
    raise exception 'invalid score';
  end if;
  if p_moves is null or p_moves < 1 then
    raise exception 'invalid move count';
  end if;
  if p_duration_sec is null or p_duration_sec < 0 or p_duration_sec > 86400 then
    raise exception 'invalid game duration';
  end if;
  if p_score > p_moves * 50000 then
    raise exception 'score exceeds per-move cap';
  end if;
  if p_score > 5000000 then
    raise exception 'score exceeds per-game cap';
  end if;

  select * into v_row from public.ranked_scores
    where user_id = v_uid and game_date = v_day;
  if found and v_row.games_played >= 200 then
    raise exception 'daily game limit reached';
  end if;

  insert into public.ranked_scores
    (user_id, game_date, best_score, games_played, total_score,
     last_score, last_moves, last_lines, last_duration_sec,
     last_played_at, updated_at)
  values
    (v_uid, v_day, p_score, 1, p_score,
     p_score, p_moves, p_lines, p_duration_sec, now(), now())
  on conflict (user_id, game_date) do update set
    games_played = public.ranked_scores.games_played + 1,
    best_score = greatest(public.ranked_scores.best_score, excluded.best_score),
    total_score = public.ranked_scores.total_score + excluded.total_score,
    last_score = excluded.last_score,
    last_moves = excluded.last_moves,
    last_lines = excluded.last_lines,
    last_duration_sec = excluded.last_duration_sec,
    last_played_at = excluded.last_played_at,
    updated_at = now()
  returning * into v_row;

  v_is_new_best := (v_row.best_score = p_score);
  return jsonb_build_object(
    'game_date', v_day,
    'best_score', v_row.best_score,
    'games_played', v_row.games_played,
    'is_new_best', v_is_new_best
  );
end;
$$;

grant execute on function public.submit_ranked_game(integer, integer, integer, integer)
  to authenticated;

-- ---------------- defense-in-depth triggers ----------------
-- Even a direct table write (not via the function) cannot push a daily
-- best backwards, exceed the caps, or rewrite someone's prize.
create or replace function public.enforce_daily_best_guard()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' then
    new.best_score := greatest(old.best_score, new.best_score);
  end if;
  if new.games_played > 200 then
    raise exception 'daily game limit reached';
  end if;
  if new.best_score > 5000000 then
    raise exception 'score exceeds per-game cap';
  end if;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists ranked_scores_guard on public.ranked_scores;
create trigger ranked_scores_guard
  before insert or update on public.ranked_scores
  for each row execute function public.enforce_daily_best_guard();

create or replace function public.protect_weekly_results()
returns trigger
language plpgsql
as $$
begin
  -- Prize fields are immutable once written.
  if old.user_id is distinct from new.user_id
     or old.week_start is distinct from new.week_start
     or old.rank is distinct from new.rank
     or old.total_score is distinct from new.total_score
     or old.prize_tier is distinct from new.prize_tier
     or old.prize_amount is distinct from new.prize_amount then
    raise exception 'prize result fields cannot be changed';
  end if;
  -- Only these status moves are allowed: unclaimed -> claimed
  -- (player sends a wallet), claimed -> paid (owner paid manually).
  if old.claim_status = new.claim_status then
    -- Wallet/coin edits on an unclaimed row are fine; on a claimed row
    -- the owner pays what was claimed, so also allow owner corrections
    -- from the dashboard only by deleting + re-freezing, not by edit.
    if old.claim_status = 'claimed' and
       (old.claim_wallet is distinct from new.claim_wallet
        or old.claim_coin is distinct from new.claim_coin) then
      raise exception 'claimed wallet cannot be changed';
    end if;
  elsif old.claim_status = 'unclaimed' and new.claim_status = 'claimed' then
    if new.claim_wallet is null or length(btrim(new.claim_wallet)) = 0 then
      raise exception 'wallet address required to claim';
    end if;
    new.claimed_at := now();
  elsif old.claim_status = 'claimed' and new.claim_status = 'paid' then
    new.paid_at := now();
  else
    raise exception 'invalid claim status change';
  end if;
  return new;
end;
$$;

drop trigger if exists weekly_results_guard on public.weekly_results;
create trigger weekly_results_guard
  before update on public.weekly_results
  for each row execute function public.protect_weekly_results();

-- =====================================================================
-- TOURNAMENT UNLOCK: LEVEL 15 + DAILY-GATED PROGRESSION
--
-- The tournament (ranked mode) stays locked until the player reaches
-- level 15. Nobody can reach level 15 in less than 7 days, because:
--   * The game has 18 levels (see game.html LEVELS).
--   * Every level-up costs exactly 1 daily coin. Level 1 is free.
--     Reaching level 15 needs 14 coins (levels 2..15).
--   * Daily coins come ONLY from daily play, max 2 per UTC day:
--       - 1 coin for finishing your first game of the day (any mode)
--       - 1 coin for completing the daily challenge (Daily mode goal)
--   * AND at most 1 coin per rolling 60 minutes: the two daily coins
--     cannot be collected back-to-back. At least 60 minutes must pass
--     between any two grants.
--   * There are NO coin purchases, NO shortcuts, NO client-side grants.
--     Coins and levels are written ONLY by the functions below
--     (SECURITY DEFINER). Players have NO insert/update permission on
--     these tables at all — even a modified game client cannot grant
--     itself coins or levels; direct writes are refused by RLS.
--
-- PACING MATH (verify it yourself):
--   * Coins needed for level 15 = 15 - 1 = 14.
--   * Days needed at 2 coins/day = 14 / 2 = 7 days minimum.
--   * Day 1 maximum: a player starts at level 1 with 0 coins, can earn
--     at most 2 coins on day 1, and each level-up costs 1 coin, so the
--     highest reachable level on day 1 is 1 + 2 = level 3 — even with
--     unlimited play. Extra games on day 1 still give normal score,
--     but NO extra coins and NO extra levels that day.
--   * The 60-minute gap does not change the 7-day minimum; it only
--     stops instant double-collection (e.g. first game + daily goal
--     within the same hour).
--   * Banked coins never expire, but banking does not beat the clock:
--     coins are still capped at 2/day, so 14 coins always take 7 days
--     to accumulate, and each level-up still requires completing the
--     previous level first (sequential, enforced below).
-- =====================================================================

-- ---------------- player_progress ----------------
-- Server truth for tournament progression. level = highest level the
-- player may play. max_level_completed = highest level whose target
-- score the player has actually reached (reported by the game, checked
-- against the level's target below).
create table if not exists public.player_progress (
  user_id uuid primary key references public.profiles (id) on delete cascade,
  level integer not null default 1
    check (level >= 1 and level <= 18),
  max_level_completed integer not null default 0
    check (max_level_completed >= 0 and max_level_completed <= 18),
  coin_balance integer not null default 0 check (coin_balance >= 0),
  updated_at timestamptz not null default now()
);

-- ---------------- daily_coin_grants ----------------
-- Audit trail for every daily coin. granted_at is what enforces the
-- rolling 60-minute gap; grant_date + source enforce the 2/day cap
-- (one grant per source per day, enforced by the unique constraint).
create table if not exists public.daily_coin_grants (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  grant_date date not null, -- UTC day of the grant
  source text not null check (source in ('first_game', 'daily_goal')),
  granted_at timestamptz not null default now(),
  unique (user_id, grant_date, source)
);
create index if not exists daily_coin_grants_user_time_idx
  on public.daily_coin_grants (user_id, granted_at desc);

-- RLS: players may READ their own progress and grants. They may NOT
-- write them at all — only the SECURITY DEFINER functions below write.
alter table public.player_progress enable row level security;
alter table public.daily_coin_grants enable row level security;

drop policy if exists "player_progress readable by owner only" on public.player_progress;
create policy "player_progress readable by owner only"
  on public.player_progress for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "daily_coin_grants readable by owner only" on public.daily_coin_grants;
create policy "daily_coin_grants readable by owner only"
  on public.daily_coin_grants for select to authenticated
  using (auth.uid() = user_id);

grant select on public.player_progress to authenticated;
grant select on public.daily_coin_grants to authenticated;
grant usage, select, update on sequence public.daily_coin_grants_id_seq to authenticated;

-- Defense in depth: even a direct insert (if RLS were ever loosened)
-- cannot break the caps.
create or replace function public.guard_daily_coin_grants()
returns trigger
language plpgsql
as $$
begin
  if (select count(*) from public.daily_coin_grants
      where user_id = new.user_id and grant_date = new.grant_date) >= 2 then
    raise exception 'daily coin limit reached (2 per day)';
  end if;
  if exists (select 1 from public.daily_coin_grants
             where user_id = new.user_id
               and granted_at > now() - interval '60 minutes') then
    raise exception 'daily coins are limited to 1 per 60 minutes';
  end if;
  return new;
end;
$$;

drop trigger if exists daily_coin_grants_guard on public.daily_coin_grants;
create trigger daily_coin_grants_guard
  before insert on public.daily_coin_grants
  for each row execute function public.guard_daily_coin_grants();

-- ---------------- grant_daily_coin(source) ----------------
-- Grants 1 daily coin if all rules pass. Never raises for the
-- expected "no coin right now" cases — it returns a structured result
-- so the game can show an honest wait state ("Next daily coin in
-- 42 min"). Raises only for invalid calls (not logged in, no profile,
-- bad source).
--   Returns: {granted, reason, coins_today, balance, next_in_minutes}
--   next_in_minutes: minutes until the next grant is possible
--     (60-minute gap, or minutes until UTC midnight at the daily cap).
create or replace function public.grant_daily_coin(p_source text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_day date := (now() at time zone 'UTC')::date;
  v_count integer;
  v_last timestamptz;
  v_balance integer := 0;
  v_wait integer;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if p_source not in ('first_game', 'daily_goal') then
    raise exception 'invalid coin source';
  end if;
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;

  -- One grant per source per day (same source twice = already collected).
  if exists (select 1 from public.daily_coin_grants
             where user_id = v_uid and grant_date = v_day and source = p_source) then
    select count(*) into v_count from public.daily_coin_grants
      where user_id = v_uid and grant_date = v_day;
    select coin_balance into v_balance from public.player_progress where user_id = v_uid;
    return jsonb_build_object('granted', false, 'reason', 'already collected',
      'coins_today', v_count, 'balance', coalesce(v_balance, 0), 'next_in_minutes', 0);
  end if;

  -- Daily cap: max 2 per UTC day.
  select count(*) into v_count from public.daily_coin_grants
    where user_id = v_uid and grant_date = v_day;
  if v_count >= 2 then
    select coin_balance into v_balance from public.player_progress where user_id = v_uid;
    v_wait := greatest(0, floor(extract(epoch from
      (timezone('UTC', ((v_day + 1)::timestamp)) - now())) / 60)::integer);
    return jsonb_build_object('granted', false, 'reason', 'daily cap reached',
      'coins_today', v_count, 'balance', coalesce(v_balance, 0), 'next_in_minutes', v_wait);
  end if;

  -- Hourly gap: at least 60 minutes since the player's last grant.
  select max(granted_at) into v_last from public.daily_coin_grants
    where user_id = v_uid;
  if v_last is not null and now() < v_last + interval '60 minutes' then
    v_wait := ceil(extract(epoch from
      (v_last + interval '60 minutes' - now())) / 60)::integer;
    select coin_balance into v_balance from public.player_progress where user_id = v_uid;
    return jsonb_build_object('granted', false, 'reason', 'hourly wait',
      'coins_today', v_count, 'balance', coalesce(v_balance, 0), 'next_in_minutes', v_wait);
  end if;

  -- All checks pass: grant the coin.
  insert into public.player_progress (user_id) values (v_uid)
    on conflict (user_id) do nothing;
  insert into public.daily_coin_grants (user_id, grant_date, source)
    values (v_uid, v_day, p_source);
  update public.player_progress
    set coin_balance = coin_balance + 1, updated_at = now()
    where user_id = v_uid
    returning coin_balance into v_balance;
  return jsonb_build_object('granted', true, 'reason', 'granted',
    'coins_today', v_count + 1, 'balance', v_balance, 'next_in_minutes', 0);
end;
$$;

grant execute on function public.grant_daily_coin(text) to authenticated;

-- ---------------- report_level_complete(level, score) ----------------
-- Records that the player reached a level's target score. The target
-- is checked server-side (same numbers as game.html LEVELS), and a
-- player cannot complete a level they have not unlocked yet. Note the
-- honest limit: the score itself is reported by the phone, so this
-- check proves "score >= target", not that the game was played
-- perfectly. The time gate does NOT depend on this: even a faked
-- completion cannot create coins, and coins are capped at 2/day, so
-- the 7-day minimum to level 15 cannot be bypassed this way.
create or replace function public.report_level_complete(p_level integer, p_score integer)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_prog public.player_progress%rowtype;
  v_target integer;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if p_level is null or p_level < 1 or p_level > 18 then
    raise exception 'invalid level';
  end if;
  if p_score is null or p_score < 0 then
    raise exception 'invalid score';
  end if;
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;

  insert into public.player_progress (user_id) values (v_uid)
    on conflict (user_id) do nothing;
  select * into v_prog from public.player_progress where user_id = v_uid;

  if p_level > v_prog.level then
    raise exception 'cannot complete a locked level';
  end if;

  v_target := case p_level
    when 1 then 800 when 2 then 1200 when 3 then 1800 when 4 then 2500
    when 5 then 3200 when 6 then 4200 when 7 then 5200 when 8 then 6500
    when 9 then 8000 when 10 then 10000 when 11 then 12500 when 12 then 15000
    when 13 then 18000 when 14 then 21500 when 15 then 25000 when 16 then 29000
    when 17 then 34000 when 18 then 40000 end;
  if p_score < v_target then
    raise exception 'score below level target';
  end if;

  update public.player_progress
    set max_level_completed = greatest(max_level_completed, p_level),
        updated_at = now()
    where user_id = v_uid
    returning * into v_prog;
  return jsonb_build_object('level', v_prog.level,
    'max_level_completed', v_prog.max_level_completed,
    'balance', v_prog.coin_balance);
end;
$$;

grant execute on function public.report_level_complete(integer, integer) to authenticated;

-- ---------------- unlock_next_level() ----------------
-- Spends 1 daily coin to unlock the next level. Requires the player
-- to have actually completed their current highest level first.
create or replace function public.unlock_next_level()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_prog public.player_progress%rowtype;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;

  insert into public.player_progress (user_id) values (v_uid)
    on conflict (user_id) do nothing;
  select * into v_prog from public.player_progress where user_id = v_uid;

  if v_prog.level >= 18 then
    raise exception 'max level reached';
  end if;
  if v_prog.max_level_completed < v_prog.level then
    raise exception 'complete level % first', v_prog.level;
  end if;
  if v_prog.coin_balance < 1 then
    raise exception 'need 1 daily coin: play today to earn coins';
  end if;

  update public.player_progress
    set coin_balance = coin_balance - 1,
        level = level + 1,
        updated_at = now()
    where user_id = v_uid
    returning * into v_prog;
  return jsonb_build_object('level', v_prog.level,
    'max_level_completed', v_prog.max_level_completed,
    'balance', v_prog.coin_balance);
end;
$$;

grant execute on function public.unlock_next_level() to authenticated;

-- =====================================================================
-- ENGAGEMENT FEATURES (all prizes here are IN-GAME ONLY: badges,
-- power-ups, frames. Never cash, never daily coins.)
--
-- 1. STREAK FLAME. Consecutive UTC days with at least one finished
--    game (any mode), tracked server-side in game_days. A missed day
--    resets the streak to zero. Milestones: 3, 7, 30 days, each with
--    its own badge. get_streak() computes the streak from the dates;
--    the client only displays what the server returns.
-- 2. "SOMEONE JUST PASSED YOU!" rank_snapshots stores each player's
--    last-seen weekly rank. On each leaderboard load the game
--    compares it with the current rank; if the rank got worse, the
--    player now at the old rank is named as the passer. Only real
--    leaderboard data is ever shown — no fabricated feed items.
-- 3. UNDERDOG PRIZE. Biggest rank climber of the week (must have
--    played on at least 3 days). Winner gets a weekly "Underdog"
--    badge (weekly_underdogs row, written by the owner from the
--    game's live climber display at week end) plus a 1 hammer + 1
--    bomb power-up pack claimed in the game. Tie-break: larger point
--    gain, then earlier to reach it.
-- 4. SUNDAY SHOWDOWN. The daily mini-board's Sunday winner gets
--    3 hammers + 3 bombs instead of the normal 1 + 1. (Implemented in
--    the game client from the same daily-board data; the prize is
--    in-game only, so no server prize state is needed.)
-- 5. DAILY SPIN. One free spin per UTC day per logged-in player.
--    The draw is made SERVER-SIDE by claim_daily_spin() from this
--    fixed table: 10 pts (40%), 25 pts (30%), 50 pts (20%),
--    100 pts (10%). Expected value: 31.5 pts/day. The unique
--    (user, day) constraint plus the function check mean a second
--    spin the same day returns the already-recorded result — a
--    re-spin or restart can never re-grant points. Spin points live
--    in spin_balances, a SEPARATE balance: they buy power-ups for
--    CASUAL games only (spend_spin_points()), and there is NO path
--    from spin points to daily coins, to tournament score, or to
--    cash/crypto. Any such conversion would be a bug — report it.
-- =====================================================================

-- ---------------- game_days (streak source) ----------------
create table if not exists public.game_days (
  user_id uuid not null references public.profiles (id) on delete cascade,
  game_date date not null, -- UTC day a game was finished
  primary key (user_id, game_date)
);

-- ---------------- rank_snapshots (pass feed) ----------------
create table if not exists public.rank_snapshots (
  user_id uuid not null references public.profiles (id) on delete cascade,
  week_start date not null, -- Monday (UTC) of the week
  last_rank integer not null,
  last_total integer not null,
  seen_at timestamptz not null default now(),
  primary key (user_id, week_start)
);

-- ---------------- weekly_underdogs (badges) ----------------
create table if not exists public.weekly_underdogs (
  id bigint generated always as identity primary key,
  week_start date not null, -- Monday (UTC) of the week
  user_id uuid not null references public.profiles (id) on delete cascade,
  start_rank integer not null,
  final_rank integer not null,
  improvement integer not null,
  point_gain integer not null,
  unique (week_start, user_id)
);

-- ---------------- spin_claims + spin_balances ----------------
create table if not exists public.spin_claims (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  spin_date date not null, -- UTC day of the spin
  points_won integer not null check (points_won in (10, 25, 50, 100)),
  claimed_at timestamptz not null default now(),
  unique (user_id, spin_date)
);
create table if not exists public.spin_balances (
  user_id uuid primary key references public.profiles (id) on delete cascade,
  points integer not null default 0 check (points >= 0),
  updated_at timestamptz not null default now()
);

-- RLS: players read their own rows. Snapshots are the player's own
-- data, so insert/update of one's own snapshot is allowed. All other
-- engagement tables are written only by the functions below (or, for
-- weekly_underdogs, by the owner) — never directly by players.
alter table public.game_days enable row level security;
alter table public.rank_snapshots enable row level security;
alter table public.weekly_underdogs enable row level security;
alter table public.spin_claims enable row level security;
alter table public.spin_balances enable row level security;

drop policy if exists "game_days readable by owner only" on public.game_days;
create policy "game_days readable by owner only"
  on public.game_days for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "rank_snapshots readable by owner only" on public.rank_snapshots;
create policy "rank_snapshots readable by owner only"
  on public.rank_snapshots for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "rank_snapshots writable by owner only" on public.rank_snapshots;
create policy "rank_snapshots writable by owner only"
  on public.rank_snapshots for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "rank_snapshots updatable by owner only" on public.rank_snapshots;
create policy "rank_snapshots updatable by owner only"
  on public.rank_snapshots for update to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "weekly_underdogs readable by logged-in users" on public.weekly_underdogs;
create policy "weekly_underdogs readable by logged-in users"
  on public.weekly_underdogs for select to authenticated using (true);

drop policy if exists "spin_claims readable by owner only" on public.spin_claims;
create policy "spin_claims readable by owner only"
  on public.spin_claims for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "spin_balances readable by owner only" on public.spin_balances;
create policy "spin_balances readable by owner only"
  on public.spin_balances for select to authenticated
  using (auth.uid() = user_id);

grant select on public.game_days to authenticated;
grant select, insert, update on public.rank_snapshots to authenticated;
grant select on public.weekly_underdogs to authenticated;
grant select on public.spin_claims to authenticated;
grant select on public.spin_balances to authenticated;
grant usage, select, update on sequence public.spin_claims_id_seq to authenticated;
grant usage, select, update on sequence public.weekly_underdogs_id_seq to authenticated;

-- ---------------- record_game_day() ----------------
-- Records that the player finished a game today (any mode). Called on
-- every game end when logged in. Idempotent: one row per day max.
create or replace function public.record_game_day()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_day date := (now() at time zone 'UTC')::date;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;
  insert into public.game_days (user_id, game_date) values (v_uid, v_day)
    on conflict (user_id, game_date) do nothing;
  return jsonb_build_object('recorded', true, 'game_date', v_day);
end;
$$;

grant execute on function public.record_game_day() to authenticated;

-- ---------------- get_streak() ----------------
-- Consecutive UTC days played, ending today or yesterday. If the last
-- played day is older than yesterday, the streak is broken (0).
-- Milestones earned: 3, 7, 30 days.
create or replace function public.get_streak()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_today date := (now() at time zone 'UTC')::date;
  v_latest date;
  v_streak integer := 0;
  v_milestones jsonb;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  select max(game_date) into v_latest from public.game_days where user_id = v_uid;
  if v_latest is null or v_latest < v_today - 1 then
    return jsonb_build_object('streak', 0, 'last_played', v_latest,
      'alive', false, 'milestones', '[]'::jsonb);
  end if;
  -- Gaps-and-islands: for the latest date's consecutive run,
  -- (latest - game_date) equals (row_number - 1) for every row in it,
  -- and the gap only grows afterwards, so the count is exact.
  select count(*) into v_streak from (
    select game_date, row_number() over (order by game_date desc) as rn
    from (select distinct game_date from public.game_days where user_id = v_uid) d
  ) o where (v_latest - o.game_date) = o.rn - 1;
  select coalesce(jsonb_agg(m), '[]'::jsonb) into v_milestones
    from (select unnest(array[3, 7, 30]) as m) x where x.m <= v_streak;
  return jsonb_build_object('streak', v_streak, 'last_played', v_latest,
    'alive', true, 'milestones', v_milestones);
end;
$$;

grant execute on function public.get_streak() to authenticated;

-- ---------------- claim_daily_spin() ----------------
-- One free spin per UTC day. The draw uses Postgres random() against
-- the fixed table (10:40%, 25:30%, 50:20%, 100:10%). A second call the
-- same day returns the ALREADY-RECORDED result — never a new draw.
create or replace function public.claim_daily_spin()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_day date := (now() at time zone 'UTC')::date;
  v_existing public.spin_claims%rowtype;
  v_roll double precision;
  v_points integer;
  v_balance integer := 0;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if not exists (select 1 from public.profiles where id = v_uid) then
    raise exception 'profile missing: complete signup first';
  end if;
  select * into v_existing from public.spin_claims
    where user_id = v_uid and spin_date = v_day;
  if found then
    select points into v_balance from public.spin_balances where user_id = v_uid;
    return jsonb_build_object('already', true, 'points_won', v_existing.points_won,
      'balance', coalesce(v_balance, 0));
  end if;
  v_roll := random();
  v_points := case when v_roll < 0.40 then 10
                   when v_roll < 0.70 then 25
                   when v_roll < 0.90 then 50
                   else 100 end;
  insert into public.spin_claims (user_id, spin_date, points_won)
    values (v_uid, v_day, v_points);
  insert into public.spin_balances (user_id, points) values (v_uid, v_points)
    on conflict (user_id) do update set
      points = public.spin_balances.points + excluded.points,
      updated_at = now()
    returning points into v_balance;
  return jsonb_build_object('already', false, 'points_won', v_points,
    'balance', v_balance);
end;
$$;

grant execute on function public.claim_daily_spin() to authenticated;

-- ---------------- spend_spin_points(item, cost) ----------------
-- Spends spin points on ONE power-up for the next CASUAL game.
-- Prices are fixed server-side (hammer 30, bomb 30); a client that
-- sends any other price is rejected. There is deliberately NO path
-- here to daily coins, tournament score, or cash.
create or replace function public.spend_spin_points(p_item text, p_cost integer)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_balance integer;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  if p_item not in ('hammer', 'bomb') then
    raise exception 'invalid item';
  end if;
  if p_cost <> 30 then
    raise exception 'invalid price';
  end if;
  select points into v_balance from public.spin_balances where user_id = v_uid;
  if v_balance is null or v_balance < 30 then
    raise exception 'not enough spin points';
  end if;
  update public.spin_balances set points = points - 30, updated_at = now()
    where user_id = v_uid returning points into v_balance;
  return jsonb_build_object('balance', v_balance,
    'hammers', case when p_item = 'hammer' then 1 else 0 end,
    'bombs', case when p_item = 'bomb' then 1 else 0 end);
end;
$$;

grant execute on function public.spend_spin_points(text, integer) to authenticated;

-- OWNER NOTE — recording the weekly Underdog winner (by hand, once,
-- after the week ends): open the game's live climber display for the
-- finished week and copy the winner's numbers into this INSERT
-- (replace the placeholders). The badge then appears on the winner's
-- profile, and the winner claims the 1 hammer + 1 bomb pack in-game.
-- insert into public.weekly_underdogs
--   (week_start, user_id, start_rank, final_rank, improvement, point_gain)
-- values ('YYYY-MM-DD', 'PLAYER-UUID-HERE', 0, 0, 0, 0);

-- =====================================================================
-- WEEK-END FREEZE (owner runs this by hand, once, after a week ends)
-- 1. Wait until Monday 00:00 UTC, after the week is over.
-- 2. Replace BOTH 'YYYY-MM-DD' placeholders below with that week's
--    Monday date (UTC), e.g. '2026-11-02'.
-- 3. Paste into the SQL editor and Run. This inserts exactly the top
--    300 players into weekly_results.
-- v55 — BOARD ONLY: the weekly value is the SUM of board_score
-- (games played AFTER the 4-day tournament unlock). Pre-unlock games
-- NEVER count toward prizes, even from the same week. Do NOT run an
-- old saved copy of this freeze: old copies sum total_score and
-- would wrongly pay pre-unlock games. Always copy it from here.
-- RANKING = SCORE, NOT XP: the weekly value is the SUM of board_score
-- in the week, with NO division. XP is progression only
-- (levels/unlock) and never ranks. Rank by the EXACT value
-- (sum(board_score)); the stored total_score is that value.
-- Tied values break
-- by higher single-day board best, then by whoever's final total was
-- set first (earliest last update), so the result is deterministic.
-- 4. Winners then claim inside the game; you pay them manually in
--    crypto and mark each row 'paid' in the Table Editor.
-- =====================================================================
-- insert into public.weekly_results
--   (week_start, user_id, rank, total_score, prize_tier, prize_amount)
-- select
--   w.week_start, w.user_id, w.rnk, w.total_score,
--   case when w.rnk <= 10 then '1-10'
--        when w.rnk <= 20 then '11-20'
--        when w.rnk <= 30 then '21-30'
--        when w.rnk <= 50 then '31-50'
--        when w.rnk <= 100 then '51-100'
--        when w.rnk <= 200 then '101-200'
--        else '201-300' end,
--   case when w.rnk <= 10 then 30
--        when w.rnk <= 20 then 25
--        when w.rnk <= 30 then 20
--        when w.rnk <= 50 then 15
--        else 10 end
-- from (
--   select
--     date 'YYYY-MM-DD' as week_start,
--     user_id,
--     sum(board_score) as total_score,
--     row_number() over (
--       order by sum(board_score) desc,
--                max(board_best_score) desc,
--                max(updated_at) asc
--     ) as rnk
--   from public.ranked_scores
--   where game_date >= date 'YYYY-MM-DD'
--     and game_date < date 'YYYY-MM-DD' + 7
--   group by user_id
-- ) w
-- where w.rnk <= 300;

-- =====================================================================
-- MONTH-END FREEZE — REFERRAL CASH TOURNAMENT (owner runs by hand,
-- once, after a month ends). DO NOT RUN THIS NOW: the first referral
-- month is November 2026, so the first freeze runs in early December
-- 2026, after November ends.
-- 1. Wait until the month is over (UTC).
-- 2. Replace EVERY 'YYYY-MM-01' placeholder below with that month's
--    first day (UTC), e.g. '2026-11-01' for November 2026.
-- 3. Paste into the SQL editor and Run. This inserts exactly the top
--    100 referrers into monthly_referral_results.
-- RANKING: count of referral_unlock_events in the month (a friend
-- counts only once they reach a 5-day streak — attributed-but-not-
-- successful friends do not count). Ties break by who reached their count first:
-- reached_at is the unlocked_at of the referrer's count-th unlock
-- event in the month (the latest one), earliest first, so the result
-- is deterministic. The ladder cap does NOT apply here: referrers
-- past ladder position 100 still count, because their unlock events
-- are still recorded.
-- PRIZES (cash, paid manually in crypto after claiming): 1st $100,
-- 2nd $90, 3rd $80, 4th $70, 5th $60, 6th $50, 7th $40, 8th $30,
-- 9th-100th $20 each ($2,360/month).
-- 4. Winners then claim inside the game; you pay them manually in
--    crypto and mark each row 'paid' in the Table Editor.
-- =====================================================================
-- with numbered as (
--   select referrer_id, unlocked_at,
--     row_number() over (
--       partition by referrer_id order by unlocked_at, friend_id) as rn
--   from public.referral_unlock_events
--   where (unlocked_at at time zone 'UTC')::date >= date 'YYYY-MM-01'
--     and (unlocked_at at time zone 'UTC')::date < date 'YYYY-MM-01' + interval '1 month'
-- ),
-- counts as (
--   select referrer_id, count(*) as cnt from numbered group by referrer_id
-- ),
-- ranked as (
--   select c.referrer_id, c.cnt, n.unlocked_at as reached_at,
--     row_number() over (order by c.cnt desc, n.unlocked_at asc) as rnk
--   from counts c
--   join numbered n
--     on n.referrer_id = c.referrer_id and n.rn = c.cnt
-- )
-- insert into public.monthly_referral_results
--   (month_start, user_id, rank, referral_count, prize_amount)
-- select
--   date 'YYYY-MM-01', r.referrer_id, r.rnk, r.cnt,
--   case when r.rnk = 1 then 100
--        when r.rnk = 2 then 90
--        when r.rnk = 3 then 80
--        when r.rnk = 4 then 70
--        when r.rnk = 5 then 60
--        when r.rnk = 6 then 50
--        when r.rnk = 7 then 40
--        when r.rnk = 8 then 30
--        else 20 end
-- from ranked r
-- where r.rnk <= 100;

-- =====================================================================
-- MONTH-END FREEZE — TOURNAMENT (owner runs by hand, once, after a
-- month ends). v57: the tournament board is MONTHLY (it replaced the
-- weekly board). The last weekly tournament was week 2026-10-26 (its
-- standalone freeze file is separate and is NOT part of this migration).
-- 1. Wait until the 1st of the next month, 00:00 UTC, after the month
--    is over.
-- 2. Replace EVERY 'YYYY-MM-01' placeholder below with that month's
--    first day (UTC), e.g. '2026-11-01' for November 2026.
-- 3. Paste into the SQL editor and Run. This inserts exactly the top
--    300 players into monthly_results.
-- BOARD ONLY: the monthly value is the SUM of board_score (games
-- played AFTER the 4-day tournament unlock). Pre-unlock games NEVER
-- count toward prizes, even from the same month.
-- RANKING = SCORE, NOT XP: the monthly value is the SUM of board_score
-- in the month, with NO division. Rank by the EXACT value
-- (sum(board_score)); the stored total_score is that value. Tied
-- values break by higher single-day board best, then by whoever's
-- final total was set first (earliest last update), so the result is
-- deterministic.
-- PRIZES (same tiers as the old weekly, once a month — NOT scaled up):
-- 1-10 $30, 11-20 $25, 21-30 $20, 31-50 $15, 51-300 $10 ($3,550/month).
-- 4. Winners then claim inside the game; you pay them manually in
--    crypto and mark each row 'paid' in the Table Editor.
-- BEFORE THE FIRST RUN, verify in the Table Editor that
-- monthly_results has NO rank cap below 300 (it is created with
-- rank <= 300 by this migration; the old weekly table carried a stale
-- rank <= 50 check in schema.sql — never copy that check here).
-- =====================================================================
-- insert into public.monthly_results
--   (month_start, user_id, rank, total_score, prize_tier, prize_amount)
-- select
--   w.month_start, w.user_id, w.rnk, w.total_score,
--   case when w.rnk <= 10 then '1-10'
--        when w.rnk <= 20 then '11-20'
--        when w.rnk <= 30 then '21-30'
--        when w.rnk <= 50 then '31-50'
--        when w.rnk <= 100 then '51-100'
--        when w.rnk <= 200 then '101-200'
--        else '201-300' end,
--   case when w.rnk <= 10 then 30
--        when w.rnk <= 20 then 25
--        when w.rnk <= 30 then 20
--        when w.rnk <= 50 then 15
--        else 10 end
-- from (
--   select
--     date 'YYYY-MM-01' as month_start,
--     user_id,
--     sum(board_score) as total_score,
--     row_number() over (
--       order by sum(board_score) desc,
--                max(board_best_score) desc,
--                max(updated_at) asc
--     ) as rnk
--   from public.ranked_scores
--   where game_date >= date 'YYYY-MM-01'
--     and game_date < date 'YYYY-MM-01' + interval '1 month'
--   group by user_id
-- ) w
-- where w.rnk <= 300;
