-- =====================================================================
-- Row Level Security for the COE Claims System
-- Run AFTER db/schema.sql. Safe to re-run (drops and recreates policies).
-- =====================================================================
-- Model
--   anon           = the public portal (coe-portal). Browser holds the
--                    publishable key, so assume anyone can call the API
--                    directly with it. The ?t= token is NOT checked here.
--   authenticated  = a logged-in admin (coe-app). No roles exist, so every
--                    Supabase Auth user is a full admin. Disable public
--                    sign-ups in Supabase Auth settings.
--
-- anon can:  INSERT claims, INSERT claim_date_rows, only while an active,
--            unexpired portal_access row exists for the claim's season,
--            and only as status='draft', entry_source='portal', amount=0.
--            SELECT exam_seasons (the portal reads its season name; see Questions).
-- exam_schedule is not covered here (table not deployed). Its policies are in
-- db/optional_exam_schedule.sql.
-- anon can NOT: select/update/delete anything else.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. Helper functions (SECURITY DEFINER)
-- anon has no SELECT on portal_access or claims, so the policy cannot
-- read them directly. These run as the table owner, return only a
-- boolean, and have a pinned search_path.
-- ---------------------------------------------------------------------
create or replace function public.portal_season_is_open(p_season_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.portal_access pa
    where pa.season_id  = p_season_id
      and pa.is_active  = true
      and pa.expires_at > now()
  );
$$;

-- A date row may be attached only to a portal draft whose season is still open.
-- claims.id is text in the live database (not uuid).
drop function if exists public.portal_claim_accepts_rows(uuid);
create or replace function public.portal_claim_accepts_rows(p_claim_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.claims c
    where c.id           = p_claim_id
      and c.status       = 'draft'
      and c.entry_source = 'portal'
      and public.portal_season_is_open(c.season_id)
  );
$$;

revoke all on function public.portal_season_is_open(text)     from public;
revoke all on function public.portal_claim_accepts_rows(text) from public;
grant execute on function public.portal_season_is_open(text)     to anon, authenticated;
grant execute on function public.portal_claim_accepts_rows(text) to anon, authenticated;


-- ---------------------------------------------------------------------
-- 2. Table privileges: start from nothing for anon
-- Supabase grants anon broad table privileges by default; RLS is then the
-- only guard. Remove them so a missing policy cannot open a table.
-- ---------------------------------------------------------------------
revoke all on public.claims, public.claim_date_rows, public.staff, public.exam_seasons,
              public.portal_access, public.app_settings,
              public.audit_log
  from anon;

grant insert on public.claims          to anon;
grant insert on public.claim_date_rows to anon;
grant select on public.exam_seasons    to anon;
-- claim_date_rows.id is an identity column; anon needs its sequence to insert.
grant usage on all sequences in schema public to anon;

grant select, insert, update, delete on
  public.claims, public.claim_date_rows, public.staff, public.exam_seasons,
  public.portal_access, public.app_settings
  to authenticated;
-- audit_log: append and read only, no edit or delete from the browser.
grant select, insert on public.audit_log to authenticated;
grant usage on all sequences in schema public to authenticated;


-- ---------------------------------------------------------------------
-- 3. Enable RLS everywhere
-- ---------------------------------------------------------------------
alter table public.claims          enable row level security;
alter table public.claim_date_rows enable row level security;
alter table public.staff           enable row level security;
alter table public.exam_seasons    enable row level security;
alter table public.portal_access   enable row level security;
alter table public.app_settings    enable row level security;
alter table public.audit_log       enable row level security;


-- Remove every pre-existing policy on the COE tables so only the ones below remain.
do $$
declare r record;
begin
  for r in
    select policyname, tablename from pg_policies
    where schemaname = 'public'
      and tablename in ('claims','claim_date_rows','staff','exam_seasons',
                        'portal_access','app_settings','audit_log')
  loop
    execute format('drop policy if exists %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;


-- ---------------------------------------------------------------------
-- 4. anon (portal) policies
-- ---------------------------------------------------------------------
drop policy if exists portal_insert_claims on public.claims;
create policy portal_insert_claims
  on public.claims
  for insert
  to anon
  with check (
        status       = 'draft'
    and entry_source = 'portal'
    and amount       = 0       -- the portal always sends 0; the admin sets amounts on approval
    and public.portal_season_is_open(season_id)
  );

drop policy if exists portal_insert_claim_date_rows on public.claim_date_rows;
create policy portal_insert_claim_date_rows
  on public.claim_date_rows
  for insert
  to anon
  with check ( public.portal_claim_accepts_rows(claim_id) );

-- The portal reads its season row to show the season name and to get the id
-- it submits. Exposes season id/name/is_active only; no claim data.
drop policy if exists portal_read_seasons on public.exam_seasons;
create policy portal_read_seasons
  on public.exam_seasons
  for select
  to anon
  using ( true );

-- No other anon policy exists, so anon select/update/delete on claims and
-- claim_date_rows, and every operation on the other tables, is denied.


-- ---------------------------------------------------------------------
-- 5. authenticated (admin app) policies: full access
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array['claims','claim_date_rows','staff','exam_seasons',
                           'portal_access','app_settings']
  loop
    execute format('drop policy if exists admin_all on public.%I', t);
    execute format(
      'create policy admin_all on public.%I for all to authenticated using (true) with check (true)', t);
  end loop;
end $$;

-- audit_log: admins may read and append, never edit or delete.
drop policy if exists admin_read_audit   on public.audit_log;
drop policy if exists admin_insert_audit on public.audit_log;
create policy admin_read_audit   on public.audit_log for select to authenticated using (true);
create policy admin_insert_audit on public.audit_log for insert to authenticated with check (true);
