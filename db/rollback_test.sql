-- =====================================================================
-- db/rollback_test.sql: security tests that leave NOTHING behind
-- =====================================================================
-- WHAT THIS DOES
--   1. Applies db/rls_policies.sql   (section 1 below, copied verbatim)
--   2. Applies db/audit_triggers.sql (section 2 below, copied verbatim)
--   3. Runs the access/audit tests in one DO block and raises an exception
--      whose message is the PASS/FAIL report. The exception aborts the
--      transaction, so the policies, triggers and test rows from steps 1-3
--      are ALL rolled back. The database ends up exactly as it started.
--
-- HOW TO RUN: paste the whole file into the Supabase SQL editor and run it
-- once. The "error" shown IS the report ("TEST RESULTS ..."). Run it on a
-- development/staging copy first. It must run as postgres (it uses
-- SET LOCAL ROLE anon / authenticated).
--
-- KEEP IN SYNC: sections 1 and 2 are copies. If you edit rls_policies.sql
-- or audit_triggers.sql, regenerate this file or the test will check old SQL.
--
-- SAFETY NOTE: the explicit BEGIN below makes the whole file one transaction
-- even in tools that run statements one by one. If you run it in such a tool
-- and the final error leaves the session "in a failed transaction", issue
-- ROLLBACK. NEVER add COMMIT.
-- Test data ids all start with 'ZZTEST'. Nothing here is committed.
-- =====================================================================

begin;


-- =====================================================================
-- 1. db/rls_policies.sql (verbatim copy)
-- =====================================================================

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


-- =====================================================================
-- 2. db/audit_triggers.sql (verbatim copy)
-- =====================================================================

-- =====================================================================
-- Database-side audit logging for claims
-- Run AFTER db/schema.sql (and rls_policies.sql). Safe to re-run.
-- =====================================================================
-- Every INSERT / UPDATE / DELETE on public.claims is written to
-- public.audit_log by the database, regardless of which client made it
-- (admin app, portal, SQL editor, a script).
--
-- The trigger function is SECURITY DEFINER because the portal's anon role
-- has no privileges on audit_log, yet portal submissions must be logged.
-- =====================================================================

create or replace function public.audit_row_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor  text;
  v_record text;
  v_old    jsonb;
  v_new    jsonb;
begin
  -- Who: the admin's email when logged in; otherwise the DB role
  -- ('anon' = portal visitor, 'postgres'/'service_role' = SQL editor / scripts).
  v_actor := coalesce(
    nullif(auth.jwt() ->> 'email', ''),
    nullif(current_setting('request.jwt.claim.email', true), ''),
    case when auth.role() = 'anon' then 'portal (anon)' end,
    session_user
  );

  if tg_op = 'INSERT' then
    v_old := null;
    v_new := to_jsonb(new);
  elsif tg_op = 'UPDATE' then
    v_old := to_jsonb(old);
    v_new := to_jsonb(new);
    -- Ignore no-op updates so they do not flood the log.
    if v_old = v_new then
      return new;
    end if;
  else  -- DELETE
    v_old := to_jsonb(old);
    v_new := null;
  end if;

  -- claims.id and claim_date_rows.id are both cast to text (audit_log.record_id is text).
  v_record := case when tg_op = 'DELETE' then (to_jsonb(old) ->> 'id')
                   else (to_jsonb(new) ->> 'id') end;

  insert into public.audit_log (table_name, record_id, action, changed_by, old_data, new_data)
  values (tg_table_name, v_record, tg_op, v_actor, v_old, v_new);

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

-- The function is only meant to be called by triggers.
revoke all on function public.audit_row_change() from public;


drop trigger if exists audit_claims on public.claims;
create trigger audit_claims
  after insert or update or delete on public.claims
  for each row execute function public.audit_row_change();

-- claim_date_rows is deliberately NOT audited (owner decision): the admin app deletes and
-- re-inserts all of a claim's date rows on every save, which would flood the log.
-- Remove a trigger left over from an earlier version of this file:
drop trigger if exists audit_claim_date_rows on public.claim_date_rows;


-- ---------------------------------------------------------------------
-- Things to know
-- 1. The browser's logAction() calls for claims were removed from coe-app, so this
--    trigger is now the only source of claims audit rows. Audit rows for staff and
--    exam_seasons are still written by the browser.
-- 2. Shape: the trigger logs the FULL row as jsonb in old_data/new_data. The Audit Log
--    screen reads data.name / work_type_id / amount, which exist in the full row, and
--    new_data.status = 'verified' still gives the "Approved portal submission" wording.
-- 3. Privacy: bank account and mobile numbers are copied into audit_log. Only
--    authenticated admins can read audit_log (see rls_policies.sql).
-- 4. Change of record: the approve step used to log {source:'portal_approval'};
--    the trigger just sees status draft -> verified.
-- ---------------------------------------------------------------------


-- =====================================================================
-- 3. TESTS. One DO block; every test has its own BEGIN ... EXCEPTION
-- block, so a failing test cannot stop the rest. PASS/FAIL lines are
-- collected in `results`, then the block raises an exception so the
-- WHOLE transaction (the two scripts above plus all test data) rolls back.
--
-- How "rejected" is judged: the statement must raise SQLSTATE 42501
-- (insufficient_privilege: covers both "permission denied" and "new row
-- violates row-level security policy"). Any OTHER error is reported as FAIL
-- (it would mean the test itself is broken, e.g. a missing column), so a typo
-- can never be mistaken for a passing security check.
-- Test data: ids start with 'ZZTEST'. Nothing here touches real rows.
-- =====================================================================
do $test$
declare
  results text := '';
  t       text;
  n       bigint;
  n2      bigint;
  rc      bigint;
  v_actor text;
begin

  -- -------------------------------------------------------------------
  -- SETUP (as postgres): test season, open portal, an admin-made claim,
  -- a date row on it, and a staff row. Seeds make "zero rows" meaningful.
  -- -------------------------------------------------------------------
  begin
    insert into public.exam_seasons (id, name) values ('ZZTEST_S1', 'ZZTEST season');
    insert into public.portal_access (season_id, expires_at, is_active)
      values ('ZZTEST_S1', now() + interval '1 hour', true);
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source)
      values ('ZZTEST_ADMIN', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST Admin Claim', 'draft', 'admin');
    insert into public.claim_date_rows (claim_id, date, session)
      values ('ZZTEST_ADMIN', '2026-01-01', 'FN');
    insert into public.staff (id, name, staff_type)
      values ('ZZTEST_ST1', 'ZZTEST Staff', 'EXT');
    results := results || 'PASS: setup (season, active portal_access +1h, admin claim, date row, staff)' || E'\n';
  exception when others then
    results := results || format('FAIL: setup (%s: %s). Later results are unreliable', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- A. anon SELECT: denied or zero rows (tables all contain seeded rows)
  -- -------------------------------------------------------------------
  foreach t in array array['claims','claim_date_rows','staff','portal_access','audit_log']
  loop
    begin
      set local role anon;
      execute format('select count(*) from public.%I', t) into n;
      reset role;
      if n = 0 then
        results := results || format('PASS: anon select on %s returns 0 rows', t) || E'\n';
      else
        results := results || format('FAIL: anon select on %s sees %s rows', t, n) || E'\n';
      end if;
    exception
      when insufficient_privilege then
        reset role;
        results := results || format('PASS: anon select on %s denied', t) || E'\n';
      when others then
        reset role;
        results := results || format('FAIL: anon select on %s unexpected error %s: %s', t, sqlstate, sqlerrm) || E'\n';
    end;
  end loop;

  -- anon CAN read exam_seasons (the one allowed read; the portal needs it)
  begin
    set local role anon;
    select count(*) into n from public.exam_seasons where id = 'ZZTEST_S1';
    reset role;
    if n = 1 then
      results := results || 'PASS: anon can read exam_seasons (portal needs it)' || E'\n';
    else
      results := results || format('FAIL: anon sees %s ZZTEST exam_seasons rows, expected 1', n) || E'\n';
    end if;
  exception when others then
    reset role;
    results := results || format('FAIL: anon read of exam_seasons %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- B. anon INSERT into claims
  -- -------------------------------------------------------------------
  -- B1. allowed: portal draft, amount 0, open season
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C1', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST Portal Person', 'draft', 'portal', 0);
    reset role;
    results := results || 'PASS: anon insert of portal draft claim (amount 0, open season) allowed' || E'\n';
  exception when others then
    reset role;
    results := results || format('FAIL: anon portal draft insert was blocked (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- B2. rejected: status 'verified'
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C2', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST x', 'verified', 'portal', 0);
    reset role;
    results := results || 'FAIL: anon insert with status verified was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon insert with status verified rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: status verified test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- B3. rejected: amount 5
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C3', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST x', 'draft', 'portal', 5);
    reset role;
    results := results || 'FAIL: anon insert with amount 5 was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon insert with amount 5 rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: amount 5 test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- B4. rejected: entry_source 'admin'
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C4', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST x', 'draft', 'admin', 0);
    reset role;
    results := results || 'FAIL: anon insert with entry_source admin was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon insert with entry_source admin rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: entry_source admin test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- C. anon INSERT into claim_date_rows
  -- -------------------------------------------------------------------
  -- C1. allowed: for the ZZTEST portal draft
  begin
    set local role anon;
    insert into public.claim_date_rows (claim_id, date, session, no_sessions)
      values ('ZZTEST_C1', '2026-01-02', 'FN', 1);
    reset role;
    results := results || 'PASS: anon date row for the ZZTEST portal draft allowed' || E'\n';
  exception when others then
    reset role;
    results := results || format('FAIL: anon date row for portal draft was blocked (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- C2. rejected: for a non-portal (admin) claim
  begin
    set local role anon;
    insert into public.claim_date_rows (claim_id, date, session, no_sessions)
      values ('ZZTEST_ADMIN', '2026-01-03', 'FN', 1);
    reset role;
    results := results || 'FAIL: anon date row for a NON-portal claim was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon date row for a non-portal claim rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: non-portal date row test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- D. portal closed / expired (changed as postgres, tested as anon)
  -- -------------------------------------------------------------------
  -- D1. is_active = false
  update public.portal_access set is_active = false where season_id = 'ZZTEST_S1';
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C5', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST x', 'draft', 'portal', 0);
    reset role;
    results := results || 'FAIL: anon claim insert with portal_access.is_active=false was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon claim insert rejected when is_active = false' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: is_active=false test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;
  -- D1b. (extra) a date row on the existing draft is also refused while closed
  begin
    set local role anon;
    insert into public.claim_date_rows (claim_id, date, session, no_sessions)
      values ('ZZTEST_C1', '2026-01-04', 'FN', 1);
    reset role;
    results := results || 'FAIL: anon date row was ALLOWED while portal closed' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: (extra) anon date row rejected when is_active = false' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: closed-portal date row test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- D2. is_active = true but expires_at in the past
  update public.portal_access
     set is_active = true, expires_at = now() - interval '1 minute'
   where season_id = 'ZZTEST_S1';
  begin
    set local role anon;
    insert into public.claims (id, season_id, work_type_id, name, status, entry_source, amount)
      values ('ZZTEST_C6', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST x', 'draft', 'portal', 0);
    reset role;
    results := results || 'FAIL: anon claim insert with expired portal_access was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon claim insert rejected when expires_at is in the past' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: expired test unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- put the portal back to open for the remaining tests
  update public.portal_access
     set is_active = true, expires_at = now() + interval '1 hour'
   where season_id = 'ZZTEST_S1';

  -- -------------------------------------------------------------------
  -- E. anon INSERT / UPDATE / DELETE on staff and audit_log: rejected.
  -- UPDATE/DELETE pass if denied OR if they touch 0 rows; FAIL if rows change.
  -- -------------------------------------------------------------------
  -- E1. staff insert
  begin
    set local role anon;
    insert into public.staff (id, name, staff_type) values ('ZZTEST_ST2', 'ZZTEST anon staff', 'EXT');
    reset role;
    results := results || 'FAIL: anon insert into staff was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon insert into staff rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon staff insert unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- E2. staff update
  begin
    set local role anon;
    update public.staff set name = 'ZZTEST hacked' where id = 'ZZTEST_ST1';
    get diagnostics rc = row_count;
    reset role;
    if rc = 0 then
      results := results || 'PASS: anon update on staff changed 0 rows' || E'\n';
    else
      results := results || format('FAIL: anon update on staff changed %s rows', rc) || E'\n';
    end if;
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon update on staff rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon staff update unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- E3. staff delete
  begin
    set local role anon;
    delete from public.staff where id = 'ZZTEST_ST1';
    get diagnostics rc = row_count;
    reset role;
    if rc = 0 then
      results := results || 'PASS: anon delete on staff removed 0 rows' || E'\n';
    else
      results := results || format('FAIL: anon delete on staff removed %s rows', rc) || E'\n';
    end if;
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon delete on staff rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon staff delete unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- E4. audit_log insert
  begin
    set local role anon;
    insert into public.audit_log (table_name, record_id, action, changed_by)
      values ('ZZTEST', 'ZZTEST_FAKE', 'INSERT', 'anon');
    reset role;
    results := results || 'FAIL: anon insert into audit_log was ALLOWED' || E'\n';
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon insert into audit_log rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon audit_log insert unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- E5. audit_log update
  begin
    set local role anon;
    update public.audit_log set action = 'ZZTEST_TAMPER' where table_name = 'claims';
    get diagnostics rc = row_count;
    reset role;
    if rc = 0 then
      results := results || 'PASS: anon update on audit_log changed 0 rows' || E'\n';
    else
      results := results || format('FAIL: anon update on audit_log changed %s rows', rc) || E'\n';
    end if;
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon update on audit_log rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon audit_log update unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- E6. audit_log delete
  begin
    set local role anon;
    delete from public.audit_log where table_name = 'claims';
    get diagnostics rc = row_count;
    reset role;
    if rc = 0 then
      results := results || 'PASS: anon delete on audit_log removed 0 rows' || E'\n';
    else
      results := results || format('FAIL: anon delete on audit_log removed %s rows', rc) || E'\n';
    end if;
  exception
    when insufficient_privilege then
      reset role;
      results := results || 'PASS: anon delete on audit_log rejected' || E'\n';
    when others then
      reset role;
      results := results || format('FAIL: anon audit_log delete unexpected error %s: %s', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- F. authenticated (fake admin email) can select / insert / update
  -- claims and staff. The JWT claims setting is what auth.jwt() reads.
  -- -------------------------------------------------------------------
  -- F1. claims select
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    select count(*) into n from public.claims where id like 'ZZTEST%';
    reset role;
    if n >= 1 then
      results := results || format('PASS: authenticated can select claims (%s ZZTEST rows visible)', n) || E'\n';
    else
      results := results || 'FAIL: authenticated sees no ZZTEST claims' || E'\n';
    end if;
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated select on claims (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F2. claims insert (admin-style: no status/entry_source, defaults apply)
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    insert into public.claims (id, season_id, work_type_id, name, amount)
      values ('ZZTEST_AUTH1', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST Admin Insert', 100);
    reset role;
    results := results || 'PASS: authenticated can insert into claims' || E'\n';
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated insert into claims (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F3. claims update
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    update public.claims set amount = 200 where id = 'ZZTEST_AUTH1';
    get diagnostics rc = row_count;
    reset role;
    if rc = 1 then
      results := results || 'PASS: authenticated can update claims' || E'\n';
    else
      results := results || format('FAIL: authenticated update on claims changed %s rows, expected 1', rc) || E'\n';
    end if;
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated update on claims (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F4. staff select
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    select count(*) into n from public.staff where id like 'ZZTEST%';
    reset role;
    if n >= 1 then
      results := results || format('PASS: authenticated can select staff (%s ZZTEST rows visible)', n) || E'\n';
    else
      results := results || 'FAIL: authenticated sees no ZZTEST staff' || E'\n';
    end if;
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated select on staff (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F5. staff insert
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    insert into public.staff (id, name, staff_type) values ('ZZTEST_ST3', 'ZZTEST Admin Staff', 'INT');
    reset role;
    results := results || 'PASS: authenticated can insert into staff' || E'\n';
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated insert into staff (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F6. staff update
  begin
    set local role authenticated;
    perform set_config('request.jwt.claims',
      '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","email":"zztest-admin@example.invalid"}', true);
    update public.staff set dept = 'ZZTEST' where id = 'ZZTEST_ST3';
    get diagnostics rc = row_count;
    reset role;
    if rc = 1 then
      results := results || 'PASS: authenticated can update staff' || E'\n';
    else
      results := results || format('FAIL: authenticated update on staff changed %s rows, expected 1', rc) || E'\n';
    end if;
  exception when others then
    reset role;
    results := results || format('FAIL: authenticated update on staff (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- F7. (extra) the audit trigger recorded the fake admin's email for F2
  begin
    select changed_by into v_actor
      from public.audit_log
     where table_name = 'claims' and record_id = 'ZZTEST_AUTH1' and action = 'INSERT'
     limit 1;
    if v_actor = 'zztest-admin@example.invalid' then
      results := results || 'PASS: (extra) audit row for the authenticated insert has changed_by = the JWT email' || E'\n';
    else
      results := results || format('FAIL: (extra) audit changed_by is %L, expected the JWT email', v_actor) || E'\n';
    end if;
  exception when others then
    results := results || format('FAIL: (extra) audit changed_by check (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- clear the fake JWT so the postgres-side audit test below is not attributed to it
  perform set_config('request.jwt.claims', '', true);

  -- -------------------------------------------------------------------
  -- G. audit trigger: update a ZZTEST claim as postgres, expect exactly
  -- ONE audit_log row for the UPDATE (and one for the earlier INSERT),
  -- i.e. no duplicate logging.
  -- -------------------------------------------------------------------
  begin
    insert into public.claims (id, season_id, work_type_id, name, amount)
      values ('ZZTEST_AUD', 'ZZTEST_S1', 'QP_EXT', 'ZZTEST Audit Subject', 0);
    update public.claims set amount = 1 where id = 'ZZTEST_AUD';
    select count(*) filter (where action = 'UPDATE'),
           count(*) filter (where action = 'INSERT')
      into n, n2
      from public.audit_log
     where table_name = 'claims' and record_id = 'ZZTEST_AUD';
    if n = 1 and n2 = 1 then
      results := results || 'PASS: claim update wrote exactly 1 UPDATE audit row (and 1 INSERT row for the creation)' || E'\n';
    else
      results := results || format('FAIL: audit rows for ZZTEST_AUD: %s UPDATE, %s INSERT (expected 1 and 1)', n, n2) || E'\n';
    end if;
  exception when others then
    results := results || format('FAIL: audit trigger test (%s: %s)', sqlstate, sqlerrm) || E'\n';
  end;

  -- -------------------------------------------------------------------
  -- Summary, then abort everything.
  -- -------------------------------------------------------------------
  results := format(E'\n%s PASS, %s FAIL\n',
                    array_length(regexp_split_to_array(results, 'PASS: '), 1) - 1,
                    array_length(regexp_split_to_array(results, 'FAIL: '), 1) - 1)
             || results;

  RAISE EXCEPTION 'TEST RESULTS (everything is rolled back):%', results;
end
$test$;

-- Only reached if the DO block somehow did not raise (it always should).
rollback;
