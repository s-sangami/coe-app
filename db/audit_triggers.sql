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
