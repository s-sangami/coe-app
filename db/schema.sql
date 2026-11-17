-- =====================================================================
-- COE Claims System: database schema (RECONSTRUCTED, not exported)
-- =====================================================================
-- This file was inferred by reading the .from()/insert/select/update/
-- delete calls in coe-app/index.html and coe-portal/index.html. It was
-- NOT dumped from the live database, so it may differ from what is
-- actually deployed.
--
-- Conventions used in the comments below:
--   (no marker)  column NAME is used by the code. Its TYPE is still an
--                inference unless a comment says otherwise.
--   -- GUESS:    the column, type, default, constraint or key is not
--                visible in the code. Verify against the live DB
--                (Supabase > Table editor, or `pg_dump --schema-only`).
--
-- Safe to run on an empty project. Uses IF NOT EXISTS, so it will NOT
-- alter tables that already exist. Do not run against production before
-- diffing it with the real schema.
-- =====================================================================

create extension if not exists pgcrypto;  -- gen_random_uuid(); built in on Supabase


-- ---------------------------------------------------------------------
-- exam_seasons: one row per exam session, e.g. 'ND25' (Nov/Dec 2025)
-- Code: insert {id,name,is_active}; select *; delete by id.
-- ---------------------------------------------------------------------
create table if not exists public.exam_seasons (
  id         text primary key,                 -- app-generated, e.g. 'ND25', 'AM28', 'ND27_1'. text because of the letter prefix
  name       text not null,                    -- e.g. 'Nov/Dec 2025'
  is_active  boolean not null default true,    -- GUESS: default and NOT NULL. Code always sends true on insert; nothing reads it
  created_at timestamptz not null default now()  -- GUESS: column not referenced in code at all
);


-- ---------------------------------------------------------------------
-- staff: directory of internal (INT) and external (EXT) staff
-- Code: select/insert/update/delete; unique-ish on (name, staff_type).
-- ---------------------------------------------------------------------
create table if not exists public.staff (
  id           text primary key,               -- GUESS: text. claims.id is text live and claims.staff_id is text; app sends uuid strings, no DB default
  name         text not null,
  staff_type   text not null
               check (staff_type in ('INT','EXT')),  -- values seen in code: 'INT' / 'EXT'. GUESS: the CHECK itself
  designation  text,
  dept         text,
  college      text,
  college_code text,                           -- GUESS: sent by the Excel import, but not by the add-staff form. May not exist live
  mobile_no    text,                           -- text, not numeric: keeps leading digits and formatting
  ac_no        text,                           -- bank account number, text on purpose (leading zeros, long)
  ifsc_code    text,
  bank         text,
  branch       text,
  created_at   timestamptz not null default now()  -- GUESS: not referenced in code
);
-- GUESS: the app checks duplicates by (name, staff_type) in code only. No unique
-- constraint is added because the app deliberately allows same-name different people.
create index if not exists staff_name_type_idx on public.staff (name, staff_type);


-- ---------------------------------------------------------------------
-- claims: one payment claim by one person for one work type in one season
-- Written by BOTH apps. Portal rows arrive as status='draft',
-- entry_source='portal'.
-- ---------------------------------------------------------------------
create table if not exists public.claims (
  -- Column list below matches the LIVE database (information_schema output supplied by
  -- the owner). Foreign keys, indexes and the sequence of columns are still not verified.
  id            text primary key,              -- LIVE: text, no default. App/portal send crypto.randomUUID() strings. (Earlier draft wrongly said uuid)
  season_id     text not null
                references public.exam_seasons(id),  -- GUESS: the FK itself (column is live)
  work_type_id  text not null,                 -- codes such as 'QP_EXT','CS','EXT_DUTY'; list lives in app code
  staff_id      text,                          -- LIVE, but not used by either app's code. GUESS: meaning (link to staff.id)
  name          text not null default '',
  dept          text default '',
  college       text default '',
  mobile_no     text default '',
  ac_no         text default '',
  ifsc_code     text default '',
  bank          text default '',
  branch        text default '',
  amount        numeric not null default 0,
  designation   text default '',
  subject_code  text default '',               -- NOTE: may hold a JSON array string for multi-subject claims
  subject_name  text default '',
  board_name    text default '',
  claim_desc    text default '',
  assigned_duty text default '',
  qty_sessions  numeric default 0,
  rate          numeric default 0,             -- LIVE, but not used by either app's code
  status        text default 'draft',          -- LIVE default 'draft', nullable. Values in code: 'draft', 'verified'. No CHECK (GUESS: none live)
  entry_source  text default 'admin',          -- LIVE default 'admin'; portal sends 'portal'
  created_at    timestamptz default now(),
  updated_at    timestamptz default now(),     -- LIVE. GUESS: whether a trigger keeps it current (none is defined here)
  college_code  text                           -- LIVE: no default, nullable
);
create index if not exists claims_season_work_idx   on public.claims (season_id, work_type_id);
create index if not exists claims_portal_draft_idx  on public.claims (entry_source, status);  -- GUESS: index, for the pending-approvals query


-- ---------------------------------------------------------------------
-- claim_date_rows: per-date lines for date-based claims
-- (practical, hall duty, squad, etc.). Child of claims.
-- ---------------------------------------------------------------------
create table if not exists public.claim_date_rows (
  id          bigint generated by default as identity primary key,  -- GUESS: the app never reads or writes a row id
  claim_id    text not null
              references public.claims(id),    -- an FK must exist: supabase-js embeds claim_date_rows(*) inside claims queries.
                                               -- GUESS: no ON DELETE CASCADE, because the app deletes children first by hand
  date        text not null default '',        -- GUESS: text. Both apps send '' when blank, which a date column would reject
  session     text not null default 'FN',      -- 'FN' / 'AN'; GUESS: default
  no_sessions integer not null default 1,      -- GUESS: integer
  ehs_rem     numeric(12,2) not null default 0,  -- external hall supervisor remuneration
  ehs_lump    numeric(12,2) not null default 0,  -- external hall supervisor lump sum
  ihs_rem     numeric(12,2) not null default 0,  -- internal hall supervisor remuneration
  rhs_rem     numeric(12,2) not null default 0,  -- reserve hall supervisor remuneration
  row_amount  numeric(12,2) not null default 0   -- this row's payable amount
  -- No qty_sessions / ehs_total / row_total columns: those names were used only by the Excel
  -- bulk importer, which has been changed to use no_sessions and row_amount.
);
create index if not exists claim_date_rows_claim_idx on public.claim_date_rows (claim_id);


-- ---------------------------------------------------------------------
-- exam_schedule: subject code -> exam date/session lookup per season
-- (uploaded as Excel; the app deletes all rows for the season, then re-inserts)
-- ---------------------------------------------------------------------
create table if not exists public.exam_schedule (
  id           bigint generated by default as identity primary key,  -- GUESS: never referenced in code
  season_id    text not null
               references public.exam_seasons(id) on delete cascade,  -- GUESS: FK. ON DELETE CASCADE per owner decision, so deleting a season removes its schedule
  subject_code text not null,                  -- upper-cased by the import
  subject_name text,
  exam_date    date,                           -- GUESS: date. Import writes 'YYYY-MM-DD' or null
  session      text not null default ''        -- 'FN' / 'AN' or ''. Import writes '' when absent
);
create index if not exists exam_schedule_season_idx on public.exam_schedule (season_id);
-- claims and claim_date_rows deliberately have NO cascade (owner decision): the app deletes children by hand.


-- ---------------------------------------------------------------------
-- portal_access: "is the external portal open for this season, until when"
-- Code only SELECTs (latest by id) and UPDATEs is_active=false.
-- It never INSERTs. See Questions in README.
-- ---------------------------------------------------------------------
create table if not exists public.portal_access (
  id         bigint generated by default as identity primary key,  -- GUESS: bigint. Code does .order('id', desc).limit(1) = "latest row"
  season_id  text not null
             references public.exam_seasons(id),  -- GUESS: FK
  is_active  boolean not null default true,    -- GUESS: default
  expires_at timestamptz not null,             -- GUESS: timestamptz. Code does new Date(access.expires_at) > now
  created_by text,                             -- GUESS: not referenced in code (who opened the portal)
  created_at timestamptz not null default now()  -- GUESS: not referenced in code
);
create index if not exists portal_access_season_idx on public.portal_access (season_id, is_active, expires_at);  -- GUESS: index


-- ---------------------------------------------------------------------
-- app_settings: key/value store shared by all admins
-- Keys seen: 'custom_depts' (JSON array as text), 'portal_url'
-- ---------------------------------------------------------------------
create table if not exists public.app_settings (
  key        text primary key,                 -- upsert uses onConflict:'key', so key must be unique or PK
  value      text,                             -- GUESS: text. 'custom_depts' is written as JSON.stringify(...), so a string
  updated_at timestamptz,
  updated_by text                              -- written only by the portal_url save (email); custom_depts save does not send it
);


-- ---------------------------------------------------------------------
-- audit_log: who changed what
-- Written by the browser (logAction) today, and by triggers in
-- db/audit_triggers.sql. Read by the Audit Log screen (last 500).
-- ---------------------------------------------------------------------
create table if not exists public.audit_log (
  id          bigint generated by default as identity primary key,  -- GUESS: never referenced in code
  table_name  text not null,                   -- 'claims', 'staff', ...
  record_id   text,                            -- app does String(recordId||''), so text
  action      text not null,                   -- 'INSERT' / 'UPDATE' / 'DELETE' (UI filters on these exact values)
  changed_by  text,                            -- user email, or 'system'
  changed_at  timestamptz not null default now(),  -- UI orders by changed_at and the app never sends it, so DB must default it
  old_data    jsonb,                           -- GUESS: jsonb (app sends JS objects or null)
  new_data    jsonb                            -- GUESS: jsonb
);
create index if not exists audit_log_changed_at_idx on public.audit_log (changed_at desc);  -- GUESS: index, for the "last 500" query
