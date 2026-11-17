# coe-app

COE Claims Management System: the admin app used by the Office of the Controller of Examinations to record, verify and report remuneration claims for each exam season.

It is a single file, `index.html` (React and Babel loaded in the browser, Supabase JS client). There is no build step and no server of our own.

## Architecture

```
 External staff                          COE office (admin)
 ┌──────────────┐                        ┌──────────────────┐
 │ coe-portal   │                        │ coe-app          │
 │ index.html   │                        │ index.html       │
 │ (anon key)   │                        │ (login + key)    │
 └──────┬───────┘                        └────────┬─────────┘
        │ INSERT only                             │ full access
        ▼                                         ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Supabase (one project, shared by both apps)             │
 │  Postgres + Row Level Security + Auth (email/password)  │
 └─────────────────────────────────────────────────────────┘
```

- **coe-app (this repo)**: admins sign in with Supabase Auth. They manage exam seasons, the staff directory, the exam schedule, claims for about 25 work types, Excel import and export, the portal link, and the audit log.
- **coe-portal** (separate repo): an anonymous form for external staff. It can only create draft claims.
- **Database**: both apps use the same Supabase project. The SQL in [`db/`](db/) is the source of truth for tables, access rules and audit logging.

### Tables

| Table | Purpose |
|---|---|
| `exam_seasons` | One row per exam session (e.g. `ND25`) |
| `claims` | One claim per person, work type and season |
| `claim_date_rows` | Per-date lines for date-based claims (hall duty, practicals and so on) |
| `staff` | Directory of internal and external staff, used for quick-fill |
| `exam_schedule` | Subject code to exam date and session, uploaded from Excel |
| `portal_access` | Whether the external portal is open for a season, and until when |
| `app_settings` | Shared key/value settings (portal URL, custom departments) |
| `audit_log` | Who changed what |

## Data flow: portal submission, draft, admin approval

1. **Open the portal.** An admin opens the Portal screen in coe-app, picks a duration and generates a link: `<portal URL>?t=<base64url(SEASONID_EXPIRYMS)>`. The admin sends this link to external staff.
2. **Submit.** The staff member opens the link, fills in the 4-step form and submits. The portal inserts one `claims` row with `status = 'draft'` and `entry_source = 'portal'`, plus `claim_date_rows` for practical or hall-duty work. The portal is anonymous, so the database must accept this insert (see [`db/rls_policies.sql`](db/rls_policies.sql)).
3. **Review.** The Portal screen in coe-app lists every claim where `entry_source = 'portal'` and `status = 'draft'`.
4. **Approve or reject.**
   - *Approve* sets `status = 'verified'` and opens the claim on its work screen so the admin can complete the details (for example, the amount for hall duty and practicals, which the portal always submits as 0).
   - *Reject* deletes the claim and its date rows.
5. **Audit.** Changes to `claims` and `claim_date_rows` are logged to `audit_log` by database triggers (see [`db/audit_triggers.sql`](db/audit_triggers.sql)).

## Database setup (from `db/`)

Use a **new, empty** Supabase project, or review the SQL against your existing one first. Nothing in `db/` is run automatically by the app.

1. Create the Supabase project.
2. In **Authentication > Providers**, keep Email enabled. In **Authentication > Settings**, **disable new user sign-ups** and create admin users by hand (see Security notes).
3. In the SQL editor, run these in order:
   1. [`db/schema.sql`](db/schema.sql): tables. This file was reconstructed from the app code, not exported. Every guess is marked `GUESS:`. Compare it with the live database before relying on it.
   2. [`db/rls_policies.sql`](db/rls_policies.sql): enables Row Level Security, creates the portal and admin policies, and revokes default anon privileges.
   3. [`db/audit_triggers.sql`](db/audit_triggers.sql): audit triggers on `claims` and `claim_date_rows`.
4. Put your project's URL and publishable (anon) key in the `SUPA_URL` / `SUPA_KEY` constants at the top of the script in both `index.html` files.
5. **Open the portal** for a season. The RLS policy only accepts portal inserts while a row in `portal_access` has `is_active = true`, a future `expires_at`, and the right `season_id`. See the Questions section below: the current admin app does not create this row.

All the SQL files are written to be re-run safely, except `schema.sql`, which will not change tables that already exist.

## Security notes

- **The portal's `?t=` token is client-side only.** It is just base64 of `SEASONID_EXPIRYMS`. It is not signed and not secret. The portal checks it in the visitor's browser to decide whether to show the form. Anyone can decode it, edit the expiry, forge a link for any season, or skip the portal and call the Supabase API directly with the publishable key. It is a convenience for honest users, not a security control.
- **The real protection is the RLS policy** in [`db/rls_policies.sql`](db/rls_policies.sql). Even with a forged link or a direct API call, the database only lets anonymous callers `INSERT` a `claims` or `claim_date_rows` row when:
  - an active, unexpired `portal_access` row exists for that season,
  - `status` is `'draft'` and `entry_source` is `'portal'`.

  Anonymous callers cannot select, update or delete claims, and cannot touch any other table. The only anon read is `exam_seasons`.
- **Closing the portal means the database row.** Deactivating the portal in the admin app sets `portal_access.is_active = false`, and from that moment the database rejects anon inserts, whatever link the visitor holds. Shortening the link's expiry does not do that, because the link expiry is client-side only.
- **What the policy does not stop.** While a season is open, anyone who knows the project URL and key can insert draft claims into it (spam), and the contents of a draft are not validated by the database. Drafts do nothing until an admin approves them. Review every draft before approving.
- **The publishable key is public by design.** Its presence in both `index.html` files is expected. Security comes from RLS, not from hiding the key. Never put a `service_role` key in either app.
- **Every logged-in user is a full admin.** The policies give any `authenticated` user full access, and there is no role table. Disable public sign-ups and create admin accounts manually, or add a role check to the policies.
- **Audit log contains personal data.** Account numbers and mobile numbers are copied into `audit_log`. Only authenticated users can read it.

## Questions to resolve

Open points from reconstructing the database from code (see also the notes at the bottom of each `db/*.sql` file):

- **Who creates `portal_access` rows?** The admin app only reads and deactivates them. Generating a link does not insert one. If rows are created by hand, or by a part of the system not in these repos, that is fine. If not, portal submissions will be rejected by the RLS policy.
- **Excel bulk-import of date rows** writes `qty_sessions`, `ehs_total` and `row_total`, which do not match the columns every other code path uses (`no_sessions`, `row_amount`). That insert looks like it fails silently.

## Development

Open `index.html` in a browser, or serve the folder with any static server. There is nothing to install.
