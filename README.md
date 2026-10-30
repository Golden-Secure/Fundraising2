# Private security report — Odoo

**To:** security@odoo.com
**Reporter:** info@togetherapps.ca
**Status:** private; please do not disclose until we agree on a timeline.

---

## Title
Privilege escalation — any internal user becomes superuser via default Mail Template rendering (discloses `database.secret`)

## Summary
In a default configuration, every internal user (`base.group_user`) is implicitly granted
the *Mail Template Editor* group. An editor can author a mail template whose dynamic
expression is evaluated by `safe_eval` with the record's `object.env` in scope. Because
`safe_eval` permits ordinary method calls, the expression can call `.sudo()` and perform
arbitrary ORM operations as **superuser** — including reading `database.secret`. That value
keys the session-token, CSRF and signature HMACs, so disclosing it lets the attacker forge a
valid session for any user, including the administrator. Net effect: a standard employee
escalates to full system compromise with no administrator interaction.

## Affected
- Verified: Odoo 20.0 Community, commit `6dca29109f4076cc6fe1edba242602a12191638f`.
- The mechanism (template-editor-by-default + `object.env` in the render context + `safe_eval`
  allowing `.sudo()`) is long-standing; earlier supported versions are likely affected but
  were not independently verified.

## Attacker prerequisites
1. An ordinary **internal** user account (`base.group_user`) — e.g. a basic employee. NOT a
   portal or public user.
2. "Restrict Template Rendering" is **off** — the default. On a brand-new database
   `base.group_user` is not yet an editor; the group is granted to all internal users the
   first time Settings is saved in the default state (effectively universal in real
   deployments). A fresh install whose Settings were never saved is not affected.

## Reproduction (synthetic accounts, local instance)
1. As admin, open and Save General Settings once with the default (Restrict Template
   Rendering unchecked). This grants `mail.group_mail_template_editor` to `base.group_user`.
2. Create a user `basic` holding only the *Internal User* group.
3. As `basic`, create a `mail.template` on model `res.partner`, Subject:
   `{{ object.env['ir.config_parameter'].sudo().get_str('database.secret') }}`
4. Render it on any partner (preview / use to send). The rendered subject is the server's
   `database.secret`.
5. Variant proving arbitrary superuser reads:
   `{{ ','.join(object.env['res.users'].sudo().search([]).mapped('login')) }}`
   returns every login, including `admin`.

## Expected vs. actual
- Expected: a `base.group_user` cannot read `ir.config_parameter`; a direct read raises
  `AccessError`.
- Actual: the same user, through a template they are permitted to author, reads
  `database.secret` and can run any ORM create/write/unlink/search as superuser.

## Observed evidence (local throwaway DB, Odoo 20.0)
```
basic: is_admin=False  is_system=False  has_editor_group=True
direct ir.config_parameter read (no sudo)                 -> AccessError (denied)
template "{{ ...sudo().get_str('database.secret') }}"     -> 74e1f173-...  (== real database.secret)
template "{{ ...res.users.sudo()...mapped('login') }}"    -> basic_emp_probe2,portal,demo,admin,light
```

## Root cause
- `addons/mail/models/mail_render_mixin.py:360-361,403` — the render context exposes `env`,
  `user` and `object` (a real recordset, so `object.env` reaches the Environment).
- `odoo/tools/rendering_tools.py:72` — inline expressions go through
  `safe_eval(expr, variables)`, which blocks dunders/imports/builtins but permits method
  calls such as `.sudo()` on context objects.
- `addons/mail/models/ir_config_parameter.py:89-99` — saving the default
  `mail.restrict.template.rendering=False` runs
  `group_user._apply_group(mail.group_mail_template_editor)`, making every internal user an
  editor and thereby skipping the dynamic-expression write-gate
  `_check_access_right_dynamic_template` (`mail_render_mixin.py:330`).

## Impact
`database.secret` → forge `res.users._compute_session_token` values, CSRF tokens and
`hash_sign` signatures → impersonate any user including admin → full tenant compromise.
Independently, arbitrary ORM read/write as superuser.

## Suggested remediation
- Do not grant Mail Template Editor to all internal users by default (make "Restrict Template
  Rendering" effectively on by default), and/or
- Render non-system-authored templates in a hardened context that does not expose
  `env`/`object.env` and treats `sudo`/cross-model traversal as unsafe inside template
  expressions.

## Regression test (sketch)
A `base.group_user` member who is a template editor must not be able to render a template
expression that calls `.sudo()` or reads `ir.config_parameter`; `_render_field` on such an
expression should raise or render empty.

## Notes on scope / prior art
A related, admin-only issue (reading file configuration via `str.format` inside `safe_eval`)
was publicly reported in March 2026; per that report Odoo patched Odoo Online and treated the
self-hosted case as an accepted risk. This report differs in being reachable by a
**non-admin internal user** and yielding **superuser** / `database.secret` in a default
configuration, which is a materially higher impact at a lower privilege.

---

## Verification environment
- Odoo 20.0 Community, commit `6dca29109f...`, local throwaway database on PostgreSQL 18, bound to 127.0.0.1 only.
- Scenario created over XML-RPC: the administrator saves Settings in the default state (grants Mail Template Editor to all internal users) and creates `basic_emp` holding **only** the *Internal User* group; that non-admin account then authors the template. Browser evidence captured with Chromium.

## Evidence (attached screenshots)
1. **`4_impact_preview.png` — Exploitation.** The non-admin user `basic_emp` (avatar "B") viewing the Email Template they created. Subject:
   `LEAKED database.secret => {{ object.env['ir.config_parameter'].sudo().get_str('database.secret') }}`
   and Body reading all user logins via `object.env['res.users'].sudo().search([])`.
   (The "Access Error: you are not allowed to access 'Model' (ir.model)" dialog is only the built-in **Preview** wizard, which reads `ir.model`; it is a UI-only limitation and does **not** block the real render, which occurs when the template is used to compose/send.)
2. **`5_impact_rendered.png` — Impact.** The same template rendered in `basic_emp`'s own session (`is_admin=False`, `is_system=False`) yields the real `database.secret` (`74e1f173-d55f-4f6d-91eb-9378d1d15e79`); "Leaked value == real database.secret → True". The same expression context also returns every user login, including `admin`.

## Console transcript (key lines, reproduced locally)
```
basic_emp is Mail Template Editor: True
basic_emp direct ir.config_parameter read (no sudo)      -> AccessError (denied)
basic_emp template render "{{ ...sudo().get_str('database.secret') }}" -> 74e1f173-d55f-4f6d-91eb-9378d1d15e79  (== real database.secret)
basic_emp template render "{{ ...res.users.sudo()...mapped('login') }}" -> basic_emp,portal,demo,admin,light
```

## Note on the render trigger
The built-in template **Preview** wizard additionally requires `ir.model` read access (which a non-admin lacks), so the practical trigger is using the template to compose/send an email, or any automated use of it. The rendering code path — `mail.template._render_field()` → `safe_eval()` with `object.env` in scope — is identical, and was exercised here directly in the non-admin user's session.
