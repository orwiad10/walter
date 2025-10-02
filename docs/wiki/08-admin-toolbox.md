# 8. Admin toolbox

## Diagnostics & secrets
* The admin debug panel surfaces encryption mode, database footprint, RAM/CPU usage, connection counts, uptime, and a password-gated secret seed reveal for troubleshooting.【F:app/templates/admin/panel.html†L3-L20】

![Admin panel](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-admin-panel.png)

## User operations
* The users screen supports name/email/role search with an inline autocomplete, and provides per-user management links.【F:app/templates/admin/users.html†L3-L37】
* Detailed user pages edit contact info, notes, roles, password resets, permission overrides, and tournament assignments with remove/add forms plus a guarded delete option.【F:app/templates/admin/user_detail.html†L1-L66】【F:app/templates/admin/user_detail.html†L67-L112】

![User management](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-user-management.png)

## Role governance
* The permissions console lists role levels and granted flags, and includes a role builder with per-permission checkboxes so admins can tune access without touching code.【F:app/templates/admin/permissions.html†L3-L33】
