# 7. Support desks: Lost & Found + incident reports

## Lost & Found kiosk
* Staff can log items with photos, location, reporter details, and status, while the list view shows cards with timestamps and quick update forms to mark returns or replace images.【F:app/templates/lost_found/index.html†L3-L94】

![Lost & Found board](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-lost-found.png)

## Incident intake
* Players submit bug reports or misconduct complaints via separate forms; misconduct entries include a user search helper to identify the reported player accurately.【F:app/templates/reports/index.html†L3-L36】

## Admin triage
* The reports dashboard summarises status, type, reporter, assignee, and submission time, and embeds inline editing for assignments, statuses, read tracking, and action notes, alongside CSV export and print buttons.【F:app/templates/admin/reports.html†L3-L102】

![Incident triage](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-reports.png)
