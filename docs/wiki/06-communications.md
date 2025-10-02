# 6. Messaging & announcements

WaLTER includes a built-in encrypted messaging suite:

* The messaging hub routes staff to the player inbox, sent archive, judge broadcasts, and admin-wide announcements based on their access level.【F:app/templates/messages/index.html†L3-L51】
* Player inboxes display unread states, previews, and shortcuts to compose or review sent mail, keeping conversations centralised.【F:app/templates/messages/player.html†L3-L28】
* Judges can target a specific tournament for a mass message, while admins can reach entire roles or the whole user base through dedicated broadcast forms.【F:app/templates/messages/judge.html†L3-L22】【F:app/templates/messages/admin.html†L3-L23】

![Messaging hub](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-messages-hub.png)
