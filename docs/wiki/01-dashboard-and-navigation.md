# 1. Dashboard & global navigation

The landing page highlights every active tournament with live operations context:

* Tournament cards list format, cut, REL, current player count, assigned head judge, and live timer chips that update automatically when any phase clock is running.【F:app/templates/index.html†L3-L44】
* Manager-level controls expose edit and delete actions inline so staff can adjust events without leaving the overview.【F:app/templates/index.html†L37-L43】
* The persistent header provides authenticated users with shortcuts to tournaments, messaging, Lost &amp; Found, incident reports, staff tools, and administrative consoles, adapting the dropdown menus based on each permission flag.【F:app/templates/base.html†L22-L63】
* Built-in JavaScript powers the responsive menu, dropdown toggles, timer countdowns, and shared user lookup widget used throughout the application.【F:app/templates/base.html†L82-L200】

![Dashboard overview](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-dashboard.png)

Timers that appear on the dashboard leverage the shared timer bar component; each entry tracks server time, supports round/draft/deck phases, and exposes start, pause, stop, and restart controls for tournament managers.【F:app/templates/tournament/_timer_bar.html†L1-L27】
