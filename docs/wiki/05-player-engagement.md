# 5. Player tools & deck submission

Tournament detail pages double as the player hub:

* Passcode-protected join forms honour approval workflows and communicate pending/rejected status directly to the player, while unauthenticated users are prompted to log in first.【F:app/templates/tournament/view.html†L21-L46】
* Once registered, players can monitor deck submission status, including timestamps and whether deck changes are locked after round one.【F:app/templates/tournament/view.html†L69-L129】
* Multiple submission channels—interactive card search, bulk paste, MTGO `.txt` upload, and optional deck imagery for draft events—cover both digital and paper workflows.【F:app/templates/tournament/view.html†L130-L194】

![Player hub & deck tools](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-tournament-overview.png)
