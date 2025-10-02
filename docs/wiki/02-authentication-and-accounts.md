# 2. Authentication & accounts

Account management flows let judges and players get online quickly:

* The login form requires email + password and presents a branded welcome panel to match the rest of the UI.【F:app/templates/login.html†L1-L19】
* New users can register with name, email, password confirmation, and optionally join a tournament immediately by supplying a passcode during signup.【F:app/templates/register.html†L1-L33】
* A default super-user (`admin@example.com` / `admin123`) is created during `flask db-init`, giving local environments instant access to administrative tooling.【F:README.md†L20-L26】
* Admins can register players individually or in bulk, optionally attaching them to an event at the same time to streamline onsite desk operations.【F:app/templates/admin/register_player.html†L3-L39】【F:app/templates/admin/bulk_register_players.html†L3-L27】

![Login screen](browser:/invocations/putorxrg/artifacts/artifacts/wiki-login.png)
