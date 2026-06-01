# MTG Tournament Swiss App (Flask + SQLite)

## Quickstart
1) Modify config.yaml
   - change settings as needed in config.yaml

2) Start Server
   - Windows: run start-server.ps1 to install pre-reqs and start the app with Waitress
   - Linux/macOS: run start-server.sh to install pre-reqs and start the app with Waitress
     - On Linux, this also ensures Nginx is installed for the included reverse-proxy setup.


## Nginx reverse proxy (Linux)

This repository includes a sample Nginx reverse-proxy config for running the app behind Nginx on port 80. The config proxies traffic to Waitress at `127.0.0.1:5000`; update `nginx/walter.conf` if your `config.yaml` uses a different `flask_port` or if you want to set a real `server_name`.

1) Start the app with Waitress:
   - `./start-server.sh`

2) Install and enable the Nginx site config:
   - `./scripts/install_nginx_config.sh`

The installer copies the config to `/etc/nginx/sites-available` and enables it via `/etc/nginx/sites-enabled` on Debian/Ubuntu-style systems. On systems that use `/etc/nginx/conf.d`, it installs `walter.conf` there instead. Use `./scripts/install_nginx_config.sh --help` to see options such as `--dry-run`, `--config`, `--site-name`, and `--no-reload`.

## Features
   - Player & Admin login
   - Tournaments: Commander, Draft, Constructed
   - WotC recommended Swiss round counts (override allowed)
   - Swiss pairing (avoid rematches, handle byes)
   - Match reporting with game wins (for GW%)
   - Standings with tiebreakers: OMW%, GW%, OGW%
   - Cut to Top 8 / Top 4
   - Builtin admin = admin@example.com, admin123

## Notes
   - Default secret key is set for dev; change FLASK_SECRET in production.
   - Passwords are stored encrypted with AES-256 using a seed specified via `PASSWORD_SEED`.
   - This is an MVP. You can extend forms, validation, and UI as needed.

## Wiki
   - See the wiki for screen shots of the app