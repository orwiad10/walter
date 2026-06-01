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

The installer copies the config to `/etc/nginx/sites-available` and enables it via `/etc/nginx/sites-enabled` on Debian/Ubuntu-style systems. On systems that use `/etc/nginx/conf.d`, it installs `walter.conf` there instead. It also disables the packaged default Nginx site so requests to the server IP show Walter instead of the "Welcome to nginx!" page. Use `./scripts/install_nginx_config.sh --help` to see options such as `--dry-run`, `--config`, `--site-name`, `--no-reload`, and `--keep-default-site`.

If you still see the default Nginx welcome page after installing, re-run `./scripts/install_nginx_config.sh` and confirm that Nginx reloaded successfully. If you see a `502 Bad Gateway` page instead, make sure the Waitress host and port in `config.yaml` match the upstream address in `nginx/walter.conf`; the included config expects Waitress at `127.0.0.1:5000`.

### HTTPS with TLS 1.3 and Let's Encrypt

For production, set `tls_domain` in `config.yaml` to your public DNS name before running `./start-server.sh`. The startup script then checks `/etc/letsencrypt/live/<domain>/fullchain.pem`; if the certificate is missing or expires within `letsencrypt_renewal_days` days (default: 30), it installs Certbot/OpenSSL if needed, installs the HTTP Nginx config for HTTP-01 validation, requests a Let's Encrypt certificate, and then installs the rendered HTTPS Nginx config. Do **not** add `fullchain.pem`, `privkey.pem`, `chain.pem`, or any other certificate/private-key material to this repository.

Example `config.yaml` options:

```yaml
tls_domain: tournaments.example.com
letsencrypt_email: admin@example.com
# Optional overrides:
# letsencrypt_renewal_days: 30
# tls_cert_dir: /etc/letsencrypt/live/tournaments.example.com
# acme_webroot: /var/www/letsencrypt
```

You can still manage the Nginx config manually:

1) Install Nginx with the HTTP config so Certbot can complete HTTP-01 validation:
   - `./scripts/install_nginx_config.sh`

2) Create the certificate on the server, replacing the domain and email:
   - `sudo mkdir -p /var/www/letsencrypt/.well-known/acme-challenge`
   - `sudo certbot certonly --webroot -w /var/www/letsencrypt -d tournaments.example.com --email admin@example.com --agree-tos --no-eff-email`

3) Install the TLS config rendered for your production domain:
   - `./scripts/install_nginx_config.sh --tls-domain tournaments.example.com`

The TLS template lives at `nginx/walter-tls.conf`. It serves HTTPS on port 443, redirects normal HTTP traffic to HTTPS, leaves `/.well-known/acme-challenge/` available on port 80 for Let's Encrypt renewals, only enables TLS 1.3, and restricts TLS 1.3 cipher suites to the FIPS-suitable AES-GCM suites `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`. If your certificate lives somewhere other than `/etc/letsencrypt/live/<domain>`, pass `--cert-dir /path/to/live/certdir`; if your ACME challenge webroot differs, pass `--acme-webroot /path/to/webroot`.

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