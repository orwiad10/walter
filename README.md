# MTG Tournament Swiss App (Flask + SQLite)

## Quickstart
1) Modify config.yaml
   - change settings as needed in config.yaml

2) Start Server
   - Windows: run start-server.ps1 to install pre-reqs and start the app with Waitress
   - Linux/macOS: run start-server.sh to install pre-reqs and start the app with Waitress
     - On Linux, this also ensures Nginx is installed for the included reverse-proxy setup.


## Nginx reverse proxy (Linux)

This repository includes a sample Nginx reverse-proxy config for running the app behind Nginx on port 80. The config proxies traffic to the Waitress address rendered from `flask_ip` and `flask_port` in `config.yaml`; update `nginx/walter.conf` only if you want to set a real `server_name`.

1) Start the app with Waitress:
   - `./start-server.sh`

2) Install and enable the Nginx site config if you are not using `start-server.sh`:
   - `./scripts/install_nginx_config.sh`

On Linux, `start-server.sh` installs the HTTP Nginx site automatically when `tls_domain` is blank so other computers on the LAN can browse to `http://<server-lan-ip>/` without connecting directly to the Waitress port. The installer copies the config to `/etc/nginx/sites-available` and enables it via `/etc/nginx/sites-enabled` on Debian/Ubuntu-style systems. On systems that use `/etc/nginx/conf.d`, it installs `walter.conf` there instead. It also disables the packaged default Nginx site so requests to the server IP show Walter instead of the "Welcome to nginx!" page. Use `./scripts/install_nginx_config.sh --help` to see options such as `--dry-run`, `--config`, `--site-name`, `--no-reload`, and `--keep-default-site`.

If LAN clients still cannot reach the app, browse to the server's LAN address on port 80 (for example, `http://192.168.1.25/`) and make sure host firewall rules allow inbound HTTP. If you see the default Nginx welcome page after installing, re-run `./scripts/install_nginx_config.sh` and confirm that Nginx reloaded successfully. If you see a `502 Bad Gateway` page instead, make sure the Waitress host and port in `config.yaml` match the upstream address in `nginx/walter.conf`; the rendered config expects Waitress at the `flask_ip` and `flask_port` values from `config.yaml`.

### HTTPS with TLS 1.3 and Let's Encrypt

For production, set `tls_domain` in `config.yaml` to your public DNS name before running `./start-server.sh`. The startup script then checks `/etc/letsencrypt/live/<domain>/fullchain.pem`; if the certificate is missing or expires within `letsencrypt_renewal_days` days (default: 30), it installs Certbot/OpenSSL if needed, installs the HTTP Nginx config for HTTP-01 validation, requests a Let's Encrypt certificate, and then installs the rendered HTTPS Nginx config. Do **not** add `fullchain.pem`, `privkey.pem`, `chain.pem`, or any other certificate/private-key material to this repository.

The `tournaments.example.com` and `admin@example.com` values below are placeholders only. Replace them with a real public DNS name that points at your server and a real contact email address before enabling TLS; `./start-server.sh` stops early with a clear error if those reserved example values are still configured.

Example `config.yaml` options:

```yaml
tls_domain: tournaments.example.com
letsencrypt_email: admin@example.com
# Optional overrides:
# letsencrypt_renewal_days: 30
# letsencrypt_dry_run: false
# tls_cert_dir: /etc/letsencrypt/live/tournaments.example.com
# acme_webroot: /var/www/letsencrypt
```

To test the ACME/HTTP-01 validation flow without creating or replacing certificate files, set `letsencrypt_dry_run: true` in `config.yaml`. Dry-run mode still requires a real public DNS name that points at the server, installs the temporary HTTP Nginx config needed for validation, runs Certbot with `--dry-run`, and then skips installing the TLS Nginx config because Certbot does not write live certificate files during a dry run.

You can still manage the Nginx config manually:

1) Install Nginx with the HTTP config so Certbot can complete HTTP-01 validation:
   - `./scripts/install_nginx_config.sh`

2) Create the certificate on the server, replacing the domain and email:
   - `sudo mkdir -p /var/www/letsencrypt/.well-known/acme-challenge`
   - `sudo certbot certonly --webroot -w /var/www/letsencrypt -d tournaments.example.com --email admin@example.com --agree-tos --no-eff-email`

3) Install the TLS config rendered for your production domain:
   - `./scripts/install_nginx_config.sh --tls-domain tournaments.example.com`

The TLS template lives at `nginx/walter-tls.conf`. It serves HTTPS on port 443, redirects normal HTTP traffic to HTTPS, leaves `/.well-known/acme-challenge/` available on port 80 for Let's Encrypt renewals, only enables TLS 1.3, and restricts TLS 1.3 cipher suites to the FIPS-suitable AES-GCM suites `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`. If your certificate lives somewhere other than `/etc/letsencrypt/live/<domain>`, pass `--cert-dir /path/to/live/certdir`; if your ACME challenge webroot differs, pass `--acme-webroot /path/to/webroot`.

## Account verification and invites

Public account registration sends a one-time 6-digit verification PIN through Mailgun before creating the user account. Set these values in `config.yaml` before enabling public self-service registration:

```yaml
mailgun_api_key: key-your-mailgun-api-key
mailgun_domain: mg.example.com
mailgun_from_email: Walter <noreply@example.com>
registration_pin_ttl_minutes: 15
account_creation_invite_only: false
```

When `account_creation_invite_only` is `true`, new users must register with a valid tournament invite/passcode.

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