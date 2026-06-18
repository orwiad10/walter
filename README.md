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

After editing `config.yaml`, restart the app so the new settings are loaded:
- Linux/macOS: `./restart-server.sh`
- Windows PowerShell: `./restart-server.ps1`

On Linux, `start-server.sh` installs the HTTP Nginx site automatically when `tls_domain` is blank so other computers on the LAN can browse to `http://<server-lan-ip>/` without connecting directly to the Waitress port. When `tls_domain` is set, the startup script requests or renews the certificate and installs the rendered TLS site from `nginx/walter-tls.conf`. The installer copies the selected config to `/etc/nginx/sites-available` and enables it via `/etc/nginx/sites-enabled` on Debian/Ubuntu-style systems. On systems that use `/etc/nginx/conf.d`, it installs the selected site config there instead. It also disables the packaged default Nginx site so requests to the server IP show Walter instead of the "Welcome to nginx!" page. The installer no longer installs Walter's old global hardening config and removes any legacy `/etc/nginx/conf.d/walter-hardening.conf` or `/etc/nginx/snippets/security-headers.conf` left by earlier deployments. Use `./scripts/install_nginx_config.sh --help` to see options such as `--dry-run`, `--config`, `--site-name`, `--no-reload`, and `--keep-default-site`.

If LAN clients still cannot reach the app, browse to the server's LAN address on port 80 (for example, `http://192.168.1.25/`) and make sure host firewall rules allow inbound HTTP. If you see the default Nginx welcome page after installing, re-run `./scripts/install_nginx_config.sh` and confirm that Nginx reloaded successfully. If you see a `502 Bad Gateway` page instead, make sure the Waitress host and port in `config.yaml` match the upstream address in `nginx/walter.conf`; the rendered config expects Waitress at the `flask_ip` and `flask_port` values from `config.yaml`.

### HTTPS with TLS 1.2/1.3 and Let's Encrypt

For production, set `tls_domain` in `config.yaml` to your public DNS name before running `./start-server.sh`. The startup script then checks `/etc/letsencrypt/live/<domain>/fullchain.pem`; if the certificate is missing or expires within `letsencrypt_renewal_days` days (default: 30), it installs Certbot/OpenSSL if needed, installs the HTTP Nginx config for HTTP-01 validation, requests a Let's Encrypt certificate, and then installs the rendered HTTPS Nginx config. Do **not** add `fullchain.pem`, `privkey.pem`, `chain.pem`, or any other certificate/private-key material to this repository.

The `tournaments.example.com` and `admin@example.com` values below are placeholders only. Replace them with a real public DNS name that points at your server and a real contact email address before enabling TLS; `./start-server.sh` stops early with a clear error if those reserved example values are still configured.

Example `config.yaml` options:

```yaml
tls_domain: tournaments.example.com
# Optional: also serve aliases covered by the same certificate.
# tls_additional_domains: www.tournaments.example.com
letsencrypt_email: admin@example.com
# Optional overrides:
# letsencrypt_renewal_days: 30
# letsencrypt_dry_run: false
# tls_cert_dir: /etc/letsencrypt/live/tournaments.example.com
# acme_webroot: /var/www/letsencrypt
```

To test the ACME/HTTP-01 validation flow without creating or replacing certificate files, set `letsencrypt_dry_run: true` in `config.yaml`. Dry-run mode still requires a real public DNS name that points at the server, installs the temporary HTTP Nginx config needed for validation, runs Certbot with `--dry-run`, and then skips installing the TLS Nginx config because Certbot does not write live certificate files during a dry run.

If Cloudflare shows **Error 525: SSL handshake failed**, verify that `tls_domain` is set to the hostname Cloudflare is proxying (for this deployment, `walter-pair.us`) and re-run `./start-server.sh` on the origin. A 525 means Cloudflare reached the origin but could not complete the TLS handshake, which is expected if the app is only serving the temporary HTTP config, if the certificate-backed HTTPS vhost was never installed, or if the origin TLS curve/cipher list does not overlap with Cloudflare's origin ClientHello. The bundled TLS template now keeps TLS 1.2/1.3 enabled, advertises X25519/P-256/P-384 curves, and includes Cloudflare-compatible AES-GCM and ChaCha20-Poly1305 suites. After the startup script installs or renews the Let's Encrypt certificate and renders `nginx/walter-tls.conf`, keep Cloudflare SSL/TLS mode on **Full (strict)** so Cloudflare validates the origin certificate instead of masking certificate problems.

You can still manage the Nginx config manually:

1) Install Nginx with the HTTP config so Certbot can complete HTTP-01 validation:
   - `./scripts/install_nginx_config.sh`

2) Create the certificate on the server, replacing the domain and email:
   - `sudo mkdir -p /var/www/letsencrypt/.well-known/acme-challenge`
   - `sudo certbot certonly --webroot -w /var/www/letsencrypt -d tournaments.example.com --email admin@example.com --agree-tos --no-eff-email`

3) Install the TLS config rendered for your production domain:
   - `./scripts/install_nginx_config.sh --tls-domain tournaments.example.com`

The TLS template lives at `nginx/walter-tls.conf`. It serves HTTPS on port 443 only for configured hostnames, redirects HTTP traffic to the canonical `tls_domain`, rejects TLS handshakes for unknown/default hostnames, leaves `/.well-known/acme-challenge/` available on port 80 for Let's Encrypt renewals, enables TLS 1.2 and TLS 1.3, and uses origin cipher/curve settings that match Cloudflare's current origin connection behavior. TLS 1.2 includes `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-CHACHA20-POLY1305`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-RSA-CHACHA20-POLY1305`, `ECDHE-ECDSA-AES256-GCM-SHA384`, and `ECDHE-RSA-AES256-GCM-SHA384`; TLS 1.3 uses the OpenSSL defaults so compatible AES-GCM and ChaCha20-Poly1305 suites remain available. If your certificate lives somewhere other than `/etc/letsencrypt/live/<domain>`, pass `--cert-dir /path/to/live/certdir`; if your ACME challenge webroot differs, pass `--acme-webroot /path/to/webroot`. To include aliases such as `www.tournaments.example.com`, set `tls_additional_domains` in `config.yaml` or pass `--tls-additional-domains www.tournaments.example.com` to the installer; the certificate request and Nginx `server_name` list must match.


## Walter bot configuration

Discord application values such as the application ID, public key, client ID, OAuth secret, permissions integer, and target channel should be configured through `config.yaml` only when the bot runtime needs them. The startup scripts export these values to the bot process as environment variables. When `bot_runtime_enabled` is `auto`, `start-server.sh` and `start-server.ps1` start the bot after Waitress whenever exactly one of `bot_runtime_module` or `bot_runtime_script` is configured. Set `bot_runtime_enabled` to `false` to disable startup even when a runtime target is configured. For production, prefer environment overrides or a secret manager for `bot_token` and `bot_secret_key`.

```yaml
bot_runtime_enabled: auto
bot_runtime_module: ""
bot_runtime_script: ""
bot_runtime_args: ""
bot_api_base_url: "http://127.0.0.1:5000"
bot_api_key: ""
bot_poll_tournament_id: ""
bot_poll_interval_seconds: 30
bot_token: ""
bot_appid: ""
bot_pubkey: ""
bot_client_id: ""
bot_secret_key: ""
bot_permissions_int: ""
bot_channel_id: ""
bot_announce_ready: true
bot_sync_guild_commands: true
```

For the included read-only Discord bot, create an administrator API key from
Settings, set `bot_runtime_script: "discord_bot.py"`, set `bot_api_key` to that
one-time key value, and set `bot_token` to the Discord bot token. The bot
registers slash commands for listing tournaments, standings, latest-round
pairings, connecting Walter accounts with `/connect`, and reporting pairing results. By default, the bot also syncs the same commands directly to every connected guild at startup so new commands such as `/connect` appear immediately instead of waiting for Discord global command propagation; set `bot_sync_guild_commands: false` to use global sync only. If `bot_channel_id` is set, it posts a startup message to that channel so you can verify the bot can write to the chat; set `bot_announce_ready: false` to suppress that message. If `bot_channel_id` and `bot_poll_tournament_id` are set, it also polls for newly paired rounds and posts pairings to that channel.

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
