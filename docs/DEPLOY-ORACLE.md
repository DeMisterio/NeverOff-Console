# Hosting the console on an Oracle Cloud instance

A start-to-finish guide for putting the admin console on an OCI compute instance
(including the Always Free Ampere A1 shape) with TLS, running as services, and
talking to your existing Supabase project.

**Time:** about 45 minutes, most of it waiting on `npm install` and DNS.

---

## What you are actually deploying

Less than you might expect:

| Piece | Where it runs |
|---|---|
| Postgres | **Supabase — not on this box.** The console's `admin` schema lives in the same database as the app, because enforcement rows reference `public.profiles`. |
| API (Fastify) | Node process on the instance, listening on `127.0.0.1:4000` |
| Workers | A second Node process on the instance |
| Web console | Static files, served by Caddy |
| Redis | **Not needed.** The job queue is Postgres-backed on purpose. |

The web bundle calls the API with **relative** paths, so both must be served from
one origin. That is not cosmetic — the session cookie is `SameSite=Strict`, and
splitting them across hostnames breaks sign-in.

---

## Before you start

- An OCI instance with a **public IP**. Ampere A1 (ARM64) is fine — every
  dependency here has an aarch64 build, including `@node-rs/argon2`.
- **Ubuntu 22.04 or 24.04** assumed below. Oracle Linux works with `dnf` in
  place of `apt`.
- A domain you control, for a subdomain like `console.yourdomain.com`.
- Your Supabase **database connection string** and **service role key**.

---

## 1. Open the ports — both firewalls

Oracle catches nearly everyone here, because there are **two** firewalls and
closing either one produces the same symptom: the site simply times out.

**a) The OCI Security List** (in the Oracle web console)

Networking → Virtual Cloud Networks → your VCN → Security Lists → default →
Add Ingress Rules:

| Source CIDR | Protocol | Destination Port |
|---|---|---|
| `0.0.0.0/0` | TCP | 80 |
| `0.0.0.0/0` | TCP | 443 |

**b) The instance's own iptables**

Oracle's Ubuntu images ship with a `REJECT` rule that drops everything not
explicitly allowed, and it sits *above* anything you append. Insert before it:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
```

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
```

```bash
sudo netfilter-persistent save
```

Check the rules landed above the REJECT line:

```bash
sudo iptables -L INPUT --line-numbers -n | head -12
```

---

## 2. Point DNS at the instance

Create an **A record** for `console.yourdomain.com` pointing at the instance's
public IP. Verify before continuing — Caddy cannot issue a certificate until
this resolves:

```bash
dig +short console.yourdomain.com
```

---

## 3. Install Node and Caddy

```bash
sudo apt update && sudo apt install -y git curl
```

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
```

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list && sudo apt update && sudo apt install -y caddy
```

---

## 4. Get the code onto the box

```bash
sudo mkdir -p /opt/neveroff-console && sudo chown $USER:$USER /opt/neveroff-console
```

```bash
git clone <your-console-repo-url> /opt/neveroff-console
```

Check what you actually got — `main` is the initial import unless you have
merged the work into it, and a clone that builds but has no console in it is a
confusing way to spend twenty minutes:

```bash
cd /opt/neveroff-console && git log --oneline -3 && ls apps/web/src/pages
```

```bash
cd /opt/neveroff-console && npm install --no-audit --no-fund
```

Install **with** dev dependencies, and keep them. `--omit=dev` looks tempting on
a server but strips TypeScript — so nothing builds — and strips `tsx`, which is
what `db:migrate` and `bootstrap:admin` run through. The services themselves run
compiled JavaScript under plain `node`; the tooling is what needs the dev tree.

`npm install` runs `build:shared` automatically. Then build the rest:

```bash
cd /opt/neveroff-console && npm run build --workspace @neveroff-console/db && npm run build --workspace @neveroff-console/api && npm run build --workspace @neveroff-console/web
```

---

## 5. Configuration

Get the connection string from **Supabase → Settings → Database → Connection
string → URI**. Use the **session pooler** (port 5432), not the transaction
pooler on 6543 — migrations need a real session.

Generate the two secrets:

```bash
node -e "console.log('SESSION_SECRET='+require('crypto').randomBytes(48).toString('base64url')); console.log('TOTP_ENCRYPTION_KEY='+require('crypto').randomBytes(48).toString('base64url'))"
```

Create `/opt/neveroff-console/.env`:

```bash
cat > /opt/neveroff-console/.env <<'EOF'
NODE_ENV=production
LOG_LEVEL=info

DATABASE_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
DB_ALLOWED_HOSTS=aws-0-<region>.pooler.supabase.com
PRODUCTION_MIGRATION_ACK=

API_PORT=4000
API_HOST=127.0.0.1
WEB_ORIGIN=https://console.yourdomain.com

SESSION_SECRET=<paste>
TOTP_ENCRYPTION_KEY=<paste>

SESSION_IDLE_TIMEOUT_MINUTES=30
SESSION_ABSOLUTE_TIMEOUT_HOURS=12

SUPABASE_URL=https://<ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<your service role key>

FIREBASE_PROJECT_ID=<same as the push-notify edge function>
FIREBASE_CLIENT_EMAIL=<...>
FIREBASE_PRIVATE_KEY=<...>

MAX_BAN_DAYS_T2=30
BULK_THRESHOLD=50
APPEAL_SLA_HOURS=72

ADMIN_IP_ALLOWLIST=
EOF
```

```bash
chmod 600 /opt/neveroff-console/.env
```

That file holds a service role key that bypasses every RLS policy you have.
`chmod 600` is the minimum; treat the box as holding production credentials
because it does.

**Firebase matters more than it looks.** Without it the console boots and warns,
but users are never told why they were restricted or when a ban lifted — which
§4 requires. Use the same service account as the existing `push-notify` edge
function.

---

## 6. Run the migrations against Supabase

Read `packages/db/migrations/0006_neveroff_integration.sql` first. It adds
`RESTRICTIVE` RLS policies to `public.messages` and `public.channel_posts`, and a
mistake there stops real users sending messages.

Check what would run:

```bash
cd /opt/neveroff-console && npm run db:migrate:status
```

Migrations touching the app schema refuse to run without an explicit
acknowledgement. Set it in `.env` when you have read the SQL:

```
PRODUCTION_MIGRATION_ACK=I understand this writes to the live NeverOff database
```

Then:

```bash
cd /opt/neveroff-console && npm run db:migrate
```

Every migration prints its post-condition checks. **If any line reads `FAIL`,
stop** — the migration applied but its guarantee is not in force.

**If enforcement misbehaves in production**, this returns the app to exactly its
prior behaviour in seconds, without touching console data:

```bash
psql "$DATABASE_URL" -f /opt/neveroff-console/packages/db/migrations/0006_neveroff_integration.down.sql
```

Do that *before* debugging. A messenger that will not send messages is a worse
problem than an unenforced ban.

> Do **not** run `npm run db:seed` here. It fabricates users and refuses any
> non-local host, but it is worth knowing why: synthetic accounts in your real
> database would be indistinguishable from real ones afterwards.

---

## 7. Create the first Super Admin

Nothing else can create an admin, because every route that does requires one to
already exist:

```bash
cd /opt/neveroff-console && npm run bootstrap:admin --workspace @neveroff-console/api -- --email you@yourdomain.com --name "Your Name"
```

It prints a one-time password, a TOTP secret, and ten recovery codes. **Add the
secret to your authenticator and save the recovery codes before closing the
terminal** — none of it is stored anywhere retrievable.

The recovery codes matter more here than anywhere else in the system. Resetting
an admin's second factor requires an admin, and this is the only one, so a lost
phone without them means hand-editing production SQL. Store them somewhere that
is not the machine you sign in from.

It refuses to run if a Super Admin already exists.

Then clear it from your shell history:

```bash
history -c && rm -f ~/.bash_history
```

---

## 8. Run the API and workers as services

```bash
sudo tee /etc/systemd/system/neveroff-console-api.service <<'EOF'
[Unit]
Description=NeverOff console API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/neveroff-console/apps/api
EnvironmentFile=/opt/neveroff-console/.env
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/neveroff-console

[Install]
WantedBy=multi-user.target
EOF
```

The worker is a separate unit on purpose: a wedged worker must not take request
serving down with it.

```bash
sudo tee /etc/systemd/system/neveroff-console-worker.service <<'EOF'
[Unit]
Description=NeverOff console workers
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/neveroff-console/apps/api
EnvironmentFile=/opt/neveroff-console/.env
ExecStart=/usr/bin/node dist/workers/index.js
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/neveroff-console

[Install]
WantedBy=multi-user.target
EOF
```

**Run exactly one worker process.** Two is safe — every job claims its rows with
`FOR UPDATE SKIP LOCKED` — but there is nothing to gain at this volume.

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now neveroff-console-api neveroff-console-worker
```

```bash
systemctl status neveroff-console-api --no-pager && curl -s localhost:4000/ready
```

`/ready` should report `postgres` ok and a migration count.

---

## 9. Caddy: TLS, static files, and the API proxy

```bash
sudo tee /etc/caddy/Caddyfile <<'EOF'
console.yourdomain.com {
    encode zstd gzip

    # The API must come first — it is more specific than the SPA fallback.
    handle /api/* {
        reverse_proxy 127.0.0.1:4000
    }
    handle /health {
        reverse_proxy 127.0.0.1:4000
    }
    handle /ready {
        reverse_proxy 127.0.0.1:4000
    }

    handle {
        root * /opt/neveroff-console/apps/web/dist
        try_files {path} /index.html
        file_server
    }

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }

    log {
        output file /var/log/caddy/console.log
    }
}
EOF
```

`try_files {path} /index.html` is what makes a deep link like `/queue/<id>` work
on refresh — without it the browser asks for a file that does not exist and gets
a 404 instead of the app.

```bash
sudo systemctl reload caddy && sudo systemctl status caddy --no-pager
```

Caddy obtains a Let's Encrypt certificate automatically on first request. If it
does not, DNS or one of the two firewalls is the cause — in that order.

Open `https://console.yourdomain.com`, sign in with the bootstrap credentials,
and change the password immediately.

---

## 10. Lock it down

This console can ban every user on your platform. It should not sit open to the
internet with only a password in front of it.

**Restrict by IP.** Set your own address in `.env` and restart the API:

```
ADMIN_IP_ALLOWLIST=203.0.113.4/32
```

Anything outside the list gets a 403 before authentication is even attempted.
Leaving it empty means no IP restriction — which is a deliberate choice, not a
default to drift into.

**Ship the audit log off the box.** It is hash-chained and append-only by
trigger, which makes tampering *detectable*. It does not make it *impossible* —
anyone with database superuser access can rewrite rows and recompute the chain.
Detection only helps if a copy exists somewhere they cannot reach.

**Keep backups.** Supabase's own backups cover the `admin` schema too, since it
lives in the same database.

---

## Operating it

| Task | Command |
|---|---|
| API logs | `journalctl -u neveroff-console-api -f` |
| Worker logs | `journalctl -u neveroff-console-worker -f` |
| Health | `curl -s localhost:4000/ready` |
| Worker health | `SELECT * FROM admin.worker_runs;` |
| Verify audit chain | `SELECT * FROM admin.verify_audit_chain(0);` — empty means intact |

**Deploying an update:**

```bash
cd /opt/neveroff-console && git pull && npm install --no-audit --no-fund && npm run build --workspaces --if-present && npm run db:migrate && sudo systemctl restart neveroff-console-api neveroff-console-worker
```

---

## When it does not work

**Site times out** — almost always the OCI Security List or the instance
iptables. Check both; see step 1.

**Caddy cannot get a certificate** — DNS is not resolving to this box yet, or
port 80 is blocked. Let's Encrypt validates over HTTP first.

**API will not start** — `journalctl -u neveroff-console-api -n 50`. A missing
or too-short `SESSION_SECRET` fails at boot with a readable message, by design.

**Sign-in succeeds then immediately logs out** — the cookie is `SameSite=Strict`
and `Secure`. The console must be on HTTPS and on a single origin. If you split
the API onto a different hostname, this is the symptom.

**Database connection refused** — check you used the session pooler on 5432, and
that the host appears in `DB_ALLOWED_HOSTS`. The client refuses unlisted hosts
before it dials.

**Everything works but nobody gets notified of a ban** — Firebase credentials
are missing. `SELECT * FROM admin.notification_outbox WHERE sent_at IS NULL;`
will be filling up.

---

## Ampere A1 notes

Nothing here needs an x86 image. `@node-rs/argon2` ships aarch64 prebuilds, so
password hashing works without a compiler toolchain.

On the 4 OCPU / 24 GB Always Free shape the console is idle most of the time —
its heaviest work is the analytics rollup every five minutes, which recomputes
whole buckets over a lookback window. If that ever becomes noticeable, the
rollup tables are the seam for moving analytics elsewhere: the query API reads
rollups and never raw events, so only the producer would change.
