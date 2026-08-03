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

- An OCI instance with a **public IP**. See the recommendation below.
- **Ubuntu 22.04 or 24.04** assumed below. Oracle Linux works with `dnf` in
  place of `apt`.
- A domain you control, for a subdomain like `console.yourdomain.com`.
- Your Supabase **database connection string** and **service role key**.

### Which instance

| | |
|---|---|
| Shape | `VM.Standard.A1.Flex`, **4 OCPU / 24 GB** |
| Image | **Canonical Ubuntu 24.04 (aarch64)** — `Minimal` is fine, see below |
| Boot volume | 50 GB (the default) |

That is the whole Always Free Ampere allocation on one instance, at no cost.

**ARM is safe here** — every native dependency ships an aarch64 glibc prebuild
(`@node-rs/argon2-linux-arm64-gnu`, `@esbuild/linux-arm64`,
`@rollup/rollup-linux-arm64-gnu`) and nothing compiles at install time. No
toolchain needed.

**Do not use the x86 free shape.** `VM.Standard.E2.1.Micro` has 1 GB of RAM;
the Vite build alone will exhaust it, leaving you building locally and copying
`dist/` up by hand on every deploy.

24 GB is more than this needs — Postgres is in Supabase, so the box runs two
mostly-idle Node processes and Caddy. 1 OCPU / 6 GB genuinely works. Take the
larger shape only because it is free, and because the build is the one moment
the machine works hard.

**Expect a capacity fight.** "Out of host capacity" on A1 is chronic in busy
regions and is not something you have configured wrong. In order of what
actually helps: upgrade the account to Pay As You Go (Always Free resources stay
free, but you gain capacity priority); try each availability domain separately;
ask for 1 OCPU / 6 GB instead, since the shape can be resized later without
rebuilding.

Your home region is fixed at signup and cannot be changed afterwards. In the
creation dialog, confirm a **public IPv4** is assigned and **save the SSH
private key** — Oracle shows it once.

**"Minimal" is often the only aarch64 Ubuntu offered, and that is fine.** It is
the same Ubuntu with a smaller preinstalled package set — same kernel, same apt
repositories, same support window. It simply omits tools a server does not need
by default. Step 0 below installs the handful this guide does use, so the rest
proceeds identically.

---

## 0. Packages this guide needs

Do this first — step 1 uses `netfilter-persistent`, which a Minimal image does
not necessarily have, and finding that out mid-firewall-edit is unpleasant.

```bash
sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y git curl gnupg ca-certificates dnsutils iptables-persistent
```

`DEBIAN_FRONTEND=noninteractive` matters: `iptables-persistent` otherwise opens
a dialog asking whether to save the current rules, and a prompt nobody is
watching will just hang. Installing it now, before you touch anything, means the
"save current rules" answer is irrelevant either way.

What each is for: `gnupg` dearmors the Caddy signing key, `dnsutils` provides
`dig` for the DNS check, `iptables-persistent` brings `netfilter-persistent` so
firewall rules survive a reboot. On a full image most are already present and
this is a no-op.

---

## 1. Open the ports — both firewalls

Oracle catches nearly everyone here, because there are **two** firewalls and
closing either one produces the same symptom: the site simply times out.

**a) The OCI Security List** (in the Oracle web console)

Networking → Virtual Cloud Networks → your VCN → Security Lists → default →
Add Ingress Rules:

| Source CIDR | Protocol | Destination Port | Why |
|---|---|---|---|
| `0.0.0.0/0` | TCP | 80 | Let's Encrypt validates over HTTP before it will issue, and again at every renewal. It cannot be closed afterwards. |
| `0.0.0.0/0` | TCP | 443 | The console itself. |

Leave the rules **stateful** (the default) and set Source Type to CIDR. Port 22
already has a rule from instance creation; narrowing it to your own address is
worthwhile, and costs nothing to change later from the OCI console.

Leave **egress** alone. The default allow-all is required — the box reaches out
to Supabase, Let's Encrypt, npm and Firebase, and nothing reaches in on those
connections.

Do **not** open 4000 or 5432. The API binds `127.0.0.1` and is reached only
through Caddy, and Postgres is not on this machine at all. An exposed 4000 would
be the API with no TLS and no reverse proxy in front of it.

**b) The instance's own iptables**

Oracle's Ubuntu images ship with a `REJECT` rule that drops everything not
explicitly allowed, and it sits *above* anything you append — so a rule added
with `-A` is never reached. It has to go in above the REJECT, and the position
of that rule varies between images. Find it rather than assuming:

```bash
sudo iptables -L INPUT --line-numbers -n
```

Insert both ports above that line number, substituting it for `N`:

```bash
sudo iptables -I INPUT N -m state --state NEW -p tcp --dport 80 -j ACCEPT && sudo iptables -I INPUT N -m state --state NEW -p tcp --dport 443 -j ACCEPT
```

Confirm they landed above the REJECT, then persist them:

```bash
sudo iptables -L INPUT --line-numbers -n
```

```bash
sudo netfilter-persistent save
```

Order is the whole point here. Rules below the REJECT are still listed, still
look correct at a glance, and do nothing at all.

---

## 2. Point DNS at the instance

Create an **A record** for `console.yourdomain.com` pointing at the instance's
public IP. Verify before continuing — Caddy cannot issue a certificate until
this resolves:

```bash
dig +short console.yourdomain.com
```

### If you do not have a domain yet

You need a hostname, not just an IP, and this is not merely about avoiding a
browser warning. The session cookie is set with `secure: true` whenever
`NODE_ENV=production`, so **a browser will refuse to store it over plain HTTP**.
Sign-in appears to succeed and then drops you straight back to the login screen.
Let's Encrypt will not issue a certificate for a bare IP address, so there is no
way around this by ignoring warnings.

The free path that works today, in about two minutes:

1. Go to [duckdns.org](https://duckdns.org) and sign in with an existing account.
2. Claim a subdomain, e.g. `neveroff-console` → `neveroff-console.duckdns.org`.
3. Set its IP to your instance's **public IPv4**.

   Overwrite whatever DuckDNS pre-fills — it detects the address of the browser
   you are sitting at, which is your own machine, not the server. Take the value
   from the OCI console (Compute → Instances → your instance → Public IP
   address), or ask the instance itself:

   ```bash
   curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/vnics/ | grep -o '"publicIp"[^,]*'
   ```

   That address is *ephemeral* by default, meaning it lasts the lifetime of the
   instance — reboots keep it, terminating the instance releases it. Convert it
   to a reserved public IP if you want it to survive a rebuild.

Then use that hostname everywhere this guide says `console.yourdomain.com` — in
`WEB_ORIGIN`, in the Caddyfile, and in the `dig` check. Everything else is
unchanged, and Caddy will get a real, publicly trusted certificate.

DuckDNS works for this specifically because `duckdns.org` is on the Public
Suffix List, so your subdomain gets its own Let's Encrypt rate-limit budget.
Wildcard-DNS services that map an IP into a shared domain do not, and you can
find their weekly issuance already exhausted by strangers.

Treat it as a way to get running, not a destination. This console can ban every
user on your platform; leaving its address dependent on a free service you have
no relationship with is a strange place to end up when a domain costs about ten
dollars a year. Moving later is a DNS record, a line in `.env`, and a line in
the Caddyfile.

**Do not "temporarily" set `NODE_ENV=development` to dodge this.** It clears the
`secure` flag and sign-in starts working over HTTP — while sending an admin
session cookie in clear text over the public internet, which is precisely the
credential worth stealing here.

---

## 3. Install Node and Caddy

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
```

```bash
node --version && npm --version
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

**The hostname is not a secret, whatever you named it.** Every certificate
Let's Encrypt issues is published to public Certificate Transparency logs, so
the address is searchable by anyone within minutes of going live and stays that
way. Picking an obscure name is not a control; the two below are.

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
