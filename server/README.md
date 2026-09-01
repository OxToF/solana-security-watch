# scan backend

Payment-agnostic HTTP backend for the self-serve scan funnel. Zero runtime
dependencies (Node `http` + `fetch`). It wraps `bin/scan.mjs`.

## Flow

```
POST /scan   {repo, email}          -> creates a pending_payment job, returns
                                       {jobId, amountUsd, payment.instructions}.
                                       The heavy scan does NOT run yet.
POST /confirm {jobId}  (admin/webhook) -> marks paid, queues the scan, which runs
                                       runScan(), emails the report, marks done.
GET  /jobs/:id                       -> job status (email redacted).
GET  /admin/jobs        (admin)      -> all jobs.
GET  /health
```

The `/confirm` gate is the single integration point for payment. Start by
confirming crypto payments by hand (`Authorization: Bearer $ADMIN_TOKEN`); later
point a Stripe webhook or an on-chain USDC watcher at the same endpoint.

## Run

```bash
ADMIN_TOKEN=$(openssl rand -hex 16) \
PAY_INSTRUCTIONS="Send 80 USDC (Solana) to <your-address>, memo = your jobId" \
RESEND_API_KEY=...        # optional; without it, emails are written to server/deliveries/
MAIL_FROM="scan@yourdomain.com" \
ALLOW_ORIGIN="https://your-landing-domain" \
node index.mjs
```

Then point the landing page at it: set `window.SSW_ENDPOINT = "https://your-backend/scan"`.

## Environment

| Var | Purpose |
|---|---|
| `PORT` | listen port (default 8787) |
| `ADMIN_TOKEN` | bearer token for `/confirm` and `/admin/jobs` (required to confirm) |
| `PAY_INSTRUCTIONS` | text shown to the buyer after `/scan` (USDC address / Stripe link) |
| `SCAN_PRICE_USD` | price shown (default 80) |
| `RESEND_API_KEY` + `MAIL_FROM` | email delivery via Resend; omit for dev disk mode |
| `ALLOW_ORIGIN` | CORS origin for the landing page (default `*`) |
| `JOBS_FILE` | job store path (default `server/data/jobs.json`) |
| `ALLOW_LOCAL` | `1` enables scanning a local path (dev/testing only — never in prod) |

## Confirm a payment (manual MVP)

```bash
curl -X POST https://your-backend/confirm \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"jobId":"<the id>"}'
```

## Deploy

Any host that runs a long-lived Node process (Fly.io, Railway, Render, a small
VPS). Not a great fit for short-timeout serverless functions, since a scan clones
a repo and can take a minute. Persist `server/data/` (a volume) so jobs survive
restarts.

## Plugging in real payment

- **Crypto (USDC):** show a deposit address + the `jobId` as memo in
  `PAY_INSTRUCTIONS`; run a small watcher that calls `/confirm` when a matching
  transfer lands. Fits a pseudonymous operator; no KYC.
- **Stripe:** create a Checkout Session per job (metadata.jobId), and have the
  `checkout.session.completed` webhook call `/confirm`.
