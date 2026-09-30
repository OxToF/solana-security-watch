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

### Agent flow (pay per call, no human in the loop)

An agent cannot click a wallet button, so it buys the same scan over HTTP 402.
The full manual an agent reads is served at `GET /skill.md` (source: `server/skill.md`).

```
POST /agent/scan {repo[,email]}       -> 402 + x402-style `accepts` (payTo, USDC mint,
                                       amount, extra.memo), jobId, accessToken (shown once).
POST /agent/scan {jobId, signature}   -> verifies the USDC transfer on-chain AND that the
                                       same tx carries the job's memo; 202 + queued.
POST /agent/check {packages:[{name,version}]} -> x402 v2, instant advisories for up to 100
                                       crates; verified first, settled only once the answer exists.
GET  /agent/jobs/:id                  -> status (Bearer accessToken).
GET  /agent/jobs/:id/report.{json,md,html} -> the report once done (Bearer accessToken).
```

The memo is what binds a payment to one job: a transfer signature is public as
soon as it lands, so without it anyone watching the merchant wallet could credit
someone else's payment to their own job. The job id is in that public memo, so
reading a report takes the separate access token, stored only as a hash. Agent
reports are kept in `REPORTS_DIR` (default: `reports/` next to `JOBS_FILE`).

**x402 v2.** The same 402 also carries a standard `PAYMENT-REQUIRED` header
(Solana mainnet, USDC, `extra.memo` = the job's memo, `extra.feePayer` from the
facilitator's `/supported`, and the `bazaar` discovery extension). A standard
client resends the request with `PAYMENT-SIGNATURE` (a signed, unsent transfer);
the server settles it through the facilitator (`FACILITATOR_URL`, PayAI by
default, free tier, no key), always against requirements rebuilt from the job,
never the client's echo, then re-checks the settled signature on-chain with the
same memo check as above. The paid answer is `200` + `PAYMENT-RESPONSE` and a
fresh `accessToken`. A facilitator settling a payment that echoes the `bazaar`
extension is also what lists the endpoint in its discovery catalog.

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
| `SCAN_PRICE_USD` | web price, a human with a branded report by email (default 80) |
| `AGENT_SCAN_PRICE_USD` | agent price of `/agent/scan` (default 0.5) |
| `CHECK_PRICE_USD` | price of one `/agent/check` request (default 0.01) |
| `OSV_QUERY_URL` | advisory database endpoint (default OSV; tests point it at a fake) |
| `RESEND_API_KEY` + `MAIL_FROM` | email delivery via Resend; omit for dev disk mode |
| `ALLOW_ORIGIN` | CORS origin for the landing page (default `*`) |
| `JOBS_FILE` | job store path (default `server/data/jobs.json`) |
| `PUBLIC_BASE_URL` | absolute base used in agent-facing URLs and `/skill.md` |
| `REPORTS_DIR` | where agent reports are kept (default `reports/` next to `JOBS_FILE`) |
| `FACILITATOR_URL` | x402 v2 facilitator (default `https://facilitator.payai.network`; `off` keeps only the memo flow) |
| `ERC8004_AGENT_ID` | agentId minted by the ERC-8004 IdentityRegistry on Base; listed in `/.well-known/agent-registration.json` |
| `LANDING_URL` | the human landing, listed as the `web` service of the registration file |
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
