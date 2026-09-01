# Deploy the scan funnel

Two pieces: the **backend** (`server/`, runs the scans) and the **landing**
(`site/`, static). Deploy the backend first, then point the landing at it.

---

## A. Backend

The backend needs a host that runs a long-lived Node process (a scan clones a repo
and takes ~1 min, so short-timeout serverless functions are a poor fit). The image
includes `git` (needed to clone targets). Build context is the repo root.

### Fly.io (recommended)

```bash
# one-time
fly launch --no-deploy                          # accept the existing fly.toml; pick your app name
fly volume create sswdata -r cdg -n 1 -s 1      # 1GB volume for the job store (/data)

# secrets (never commit these — set them here)
fly secrets set \
  ADMIN_TOKEN="$(openssl rand -hex 16)" \
  MERCHANT_WALLET="7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P" \
  SOLANA_RPC_URL="https://your-helius-or-quicknode-rpc" \
  PAY_INSTRUCTIONS="Send 80 USDC (Solana) to <your-address>, memo = your jobId" \
  RESEND_API_KEY="re_..." \
  MAIL_FROM="scan@yourdomain.com" \
  ALLOW_ORIGIN="https://your-landing-domain"

fly deploy
```

Note the `ADMIN_TOKEN` you generated (needed to confirm payments). Your scan
endpoint is then `https://<app>.fly.dev/scan`.

Without `RESEND_API_KEY` the backend still runs but writes emails to disk instead
of sending them — fine for a first manual test, not for real customers.

### Railway (alternative)

`railway.json` points Railway at `server/Dockerfile`. In the Railway dashboard:
add a **volume** mounted at `/data`, and set the same env vars
(`ADMIN_TOKEN`, `PAY_INSTRUCTIONS`, `RESEND_API_KEY`, `MAIL_FROM`, `ALLOW_ORIGIN`,
`JOBS_FILE=/data/jobs.json`), then deploy.

### Health check

```bash
curl https://<your-backend>/health          # -> {"ok":true}
```

---

## B. Landing (`site/`)

It's one static file plus `config.js`. **Edit `site/config.js`** first:

```js
window.SSW_ENDPOINT = "https://<your-backend>/scan";
window.SSW_CONTACT  = "you@yourdomain.com";
```

Then host the `site/` folder anywhere static:

- **Vercel / Netlify:** new project from the repo, set the output/publish directory to `site`.
- **Cloudflare Pages:** same, build output directory `site`.
- **GitHub Pages:** push, then Settings → Pages → deploy from `main` `/site` (or move `site/` to `/docs`).

The backend's `ALLOW_ORIGIN` must equal the landing's final URL, or the browser
blocks the request (CORS). While `SSW_ENDPOINT` is left `null`, the form falls back
to a prefilled email so you still capture leads with no backend.

---

## C. First sales, by hand (before automating payment)

1. A buyer submits the form → the backend creates a job in `pending_payment` and
   shows your `PAY_INSTRUCTIONS`. No scan runs yet.
2. They pay (USDC to your address with the `jobId` as memo, or your Stripe link).
3. You confirm the payment yourself:

```bash
curl -X POST https://<your-backend>/confirm \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"jobId":"<the id>"}'
```

The scan runs and the report is emailed automatically. List pending jobs anytime:

```bash
curl -H "authorization: Bearer $ADMIN_TOKEN" https://<your-backend>/admin/jobs
```

Automate step 3 later (a USDC watcher or a Stripe webhook that calls `/confirm`)
only once the demand is proven.

---

## D. Payments (wallet connect, USDC on Solana)

The landing lets a buyer connect a Solana wallet (Phantom) and pay in USDC. Config
lives in `site/config.js`:

```js
window.SSW_API_BASE    = "https://<your-backend>";   // enables auto delivery; null = manual
window.SSW_WALLET      = "<your USDC recipient address>";
window.SSW_RPC         = "https://<your-rpc>";        // replace the public one before real traffic
window.SSW_AMOUNT_USDC = 80;                          // set to 1 for your first test payment
```

Backend needs `MERCHANT_WALLET` (same address) and `SOLANA_RPC_URL`. On payment the
page sends the USDC transfer, then calls `POST /pay/verify {jobId, signature}`; the
backend confirms on-chain (correct mint, amount, recipient; each signature usable
once) and runs the scan. While `SSW_API_BASE` is null the payment still works but
the payer is told to email you the signature (you confirm with `/confirm` by hand).

**Test with a real payment before sharing the link.** Set `SSW_AMOUNT_USDC = 1`,
pay yourself once end to end, confirm the report arrives, then set it back to `80`.

## Fix Vercel auto-deploy (important)

The project auto-deploys on every push, but its **Root Directory** must be `site`,
or the build runs from the repo root (no `index.html` there) and the site 404s.
In the Vercel dashboard: Project → Settings → General → **Root Directory** → set to
`site` → Save. After that, every `git push` redeploys the landing correctly. Until
you set it, deploy manually with `npx vercel --prod` from the `site/` folder.
