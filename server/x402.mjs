// x402 v2 over HTTP, settled by a facilitator (PayAI by default: free tier, no key).
//
// Why a facilitator when verify.mjs can already read a payment off the chain:
// a standard x402 client (the fetch wrappers agents use) does not submit a
// transfer and report its signature. It signs a transfer, leaves the fee payer
// slot to the facilitator, and hands us the unsent transaction in the
// PAYMENT-SIGNATURE header. Only a facilitator can land that. It is also the
// only way into the Bazaar: a facilitator catalogs an endpoint when it settles
// a payment that echoes the endpoint's `bazaar` extension.
//
// Zero deps: fetch + Buffer.

export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

export const encodeHeader = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");
export function decodeHeader(value) {
  try { return JSON.parse(Buffer.from(String(value), "base64").toString("utf8")); }
  catch { return null; }
}

export class Facilitator {
  constructor({ url, fetchImpl = globalThis.fetch, ttlMs = 10 * 60_000 }) {
    this.url = url.replace(/\/$/, "");
    this.fetch = fetchImpl;
    this.ttlMs = ttlMs;
    this._supported = null;
    this._at = 0;
  }

  async _post(path, body) {
    const res = await this.fetch(`${this.url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    if (!json) throw new Error(`facilitator ${path} ${res.status}: ${text.slice(0, 200)}`);
    return json;
  }

  // The Solana fee payer is the facilitator's own key; the client must build its
  // transaction around it, so it goes into `extra.feePayer` of every quote.
  async feePayer(network) {
    if (!this._supported || Date.now() - this._at > this.ttlMs) {
      const res = await this.fetch(`${this.url}/supported`);
      if (!res.ok) throw new Error(`facilitator /supported ${res.status}`);
      this._supported = await res.json();
      this._at = Date.now();
    }
    const kind = (this._supported.kinds || []).find(
      (k) => k.x402Version === 2 && k.scheme === "exact" && k.network === network,
    );
    if (!kind || !kind.extra || !kind.extra.feePayer) throw new Error(`facilitator does not settle exact on ${network}`);
    return kind.extra.feePayer;
  }

  verify(paymentPayload, paymentRequirements) {
    return this._post("/verify", { x402Version: 2, paymentPayload, paymentRequirements });
  }

  settle(paymentPayload, paymentRequirements) {
    return this._post("/settle", { x402Version: 2, paymentPayload, paymentRequirements });
  }
}

// The `bazaar` extension: what a discovery catalog shows an agent about one
// POST endpoint. Same-document JSON Schema only (the spec forbids external $ref).
export function bazaarExtension({ exampleBody, properties, required, outputExample }) {
  return {
    info: {
      input: { type: "http", method: "POST", bodyType: "json", body: exampleBody },
      output: { type: "json", example: outputExample },
    },
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      properties: {
        input: {
          type: "object",
          properties: {
            type: { type: "string", const: "http" },
            method: { type: "string", enum: ["POST"] },
            bodyType: { type: "string", enum: ["json"] },
            body: { type: "object", properties, required },
          },
          required: ["type", "method", "bodyType", "body"],
          additionalProperties: false,
        },
        output: {
          type: "object",
          properties: { type: { type: "string" }, example: { type: "object" } },
          required: ["type"],
        },
      },
      required: ["input"],
    },
  };
}
