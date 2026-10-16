// Anchor-aware analysis of a program's source.
//
// The old scan grepped for words (UncheckedAccount, init_if_needed, invoke) across
// the whole repo, framework code included, and called every hit a lead. This reads
// what Anchor reads: each #[derive(Accounts)] struct, each field's type and
// constraints, and the handlers that take that context. A rule fires only when the
// defect is actually there AND no guard against it can be seen, in the constraints
// or in the handler. Each finding names the field, shows the code, says why it is
// exploitable on Solana and how to fix it.
//
// Static and syntactic: it does not type-check or execute the program. Rules are
// written to stay quiet when a guard is visible, so a silent rule is not a proof.

import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

// --- source handling ------------------------------------------------------------------
// Blank out comments and string contents, keeping offsets and line breaks, so brace
// and bracket matching cannot be fooled by a "{" in a string or a comment.
export function maskRust(src) {
  const out = src.split("");
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === "/" && d === "/") { while (i < n && src[i] !== "\n") out[i++] = " "; continue; }
    if (c === "/" && d === "*") {
      let depth = 0;
      do {
        if (src[i] === "/" && src[i + 1] === "*") { depth++; out[i] = out[i + 1] = " "; i += 2; continue; }
        if (src[i] === "*" && src[i + 1] === "/") { depth--; out[i] = out[i + 1] = " "; i += 2; continue; }
        if (src[i] !== "\n") out[i] = " ";
        i++;
      } while (i < n && depth > 0);
      continue;
    }
    if (c === "b" && d === '"') { i++; continue; }
    if (c === '"') {
      i++;
      while (i < n && src[i] !== '"') { if (src[i] === "\\") { out[i] = " "; i++; } if (src[i] !== "\n") out[i] = " "; i++; }
      i++;
      continue;
    }
    if (c === "r" && (d === '"' || (d === "#" && /^r#+"/.test(src.slice(i, i + 10))))) {
      const m = /^r(#*)"/.exec(src.slice(i));
      const end = `"${m[1]}`;
      const j = src.indexOf(end, i + m[0].length);
      for (let k = i + m[0].length; k < (j < 0 ? n : j); k++) if (src[k] !== "\n") out[k] = " ";
      i = j < 0 ? n : j + end.length;
      continue;
    }
    // A char literal ('{'), not a lifetime ('info).
    if (c === "'" && src[i + 2] === "'" ) { out[i + 1] = " "; i += 3; continue; }
    if (c === "'" && d === "\\") { const j = src.indexOf("'", i + 2); for (let k = i + 1; k < j; k++) out[k] = " "; i = j + 1; continue; }
    i++;
  }
  return out.join("");
}

function matchClose(s, open, oc = "{", cc = "}") {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === oc) depth++;
    else if (s[i] === cc && --depth === 0) return i;
  }
  return -1;
}

// Split on commas that sit at depth 0 of (), [], {}, <>.
function splitTop(s, sep = ",") {
  const out = [];
  let depth = 0, cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if ("([{<".includes(c)) depth++;
    else if (")]}>".includes(c) && !(c === ">" && s[i - 1] === "-")) depth--;
    if (c === sep && depth === 0) { out.push(cur.trim()); cur = ""; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const lineAt = (s, idx) => s.slice(0, idx).split("\n").length;

// Remove #[cfg(test)] items: test modules are not part of the program.
function stripTestModules(masked) {
  let s = masked;
  for (;;) {
    const m = /#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{/.exec(s);
    if (!m) return s;
    const open = m.index + m[0].length - 1;
    const close = matchClose(s, open);
    if (close < 0) return s;
    s = s.slice(0, m.index) + s.slice(m.index, close + 1).replace(/[^\n]/g, " ") + s.slice(close + 1);
  }
}

function rustFiles(dir) {
  const out = [];
  const walk = (d) => {
    let es; try { es = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of es) {
      const p = join(d, e.name);
      if (e.isDirectory()) { if (!["target", "tests", "benches", "examples", "fuzz", "node_modules", ".git"].includes(e.name)) walk(p); }
      else if (e.name.endsWith(".rs") && !/(^|_)tests?(_|\.rs$)|test_util/.test(e.name)) out.push(p);
    }
  };
  walk(dir);
  return out;
}

// --- accounts structs -------------------------------------------------------------------
const WRAPPERS = /^(Option|Box)<(.+)>$/;
function classify(type) {
  let t = type.replace(/\s+/g, " ").trim();
  let optional = false;
  for (let m; (m = WRAPPERS.exec(t)); t = m[2].trim()) if (m[1] === "Option") optional = true;
  const m = /^([A-Za-z_][\w:]*)\s*(?:<(.*)>)?$/.exec(t);
  const kind = m ? m[1].split("::").pop() : t;
  const args = m && m[2] ? splitTop(m[2]).filter((a) => !a.startsWith("'")) : [];
  return { kind, inner: args[0] ? args[0].split("::").pop() : null, optional };
}

function parseConstraints(attrBody) {
  const c = { mut: false, init: false, initIfNeeded: false, signer: false, executable: false, zero: false,
    seeds: null, hasOne: [], constraints: [], address: null, owner: null, close: null, tokenish: false, raw: attrBody };
  for (const item of splitTop(attrBody)) {
    const [k, ...rest] = item.split("=");
    const key = k.trim();
    const val = rest.join("=").trim();
    if (key === "mut") c.mut = true;
    else if (key === "init") { c.init = true; c.mut = true; }
    else if (key === "init_if_needed") { c.initIfNeeded = true; c.mut = true; }
    else if (key === "signer") c.signer = true;
    else if (key === "executable") c.executable = true;
    else if (key === "zero") { c.zero = true; c.mut = true; }
    else if (key === "seeds") c.seeds = val;
    else if (key === "has_one") c.hasOne.push(val.split("@")[0].trim());
    else if (key === "constraint") c.constraints.push(val);
    else if (key === "address") c.address = val;
    else if (key === "owner") c.owner = val;
    else if (key === "close") { c.close = val; c.mut = true; }
    else if (/^(token|associated_token|mint)::/.test(key)) c.tokenish = true;
    else if (key.startsWith("realloc")) c.mut = true;
  }
  return c;
}

function parseAccountsStructs(file, raw, masked) {
  const structs = [];
  const re = /#\[derive\(([^)]*)\bAccounts\b[^)]*\)\]/g;
  for (let m; (m = re.exec(masked)); ) {
    const sm = /struct\s+(\w+)[^{;]*\{/.exec(masked.slice(m.index));
    if (!sm) continue;
    const open = m.index + sm.index + sm[0].length - 1;
    const close = matchClose(masked, open);
    if (close < 0) continue;
    const body = masked.slice(open + 1, close);
    const rawBody = raw.slice(open + 1, close);
    const fields = [];
    let i = 0, attrs = [], docs = [];
    while (i < body.length) {
      if (/\s/.test(body[i])) { i++; continue; }
      if (body.startsWith("#[", i)) {
        const end = matchClose(body, i + 1, "[", "]");
        attrs.push(rawBody.slice(i + 2, end));
        i = end + 1;
        continue;
      }
      // Doc comments are blanked in `body`, so read them from the raw text by line.
      const fm = /^(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*/.exec(body.slice(i));
      if (!fm) { i++; continue; }
      const start = i;
      i += fm[0].length;
      let depth = 0, j = i;
      for (; j < body.length; j++) {
        const ch = body[j];
        if (ch === "<" || ch === "(") depth++;
        else if ((ch === ">" && body[j - 1] !== "-") || ch === ")") depth--;
        else if (ch === "," && depth === 0) break;
      }
      const type = body.slice(i, j).trim();
      const absLine = lineAt(raw, open + 1 + start);
      // Doc lines just above the field (and above its attributes).
      const above = raw.split("\n").slice(Math.max(0, absLine - 1 - 12), absLine - 1).reverse();
      docs = [];
      for (const l of above) {
        const t = l.trim();
        if (t.startsWith("///")) docs.unshift(t.replace(/^\/\/\/\s?/, ""));
        else if (t.startsWith("#[") || t.startsWith(")]") || t === "" || t.startsWith("//") || /^[\w:]+\s*=|^[a-z_]+,?$|^\]|^\)/.test(t)) continue;
        else break;
      }
      const acct = attrs.filter((a) => /^account\s*\(/.test(a)).map((a) => a.replace(/^account\s*\(/, "").replace(/\)\s*$/, "")).join(", ");
      fields.push({ name: fm[1], type, line: absLine, ...classify(type), c: parseConstraints(acct), docs: docs.join(" ") });
      attrs = [];
      i = j + 1;
    }
    structs.push({ name: sm[1], file, line: lineAt(raw, m.index), fields, text: masked.slice(m.index, close + 1) });
  }
  return structs;
}

// Handlers: every fn whose argument list takes Context<..., Name>.
function findHandlers(files) {
  const byStruct = new Map();
  for (const f of files) {
    const re = /fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*?)Context\s*<\s*(?:'[\w]+\s*,\s*)*(?:'[\w]+\s*,\s*)?(\w+)(?:\s*<[^>]*>)?\s*>/g;
    for (let m; (m = re.exec(f.masked)); ) {
      const open = f.masked.indexOf("{", m.index + m[0].length);
      if (open < 0) continue;
      const close = matchClose(f.masked, open);
      if (close < 0) continue;
      const h = { fn: m[1], file: f.rel, line: lineAt(f.masked, m.index), body: f.masked.slice(open, close + 1), start: open, sig: f.masked.slice(m.index, open) };
      if (!byStruct.has(m[3])) byStruct.set(m[3], []);
      byStruct.get(m[3]).push(h);
    }
  }
  return byStruct;
}

// --- rules ---------------------------------------------------------------------------------
// Not `owner`: in most programs it names the beneficiary of a permissionless crank,
// bound by has_one on purpose. Not new_/pending_: a two-step handover names its target.
const AUTH_NAME = /^(?!new_|pending_|old_|next_|proposed_)(authority|admin|signer|manager|operator|governor|.*_authority|.*_admin)$/;
const PROGRAM_NAME = /(^|_)program$/;
const SYSVAR_NAME = /^(clock|rent|instructions?|instructions_sysvar|sysvar_.*|.*_sysvar|recent_blockhashes|slot_hashes|stake_history|epoch_schedule)$/;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function mentions(text, name) { return new RegExp(`\\b${name}\\b`).test(text); }

// Local names that stand for an account: `let (a, b) = (x.key(), y.key())`,
// `let k = r.x.key()`, `if let Some(h) = r.x.as_ref()`, `r.x.as_ref().is_none_or(|h| ...)`.
function aliasFields(text, fieldNames) {
  const map = new Map();
  const isField = (n) => fieldNames.has(n);
  // let (a, Some(b), ..) = (x.key(), y.as_deref_mut(), ..)  — parentheses balanced by hand.
  for (const m of text.matchAll(/let\s*\(/g)) {
    const lOpen = m.index + m[0].length - 1, lClose = matchClose(text, lOpen, "(", ")");
    const eq = /^\s*=\s*\(/.exec(text.slice(lClose + 1));
    if (lClose < 0 || !eq) continue;
    const rOpen = lClose + eq[0].length, rClose = matchClose(text, rOpen, "(", ")");
    if (rClose < 0) continue;
    const ls = splitTop(text.slice(lOpen + 1, lClose)), rs = splitTop(text.slice(rOpen + 1, rClose));
    ls.forEach((l, k) => {
      const f = rs[k] && /(\w+)\s*(?:\.\s*(?:key|to_account_info|as_deref_mut|as_deref|as_ref|as_mut)\(\)|$)/.exec(rs[k].trim());
      const name = l.replace(/^mut\s+/, "").replace(/^Some\s*\(\s*(?:mut\s+)?(\w+)\s*\)$/, "$1").trim();
      if (f && isField(f[1]) && /^\w+$/.test(name)) map.set(name, f[1]);
    });
  }
  for (const m of text.matchAll(/let\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=\s*&(?:mut\s+)?(?:\w+\.)*?(\w+)\s*;/g)) if (isField(m[2])) map.set(m[1], m[2]);
  for (const m of text.matchAll(/let\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=\s*(?:\w+\.)*?(\w+)\s*\.\s*as_(?:deref_mut|deref|ref|mut)\(\)/g)) if (isField(m[2])) map.set(m[1], m[2]);
  for (const m of text.matchAll(/let\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=\s*[^;]*?\b(\w+)\s*\.\s*(?:key|to_account_info)\(\)\s*;/g)) if (isField(m[2])) map.set(m[1], m[2]);
  for (const m of text.matchAll(/Some\s*\(\s*(\w+)\s*\)\s*=\s*[^;{]*?\b(\w+)\s*\.\s*as_(?:ref|mut)\(\)/g)) if (isField(m[2])) map.set(m[1], m[2]);
  for (const m of text.matchAll(/\b(\w+)\s*\.\s*as_(?:ref|mut)\(\)\s*\.\s*\w+\s*\(\s*\|\s*(\w+)\s*\|/g)) if (isField(m[1])) map.set(m[2], m[1]);
  let out = text;
  for (const [alias, field] of map) if (alias !== field) out = out.replace(new RegExp(`\\b${alias}\\b`, "g"), field);
  return out;
}

// What fixes an account's identity, if anything: an address, distinct seeds, a mint.
function seedParts(f) { return f.c.seeds ? splitTop(f.c.seeds.replace(/^\[|\]$/g, "")) : null; }
function selfSeeded(f) { const p = seedParts(f); return !!p && p.some((x) => mentions(x, f.name)); }
function pinOf(f) {
  if (f.c.address) return `address:${f.c.address}`;
  if (f.c.seeds && !selfSeeded(f)) return `seeds:${f.c.seeds}`;
  if (f.c.tokenish) return `token:${f.c.raw.match(/(?:token|associated_token)::(?:mint|authority)\s*=\s*[^,]+/g)?.join("|") || f.c.raw}`;
  return null;
}

// Does any constraint, the struct, or code the handler runs compare the two accounts?
function distinctnessProved(a, b, s, text) {
  if (a.c.init || b.c.init) return true; // created by this instruction: cannot already be the other
  const pair = new RegExp(`\\b${a.name}\\b[^;\\n]*(!=|\\bne\\b)[^;\\n]*\\b${b.name}\\b|\\b${b.name}\\b[^;\\n]*(!=|\\bne\\b)[^;\\n]*\\b${a.name}\\b|keys_neq!\\s*\\([^;]*\\b${a.name}\\b[^;]*\\b${b.name}\\b|keys_neq!\\s*\\([^;]*\\b${b.name}\\b[^;]*\\b${a.name}\\b`);
  if ([...a.c.constraints, ...b.c.constraints, text].some((t) => pair.test(t))) return true;
  // `if a.key() == b.key() { return Err(..) }`: equality as the condition of a refusal.
  const refusal = new RegExp(`if\\s+[^{;]*\\b(${a.name}|${b.name})\\b[^{;]*==[^{;]*\\b(${a.name}|${b.name})\\b[^{;]*\\{\\s*(return\\s+)?(Err|err!)`);
  const m = refusal.exec(text);
  if (m && m[1] !== m[2]) return true;
  const sa = seedParts(a), sb = seedParts(b);
  if (sa && sb && !selfSeeded(a) && !selfSeeded(b)) {
    if (sa.length !== sb.length) return true;
    const diff = sa.map((x, k) => [x, sb[k]]).filter(([x, y]) => x.replace(/\s/g, "") !== y.replace(/\s/g, ""));
    if (!diff.length) return false; // the same seeds: the same account, always
    // Different literal or constant seeds can never collide.
    const constant = (x) => /^b?"|^\[?\s*b?"|^[A-Z][A-Z0-9_]*(\.as_ref\(\))?$|^&?\[\s*\d/.test(x.trim());
    if (diff.some(([x, y]) => constant(x) && constant(y))) return true;
    // Seeds that differ only by other accounts of this struct (pool A vs pool B): distinct
    // exactly when those accounts are, which their own pair already covers.
    const fieldsIn = (x) => s.fields.map((f) => f.name).filter((n) => mentions(x, n));
    if (diff.every(([x, y]) => fieldsIn(x).length && fieldsIn(y).length && fieldsIn(x).join() !== fieldsIn(y).join())) return true;
    // Seeds from different arguments the handler orders against each other.
    const ids = diff.flatMap(([x, y]) => [/^&?(\w+)/.exec(x)?.[1], /^&?(\w+)/.exec(y)?.[1]]).filter(Boolean);
    const guarded = (id) => new RegExp(`(require|assert)[^;]*\\b${id}\\b[^;]*(<|>|!=|==)`).test(text);
    if (ids.length >= 2 && ids.every(guarded)) return true;
    return false;
  }
  const pa = pinOf(a), pb = pinOf(b);
  return !!(pa && pb && pa !== pb);
}

function validated(f, s) {
  const c = f.c;
  if (c.address || c.owner || c.seeds || c.init || c.executable || c.tokenish) return true;
  if (c.constraints.some((x) => mentions(x, f.name))) return true;
  if (s.fields.some((o) => o.c.hasOne.includes(f.name) || o.c.constraints.some((x) => mentions(x, f.name)) || (o.c.seeds && false))) return true;
  return false;
}

// Test doubles shipped as programs (programs/mocks, test-programs) are never deployed.
const NOT_DEPLOYED = /(^|\/)(mocks?|test[-_]?programs?|tests?|fuzz|benches)(\/|$)/;

export function analyzeAnchor(programDirs, repoDir) {
  const files = [];
  const skipped = programDirs.filter((d) => NOT_DEPLOYED.test(relative(repoDir, d)));
  for (const d of programDirs.filter((x) => !skipped.includes(x))) for (const p of rustFiles(join(d, "src"))) {
    const raw = readFileSync(p, "utf8");
    files.push({ path: p, rel: relative(repoDir, p), raw, masked: stripTestModules(maskRust(raw)) });
  }
  const structs = files.flatMap((f) => parseAccountsStructs(f.rel, f.raw, f.masked).map((s) => ({ ...s, raw: f.raw })));
  const handlers = findHandlers(files);
  const findings = [];
  const add = (x) => findings.push(x);
  const snippetOf = (raw, line) => {
    const ls = raw.split("\n");
    const from = Math.max(1, line - 3), to = Math.min(ls.length, line + 3);
    return { from, focus: line, lines: ls.slice(from - 1, to) };
  };

  // Plain Borsh structs of the program (not #[account]): name -> field names. Their bytes
  // carry no type tag unless a field says so.
  const structFields = new Map();
  for (const f of files) for (const m of f.masked.matchAll(/#\[derive\(([^)]*)\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+(\w+)\s*\{([^}]*)\}/g)) {
    if (!/(Borsh|Anchor)Deserialize/.test(m[1])) continue;
    const before = f.masked.slice(Math.max(0, m.index - 200), m.index);
    if (/#\[account(\([^)]*\))?\]\s*$/.test(before)) continue;
    structFields.set(m[2], [...m[3].matchAll(/(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:/g)].map((x) => x[1]));
  }
  let initIfNeeded = 0; // state accounts the takeover rule examined
  const localTypes = new Set();
  for (const f of files) for (const m of f.masked.matchAll(/#\[account(?:\([^)]*\))?\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+(\w+)/g)) localTypes.add(m[1]);

  // Every fn in the program, so a check in a helper the handler calls still counts.
  const fnBodies = new Map();
  const fnSigs = [];
  for (const f of files) for (const m of f.masked.matchAll(/fn\s+(\w+)\s*(?:<[^>{]*>)?\s*\([^{;]*\{/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(f.masked, open);
    if (close > 0) fnBodies.set(m[1], (fnBodies.get(m[1]) || "") + f.masked.slice(open, close + 1));
    if (close > 0) fnSigs.push({ sig: m[0], body: f.masked.slice(open, close + 1), file: f.rel, from: lineAt(f.masked, open), to: lineAt(f.masked, close) });
  }
  const reachableText = (bodies) => {
    const seen = new Set();
    let frontier = bodies, out = bodies.join("\n");
    for (let depth = 0; depth < 3; depth++) {
      const next = [];
      for (const b of frontier) for (const m of b.matchAll(/\b(\w+)\s*(?:::<[^>]*>)?\s*\(/g)) {
        if (seen.has(m[1]) || !fnBodies.has(m[1])) continue;
        seen.add(m[1]); next.push(fnBodies.get(m[1]));
      }
      out += "\n" + next.join("\n");
      frontier = next;
    }
    return out;
  };

  for (const s of structs) {
    const hs = handlers.get(s.name) || [];
    const hText = hs.map((h) => h.body).join("\n");
    const fieldNames = new Set(s.fields.map((f) => f.name));
    // Helpers that take this context by reference (fn route(a: &mut Ctx)) run for every handler.
    const helpers = fnSigs.filter((x) => new RegExp(`\\b${s.name}\\b`).test(x.sig) && !/Context\s*</.test(x.sig)).map((x) => x.body);
    // What each handler runs, separately: a check in one handler does not protect another
    // handler that takes the same accounts struct.
    const perHandler = (hs.length ? hs : [null]).map((h) => ({ h, text: aliasFields(reachableText([...(h ? [h.body] : []), ...helpers]) + "\n" + s.text, fieldNames) }));
    const runText = perHandler.map((x) => x.text).join("\n");

    for (const h of hs) {
      // A PDA verified with a bump the caller chose: several bumps give valid addresses for
      // the same seeds, so the "same" PDA has up to 255 versions.
      for (const m of h.body.matchAll(/create_program_address\s*\(/g)) {
        const close = matchClose(h.body, m.index + m[0].length - 1, "(", ")");
        const bump = close > 0 && /&\s*\[\s*(\w+)\s*\]/.exec(h.body.slice(m.index, close));
        if (!bump || !new RegExp(`\\b${bump[1]}\\s*:\\s*u8\\b`).test(h.sig) || /find_program_address/.test(h.body)) continue;
        const line = h.line + h.sig.split("\n").length - 1 + h.body.slice(0, m.index).split("\n").length - 1;
        const file = files.find((x) => x.rel === h.file);
        add({ rule: "bump-canonicalization", severity: "high", confidence: "medium", struct: s.name, field: bump[1], file: h.file, line, handlers: [h.fn],
          title: `\`${h.fn}\` accepts any bump for its PDA`,
          why: `The address is rebuilt with \`create_program_address\` and a \`${bump[1]}\` taken from the instruction arguments. Several bumps give a valid address for the same seeds, so a caller can make the program accept a different account than the canonical PDA, with its own contents.`,
          fix: `Derive with \`find_program_address\` and require that bump, or use \`#[account(seeds = [..], bump = stored.bump)]\` with the canonical bump stored at creation.`,
          snippet: snippetOf(file.raw, line) });
      }
      // Signer seeds made of a mint alone: every account built on the same mint shares the
      // signer, so one user's pool can sign transfers out of another's vault.
      for (const m of reachableText([h.body, ...helpers]).matchAll(/let\s+(\w+)\s*=\s*&\s*\[\s*([^\]]*?)\s*,\s*&\s*\[\s*[\w.]*bump\s*\]\s*,?\s*\]\s*;/g)) {
        const parts = splitTop(m[2]);
        if (parts.length !== 1 || !/\.mint\b/.test(parts[0]) || /"/.test(parts[0])) continue;
        if (!new RegExp(`with_signer\\s*\\(\\s*&\\s*\\[\\s*${m[1]}\\b|invoke_signed\\s*\\([^;]*\\b${m[1]}\\b|new_with_signer\\s*\\([^;]*\\b${m[1]}\\b`).test(h.body)) continue;
        const file = files.find((x) => x.rel === h.file);
        const line = h.line + h.sig.split("\n").length - 1 + h.body.slice(0, h.body.indexOf(m[0])).split("\n").length - 1;
        add({ rule: "pda-sharing", severity: "high", confidence: "medium", struct: s.name, field: null, file: h.file, line, handlers: [h.fn],
          title: `\`${h.fn}\` signs with a PDA shared by every account of the same mint`,
          why: `The signer seeds are only \`${parts[0].trim()}\` and a bump. Any other account of this program built on the same mint derives the same signer, so whoever controls one can sign for all of them, for example moving tokens out of a vault that is not theirs.`,
          fix: `Put what makes the authority unique in its seeds (the destination, the user, the pool's own key), and check them with \`#[account(seeds = [..], bump)]\`.`,
          snippet: snippetOf(file.raw, line) });
      }
    }

    for (const f of s.fields) {
      const loose = f.kind === "UncheckedAccount" || f.kind === "AccountInfo";
      // Arbitrary CPI target: a program taken as a raw account and never pinned.
      // ...and only when the call goes to it: `program_id: X.key()` or `CpiContext::new(X..)`.
      // A CPI to a hard-coded id (program_id: SOME_ID) merely lists the account.
      // An instruction builder takes the program id first: spl_token::instruction::transfer(X.key, ..).
      const targetsIt = new RegExp(`program_id\\s*:\\s*[\\w.]*\\b${f.name}\\b|CpiContext::new(?:_with_signer)?\\s*\\(\\s*[\\w.]*\\b${f.name}\\b|Instruction::new_with_\\w+\\s*\\(\\s*[\\w.]*\\b${f.name}\\b|instruction::\\w+\\s*\\(\\s*&?[\\w.]*\\b${f.name}\\b`).test(runText);
      const pinnedInCode = new RegExp(`${f.name}\\.key(\\(\\))?\\s*(==|!=)|(==|!=)\\s*&?\\s*[\\w.]*\\b${f.name}\\s*\\.\\s*key\\b|check_id\\(\\s*[^)]*${f.name}|require_keys_eq!\\s*\\([^;]*\\b${f.name}\\b`).test(runText);
      if (loose && PROGRAM_NAME.test(f.name) && targetsIt && !validated(f, s) && !pinnedInCode) {
        add({ rule: "arbitrary-cpi", severity: "high", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
          title: `\`${f.name}\` is a program account nobody checks`,
          why: `\`${s.name}.${f.name}\` is a raw ${f.kind}, with no \`address\` constraint and no key comparison in the handler. If the instruction makes a CPI to it, the caller chooses which program runs: a look-alike program can accept the call and do nothing, or return fake data, while this program believes the transfer or the check happened.`,
          fix: `Type it \`Program<'info, T>\` (Anchor checks the program id), or add \`#[account(address = expected_program::ID)]\`.`,
          snippet: snippetOf(s.raw, f.line) });
        continue;
      }
      // Missing signer: an authority that only has to be named, not to sign.
      if (AUTH_NAME.test(f.name) && ["UncheckedAccount", "AccountInfo", "SystemAccount"].includes(f.kind) && !f.c.signer && !f.c.seeds
          && !new RegExp(`${f.name}\\.is_signer`).test(hText + s.text)) {
        const gated = s.fields.filter((o) => o.c.hasOne.includes(f.name) || o.c.constraints.some((x) => mentions(x, f.name))).map((o) => o.name);
        // Compared to a stored key in the handler is gating too. Neither: the key is only
        // recorded (a creator naming an admin), which authorizes nothing here.
        const comparedInCode = new RegExp(`\\b${f.name}\\s*\\.\\s*key\\(\\)\\s*==|==\\s*[^;\\n]*\\b${f.name}\\s*\\.\\s*key\\(\\)|keys_eq!\\s*\\([^;]*\\b${f.name}\\b`).test(runText);
        // Another account signs (a keeper, a payer): the unsigned "authority" is then most often
        // the owner being acted upon in a permissionless instruction. Worth a look, not a verdict.
        const otherSigner = s.fields.find((o) => o !== f && (o.kind === "Signer" || o.c.signer));
        if (gated.length || comparedInCode) {
        add({ rule: "missing-signer", severity: "critical", confidence: otherSigner ? "low" : gated.length ? "high" : "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
          title: `\`${f.name}\` is checked by key but never has to sign`,
          why: gated.length
            ? `\`${gated.join("`, `")}\` require${gated.length > 1 ? "" : "s"} \`${f.name}\` to match a stored key (has_one / constraint), but \`${f.name}\` is a ${f.kind}: anyone can pass the right public key without holding the private key. The authority check is decorative.`
            : `The handler compares \`${f.name}\` to a stored key, but \`${f.name}\` is a ${f.kind} with no \`signer\` constraint and no \`is_signer\` check: anyone can pass the right public key without holding the private key.`,
          fix: `Type it \`Signer<'info>\`, or add the \`signer\` constraint.`,
          snippet: snippetOf(s.raw, f.line) });
          continue;
        }
        // Not compared to anything either. Two shapes are not an authority check at all:
        // a key recorded into an account this instruction creates (a creator naming an
        // admin), and an account handed to a CPI whose callee checks the signature.
        const recorded = new RegExp(`\\.\\s*\\w+\\s*=\\s*[^;=]*\\b${f.name}\\s*\\.\\s*key\\b`).test(runText) && s.fields.some((o) => o.c.init || o.c.initIfNeeded || o.c.zero);
        const forwarded = new RegExp(`instruction::\\w+\\s*\\([^;]*\\b${f.name}\\b`).test(runText)
          || (/\binvoke(_signed)?\s*\(|CpiContext::new/.test(runText) && new RegExp(`\\b${f.name}\\s*\\.\\s*(clone|to_account_info)\\(\\)`).test(runText));
        if (!recorded && !forwarded) {
          add({ rule: "missing-signer", severity: "high", confidence: otherSigner ? "low" : "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
            title: `\`${f.name}\` acts as the authority but never has to sign`,
            why: `\`${f.name}\` is a ${f.kind} with no \`signer\` constraint and no \`is_signer\` check. Whatever this instruction does on behalf of \`${f.name}\`, anyone can do it by passing that public key.`,
            fix: `Type it \`Signer<'info>\`, or add the \`signer\` constraint.`,
            snippet: snippetOf(s.raw, f.line) });
          continue;
        }
      }
      // Sysvar taken as a raw account: a forged "clock" or "instructions" account.
      // Handed to a CPI (the stake program reading stake_history), the callee checks it.
      const sysvarForwarded = /\binvoke(_signed)?\s*\(|CpiContext::new/.test(runText) && new RegExp(`\\b${f.name}\\s*\\.\\s*(clone|to_account_info)\\(\\)`).test(runText);
      if (loose && SYSVAR_NAME.test(f.name) && !f.c.address && !sysvarForwarded && !new RegExp(`${f.name}[^;]*(sysvar::|::ID|::id\\(\\))`).test(hText)) {
        add({ rule: "unchecked-sysvar", severity: "high", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
          title: `Sysvar \`${f.name}\` is read from an unverified account`,
          why: `\`${f.name}\` is a raw ${f.kind} without an address check. A caller can pass an account they control with forged contents (the Wormhole exploit used a fake instructions sysvar).`,
          fix: `Use \`Sysvar<'info, Clock>\` / \`Clock::get()\`, or \`#[account(address = sysvar::instructions::ID)]\`.`,
          snippet: snippetOf(s.raw, f.line) });
        continue;
      }
      // Data read from an account whose owner nobody checked.
      if (loose && !validated(f, s)) {
        const reads = new RegExp(`${f.name}\\s*\\.\\s*(try_borrow_data|data\\s*\\.\\s*borrow|try_borrow_mut_data)|${f.name}[^;\\n]*(try_from_slice|try_deserialize|from_le_bytes)`).test(hText);
        // An owner check compares the owner to a program id. `x.owner` alone proves nothing:
        // the decoded data often has an `owner` field too (an SPL token account's).
        const ownerChecked = new RegExp(`${f.name}\\s*\\.\\s*owner\\s*(==|!=)\\s*[^;\\n]*(ID\\b|id\\(\\)|program_id)|(ID\\b|id\\(\\)|program_id)[^;\\n]*(==|!=)\\s*&?\\s*[\\w.]*\\b${f.name}\\s*\\.\\s*owner\\b|${f.name}[^;\\n]*\\.owner\\(\\)\\s*(==|!=)|(Account|AccountLoader|InterfaceAccount)(::<[^>]*>)?::try_from\\([^)]*${f.name}|check_program_account\\s*\\([^)]*${f.name}`).test(hText)
          // Debiting an account's lamports only succeeds for its owner: the runtime checks it.
          || new RegExp(`${f.name}[^;\\n]*lamports[^;\\n]*borrow_mut\\(\\)\\s*=|${f.name}[^;\\n]*try_borrow_mut_lamports`).test(hText);
        // What the handler decodes from it: `let v = T::try_from_slice(&..f.data.borrow())`.
        const decoded = [...hText.matchAll(new RegExp(`let\\s+(?:mut\\s+)?(\\w+)\\s*(?::[^=]*)?=\\s*([A-Z]\\w*)\\s*::\\s*(try_from_slice|unpack|unpack_unchecked|deserialize|try_deserialize)\\s*\\([^;]*\\b${f.name}\\b`, "g"))].map((m) => ({ v: m[1], type: m[2], how: m[3] }));
        const writesBack = new RegExp(`${f.name}\\s*\\.\\s*try_borrow_mut_data|serialize\\s*\\([^;]*\\b${f.name}\\b`).test(hText) || /\.serialize\s*\(/.test(hText) && new RegExp(`${f.name}[^;]*try_borrow_mut_data`).test(hText);
        for (const d of decoded) {
          const local = structFields.get(d.type);
          const disc = local && local.find((x) => /discrimina|account_type|\bkind\b|\btag\b|is_initiali[sz]ed|initiali[sz]ed/.test(x));
          const checksDisc = disc && new RegExp(`\\b${d.v}\\s*\\.\\s*${disc}\\b\\s*(==|!=)|!\\s*${d.v}\\s*\\.\\s*${disc}\\b|(==|!=)\\s*${d.v}\\s*\\.\\s*${disc}\\b|require[^;]*\\b${d.v}\\s*\\.\\s*${disc}\\b`).test(hText);
          const authWrite = new RegExp(`\\b${d.v}\\s*\\.\\s*(\\w*(?:authority|owner|admin)\\w*)\\s*=(?!=)`).exec(hText);
          // Initialization of a raw account with no "already initialized" flag checked.
          if (writesBack && authWrite && !checksDisc) {
            add({ rule: "reinit-takeover", severity: "critical", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
              handlers: hs.map((h) => h.fn),
              title: `Anyone can re-initialize \`${f.name}\` and become its \`${authWrite[1]}\``,
              why: `The handler decodes \`${f.name}\` as \`${d.type}\`, writes \`${authWrite[1]}\` and stores it back, without checking that the account was not initialized already. Calling it again on a live account replaces its ${authWrite[1]}.`,
              fix: `Use \`#[account(init, ..)]\` with a typed \`Account<'info, ${d.type}>\`, or store an \`is_initialized\` flag and refuse when it is set.`,
              snippet: snippetOf(s.raw, f.line) });
            continue;
          }
          // Type cosplay: a plain Borsh type decoded from raw bytes with nothing that says
          // which type the bytes are. Another account of this program with a compatible
          // layout (or a forged one) decodes just as well.
          if (local && d.how === "try_from_slice" && !checksDisc && !writesBack) {
            add({ rule: "type-cosplay", severity: "high", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
              title: `\`${f.name}\` is decoded as \`${d.type}\` with no type discriminator`,
              why: `\`${d.type}\` is a plain Borsh struct${disc ? ` whose \`${disc}\` field is never checked` : " with no discriminator field"}: any account with a compatible layout decodes as \`${d.type}\`, so a caller can pass a different account type of this program and have it read as a \`${d.type}\`.`,
              fix: `Make \`${d.type}\` an \`#[account]\` and load it as \`Account<'info, ${d.type}>\` (Anchor checks the 8-byte discriminator), or add a discriminator field and check it.`,
              snippet: snippetOf(s.raw, f.line) });
          }
          // Account data matching: decoded, used, and never compared to what it should be.
          const compared = new RegExp(`\\b${d.v}\\s*\\.\\s*\\w+\\s*(==|!=)|(==|!=)\\s*&?\\s*${d.v}\\s*\\.\\s*\\w+|require\\w*!\\s*\\([^;]*\\b${d.v}\\s*\\.\\s*\\w+`).test(hText);
          if (!compared && !writesBack) {
            add({ rule: "unmatched-account-data", severity: "high", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
              title: `\`${f.name}\` is used without checking it is the right account`,
              why: `The handler decodes \`${f.name}\` as \`${d.type}\` and uses its contents, but never compares any of its fields (owner, mint, authority) to the accounts of this instruction: any \`${d.type}\` will do, someone else's included.`,
              fix: `Compare the decoded fields to the expected keys (\`${d.v}.owner == authority.key()\`), or load it as a typed account with \`has_one\` / \`constraint\`.`,
              snippet: snippetOf(s.raw, f.line) });
          }
        }
        if (reads && !ownerChecked && decoded.every((d) => new RegExp(`\\b${d.v}\\s*\\.\\s*\\w+\\s*(==|!=)|(==|!=)\\s*&?\\s*${d.v}\\s*\\.\\s*\\w+`).test(hText))) {
          add({ rule: "unverified-account-data", severity: "high", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
            title: `\`${f.name}\`'s data is trusted without checking who owns it`,
            why: `The handler reads \`${f.name}\`'s bytes, but \`${f.name}\` is a raw ${f.kind} and neither a constraint nor the handler checks its owner. Anyone can create an account with the same layout, owned by their own program, holding whatever values suit them.`,
            fix: `Load it as \`Account<'info, T>\` / \`AccountLoader\`, or check \`${f.name}.owner == &expected_program::ID\` before reading.`,
            snippet: snippetOf(s.raw, f.line) });
          continue;
        }
        if (f.c.mut && !/CHECK/.test(f.docs)) {
          add({ rule: "unchecked-mut-account", severity: "medium", confidence: "low", struct: s.name, field: f.name, file: s.file, line: f.line,
            title: `\`${f.name}\` is writable and unconstrained, with no CHECK note`,
            why: `A mutable ${f.kind} with no address, owner, seeds or has_one constraint: any account can be passed. It may be harmless (a lamports recipient), but nothing in the code says why.`,
            fix: `Constrain it, or document why any account is acceptable with a \`/// CHECK:\` comment.`,
            snippet: snippetOf(s.raw, f.line) });
        }
      }
    }

    // The same program-owned account passed twice: Anchor does not refuse it, and writes
    // every mutable copy back at exit, so the last copy wins.
    const groups = new Map();
    for (const f of s.fields) {
      // Mutable by constraint, or written by the handler (`&mut ctx.accounts.x`, `x.field = ..`):
      // a transaction can mark the account writable without the struct saying `mut`.
      const written = new RegExp(`&mut\\s+[\\w.]*\\b${f.name}\\b|\\b${f.name}\\s*\\.\\s*\\w+\\s*([+\\-*/]?=)(?!=)`).test(runText);
      if (!(f.c.mut || written) || !["Account", "AccountLoader", "InterfaceAccount"].includes(f.kind) || !f.inner) continue;
      const k = `${f.kind}<${f.inner}>`;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    for (const [k, fs] of groups) {
      for (let x = 0; x < fs.length; x++) for (let y = x + 1; y < fs.length; y++) {
        const [a, b] = [fs[x], fs[y]];
        const unguarded = perHandler.filter((x) => !distinctnessProved(a, b, s, x.text));
        if (!unguarded.length) continue;
        // lib.rs wrappers take the same Context as the handler they call: one name each.
        const where = [...new Set(unguarded.filter((x) => x.h).map((x) => `\`${x.h.fn}\``))];
        const guardedBy = [...new Set(perHandler.filter((x) => x.h && !unguarded.includes(x)).map((x) => `\`${x.h.fn}\``))].filter((n) => !where.includes(n));
        const programOwned = a.kind !== "InterfaceAccount" && localTypes.has(a.inner);
        // The write-back hazard is specific to accounts this program owns and serializes.
        // Two token accounts passed twice make a self-transfer, which is rarely exploitable
        // and would bury the findings that matter.
        if (!programOwned) continue;
        // Each one compared to a stored key elsewhere: likely distinct by the program's own
        // invariants, which this reading cannot follow. Kept, as a note to verify.
        const pinnedElsewhere = (f) => new RegExp(`\\b${f.name}\\b\\s*\\.\\s*key\\(\\)\\s*==|==\\s*[^;\\n]*\\b${f.name}\\b\\s*\\.\\s*key\\(\\)`).test(runText) || !!f.c.address || (!!f.c.seeds && !selfSeeded(f));
        const conf = pinnedElsewhere(a) && pinnedElsewhere(b) ? "low" : "medium";
        add({ rule: "duplicate-mutable-accounts", severity: programOwned ? "high" : "medium", confidence: conf, struct: s.name, field: `${a.name}, ${b.name}`, file: s.file, line: b.line,
          title: `\`${a.name}\` and \`${b.name}\` can be the same account`,
          why: programOwned
            ? `Both are mutable \`${k}\`. Anchor accepts the same account twice and, at the end of the instruction, writes each deserialized copy back in field order: the stale copy of \`${b.name}\` overwrites what the handler wrote through \`${a.name}\`. A caller who passes one account in both slots can revert a balance or reserve update (seen in practice: a pool recording funds its vault no longer held).`
            : `Both are mutable \`${k}\` and nothing proves they differ. Passed twice, a transfer "from A to B" becomes a self-transfer, and any accounting based on both balances counts the same funds twice.`,
          fix: `Add \`constraint = ${a.name}.key() != ${b.name}.key()\` to the struct, which covers every handler${guardedBy.length ? ` (today only ${guardedBy.join(", ")} check${guardedBy.length > 1 ? "" : "s"} it)` : ""}, or \`require_keys_neq!\` at the top of ${where.length ? where.join(", ") : "the handler"}.`,
          handlers: where.map((w) => w.replace(/`/g, "")),
          snippet: snippetOf(s.raw, b.line) });
      }
    }

    // init_if_needed on a program-owned state account: a second call must not reset it.
    for (const f of s.fields.filter((f) => f.c.initIfNeeded && !f.c.tokenish && localTypes.has(f.inner))) {
      // The takeover shape: the handler writes an authority into it, the seeds do not bind it
      // to that signer, and nothing checks the account was blank. Anyone calling second wins.
      const takeovers = [];
      for (const { h, text } of perHandler) {
        if (!h) continue;
        for (const m of text.matchAll(new RegExp(`\\b${f.name}\\s*\\.\\s*(\\w*(?:authority|owner|admin|manager|operator|governor)\\w*)\\s*=(?!=)\\s*([^;]+);`, "g"))) {
          const who = /(\w+)\s*\.\s*key\(\)/.exec(m[2])?.[1];
          const bound = who && f.c.seeds && mentions(f.c.seeds, who);
          const guarded = new RegExp(`${f.name}\\s*\\.\\s*${m[1]}\\s*(==|!=)|${f.name}\\s*\\.\\s*\\w*initiali[sz]ed|Pubkey::default\\(\\)`).test(text);
          if (!bound && !guarded) takeovers.push({ h, field: m[1] });
        }
      }
      if (takeovers.length) {
        const t = takeovers[0];
        add({ rule: "reinit-takeover", severity: "critical", confidence: "medium", struct: s.name, field: f.name, file: s.file, line: f.line,
          handlers: [...new Set(takeovers.map((x) => x.h.fn))],
          title: `Anyone can re-run \`${t.h.fn}\` and become \`${f.name}.${t.field}\``,
          why: `\`${f.name}\` is \`init_if_needed\`, so a second call reuses the existing \`${f.inner}\` instead of failing. \`${t.h.fn}\` then writes \`${f.name}.${t.field}\` unconditionally, and the seeds do not tie the account to that signer: whoever calls after the legitimate owner takes over the account.`,
          fix: `Use \`init\` (fails if the account exists), or refuse when \`${f.name}.${t.field} != Pubkey::default()\`.`,
          snippet: snippetOf(s.raw, f.line) });
      } else initIfNeeded++;
    }

    // remaining_accounts used without owner or key checks.
    for (const h of hs) {
      if (!/remaining_accounts/.test(h.body)) continue;
      // Reported only when the handler itself reads their bytes or moves their lamports.
      // Handed to a helper (load_maps(remaining_accounts), a parser) or to a CPI, they are
      // checked there: production programs validate them in shared loaders.
      const readsThem = /remaining_accounts[^;]*?(try_borrow_data|data\s*\.\s*borrow|try_from_slice|try_deserialize|from_le_bytes|lamports\s*\(\s*\)\s*\.\s*borrow_mut|try_borrow_mut_lamports)/.test(h.body)
        || /for\s+(\w+)\s+in\s+[^{]*remaining_accounts[\s\S]*?\{[\s\S]*?\b\1\s*\.\s*(try_borrow_data|data\s*\.\s*borrow|try_borrow_mut_lamports)/.test(h.body);
      if (!readsThem) continue;
      if (/\.owner\b|(Account|AccountLoader|InterfaceAccount)(::<[^>]*>)?::try_from|\.key\(\)\s*(==|!=)|key\s*==|find_program_address|create_program_address/.test(reachableText([h.body]))) continue;
      const line = h.line + h.body.slice(0, h.body.indexOf("remaining_accounts")).split("\n").length - 1;
      const f = files.find((x) => x.rel === h.file);
      add({ rule: "unchecked-remaining-accounts", severity: "high", confidence: "medium", struct: s.name, field: "remaining_accounts", file: h.file, line,
        title: `\`${h.fn}\` uses remaining_accounts without checking them`,
        why: `Accounts in \`ctx.remaining_accounts\` get no Anchor validation at all. The handler checks neither their owner nor their key, so a caller can pass any account in those positions.`,
        fix: `Deserialize them with \`Account::<T>::try_from\` (checks owner and discriminator) and compare keys against expected PDAs.`,
        snippet: snippetOf(f.raw, line) });
    }
  }

  const hasDefund = fnSigs.some((x) => /(==|!=)\s*[\w:]*CLOSED_ACCOUNT_DISCRIMINATOR|CLOSED_ACCOUNT_DISCRIMINATOR\s*(==|!=)/.test(x.body));
  // Code-level rules over every program file.
  for (const f of files) {
    const lines = f.masked.split("\n");
    // u128 locals in this file: `let x: u128 = ..` or `let x = .. as u128 ..`.
    const wide = new Set([...f.masked.matchAll(/let\s+(?:mut\s+)?(\w+)\s*(?::\s*u128\b[^=]*=|=[^;]*\bas\s+u128\b)/g)].map((m) => m[1]));
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      // A bound checked on the truncated value: the check passes, the full value is used.
      const guard = /(require!|require_gte!|require_gt!|assert!|\bif\b)[^;{]*?\b(\w+)\s+as\s+u(64|32|16|8)\b\s*(<=|<|>=|>|==|,)/.exec(l);
      if (guard && wide.has(guard[2])) {
        add({ rule: "truncated-bound-check", severity: "high", confidence: "medium", struct: null, field: guard[2], file: f.rel, line: i + 1,
          title: `A cap is checked on \`${guard[2]} as u${guard[3]}\`, not on \`${guard[2]}\``,
          why: `\`${guard[2]}\` is a u128 and \`as u${guard[3]}\` keeps only its low bits, so a value of 2^${guard[3]} + 1 passes this check as 1 while the full value is used afterwards. This is the shape of the Cetus overflow (May 2025, $223M).`,
          fix: `Compare in the wide type (\`${guard[2]} <= CAP as u128\`), or convert with \`u${guard[3]}::try_from(${guard[2]})?\` first and use only the converted value.`,
          snippet: snippetOf(f.raw, i + 1) });
        continue;
      }
      // u128 math cast down without a bound: the Cetus class, silently truncating.
      if (/\bas u(64|32|16|8)\b/.test(l)) {
        const stmt = lines.slice(Math.max(0, i - 4), i + 1).join(" ");
        if (/u128/.test(stmt) && !/\.min\(|try_from|try_into|checked_|saturating_|MAX\s+as\s+u128|<=\s*u(64|32)::MAX/.test(stmt)) {
          add({ rule: "truncating-cast", severity: "low", confidence: "low", struct: null, field: null, file: f.rel, line: i + 1,
            title: "A u128 result is cast down with `as` and no bound",
            why: "`as` silently drops the high bits when the value does not fit, even with overflow-checks on. In AMM and reward math this turns an overflow into a tiny wrong number instead of an error (Cetus, May 2025: $223M).",
            fix: "Use `u64::try_from(x).map_err(...)?`, or bound the value explicitly before casting.",
            snippet: snippetOf(f.raw, i + 1) });
        }
      }
      // Token-2022: plain `transfer` ignores decimals and fails or misbehaves on mints with hooks or fees.
      // A function that also calls transfer_checked branches on the token program (plain
      // transfer kept for classic SPL Token): deliberate, not a finding.
      const inFn = fnSigs.find((x) => x.file === f.rel && x.from <= i + 1 && i + 1 <= x.to);
      if (/token_interface::transfer\s*\(|token_2022::transfer\s*\(|spl_token_2022::instruction::transfer\s*\(/.test(l) && !(inFn && /transfer_checked/.test(inFn.body))) {
        add({ rule: "token2022-unchecked-transfer", severity: "medium", confidence: "high", struct: null, field: null, file: f.rel, line: i + 1,
          title: "Token-2022 transfer without `_checked`",
          why: "`transfer` is deprecated for Token-2022: it skips the mint and decimals check, and does not run transfer hooks. With a mint that has a transfer fee, the amount received differs from the amount sent and your accounting drifts.",
          fix: "Use `transfer_checked` with the mint account and its decimals; account for transfer fees if the mint can have them.",
          snippet: snippetOf(f.raw, i + 1) });
      }
      // Manual close: lamports drained but the account left behind can be revived. Judged on
      // the whole function: safe only when the data is marked closed AND the program can
      // defund a closed account someone refunded (Anchor's own scheme), or when the account
      // is reassigned to the system program.
      if (/lamports\s*\(\s*\)\s*\.borrow_mut\(\)\s*=\s*0|\*\*[^=]*lamports[^=]*=\s*0\s*;/.test(l)) {
        const fn = fnSigs.find((x) => x.file === f.rel && x.from <= i + 1 && i + 1 <= x.to);
        const body = fn ? fn.body : lines.slice(i, i + 8).join(" ");
        const isDefund = /(==|!=)\s*[\w:]*CLOSED_ACCOUNT_DISCRIMINATOR|CLOSED_ACCOUNT_DISCRIMINATOR\s*(==|!=)/.test(body);
        const marked = /CLOSED_ACCOUNT_DISCRIMINATOR/.test(body);
        const reassigned = /\bassign\s*\(|realloc\s*\(\s*0|\.close\s*\(/.test(body);
        if (!isDefund && !reassigned && !(marked && hasDefund)) {
          add({ rule: "manual-close-revival", severity: "medium", confidence: "medium", struct: null, field: null, file: f.rel, line: i + 1,
            title: marked ? "Closed account can be revived: no instruction defunds it" : "Account closed by draining lamports, not marked closed",
            why: marked
              ? "The data is marked closed, but the lamports are only zeroed for this transaction: another instruction in it can refund the account, and nothing in the program lets anyone drain a closed account afterwards, so it survives as a closed zombie that can be reused."
              : "Zeroing the lamports does not delete the account before the transaction ends: another instruction in the same transaction can refund it, and its data (zeroed or not) is still there to be read, or re-initialized by a `zero` / init-style instruction.",
            fix: "Use Anchor's `close = recipient` constraint, or zero the data and assign the account to the system program after moving the lamports.",
            snippet: snippetOf(f.raw, i + 1) });
        }
      }
    }
  }

  mathRules(fnSigs, files, add, snippetOf);

  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return {
    findings,
    stats: { initIfNeeded, skippedTestPrograms: skipped.map((d) => relative(repoDir, d)), files: files.length, structs: structs.length, fields: structs.reduce((n, s) => n + s.fields.length, 0), handlers: [...handlers.values()].reduce((n, h) => n + h.length, 0) },
    declaredIds: [...new Set(files.flatMap((f) => [...f.raw.matchAll(/declare_id!\s*\(\s*"([1-9A-HJ-NP-Za-km-z]{32,44})"\s*\)/g)].map((m) => m[1])))],
  };
}

// What the analysis checks, for the report's coverage table: a clean result reads as
// "checked and found nothing", never as "did not look".
export const RULES = [
  { id: "missing-signer", name: "Authority that never has to sign", scope: "every authority-like account" },
  { id: "unmatched-account-data", name: "Account data not matched to the expected accounts", scope: "every account decoded by hand" },
  { id: "type-cosplay", name: "Type cosplay (no discriminator)", scope: "every Borsh type decoded from raw bytes" },
  { id: "bump-canonicalization", name: "Non-canonical PDA bump", scope: "every create_program_address" },
  { id: "pda-sharing", name: "PDA signer shared across accounts", scope: "every PDA signature" },
  { id: "reinit-takeover", name: "Re-initialization takeover (init_if_needed)", scope: "every init_if_needed state account" },
  { id: "duplicate-mutable-accounts", name: "Same account passed twice (write-back)", scope: "every pair of mutable program-owned accounts" },
  { id: "arbitrary-cpi", name: "Unchecked CPI target", scope: "every program account taken raw" },
  { id: "unverified-account-data", name: "Data read from an account of unknown owner", scope: "every UncheckedAccount / AccountInfo" },
  { id: "unchecked-sysvar", name: "Forged sysvar", scope: "every sysvar taken raw" },
  { id: "unchecked-remaining-accounts", name: "remaining_accounts used without checks", scope: "every handler" },
  { id: "unchecked-mut-account", name: "Writable account with no constraint and no CHECK note", scope: "every UncheckedAccount / AccountInfo" },
  { id: "token2022-unchecked-transfer", name: "Token-2022 transfer without _checked", scope: "every token CPI" },
  { id: "manual-close-revival", name: "Account closed by draining lamports only", scope: "every manual close" },
  { id: "truncated-bound-check", name: "Bound checked on a truncated value", scope: "every check on a narrowing cast" },
  { id: "truncating-cast", name: "u128 result cast down with `as`", scope: "every narrowing cast" },
  { id: "rounding-up-payout", name: "Payout or minted shares rounded up", scope: "every ceiling division" },
  { id: "reward-accumulator-precision", name: "Reward per share computed without a precision factor", scope: "every reward accumulator" },
  { id: "divide-before-multiply", name: "Division before multiplication", scope: "every arithmetic expression" },
];

// --- arithmetic: rounding direction and precision ------------------------------------
// Where economic bugs show up in the code itself, without knowing what the numbers mean:
// which way a division rounds when value leaves the program, and where precision is lost
// before it is used. Rounding must favour the protocol: down on what it pays or mints,
// never to zero on what it charges.

const CEIL = /\.\w*div_ceil\s*\(|\bceil_div\w*\s*\(|\bceil_division\w*\s*\(|\.checked_ceil_div\s*\(|\b\w*_round_up\b(?!_if)\w*\s*\(|\bdiv_up\s*\(|\bmul_div_ceil\s*\(|\.ceil\s*\(|\+\s*\(?\s*(\w+)\s*-\s*1\s*\)?\s*\)\s*\/\s*\(?\s*\1\b|\.\w*_add\s*\(\s*(\w+)\s*-\s*1\s*\)[^;]*?\.\w*_div\s*\(\s*\2\s*\)/;
const PAID_OUT = /(get_amount_out|calc\w*_out|compute\w*_out|amount_out|out_amount|payout|pay_out|withdraw|redeem|claim|reward|owed|refund|proceeds|to_user|user_amount|assets_out|tokens_out|_out$|^out$|(?:shares|lp)(?:_to)?_mint|minted|mint_amount|lp_out|shares_out)/i;
const STRONG_OUT = /payout|pay_out|redeem|withdraw|claim|refund|owed|proceeds/i;
const FUNDING = /init|^set_|fund|deposit|^add_|create|top_?up|bribe|notify|seed/i;
const CHARGED = /fee|cost|required|need|debt|repay|premium|price|strike|amount_in|in_amount|deposit_needed|_in$|min_|max_/i;
const PRECISION = /PRECISION|SCALE|MULTIPLIER|DECIMALS|\bONE\b|\bWAD\b|\bRAY\b|\bE\d+\b|1_?000_?000_?000|10u128\.pow|10_u128\.pow|\.pow\s*\(|1e\d+|<<\s*\d{2}/;
const ACCUMULATOR = /\b(\w*(?:per_share|per_lp|per_token|per_unit|per_stake|per_vote|per_weight|reward_index|reward_rate_stored|acc_\w+)\w*)\s*(?:\+=|=\s*[\w.]*\b\1\s*\.\s*(?:checked|saturating|wrapping)_add)/;
const DENOM_WORD = /(total|supply|staked|weight|lp\b|_lp|shares|votes|liquidity)/i;

function statementsOf(body) {
  // `let x = ..;`, `x = ..;`, `x += ..;` at any depth, with their offset in the body.
  const out = [];
  for (const m of body.matchAll(/(?:let\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=|([\w.]+)\s*(\+=|-=|=)(?!=))([^;]*);/g)) {
    out.push({ name: m[1] || m[2], op: m[3] || "let", expr: m[4], text: m[0], index: m.index });
  }
  return out;
}

function mathRules(fnSigs, files, add, snippetOf) {
  for (const fn of fnSigs) {
    if (/^fn\s+test_|#\[test\]/.test(fn.sig)) continue;
    const file = files.find((x) => x.rel === fn.file);
    const at = (idx) => fn.from + fn.body.slice(0, idx).split("\n").length - 1;
    const stmts = statementsOf(fn.body);
    // A function named for what it pays out returns it: its tail expression counts too.
    const fnName = (/fn\s+(\w+)/.exec(fn.sig) || [])[1] || "";
    const tail = fn.body.replace(/\s*\}\s*$/, "").split(/;/).pop();
    if (fnName && /->/.test(fn.sig) && !/=/.test(tail.replace(/[=!<>]=|=>/g, ""))) stmts.push({ name: fnName, op: "let", expr: tail, text: tail, index: fn.body.lastIndexOf(tail) });
    for (const st of stmts) {
      const leaf = String(st.name).split(".").pop();
      // 1. Ceiling on what leaves the program.
      // Confident only when the value and the function both say "paid out"; never on the
      // funding side (initializing or topping up rewards rounds up what the funder pays).
      if (CEIL.test(st.expr) && PAID_OUT.test(leaf) && !CHARGED.test(leaf) && !FUNDING.test(fnName) && !FUNDING.test(fn.file.split("/").pop()) && !/fee/i.test(st.expr)) {
        const line = at(st.index);
        const sure = STRONG_OUT.test(leaf) && STRONG_OUT.test(fnName);
        add({ rule: "rounding-up-payout", severity: "high", confidence: sure ? "medium" : "low", struct: null, field: leaf, file: fn.file, line,
          title: `\`${leaf}\` is rounded up`,
          why: `\`${leaf}\` is what the program pays out or mints, and it is computed with a ceiling division. Every inexact division hands the caller one base unit more than the pool owes; repeated with small amounts, that drains the reserve (the Balancer V2 rounding class).`,
          fix: "Round down what the program pays or mints (plain integer division), and round up only what it charges.",
          snippet: snippetOf(file.raw, line) });
      }
      // 2. Division, then multiplication: the remainder is lost before it is scaled up.
      const dm = /(\b[\w.]+(?:\([^()]*\))?)\s*\/\s*(\(?[\w.]+(?:\([^()]*\))?\)?)\s*\*\s*(\(?[\w.]+)/.exec(st.expr)
        || /\.(?:checked|saturating|safe|try)_div\s*\(\s*([^()]*(?:\([^()]*\))?[^()]*)\)\s*(?:\?|\.unwrap\(\)|\.ok_or[^.]*?\)\??|\.expect\([^()]*\))?\s*\.(?:checked|saturating|safe|try)_mul\s*\(\s*([^()]*(?:\([^()]*\))?[^()]*)\)/.exec(st.expr);
      if (dm) {
        const [divisor, mult] = dm.length === 4 ? [dm[2], dm[3]] : [dm[1], dm[2]];
        const clean = (x) => String(x).replace(/[()\s]/g, "");
        const constOnly = (x) => /^[A-Z0-9_]+$|^\d[\d_]*(?:u\d+)?$/.test(clean(x));
        // `t / WEEK * WEEK` floors on purpose (lock periods, ticks); constants fold at compile time.
        // Decimal or precision rescaling (`/ 10^a * 10^b`, `/ PRECISION * x`) is deliberate.
        const scale = (x) => PRECISION.test(x) || /^\d/.test(clean(x)) || /pow|BUFFER|DECIMAL/i.test(x);
        if (clean(divisor) !== clean(mult) && !scale(divisor) && !scale(mult) && !(constOnly(divisor) && constOnly(mult)) && !(dm.length === 4 && constOnly(dm[1]) && constOnly(divisor))) {
          const line = at(st.index);
          add({ rule: "divide-before-multiply", severity: "medium", confidence: "low", struct: null, field: leaf, file: fn.file, line,
            title: `\`${leaf}\` divides before it multiplies`,
            why: `The expression divides by \`${clean(divisor)}\` and then multiplies by \`${clean(mult)}\`: the remainder of the division is dropped and the error is scaled up. In reward, lock-weight and price math this pays some users less, or rounds a small position to nothing.`,
            fix: "Multiply first, then divide (in u128 if needed), unless the truncation is intended.",
            snippet: snippetOf(file.raw, line) });
        }
      }
    }
    // 3. A reward-per-share accumulator updated from a division by the total, with no scale.
    const acc = ACCUMULATOR.exec(fn.body);
    if (acc) {
      const divides = stmts.filter((st) => (/\/|_div\b|_div\s*\(/.test(st.expr)) && DENOM_WORD.test(st.expr.split(/\/|_div/).slice(1).join(" ")));
      if (divides.length && !divides.some((st) => PRECISION.test(st.expr)) && !PRECISION.test(acc[0])) {
        const line = at(acc.index);
        add({ rule: "reward-accumulator-precision", severity: "medium", confidence: "medium", struct: null, field: acc[1], file: fn.file, line,
          title: `\`${acc[1]}\` accumulates rewards without a precision factor`,
          why: `The reward per share is the new rewards divided by the total, in integers, with no scaling constant. When emissions per update are smaller than the total staked, each update adds zero, and the time window is consumed anyway: those rewards are lost for every staker. Updating often makes it worse.`,
          fix: "Multiply the rewards by a large constant before dividing (for example 1e12, in u128), and divide by the same constant when paying out.",
          snippet: snippetOf(file.raw, line) });
      }
    }
  }
}
