// The free tier: what a person can try before paying anything.
//
// A program check is given whole: it is the question a phone user actually has
// ("who can change this program tomorrow?") and costs a few RPC calls.
// A repo scan runs for real, but only a preview leaves the server: the risk rating
// and its summary, every count, the coverage table, the deployed program, and the
// FIRST issue in full. The other issues travel as their severity alone, so the blur
// in the page hides nothing a curious visitor could read from the network tab.

// Bumped whenever the preview's shape OR the engine's findings change: an older cached
// preview is rescanned rather than served, so a fixed false positive never comes back
// from the cache. 3: engine precision pass (arbitrary-cpi, remaining_accounts, signer).
// 4: sealevel-attacks classes and the production-protocol precision pass.
export const PREVIEW_VERSION = 4;

// `summary` is the object summarize() builds from a scan result.
export function previewOf(summary) {
  const [first, ...rest] = summary.findings;
  const attention = summary.dependencies.onchain.filter((a) => a.verdict !== "not-exploitable");
  const shownAdvisory = attention[0] || summary.dependencies.onchain[0] || null;
  const totalAdvisories = summary.dependencies.onchain.length + summary.dependencies.offchain.length + summary.dependencies.unmaintained.length;
  return {
    v: PREVIEW_VERSION,
    repo: summary.repo,
    date: summary.date,
    commit: summary.commit,
    risk: summary.risk,
    summary: summary.summary,
    programs: summary.programs,
    counts: summary.counts,
    coverage: summary.coverage,
    deployed: summary.deployed,
    hygiene: summary.hygiene,
    shown: {
      finding: first || null,
      // With nothing to fix, the first note to verify is what proves the reading is real.
      review: first ? null : summary.review[0] || null,
      advisory: shownAdvisory,
    },
    hidden: {
      findings: rest.map((f) => ({ severity: f.severity })),
      review: Math.max(0, summary.review.length - (first ? 0 : summary.review.length ? 1 : 0)),
      advisories: Math.max(0, totalAdvisories - (shownAdvisory ? 1 : 0)),
    },
    disclaimer: summary.disclaimer,
  };
}

// A public repo scanned for free in the last hours is served from that run:
// the same visitor (or a reviewer) retrying costs nothing, and nothing changed.
export const FREE_SCAN_REUSE_MS = 6 * 60 * 60 * 1000;
export function reusableFreeJob(jobs, repo, now = Date.now()) {
  return jobs.find((j) => j.free && j.repo === repo && j.status === "done" && j.preview && j.preview.v === PREVIEW_VERSION && now - Date.parse(j.updatedAt) < FREE_SCAN_REUSE_MS) || null;
}
