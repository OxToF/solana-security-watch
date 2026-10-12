// The free tier: what a person can try before paying anything.
//
// A program check is given whole: it is the question a phone user actually has
// ("who can change this program tomorrow?") and costs a few RPC calls.
// A repo scan runs for real, but only a preview leaves the server: every count,
// the build hygiene, the bug classes found, and ONE advisory and ONE code lead in
// full. The rest is never sent, so the blur in the page hides nothing a curious
// visitor could read from the network tab.

const SEV_RANK = { CRITICAL: 5, HIGH: 4, MODERATE: 3, MEDIUM: 3, LOW: 2 };
const sevRank = (s) => SEV_RANK[String(s || "").toUpperCase().split(" ")[0]] || 1;

const advisoryView = (a) => ({ id: a.id, url: a.url, severity: a.severity, summary: a.summary, crates: a.crates, onchain: !!a.onchain });

// `summary` is the object summarize() builds from a scan result.
export function previewOf(summary) {
  const on = [...summary.onchainAdvisories].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const off = [...summary.toolchainAdvisories, ...summary.unmaintainedCrates].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  // Show the advisory that matters most: the worst on the deployed surface, else the worst elsewhere.
  const shownAdvisory = on[0] || off[0] || null;
  const advisoriesTotal = on.length + off.length;

  const classes = [...summary.codeLeads].sort((a, b) => b.total - a.total);
  const top = classes.find((c) => c.hits.length);
  const shownLead = top ? { class: top.class, label: top.label, ...top.hits[0] } : null;
  const leadsTotal = classes.reduce((s, c) => s + c.total, 0);

  return {
    repo: summary.repo,
    date: summary.date,
    counts: summary.counts,
    hygiene: summary.hygiene,
    // Which classes were hit and how often, without where.
    classes: classes.map((c) => ({ class: c.class, label: c.label, total: c.total })),
    shown: { advisory: shownAdvisory && advisoryView(shownAdvisory), lead: shownLead },
    hidden: {
      advisories: Math.max(0, advisoriesTotal - (shownAdvisory ? 1 : 0)),
      leads: Math.max(0, leadsTotal - (shownLead ? 1 : 0)),
    },
    disclaimer: summary.disclaimer,
  };
}

// A public repo scanned for free in the last hours is served from that run:
// the same visitor (or a reviewer) retrying costs nothing, and nothing changed.
export const FREE_SCAN_REUSE_MS = 6 * 60 * 60 * 1000;
export function reusableFreeJob(jobs, repo, now = Date.now()) {
  return jobs.find((j) => j.free && j.repo === repo && j.status === "done" && j.preview && now - Date.parse(j.updatedAt) < FREE_SCAN_REUSE_MS) || null;
}
