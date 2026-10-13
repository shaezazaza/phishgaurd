/* Shared result card (used by the Gmail banner and the popup). Everything from the email is escaped. */
(function (root) {
  "use strict";
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const LABEL = { HIGH: "High risk", MEDIUM: "Be careful", LOW: "Looks safe" };

  const CSS = `
  .pg { --hi:#b3261e; --hi-bg:#fdecea; --md:#8a5300; --md-bg:#fff4e0; --lo:#1e6b34; --lo-bg:#e9f5ec;
        --ink:#1f1f1f; --muted:#5f6368; --line:#e3e3e3; --card:#ffffff;
        font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--ink);
        background: var(--card); border: 1px solid var(--line); border-left: 5px solid var(--accent);
        border-radius: 10px; padding: 12px 14px; margin: 0 0 12px; max-width: 760px; box-sizing: border-box; }
  @media (prefers-color-scheme: dark) {
    .pg.auto { --hi:#f2b8b5; --hi-bg:#3a1d1b; --md:#f5c26b; --md-bg:#3a2c12; --lo:#8fd19e; --lo-bg:#16301d;
               --ink:#e8eaed; --muted:#a8acb1; --line:#3c4043; --card:#202124; }
  }
  .pg.HIGH { --accent: var(--hi); --tint: var(--hi-bg); } .pg.MEDIUM { --accent: var(--md); --tint: var(--md-bg); }
  .pg.LOW { --accent: var(--lo); --tint: var(--lo-bg); }
  .pg .top { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .pg .score { background: var(--tint); color: var(--accent); font-weight:700; border-radius:999px; padding:2px 10px;
               font-variant-numeric: tabular-nums; }
  .pg .title { font-weight:650; color: var(--accent); }
  .pg .brand { margin-left:auto; color: var(--muted); font-size:11px; letter-spacing:.02em; }
  .pg .action { margin:6px 0 0; }
  .pg .chips { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }
  .pg .chip { border:1px solid var(--line); border-radius:999px; padding:1px 8px; font-size:12px; color: var(--muted); }
  .pg details { margin-top:8px; }
  .pg summary { cursor:pointer; color: var(--muted); font-size:12px; user-select:none; }
  .pg ul { list-style:none; margin:6px 0 0; padding:0; }
  .pg li { display:grid; grid-template-columns: 52px 1fr; gap:8px; padding:3px 0; border-top:1px solid var(--line); }
  .pg li:first-child { border-top:0; }
  .pg .pts { text-align:right; font-variant-numeric: tabular-nums; color: var(--muted); }
  .pg .pts.plus { color: var(--accent); font-weight:600; }
  .pg .why { overflow-wrap:anywhere; }
  .pg .note { color: var(--muted); font-size:11.5px; margin-top:6px; }
  .pg .x { background:none; border:0; color: var(--muted); cursor:pointer; font-size:16px; line-height:1; padding:0 2px; }
  `;

  function resultHTML(r, opts) {
    opts = opts || {};
    const reasons = r.reasons.map(x => {
      const p = x.points;
      const cls = p > 0 ? "pts plus" : "pts";
      const sign = p > 0 ? "+" : "";
      return `<li><span class="${cls}">${sign}${esc(Math.round(p * 10) / 10)}</span><span class="why">${esc(x.reason)}</span></li>`;
    }).join("");
    const chips = (r.tactics || []).map(t => `<span class="chip">${esc(t)}</span>`).join("");
    const authKnown = r.auth && (r.auth.spf !== "none" || r.auth.dkim !== "none" || r.auth.dmarc !== "none");
    const auth = authKnown ? `<div class="note">Sender checks: SPF ${esc(r.auth.spf)} · DKIM ${esc(r.auth.dkim)} · DMARC ${esc(r.auth.dmarc)}</div>`
      : (opts.headerNote ? `<div class="note">${esc(opts.headerNote)}</div>` : "");
    return `<div class="pg auto ${esc(r.level)}" role="status">
      <div class="top">
        <span class="score">${esc(r.risk)}/100</span>
        <span class="title">${LABEL[r.level] || esc(r.level)}</span>
        <span class="brand">PhishGuard</span>
        ${opts.closable ? '<button class="x" title="Hide" aria-label="Hide">×</button>' : ""}
      </div>
      <div class="action">${esc(r.action)}</div>
      ${chips ? `<div class="chips">${chips}</div>` : ""}
      <details ${opts.open ? "open" : ""}><summary>Why this score</summary><ul>${reasons}</ul></details>
      ${auth}
    </div>`;
  }

  root.PhishGuardUI = { CSS, resultHTML, esc };
})(typeof self !== "undefined" ? self : this);
