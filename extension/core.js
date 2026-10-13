/* PhishGuard core: JavaScript port of the Python scorer (text model + rules + blocklist).
 * No DOM needed, so the same file runs in the extension and in Node (for tests).
 *
 * email object fields (same as the Python parser):
 *   from, reply_to, return_path, subject, body, urls[], html_links[[href, text]], attachments[], auth_results
 */
(function (root) {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const W = "[\\p{L}\\p{N}_]"; // python \w (unicode)
  const RE_URL = /(https?:\/\/|www\.)\S+/giu;
  const RE_EMAIL = new RegExp(`[\\p{L}\\p{N}_.+-]+@[\\p{L}\\p{N}_-]+(\\.[\\p{L}\\p{N}_-]+)*`, "giu");
  const RE_DATASET = new RegExp(`(?<!${W})(enron|ect|hou|phishing[\\s_@]*pot|example\\.com)(?!${W})`, "giu");
  const RE_JUNK = new RegExp(`(?<!${W})${W}{25,}(?!${W})`, "gu");
  const RE_TOKEN = new RegExp(`(?<!${W})[a-z][a-z']+(?!${W})`, "gu");

  const TWO_PART = new Set(["co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "nic.in", "firm.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "net.br", "org.br", "gov.br", "com.au", "net.au", "org.au",
    "co.jp", "co.za", "com.mx", "com.cn", "com.sg", "com.tr", "co.kr", "com.ar", "com.pk", "com.ng", "co.id", "com.my"]);

  const SHARED_SUFFIXES = ["sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "sharepoint.com",
    "onedrive.live.com", "1drv.ms", "dropbox.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "web.app",
    "firebaseapp.com", "blogspot.com", "wixsite.com", "weebly.com", "000webhostapp.com", "glitch.me", "notion.site",
    "canva.site", "ipfs.io", "workers.dev", "bit.ly", "t.co", "tinyurl.com"];

  function cut(s, n) { // slice by code points like Python
    s = s || "";
    if (s.length <= n) return s;
    return Array.from(s).slice(0, n).join("");
  }

  function baseDomain(host) {
    host = (host || "").toLowerCase().replace(/^[. ]+|[. ]+$/g, "").split(":")[0];
    if (!host || /^[\d.]+$/.test(host)) return host;
    const p = host.split(".");
    if (p.length >= 3 && TWO_PART.has(p.slice(-2).join("."))) return p.slice(-3).join(".");
    return p.slice(-2).join(".");
  }

  function addrOf(s) { // "Name <a@b.com>" -> a@b.com
    s = s || "";
    const m = s.match(/<([^<>\s]+@[^<>\s]+)>/) || s.match(/[^\s<>"',;:]+@[^\s<>"',;:]+/);
    return m ? (m[1] || m[0]).trim() : "";
  }
  function domainOf(s) { const a = addrOf(s); return a ? a.split("@").pop().toLowerCase() : ""; }

  function hostOf(u) {
    try { return (new URL(u.includes("://") ? u : "http://" + u).hostname || "").toLowerCase().replace(/^\[|\]$/g, ""); }
    catch (e) { return ""; }
  }
  function isShared(h) { return SHARED_SUFFIXES.some(s => h === s || h.endsWith("." + s)); }
  function countSub(hay, needle) { return needle ? hay.split(needle).length - 1 : 0; }

  // ------------------------------------------------------------------ text model
  function cleanText(subject, body, maxChars) {
    let t = `${subject || ""} \n ${cut(body || "", maxChars || 6000)}`;
    t = t.replace(RE_URL, " ").replace(RE_EMAIL, " ").replace(RE_DATASET, " ").replace(RE_JUNK, " ");
    t = t.toLowerCase();
    return t.replace(/\s+/gu, " ").trim();
  }

  function textCues(M, clean) {
    const out = {};
    for (const [k, words] of Object.entries(M.cues)) out["cue_" + k] = words.reduce((a, w) => a + countSub(clean, w), 0);
    return out;
  }

  class TextModel {
    constructor(M) {
      this.M = M;
      this.index = new Map(M.terms.map((t, i) => [t, i]));
      this.stop = new Set(M.stop_words);
    }
    vector(clean) {
      const toks = (clean.match(RE_TOKEN) || []).filter(t => !this.stop.has(t));
      const tf = new Map();
      const add = g => { const i = this.index.get(g); if (i !== undefined) tf.set(i, (tf.get(i) || 0) + 1); };
      for (let n = 1; n <= this.M.ngram_max; n++)
        for (let i = 0; i + n <= toks.length; i++) add(n === 1 ? toks[i] : toks.slice(i, i + n).join(" "));
      let norm = 0;
      const vec = new Map();
      for (const [i, c] of tf) { const v = (1 + Math.log(c)) * this.M.idf[i]; vec.set(i, v); norm += v * v; }
      norm = Math.sqrt(norm) || 1;
      for (const [i, v] of vec) vec.set(i, v / norm);
      const cues = textCues(this.M, clean);
      const cueVals = this.M.cue_names.map(k => Math.log1p(cues[k]) * this.M.cue_weight);
      return { vec, cueVals, cues };
    }
    score(subject, body) {
      const clean = cleanText(subject, body);
      const { vec, cueVals, cues } = this.vector(clean);
      let z = this.M.intercept;
      const contrib = [];
      for (const [i, v] of vec) { const c = v * this.M.coef[i]; z += c; contrib.push([this.M.terms[i], c]); }
      cueVals.forEach((v, j) => { const c = v * this.M.cue_coef[j]; z += c; contrib.push([this.M.cue_names[j], c]); });
      const p = 1 / (1 + Math.exp(-z));
      contrib.sort((a, b) => b[1] - a[1]);
      return { p, cues, words: contrib.filter(([n, c]) => c > 0 && !n.startsWith("cue_")).slice(0, 8).map(x => x[0]) };
    }
  }

  // ------------------------------------------------------------------ rule signs
  const LOOKALIKE = /(\d(?=[a-z])|(?<=[a-z])\d|rn|vv|-secure|-security|-verify|-login|-update|-support|-account)/;

  function linkSigns(M, e) {
    const urls = e.urls || [];
    const hosts = urls.map(hostOf).filter(Boolean);
    const senderBase = baseDomain(domainOf(e.from));
    const linkBases = new Set(hosts.map(baseDomain));
    let textMismatch = 0;
    for (const [href, txt] of (e.html_links || [])) {
      const shown = (txt || "").toLowerCase().match(/([a-z0-9-]+\.)+[a-z]{2,}/);
      if (shown && (href || "").toLowerCase().startsWith("http") && baseDomain(shown[0]) !== baseDomain(hostOf(href)))
        textMismatch++;
    }
    const netloc = u => { const m = u.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i); return m ? m[1] : ""; };
    return {
      num_links: urls.length,
      link_ip_address: +hosts.some(h => /^[\d.]+$/.test(h)),
      link_shortener: +hosts.some(h => M.shorteners.includes(baseDomain(h)) || M.shorteners.includes(h)),
      link_risky_tld: +hosts.some(h => M.risky_tlds.includes(h.split(".").pop())),
      link_punycode: +hosts.some(h => h.includes("xn--")),
      link_has_at: +urls.some(u => netloc(u).includes("@")),
      link_many_subdomains: +hosts.some(h => (h.match(/\./g) || []).length >= 4),
      link_text_mismatch: textMismatch,
      link_not_sender_domain: +(!!senderBase && linkBases.size > 0 && !linkBases.has(senderBase)),
      link_http_only: +urls.some(u => u.toLowerCase().startsWith("http://")),
    };
  }

  function displayName(from) {
    const m = (from || "").match(/^\s*"?([^"<]*)"?\s*</);
    return (m ? m[1] : "").trim().toLowerCase();
  }
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function senderSigns(M, e) {
    const sbase = baseDomain(domainOf(e.from));
    const reply = domainOf(e.reply_to), rpath = domainOf(e.return_path);
    const name = displayName(e.from);
    let impersonated = "";
    const hay = name + " " + (e.subject || "").toLowerCase();
    for (const [brand, real] of Object.entries(M.brands)) {
      if (new RegExp(`(?<!${W})${esc(brand)}(?!${W})`, "u").test(hay) && sbase && sbase !== real && !sbase.endsWith("." + real)) {
        impersonated = brand; break;
      }
    }
    return {
      reply_to_mismatch: +(!!reply && baseDomain(reply) !== sbase),
      return_path_mismatch: +(!!rpath && !!sbase && baseDomain(rpath) !== sbase),
      free_mail_sender: +M.free_mail.includes(sbase),
      display_name_has_email: +name.includes("@"),
      brand_impersonation: impersonated,
      lookalike_sender: +(!!sbase && LOOKALIKE.test(sbase.split(".")[0])),
      sender_risky_tld: sbase ? +M.risky_tlds.includes(sbase.split(".").pop()) : 0,
    };
  }

  function attachmentSigns(M, e) {
    const n = (e.attachments || []).map(a => a.toLowerCase());
    return {
      num_attachments: n.length,
      risky_attachment: +n.some(x => M.risky_ext.some(ext => x.endsWith(ext))),
      archive_attachment: +n.some(x => M.archive_ext.some(ext => x.endsWith(ext))),
      double_extension: +n.some(x => /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.\w{2,4}$/.test(x)),
    };
  }

  function authSigns(e) {
    const a = (e.auth_results || "").toLowerCase();
    const res = k => { const m = a.match(new RegExp(`(?<!${W})${k}\\s*=\\s*(\\w+)`, "u")); return m ? m[1] : "none"; };
    let spf = res("spf"); const dkim = res("dkim"), dmarc = res("dmarc");
    if (spf === "none") {
      const m = a.match(/(?<![\w])(pass|fail|softfail|neutral|permerror|temperror)(?![\w])/);
      spf = m && a.includes("spf") ? m[1] : "none";
    }
    return { spf, dkim, dmarc, has_auth_results: +!!a };
  }

  function scoreRules(M, e) {
    const hits = [];
    const add = (k, v) => { const r = M.rules[k]; hits.push({ rule: k, points: r.points, reason: r.reason.replace("{v}", v || "") }); };
    const auth = authSigns(e), snd = senderSigns(M, e), lnk = linkSigns(M, e), att = attachmentSigns(M, e);
    if (auth.has_auth_results) {
      if (auth.spf === "fail") add("spf_fail"); else if (auth.spf === "softfail") add("spf_softfail");
      if (auth.dkim === "fail") add("dkim_fail");
      if (auth.dmarc === "fail") add("dmarc_fail");
      if (auth.spf === "pass" && auth.dkim === "pass" && auth.dmarc === "pass") add("auth_all_pass");
    }
    for (const k of ["reply_to_mismatch", "return_path_mismatch", "display_name_has_email", "lookalike_sender",
      "sender_risky_tld", "free_mail_sender"]) if (snd[k]) add(k);
    if (snd.brand_impersonation) add("brand_impersonation", snd.brand_impersonation);
    for (const k of ["link_ip_address", "link_shortener", "link_risky_tld", "link_punycode", "link_has_at",
      "link_many_subdomains", "link_text_mismatch", "link_http_only"]) if (lnk[k]) add(k);
    for (const k of ["risky_attachment", "archive_attachment", "double_extension"]) if (att[k]) add(k);
    return { points: hits.reduce((a, h) => a + h.points, 0), hits, signs: { ...auth, ...snd, ...lnk, ...att } };
  }

  function verifiedBrandSender(M, e, s) {
    const sbase = baseDomain(domainOf(e.from));
    const passed = s.dmarc === "pass" || (s.dkim === "pass" && s.spf === "pass");
    return passed && Object.values(M.brands).includes(sbase);
  }

  // ------------------------------------------------------------------ blocklist
  class Blocklist {
    constructor(text) {
      this.hosts = new Set();
      if (text) for (const line of text.split("\n")) { const l = line.trim().toLowerCase(); if (l && !l.startsWith("#") && !l.includes("/")) this.hosts.add(l); }
    }
    get size() { return this.hosts.size; }
    check(urls) {
      const hits = [];
      for (const u of urls || []) {
        const h = hostOf(u);
        if (h && !isShared(h) && (this.hosts.has(h) || (h.startsWith("www.") && this.hosts.has(h.slice(4)))))
          hits.push({ url: u, source: "offline blocklist", detail: `domain ${h} is on a phishing blocklist` });
      }
      return hits;
    }
  }

  // ------------------------------------------------------------------ main scorer
  class PhishGuard {
    constructor(model, blocklist) { this.M = model; this.text = new TextModel(model); this.blocklist = blocklist || null; }

    scan(e, extraIntelHits) {
      const M = this.M;
      const t = this.text.score(e.subject, e.body);
      const r = scoreRules(M, e);
      const intel = (this.blocklist ? this.blocklist.check(e.urls) : []).concat(extraIntelHits || []);
      let textPts = M.text_weight * t.p, calmed = false;
      if (verifiedBrandSender(M, e, r.signs) && !intel.length) { textPts *= 0.4; calmed = true; }
      let risk = textPts + r.points + (intel.length ? M.intel_points : 0);
      risk = Math.round(Math.max(0, Math.min(100, risk)));
      const level = risk >= M.high ? "HIGH" : risk >= M.medium ? "MEDIUM" : "LOW";
      const action = { HIGH: "Do not click anything. Report it as phishing.",
        MEDIUM: "Be careful. Check the sender before you click or reply.",
        LOW: "No strong warning signs." }[level];
      const tactics = Object.entries(t.cues).filter(([, v]) => v > 0).map(([k]) => M.tactic_names[k]);
      const reasons = intel.map((h, n) => ({ points: n === 0 ? M.intel_points : 0, reason: `Threat intel (${h.source}): ${h.detail}` }));
      reasons.push(...r.hits.map(h => ({ points: h.points, reason: h.reason })).sort((a, b) => b.points - a.points));
      reasons.push({ points: Math.round(textPts * 10) / 10,
        reason: `Text model says ${Math.round(t.p * 100)}% phishing-like` +
          (t.words.length && t.p >= 0.3 ? ` (key words: ${t.words.slice(0, 6).join(", ")})` : "") +
          (calmed ? " - lowered because sender is the verified real brand" : "") });
      return { risk, level, action, text_probability: t.p, tactics, reasons, intel_hits: intel,
        auth: { spf: r.signs.spf, dkim: r.signs.dkim, dmarc: r.signs.dmarc } };
    }
  }

  const api = { PhishGuard, TextModel, Blocklist, cleanText, baseDomain, hostOf, scoreRules };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PhishGuardCore = api;
})(typeof self !== "undefined" ? self : this);
