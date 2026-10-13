/* Tiny e-mail source (.eml / Gmail "Show original") parser.
 * parseEmailSource(raw, htmlTools) -> same email object the scorer uses.
 * htmlTools = { toText(html), links(html) -> [[href, text]] } (DOM-based in the popup).
 */
(function (root) {
  "use strict";
  const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;

  function decodeBytes(bytes, charset) {
    try { return new TextDecoder((charset || "utf-8").toLowerCase().replace(/^"|"$/g, ""), { fatal: false }).decode(bytes); }
    catch (e) { return new TextDecoder("latin1").decode(bytes); }
  }
  function b64ToBytes(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, "");
    const bin = typeof atob === "function" ? atob(s) : Buffer.from(s, "base64").toString("binary");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function qpToBytes(s, header) {
    if (header) s = s.replace(/_/g, " ");
    s = s.replace(/=\r?\n/g, "");
    const out = [];
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
      else { const c = s.charCodeAt(i); out.push(c < 256 ? c : 63); }
    }
    return new Uint8Array(out);
  }
  function decodeWords(v) { // =?utf-8?B?...?=
    return (v || "").replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=(\s+(?==\?))?/g, (_, cs, enc, txt) =>
      decodeBytes(enc.toUpperCase() === "B" ? b64ToBytes(txt) : qpToBytes(txt, true), cs));
  }

  function splitHead(raw) {
    const m = raw.match(/\r?\n\r?\n/);
    const head = m ? raw.slice(0, m.index) : raw;
    const body = m ? raw.slice(m.index + m[0].length) : "";
    const headers = {};
    for (const line of head.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
      const i = line.indexOf(":");
      if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); (headers[k] = headers[k] || []).push(line.slice(i + 1).trim()); }
    }
    return { headers, body };
  }
  const h1 = (h, k) => (h[k] || [""])[0];
  function param(value, name) {
    // RFC 2231 form: filename*=utf-8''Spin%20Dragons  (also split as filename*0*=...)
    const ext = [...(value || "").matchAll(new RegExp(`${name}\\*(\\d+)?\\*=\\s*"?([^;"]*)"?`, "gi"))];
    if (ext.length) {
      let v = ext.map(m => m[2]).join("");
      const mm = v.match(/^([^']*)'[^']*'(.*)$/);
      if (mm) v = mm[2];
      try { return decodeURIComponent(v); } catch (e) { return v; }
    }
    const m = (value || "").match(new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|([^;\\s]*))`, "i"));
    return m ? decodeWords(m[1] !== undefined ? m[1] : m[2]) : "";
  }

  function walk(part, acc) {
    const ctype = h1(part.headers, "content-type") || "text/plain";
    const type = ctype.split(";")[0].trim().toLowerCase();
    if (type.startsWith("multipart/")) {
      const b = param(ctype, "boundary");
      if (!b) return;
      const pieces = part.body.split(new RegExp(`\\r?\\n?--${b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:--)?[ \\t]*\\r?\\n?`));
      for (const p of pieces.slice(1)) if (p.trim()) walk(splitHead(p), acc);
      return;
    }
    const disp = h1(part.headers, "content-disposition");
    const fname = param(disp, "filename") || param(ctype, "name");
    if (fname || /attachment/i.test(disp)) { acc.attachments.push(fname || "unnamed." + type.split("/").pop()); return; }
    const cte = h1(part.headers, "content-transfer-encoding").toLowerCase();
    const cs = param(ctype, "charset") || "utf-8";
    // pasted source is already text; only base64 / quoted-printable parts need decoding
    const text = cte === "base64" ? decodeBytes(b64ToBytes(part.body), cs)
      : cte === "quoted-printable" ? decodeBytes(qpToBytes(part.body), cs) : part.body;
    if (type === "text/plain") acc.plain.push(text);
    else if (type === "text/html") acc.html.push(text);
  }

  function parseEmailSource(raw, htmlTools) {
    const top = splitHead(raw);
    const acc = { plain: [], html: [], attachments: [] };
    walk(top, acc);
    const html = acc.html.join("\n");
    let body = acc.plain.join("\n").trim();
    if (!body && html) body = htmlTools.toText(html);
    const links = html ? htmlTools.links(html) : [];
    const urls = [...new Set(links.map(l => l[0]).filter(u => /^http/i.test(u)).concat(body.match(URL_RE) || []))];
    const h = top.headers;
    const auth = [].concat(h["authentication-results"] || [], h["arc-authentication-results"] || [], h["received-spf"] || []).join(" ");
    return {
      from: decodeWords(h1(h, "from")), reply_to: decodeWords(h1(h, "reply-to")), return_path: h1(h, "return-path"),
      subject: decodeWords(h1(h, "subject")), body, html_links: links, urls, attachments: acc.attachments,
      auth_results: auth.trim(), has_headers: !!(h["received"] || auth),
    };
  }

  const api = { parseEmailSource };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.PhishGuardMime = api;
})(typeof self !== "undefined" ? self : this);
