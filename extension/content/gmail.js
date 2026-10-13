/* Gmail content script: finds each open email, sends it to the background scorer,
 * and shows a PhishGuard banner above the message body.
 * Gmail's page structure changes now and then; the selectors are kept in one place below. */
(function () {
  "use strict";
  const SEL = {
    body: "div.a3s",                       // message body
    message: "div.adn, [data-message-id]", // one message in a thread
    sender: "span.gD[email], span[email].gD, h3 span[email]",
    subject: "h2.hP",
    attachment: "span.aV3, div.aQH [download_url]",
  };
  const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
  const results = new WeakMap(); // body element -> result
  let lastResult = null;

  function unwrap(href) { // Gmail sometimes wraps links in google.com/url?q=...
    try {
      const u = new URL(href);
      if (/(^|\.)google\.com$/.test(u.hostname) && u.pathname === "/url") return u.searchParams.get("q") || u.searchParams.get("url") || href;
    } catch (e) { /* ignore */ }
    return href;
  }

  function extract(body) {
    const msg = body.closest(SEL.message) || body.parentElement;
    const s = msg.querySelector(SEL.sender);
    const email = s ? s.getAttribute("email") || "" : "";
    const name = s ? (s.getAttribute("name") || s.textContent || "").trim() : "";
    const subject = (document.querySelector(SEL.subject) || {}).textContent || "";
    const links = [...body.querySelectorAll("a[href]")]
      .map(a => [unwrap(a.href), (a.textContent || "").trim()])
      .filter(l => /^https?:/i.test(l[0]));
    const text = body.innerText || body.textContent || "";
    const urls = [...new Set(links.map(l => l[0]).concat(text.match(URL_RE) || []))];
    const attachments = [...msg.querySelectorAll(SEL.attachment)].map(el => {
      const d = el.getAttribute("download_url");
      return d ? d.split(":")[1] || "" : (el.textContent || "").trim();
    }).filter(Boolean);
    return {
      from: name && email ? `"${name}" <${email}>` : email, reply_to: "", return_path: "",
      subject: subject.trim(), body: text, urls, html_links: links, attachments: [...new Set(attachments)], auth_results: "",
    };
  }

  function showBanner(body, r) {
    let host = body.previousElementSibling;
    if (!host || !host.classList || !host.classList.contains("phishguard-host")) {
      host = document.createElement("div");
      host.className = "phishguard-host";
      host.attachShadow({ mode: "open" });
      body.parentElement.insertBefore(host, body);
    }
    host.shadowRoot.innerHTML = `<style>${PhishGuardUI.CSS}</style>` + PhishGuardUI.resultHTML(r, {
      closable: true,
      headerNote: "Sender checks (SPF/DKIM) need the full email: ⋮ → Show original → copy → PhishGuard popup.",
    });
    const x = host.shadowRoot.querySelector(".x");
    if (x) x.addEventListener("click", () => { host.style.display = "none"; });
  }

  function scanBody(body) {
    if (body.dataset.pgState) return;
    body.dataset.pgState = "pending";
    const email = extract(body);
    if (!email.body.trim() && !email.subject) { delete body.dataset.pgState; return; }
    chrome.runtime.sendMessage({ type: "scan", email }, r => {
      if (chrome.runtime.lastError || !r || r.error) { delete body.dataset.pgState; return; }
      body.dataset.pgState = "done";
      results.set(body, r);
      lastResult = { result: r, subject: email.subject, from: email.from };
      showBanner(body, r);
    });
  }

  function scanAll() {
    document.querySelectorAll(SEL.body).forEach(body => {
      if (body.parentElement && body.parentElement.closest(SEL.body)) return; // nested quote
      if (!body.offsetParent) return;                                          // collapsed / hidden
      scanBody(body);
      // Gmail sometimes rebuilds the area above the body; put the banner back if it vanished
      const r = results.get(body);
      const prev = body.previousElementSibling;
      if (r && !(prev && prev.classList && prev.classList.contains("phishguard-host"))) showBanner(body, r);
    });
  }

  let timer = null;
  new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(scanAll, 400); })
    .observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", () => setTimeout(scanAll, 600));
  scanAll();

  chrome.runtime.onMessage.addListener((msg, _s, send) => {
    if (msg.type === "getLast") send(lastResult);
  });
})();
