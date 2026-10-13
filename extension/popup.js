/* Popup: show the current Gmail email's result, or check pasted text / full email source. */
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;

  function render(el, r, opts) {
    el.innerHTML = `<style>${PhishGuardUI.CSS}</style>` + PhishGuardUI.resultHTML(r, Object.assign({ open: true }, opts || {}));
  }
  function empty(el, msg) { el.innerHTML = `<div class="empty">${PhishGuardUI.esc(msg)}</div>`; }
  function scan(email) {
    return new Promise(res => chrome.runtime.sendMessage({ type: "scan", email, badge: false }, r => res(r)));
  }

  // tabs ---------------------------------------------------------------
  function showTab(name) {
    document.querySelectorAll("nav button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
    document.querySelectorAll(".tab").forEach(s => { s.hidden = s.id !== "tab-" + name; });
  }
  document.querySelectorAll("nav button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));

  // this email ---------------------------------------------------------
  async function loadCurrent() {
    const out = $("email-out");
    if (location.hash === "#selection") {
      const { lastSelection } = await chrome.storage.session.get("lastSelection");
      if (lastSelection) {
        out.innerHTML = `<p class="hint">Selected text: “${PhishGuardUI.esc(lastSelection.text)}${lastSelection.text.length >= 300 ? "…" : ""}”</p>`;
        const box = document.createElement("div"); out.appendChild(box);
        render(box, lastSelection.result);
        return;
      }
    }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !/^https:\/\/mail\.google\.com\//.test(tab.url || "")) {
      return empty(out, "Open an email in Gmail to see its score here, or use the other tabs to check any message.");
    }
    chrome.tabs.sendMessage(tab.id, { type: "getLast" }, last => {
      if (chrome.runtime.lastError || !last) return empty(out, "No email scanned yet. Open an email in Gmail (reload the Gmail tab if you just installed PhishGuard).");
      out.innerHTML = `<p class="hint"><b>${PhishGuardUI.esc(last.subject || "(no subject)")}</b><br>${PhishGuardUI.esc(last.from)}</p>`;
      const box = document.createElement("div"); out.appendChild(box);
      render(box, last.result, { headerNote: "For sender checks (SPF/DKIM), use the “Full email” tab." });
    });
  }

  // paste text ---------------------------------------------------------
  $("t-go").addEventListener("click", async () => {
    const body = $("t-body").value;
    if (!body.trim() && !$("t-subject").value.trim()) return empty($("text-out"), "Paste a message first.");
    const email = { from: $("t-from").value.trim(), reply_to: "", return_path: "", subject: $("t-subject").value,
      body, urls: [...new Set(body.match(URL_RE) || [])], html_links: [], attachments: [], auth_results: "" };
    render($("text-out"), await scan(email));
  });

  // full source --------------------------------------------------------
  const htmlTools = {
    toText(html) {
      const d = new DOMParser().parseFromString(html, "text/html");
      d.querySelectorAll("style,script,head,title,meta,noscript").forEach(n => n.remove());
      return (d.body ? d.body.textContent : "").replace(/ /g, " ");
    },
    links(html) {
      const d = new DOMParser().parseFromString(html, "text/html");
      return [...d.querySelectorAll("a[href]")].map(a => [a.getAttribute("href").trim(), (a.textContent || "").trim()]);
    },
  };
  $("s-go").addEventListener("click", async () => {
    const raw = $("s-raw").value;
    if (!/^[\w-]+:/m.test(raw)) return empty($("source-out"), "That doesn't look like an email source. Use Gmail's “Show original” and copy everything.");
    const email = PhishGuardMime.parseEmailSource(raw, htmlTools);
    const r = await scan(email);
    $("source-out").innerHTML = `<p class="hint"><b>${PhishGuardUI.esc(email.subject || "(no subject)")}</b><br>${PhishGuardUI.esc(email.from)}` +
      (email.attachments.length ? `<br>Attachments: ${PhishGuardUI.esc(email.attachments.join(", "))}` : "") + "</p>";
    const box = document.createElement("div"); $("source-out").appendChild(box);
    render(box, r, { headerNote: "No SPF/DKIM/DMARC results found in this source." });
  });

  // settings / status --------------------------------------------------
  chrome.storage.local.get("gsbKey").then(({ gsbKey }) => { $("gsb").value = gsbKey || ""; });
  $("gsb-save").addEventListener("click", async () => {
    await chrome.storage.local.set({ gsbKey: $("gsb").value.trim() });
    $("gsb-msg").textContent = "Saved.";
    refreshStatus();
  });
  function refreshStatus() {
    chrome.runtime.sendMessage({ type: "status" }, s => {
      if (!s) return;
      $("status").textContent = `${s.blocklist.toLocaleString()} blocked domains` + (s.safeBrowsing ? " · Safe Browsing on" : " · offline");
    });
  }

  refreshStatus();
  loadCurrent();
})();
