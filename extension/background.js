/* Service worker: holds the model + blocklist and scores emails sent by the Gmail script and the popup. */
importScripts("core.js");

let guardPromise = null;
let blocklistSize = 0;

function getGuard() {
  if (!guardPromise) {
    guardPromise = (async () => {
      const model = await (await fetch(chrome.runtime.getURL("model/model.json"))).json();
      let bl = null;
      try {
        const txt = await (await fetch(chrome.runtime.getURL("model/blocklist-domains.txt"))).text();
        bl = new PhishGuardCore.Blocklist(txt);
        blocklistSize = bl.size;
      } catch (e) { /* blocklist is optional */ }
      return new PhishGuardCore.PhishGuard(model, bl);
    })();
  }
  return guardPromise;
}

// Optional Google Safe Browsing check (only if the user saved an API key). Sends link URLs to Google.
async function safeBrowsing(urls) {
  const { gsbKey } = await chrome.storage.local.get("gsbKey");
  if (!gsbKey || !urls.length) return [];
  const body = {
    client: { clientId: "phishguard-extension", clientVersion: "0.1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"],
      threatEntries: urls.slice(0, 20).map(url => ({ url })),
    },
  };
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    return (j.matches || []).map(m => ({ url: m.threat.url, source: "Google Safe Browsing", detail: m.threatType }));
  } catch (e) { return []; }
}

async function scan(email) {
  const g = await getGuard();
  const extra = await safeBrowsing(email.urls || []);
  return g.scan(email, extra);
}

function setBadge(tabId, r) {
  if (tabId == null) return;
  const map = { HIGH: ["!", "#c62828"], MEDIUM: ["?", "#b26a00"], LOW: ["", "#2e7d32"] };
  const [text, color] = map[r.level];
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
function emailFromText(subject, body, sender) {
  return { from: sender || "", reply_to: "", return_path: "", subject: subject || "", body: body || "",
    urls: [...new Set((body || "").match(URL_RE) || [])], html_links: [], attachments: [], auth_results: "" };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "scan") {
    scan(msg.email).then(r => {
      if (sender.tab && msg.badge !== false) setBadge(sender.tab.id, r);
      sendResponse(r);
    }).catch(err => sendResponse({ error: String(err) }));
    return true; // async
  }
  if (msg.type === "status") {
    getGuard().then(async () => {
      const { gsbKey } = await chrome.storage.local.get("gsbKey");
      sendResponse({ blocklist: blocklistSize, safeBrowsing: !!gsbKey });
    });
    return true;
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "pg-check", title: "Check selected text with PhishGuard", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "pg-check") return;
  const email = emailFromText("", info.selectionText || "", "");
  const result = await scan(email);
  await chrome.storage.session.set({ lastSelection: { text: (info.selectionText || "").slice(0, 300), result } });
  chrome.windows.create({ url: chrome.runtime.getURL("popup.html#selection"), type: "popup", width: 440, height: 640 });
});
