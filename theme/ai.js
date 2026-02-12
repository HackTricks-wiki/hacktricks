/**
 * HackTricks Training Discounts



(() => {
  try {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") return;
  } catch (e) {}
  const KEY = 'htSummerDiscountsDismissed';
  const IMG = '/ima * HackTricks AI Chat Widget v1.17 – enhanced resizable sidebar
 * ---------------------------------------------------
 * ❶ Markdown rendering + sanitised (same as before)
 * ❷ ENHANCED: improved drag‑to‑resize panel with better UXdiscount.jpeg';
  const TXT = 'Click here for HT Summer Discounts, Last Days!';
  const URL = 'https://hacktricks-training.com';

  // Stop if user already dismissed
  if (localStorage.getItem(KEY) === 'true') return;

  // Quick helper
  const $ = (tag, css = '') => Object.assign(document.cr    p.innerHTML = `
      <div id="ht-ai-header">
        <strong>HackTricks AI Chat</strong>
        <span style="font-size:11px;opacity:0.6;margin-left:8px;">↔ Drag edge to resize</span>
        <div class="ht-actions">
          <button id="ht-ai-reset" title="Reset">↺</button>
          <span id="ht-ai-close" title="Close">✖</span>
        </div>
      </div>
      <div id="ht-ai-chat"></div>
      <div id="ht-ai-input">
        <textarea id="ht-ai-question" placeholder="Type your question…"></textarea>
        <button id="ht-ai-send">Send</button>
      </div>`;tag), { style: css });

  // --- Overlay (blur + dim) ---
  const overlay = $('div', `
    position: fixed; inset: 0;
    background: rgba(0,0,0,.4);
    backdrop-filter: blur(6px);
    display: flex; justify-content: center; align-items: center;
    z-index: 10000;
  `);

  // --- Modal ---
  const modal = $('div', `
    max-width: 90vw; width: 480px;
    background: #fff; border-radius: 12px; overflow: hidden;
    box-shadow: 0 8px 24px rgba(0,0,0,.35);
    font-family: system-ui, sans-serif;
    display: flex; flex-direction: column; align-items: stretch;
  `);

  // --- Title bar (link + close) ---
  const titleBar = $('div', `
    position: relative;
    padding: 1rem 2.5rem 1rem 1rem; // room for the close button
    text-align: center;
    background: #222; color: #fff;
    font-size: 1.3rem; font-weight: 700;
  `);

  const link = $('a', `
    color: inherit;
    text-decoration: none;
    display: block;
  `);
  link.href = URL;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = TXT;
  titleBar.appendChild(link);

  // Close "X" (no persistence)
  const closeBtn = $('button', `
    position: absolute; top: .25rem; right: .5rem;
    background: transparent; border: none;
    color: #fff; font-size: 1.4rem; line-height: 1;
    cursor: pointer; padding: 0; margin: 0;
  `);
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.textContent = '✕';
  closeBtn.onclick = () => overlay.remove();
  titleBar.appendChild(closeBtn);

  // --- Image ---
  const img = $('img');
  img.src = IMG; img.alt = TXT; img.style.width = '100%';

  // --- Checkbox row ---
  const label = $('label', `
    display: flex; align-items: center; justify-content: center; gap: .6rem;
    padding: 1rem; font-size: 1rem; color: #222; cursor: pointer;
  `);
  const cb = $('input'); cb.type = 'checkbox'; cb.style.scale = '1.2';
  cb.onchange = () => {
    if (cb.checked) {
      localStorage.setItem(KEY, 'true');
      overlay.remove();
    }
  };
  label.append(cb, document.createTextNode("Don't show again"));

  // --- Assemble & inject ---
  modal.append(titleBar, img, label);
  overlay.appendChild(modal);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => document.body.appendChild(overlay), { once: true });
  } else {
    document.body.appendChild(overlay);
  }
})();
*/


/**
 * HackTricks AI Chat Widget v1.16 – resizable sidebar
 * ---------------------------------------------------
 * ❶ Markdown rendering + sanitised (same as before)
 * ❷ NEW: drag‑to‑resize panel, width persists via localStorage
 */



(function () {
  const LOG = "[HackTricks-AI]";
  /* ---------------- User‑tunable constants ---------------- */
  const MAX_CONTEXT  = 3000;   // highlighted‑text char limit
  const MAX_QUESTION = 500;    // question char limit
  const MIN_W        = 250;    // ← resize limits →
  const MAX_W        = 800;
  const DEF_W        = 350;    // default width (if nothing saved)
  const TOOLTIP_TEXT =
    "💡 Highlight any text on the page,\nthen click to ask HackTricks AI about it";

  const API_BASE  = "https://ai.hacktricks.wiki/api/assistants/threads";
  const AUTH_STATUS_URL = "https://ai.hacktricks.wiki/api/auth/status";
  const LOGIN_URL = "https://tools.hacktricks.wiki/";
  const BRAND_RED = "#b31328";

  /* ------------------------------ State ------------------------------ */
  let threadId  = null;
  let isRunning = false;
  let isAuthenticated = false;

  /* ---------- helpers ---------- */
  const $ = (sel, ctx = document) => ctx.querySelector(sel);
  if (document.getElementById("ht-ai-btn")) {
    console.warn(`${LOG} Widget already injected.`);
    return;
  }
  (document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", init)
    : init());

  /* =================================================================== */
  /*  🔗 1. 3rd‑party libs → Markdown & sanitiser                        */
  /* =================================================================== */
  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement("script");
      s.src = src;
      s.onload = res;
      s.onerror = () => rej(new Error(`Failed to load ${src}`));
      document.head.appendChild(s);
    });
  }
  async function ensureDeps() {
    const deps = [];
    if (typeof marked === "undefined")
      deps.push(loadScript("https://cdn.jsdelivr.net/npm/marked/marked.min.js"));
    if (typeof DOMPurify === "undefined")
      deps.push(
        loadScript(
          "https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.2.5/purify.min.js"
        )
      );
    if (deps.length) await Promise.all(deps);
  }
  const mdToSafeHTML = (md) =>
    DOMPurify.sanitize(marked.parse(md, { mangle: false, headerIds: false }), {
      USE_PROFILES: { html: true }
    });

  /* =================================================================== */
  async function init() {
    try {
      await ensureDeps();
    } catch (e) {
      console.error(`${LOG} Could not load dependencies`, e);
      return;
    }

    console.log(`${LOG} Injecting widget… v1.16`);

    injectStyles();

    const btn      = createFloatingButton();
    createTooltip(btn);
    const panel    = createSidebar();             // ← panel with resizer
    const chatLog  = $("#ht-ai-chat");
    const sendBtn  = $("#ht-ai-send");
    const inputBox = $("#ht-ai-question");
    const resetBtn = $("#ht-ai-reset");
    const closeBtn = $("#ht-ai-close");

    await refreshAuthState(btn);
    if (isAuthenticated) {
      await ensureThreadId();
    }

    /* ------------------- Selection snapshot ------------------- */
    let savedSelection = "";
    btn.addEventListener("pointerdown", () => {
      savedSelection = window.getSelection().toString().trim();
    });

    /* ------------------- Helpers ------------------------------ */
    function addMsg(text, cls) {
      const b = document.createElement("div");
      b.className = `ht-msg ${cls}`;
      b[cls === "ht-ai" ? "innerHTML" : "textContent"] =
        cls === "ht-ai" ? mdToSafeHTML(text) : text;
      chatLog.appendChild(b);
      chatLog.scrollTop = chatLog.scrollHeight;
      return b;
    }
    const LOADER_HTML =
      '<span class="ht-loading"><span></span><span></span><span></span></span>';

    const setInputDisabled = (d) => {
      inputBox.disabled = d;
      sendBtn.disabled  = d;
    };
    const clearThreadCookie = () => {
      document.cookie = "threadId=; Path=/; Max-Age=0";
      threadId = null;
    };
    const resetConversation = () => {
      chatLog.innerHTML = "";
      clearThreadCookie();
      panel.classList.remove("open");
    };

    /* ------------------- Panel open / close ------------------- */
    btn.addEventListener("click", async () => {
      const ok = await refreshAuthState(btn);
      if (!ok) {
        showLoginPopup();
        return;
      }
      if (!savedSelection) {
        alert("Please highlight some text first.");
        return;
      }
      if (savedSelection.length > MAX_CONTEXT) {
        alert(`Highlighted text is too long. Max ${MAX_CONTEXT} chars.`);
        return;
      }
      chatLog.innerHTML = "";
      addMsg(savedSelection, "ht-context");
      panel.classList.add("open");
      inputBox.focus();
    });
    closeBtn.addEventListener("click", resetConversation);
    resetBtn.addEventListener("click", resetConversation);

    /* --------------------------- Messaging --------------------------- */
    async function sendMessage(question, context = null) {
      if (!threadId) await ensureThreadId();
      if (isRunning) {
        addMsg("Please wait until the current operation completes.", "ht-ai");
        return;
      }
      isRunning = true;
      setInputDisabled(true);
      const loading = addMsg("", "ht-ai");
      loading.innerHTML = LOADER_HTML;

      const content = context
        ? `### Context:\n${context}\n\n### Question to answer:\n${question}`
        : question;
      try {
        const res = await fetch(`${API_BASE}/${threadId}/messages`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content })
        });
        if (!res.ok) {
          let err = `Unknown error: ${res.status}`;
          try {
            const e = await res.json();
            if (e.error) err = `Error: ${e.error}`;
            else if (res.status === 429) err = "Rate limit exceeded.";
          } catch (_) {}
          loading.textContent = err;
          return;
        }
        const data = await res.json();
        loading.remove();
        if (Array.isArray(data.response))
          data.response.forEach((p) =>
            addMsg(
              p.type === "text" && p.text && p.text.value
                ? p.text.value
                : JSON.stringify(p),
              "ht-ai"
            )
          );
        else if (typeof data.response === "string")
          addMsg(data.response, "ht-ai");
        else addMsg(JSON.stringify(data, null, 2), "ht-ai");
      } catch (e) {
        console.error("Error sending message:", e);
        loading.textContent = "An unexpected error occurred.";
      } finally {
        isRunning = false;
        setInputDisabled(false);
        chatLog.scrollTop = chatLog.scrollHeight;
      }
    }
    async function handleSend() {
      const q = inputBox.value.trim();
      if (!q) return;
      if (q.length > MAX_QUESTION) {
        alert(`Question too long (${q.length}). Max ${MAX_QUESTION}.`);
        return;
      }
      inputBox.value = "";
      addMsg(q, "ht-user");
      await sendMessage(q, savedSelection || null);
    }
    sendBtn.addEventListener("click", handleSend);
    inputBox.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    });
  } /* end init */

  /* =================================================================== */
  async function ensureThreadId() {
    const m = document.cookie.match(/threadId=([^;]+)/);
    if (m && m[1]) {
      threadId = m[1];
      return;
    }
    try {
      const r = await fetch(API_BASE, { method: "POST", credentials: "include" });
      const d = await r.json();
      if (!r.ok || !d.threadId) throw new Error(`${r.status} ${r.statusText}`);
      threadId = d.threadId;
      document.cookie =
        `threadId=${threadId}; Path=/; Secure; SameSite=Strict; Max-Age=7200`;
    } catch (e) {
      console.error("Error creating threadId:", e);
      console.log("Failed to initialise the conversation. Please refresh.");
      throw e;
    }
  }

  /* =================================================================== */
  function injectStyles() {
    let css = `
#ht-ai-btn{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);min-width:60px;height:60px;border-radius:30px;background:var(--ht-ai-fab-bg,linear-gradient(45deg,#b31328,#d42d3f,#2d5db4,#3470e4));background-size:300% 300%;animation:gradientShift 8s ease infinite;color:var(--ht-ai-fab-fg,#fff);font-size:18px;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:99999;box-shadow:0 12px 26px var(--ht-ai-shadow,rgba(0,0,0,.45));transition:opacity .2s, filter .2s; padding:0 20px;border:1px solid var(--ht-ai-fab-border,rgba(255,255,255,.12))}
#ht-ai-btn.ht-ai-locked{filter:grayscale(.2);opacity:.85}
#ht-ai-btn span{margin-left:8px;font-weight:bold}
@keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
#ht-ai-btn:hover{opacity:.85}
@media(max-width:768px){#ht-ai-btn{display:none}}
#ht-ai-tooltip{position:fixed;padding:6px 8px;background:var(--ht-ai-tooltip-bg,#111);color:var(--ht-ai-tooltip-fg,#fff);border-radius:6px;font-size:13px;white-space:pre-wrap;pointer-events:none;opacity:0;transform:translate(-50%,-8px);transition:opacity .15s ease,transform .15s ease;z-index:100000;box-shadow:0 8px 20px var(--ht-ai-shadow,rgba(0,0,0,.35))}
#ht-ai-tooltip.show{opacity:1;transform:translate(-50%,-12px)}
#ht-ai-panel{position:fixed;top:0;right:0;height:100%;max-width:90vw;background:var(--ht-ai-panel-bg,#0b0b0b);color:var(--ht-ai-panel-fg,#fff);display:flex;flex-direction:column;transform:translateX(100%);transition:transform .3s ease;z-index:100000;font-family:var(--body-font,system-ui)}
#ht-ai-panel.open{transform:translateX(0)}
@media(max-width:768px){#ht-ai-panel{display:none}}
#ht-ai-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--ht-ai-border,#333);background:var(--ht-ai-header-bg,transparent);flex-wrap:wrap}
#ht-ai-header strong{flex-shrink:0}
#ht-ai-header .ht-actions{display:flex;gap:8px;align-items:center;margin-left:auto}
#ht-ai-close,#ht-ai-reset{cursor:pointer;font-size:18px;background:none;border:none;color:var(--ht-ai-panel-fg,#fff);padding:0}
#ht-ai-close:hover,#ht-ai-reset:hover{opacity:.7}
#ht-ai-chat{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:8px;font-size:14px;background:var(--ht-ai-chat-bg,transparent)}
.ht-msg{max-width:90%;line-height:1.3;padding:8px 10px;border-radius:8px;white-space:pre-wrap;word-wrap:break-word}
.ht-msg p{margin:0 0 4px}
.ht-msg p:last-child{margin-bottom:0}
.ht-msg h1,.ht-msg h2,.ht-msg h3,.ht-msg h4,.ht-msg h5,.ht-msg h6{margin:2px 0 4px;line-height:1.15}
.ht-msg ul,.ht-msg ol{margin:0 0 4px 14px;padding:0}
.ht-msg li{margin:0 0 2px}
.ht-msg pre{margin:4px 0;padding:6px 8px;border-radius:6px;background:rgba(0,0,0,.2);overflow:auto}
.ht-msg blockquote{margin:2px 0;padding-left:8px;border-left:2px solid rgba(255,255,255,.2)}
.ht-msg code{font-size:.95em}
.ht-user{align-self:flex-end;background:var(--ht-ai-user-bg,${BRAND_RED});color:var(--ht-ai-user-fg,#fff)}
.ht-ai{align-self:flex-start;background:var(--ht-ai-bot-bg,#222);color:var(--ht-ai-bot-fg,#fff)}
.ht-context{align-self:flex-start;background:var(--ht-ai-context-bg,#333);color:var(--ht-ai-context-fg,#ddd);font-style:italic;font-size:13px}
#ht-ai-input{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--ht-ai-border,#333);background:var(--ht-ai-input-bg,transparent)}
#ht-ai-question{flex:1;min-height:40px;max-height:120px;resize:vertical;padding:8px;border-radius:8px;border:1px solid var(--ht-ai-border,#333);background:var(--ht-ai-field-bg,#111);color:var(--ht-ai-panel-fg,#fff);font-size:14px}
#ht-ai-question::placeholder{color:var(--ht-ai-muted,#aaa)}
#ht-ai-send{padding:0 18px;border:none;border-radius:8px;background:var(--ht-ai-accent,${BRAND_RED});color:var(--ht-ai-accent-fg,#fff);font-size:14px;cursor:pointer}
#ht-ai-send:disabled{opacity:.5;cursor:not-allowed}
/* Loader */
.ht-loading{display:inline-flex;align-items:center;gap:4px}
.ht-loading span{width:6px;height:6px;border-radius:50%;background:#888;animation:ht-bounce 1.2s infinite ease-in-out}
.ht-loading span:nth-child(2){animation-delay:0.2s}
.ht-loading span:nth-child(3){animation-delay:0.4s}
@keyframes ht-bounce{0%,80%,100%{transform:scale(0);}40%{transform:scale(1);} }
::selection{background:#ffeb3b;color:#000}
::-moz-selection{background:#ffeb3b;color:#000}
/* NEW: resizer handle */
#ht-ai-resizer{position:absolute;left:0;top:0;width:8px;height:100%;cursor:ew-resize;background:var(--ht-ai-resizer-bg,rgba(255,255,255,.08));border-right:1px solid var(--ht-ai-resizer-border,rgba(255,255,255,.15));transition:background .2s ease}
#ht-ai-resizer:hover{background:var(--ht-ai-resizer-bg-hover,rgba(255,255,255,.15));border-right:1px solid var(--ht-ai-resizer-border-hover,rgba(255,255,255,.3))}
#ht-ai-resizer:active{background:var(--ht-ai-resizer-bg-active,rgba(255,255,255,.25))}
#ht-ai-resizer::before{content:'';position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:2px;height:20px;background:var(--ht-ai-resizer-handle,rgba(255,255,255,.4));border-radius:1px}`;
    css += `
#ht-ai-login-overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--ht-ai-overlay-bg,rgba(0,0,0,.6));backdrop-filter:blur(6px);z-index:100200}
#ht-ai-login-card{max-width:420px;width:calc(100% - 32px);padding:20px;border-radius:14px;background:var(--ht-ai-panel-bg,#111);border:1px solid var(--ht-ai-border,rgba(255,255,255,.08));box-shadow:0 12px 28px var(--ht-ai-shadow,rgba(0,0,0,.4));text-align:center;color:var(--ht-ai-panel-fg,#fff);font-family:var(--body-font,system-ui)}
.ht-ai-login-title{font-size:1.1rem;font-weight:700;margin-bottom:8px}
.ht-ai-login-text{font-size:.95rem;color:var(--ht-ai-muted,#cfcfcf);margin-bottom:12px}
.ht-ai-login-link{display:inline-block;margin-bottom:16px;color:var(--ht-ai-accent,#ff6b5b);text-decoration:none;word-break:break-all}
.ht-ai-login-link:hover{text-decoration:underline}
.ht-ai-login-close{background:var(--ht-ai-accent,#b31328);color:var(--ht-ai-accent-fg,#fff);border:none;border-radius:8px;padding:8px 14px;cursor:pointer}
.ht-ai-login-close:hover{opacity:.9}
`;
    const s = document.createElement("style");
    s.id = "ht-ai-style";
    s.textContent = css;
    document.head.appendChild(s);
  }

  /* =================================================================== */
  function createFloatingButton() {
    const d = document.createElement("div");
    d.id = "ht-ai-btn";
    d.innerHTML = "🤖<span>HackTricksAI</span>";
    document.body.appendChild(d);
    return d;
  }
  function createTooltip(btn) {
    const t = document.createElement("div");
    t.id = "ht-ai-tooltip";
    t.textContent = TOOLTIP_TEXT;
    document.body.appendChild(t);
    btn.addEventListener("mouseenter", () => {
      const r = btn.getBoundingClientRect();
      t.style.left = `${r.left + r.width / 2}px`;
      t.style.top  = `${r.top}px`;
      t.classList.add("show");
    });
    btn.addEventListener("mouseleave", () => t.classList.remove("show"));
  }

  async function checkAuthStatus() {
    try {
      const res = await fetch(AUTH_STATUS_URL, { method: "GET", credentials: "include" });
      isAuthenticated = res.ok;
      return isAuthenticated;
    } catch (e) {
      isAuthenticated = false;
      return false;
    }
  }

  function setAuthButtonState(btn, ok) {
    btn.classList.toggle("ht-ai-locked", !ok);
  }

  async function refreshAuthState(btn) {
    const ok = await checkAuthStatus();
    setAuthButtonState(btn, ok);
    return ok;
  }

  function showLoginPopup() {
    if (document.getElementById("ht-ai-login-overlay")) return;
    const overlay = document.createElement("div");
    overlay.id = "ht-ai-login-overlay";
    overlay.innerHTML = `
      <div id="ht-ai-login-card">
        <div class="ht-ai-login-title">Sign in required</div>
        <div class="ht-ai-login-text">
          To use HackTricks AI, please log in or create a free account on HT Tools and refresh this page.
        </div>
        <a class="ht-ai-login-link" href="${LOGIN_URL}" target="_blank" rel="noopener noreferrer">${LOGIN_URL}</a>
        <button class="ht-ai-login-close" type="button">Close</button>
      </div>
    `;
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });
    overlay.querySelector(".ht-ai-login-close").addEventListener("click", () => overlay.remove());
    document.body.appendChild(overlay);
  }

  /* =================================================================== */
  function createSidebar() {
    const saved = parseInt(localStorage.getItem("htAiWidth") || DEF_W, 10);
    const width = Math.min(Math.max(saved, MIN_W), MAX_W);

    const p = document.createElement("div");
    p.id = "ht-ai-panel";
    p.style.width = width + "px";               // ← applied width
    p.innerHTML = `
      <div id="ht-ai-header"><strong>HackTricks AI Chat</strong>
        <div class="ht-actions">
          <button id="ht-ai-reset" title="Reset">↺</button>
          <span id="ht-ai-close" title="Close">✖</span>
        </div>
      </div>
      <div id="ht-ai-chat"></div>
      <div id="ht-ai-input">
        <textarea id="ht-ai-question" placeholder="Type your question…"></textarea>
        <button id="ht-ai-send">Send</button>
      </div>`;
    /* NEW: resizer strip */
    const resizer = document.createElement("div");
    resizer.id = "ht-ai-resizer";
    p.appendChild(resizer);
    document.body.appendChild(p);
    addResizeLogic(resizer, p);
    return p;
  }

  /* ---------------- resize behaviour ---------------- */
  function addResizeLogic(handle, panel) {
    let startX, startW, dragging = false;

    const onMove = (e) => {
      if (!dragging) return;
      e.preventDefault();
      const clientX = e.clientX || (e.touches && e.touches[0].clientX);
      const dx = startX - clientX;           // dragging leftwards ⇒ +dx
      let newW = startW + dx;
      newW = Math.min(Math.max(newW, MIN_W), MAX_W);
      panel.style.width = newW + "px";
    };

    const onUp = () => {
      if (!dragging) return;
      dragging = false;
      handle.style.background = "";
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      localStorage.setItem("htAiWidth", parseInt(panel.style.width, 10));
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.removeEventListener("touchmove", onMove);
      document.removeEventListener("touchend", onUp);
    };

    const onStart = (e) => {
      e.preventDefault();
      dragging = true;
      startX = e.clientX || (e.touches && e.touches[0].clientX);
      startW = parseInt(window.getComputedStyle(panel).width, 10);
      handle.style.background = "rgba(255,255,255,.25)";
      document.body.style.userSelect = "none";
      document.body.style.cursor = "ew-resize";
      
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
      document.addEventListener("touchmove", onMove, { passive: false });
      document.addEventListener("touchend", onUp);
    };

    handle.addEventListener("mousedown", onStart);
    handle.addEventListener("touchstart", onStart, { passive: false });
  }
})();
