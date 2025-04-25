/**
 * HackTricks AI Chat Widget v1.14 – animated typing indicator
 * ------------------------------------------------------------------------
 * • Replaces the static “…” placeholder with a three‑dot **bouncing** loader
 *   while waiting for the assistant’s response.
 * ------------------------------------------------------------------------
 */
(function () {
  const LOG = "[HackTricks-AI]";

  /* ---------------- User‑tunable constants ---------------- */
  const MAX_CONTEXT  = 3000;     // highlighted‑text char limit
  const MAX_QUESTION = 500;      // question char limit
  const TOOLTIP_TEXT =
    "💡 Highlight any text on the page,\nthen click to ask HackTricks AI about it";

  const API_BASE   = "https://www.hacktricks.ai/api/assistants/threads";
  const BRAND_RED  = "#b31328"; // HackTricks brand

  /* ------------------------------ State ------------------------------ */
  let threadId  = null;
  let isRunning = false;

  const $ = (sel, ctx = document) => ctx.querySelector(sel);
  if (document.getElementById("ht-ai-btn")) { console.warn(`${LOG} Widget already injected.`); return; }
  (document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", init) : init());

  /* ==================================================================== */
  async function init() {
    console.log(`${LOG} Injecting widget… v1.14`);
    await ensureThreadId();
    injectStyles();

    const btn      = createFloatingButton();
    createTooltip(btn);
    const panel    = createSidebar();
    const chatLog  = $("#ht-ai-chat");
    const sendBtn  = $("#ht-ai-send");
    const inputBox = $("#ht-ai-question");
    const resetBtn = $("#ht-ai-reset");
    const closeBtn = $("#ht-ai-close");

    /* ------------------- Selection snapshot ------------------- */
    let savedSelection = "";
    btn.addEventListener("pointerdown", () => { savedSelection = window.getSelection().toString().trim(); });

    /* ------------------- Helpers ------------------------------ */
    function addMsg(text, cls) {
      const b = document.createElement("div");
      b.className = `ht-msg ${cls}`;
      b.textContent = text;
      chatLog.appendChild(b);
      chatLog.scrollTop = chatLog.scrollHeight;
      return b;
    }
    const LOADER_HTML = '<span class="ht-loading"><span></span><span></span><span></span></span>';

    function setInputDisabled(d) { inputBox.disabled = d; sendBtn.disabled = d; }
    function clearThreadCookie() { document.cookie = "threadId=; Path=/; Max-Age=0"; threadId = null; }
    function resetConversation() { chatLog.innerHTML=""; clearThreadCookie(); panel.classList.remove("open"); }

    /* ------------------- Panel open / close ------------------- */
    btn.addEventListener("click", () => {
      if (!savedSelection) { alert("Please highlight some text first to then ask Hacktricks AI about it."); return; }
      if (savedSelection.length > MAX_CONTEXT) { alert(`Highlighted text is too long (${savedSelection.length} chars). Max allowed: ${MAX_CONTEXT}.`); return; }
      chatLog.innerHTML=""; addMsg(savedSelection, "ht-context"); panel.classList.add("open"); inputBox.focus();
    });
    closeBtn.addEventListener("click", resetConversation);
    resetBtn.addEventListener("click", resetConversation);

    /* --------------------------- Messaging --------------------------- */
    async function sendMessage(question, context=null) {
      if (!threadId) await ensureThreadId();
      if (isRunning) { addMsg("Please wait until the current operation completes.", "ht-ai"); return; }

      isRunning = true; setInputDisabled(true);
      const loadingBubble = addMsg("", "ht-ai");
      loadingBubble.innerHTML = LOADER_HTML;

      const content = context ? `Context:\n${context}\n\nQuestion:\n${question}` : question;
      try {
        const res = await fetch(`${API_BASE}/${threadId}/messages`, { method:"POST", credentials:"include", headers:{"Content-Type":"application/json"}, body:JSON.stringify({content}) });
        if (!res.ok) {
          let err=`Unknown error: ${res.status}`;
          try { const e=await res.json(); if(e.error) err=`Error: ${e.error}`; else if(res.status===429) err="Rate limit exceeded. Please try again later."; } catch(_){}
          loadingBubble.textContent = err; return; }
        const data = await res.json();
        loadingBubble.remove();
        if (Array.isArray(data.response)) data.response.forEach(p=>{ addMsg( p.type==="text"&&p.text&&p.text.value ? p.text.value : JSON.stringify(p), "ht-ai"); });
        else if (typeof data.response === "string") addMsg(data.response, "ht-ai");
        else addMsg(JSON.stringify(data,null,2), "ht-ai");
      } catch (e) { console.error("Error sending message:",e); loadingBubble.textContent="An unexpected error occurred."; }
      finally { isRunning=false; setInputDisabled(false); chatLog.scrollTop=chatLog.scrollHeight; }
    }

    async function handleSend(){ const q=inputBox.value.trim(); if(!q)return; if(q.length>MAX_QUESTION){alert(`Your question is too long (${q.length} chars). Max allowed: ${MAX_QUESTION}.`); return;} inputBox.value=""; addMsg(q,"ht-user"); await sendMessage(q,savedSelection||null);}    
    sendBtn.addEventListener("click", handleSend);
    inputBox.addEventListener("keydown", e=>{ if(e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); handleSend(); } });
  }

  /* ==================================================================== */
  async function ensureThreadId(){ const m=document.cookie.match(/threadId=([^;]+)/); if(m&&m[1]){threadId=m[1];return;} try{ const r=await fetch(API_BASE,{method:"POST",credentials:"include"}); const d=await r.json(); if(!r.ok||!d.threadId) throw new Error(`${r.status} ${r.statusText}`); threadId=d.threadId; document.cookie=`threadId=${threadId}; Path=/; Secure; SameSite=Strict; Max-Age=7200`; }catch(e){ console.error("Error creating threadId:",e); alert("Failed to initialise the conversation. Please refresh and try again."); throw e; }}

  /* ==================================================================== */
  function injectStyles(){ const css=`
      #ht-ai-btn{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);width:60px;height:60px;border-radius:50%;background:#1e1e1e;color:#fff;font-size:28px;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:99999;box-shadow:0 2px 8px rgba(0,0,0,.4);transition:opacity .2s}
      #ht-ai-btn:hover{opacity:.85}
      @media(max-width:768px){#ht-ai-btn{display:none}}
      #ht-ai-tooltip{position:fixed;padding:6px 8px;background:#111;color:#fff;border-radius:4px;font-size:13px;white-space:pre-wrap;pointer-events:none;opacity:0;transform:translate(-50%,-8px);transition:opacity .15s ease,transform .15s ease;z-index:100000}
      #ht-ai-tooltip.show{opacity:1;transform:translate(-50%,-12px)}
      #ht-ai-panel{position:fixed;top:0;right:0;height:100%;width:350px;max-width:90vw;background:#000;color:#fff;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .3s ease;z-index:100000;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial,sans-serif}
      #ht-ai-panel.open{transform:translateX(0)}
      @media(max-width:768px){#ht-ai-panel{display:none}}
      #ht-ai-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid #333}
      #ht-ai-header .ht-actions{display:flex;gap:8px;align-items:center}
      #ht-ai-close,#ht-ai-reset{cursor:pointer;font-size:18px;background:none;border:none;color:#fff;padding:0}
      #ht-ai-close:hover,#ht-ai-reset:hover{opacity:.7}
      #ht-ai-chat{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:12px;font-size:14px}
      .ht-msg{max-width:90%;line-height:1.4;padding:10px 12px;border-radius:8px;white-space:pre-wrap;word-wrap:break-word}
      .ht-user{align-self:flex-end;background:${BRAND_RED}}
      .ht-ai{align-self:flex-start;background:#222}
      .ht-context{align-self:flex-start;background:#444;font-style:italic;font-size:13px}
      #ht-ai-input{display:flex;gap:8px;padding:12px 16px;border-top:1px solid #333}
      #ht-ai-question{flex:1;min-height:40px;max-height:120px;resize:vertical;padding:8px;border-radius:6px;border:none;font-size:14px}
      #ht-ai-send{padding:0 18px;border:none;border-radius:6px;background:${BRAND_RED};color:#fff;font-size:14px;cursor:pointer}
      #ht-ai-send:disabled{opacity:.5;cursor:not-allowed}
      /* Loader animation */
      .ht-loading{display:inline-flex;align-items:center;gap:4px}
      .ht-loading span{width:6px;height:6px;border-radius:50%;background:#888;animation:ht-bounce 1.2s infinite ease-in-out}
      .ht-loading span:nth-child(2){animation-delay:0.2s}
      .ht-loading span:nth-child(3){animation-delay:0.4s}
      @keyframes ht-bounce{0%,80%,100%{transform:scale(0);}40%{transform:scale(1);} }
      ::selection{background:#ffeb3b;color:#000}
      ::-moz-selection{background:#ffeb3b;color:#000}`;
    const s=document.createElement("style"); s.id="ht-ai-style"; s.textContent=css; document.head.appendChild(s);}  

  function createFloatingButton(){ const d=document.createElement("div"); d.id="ht-ai-btn"; d.textContent="🤖"; document.body.appendChild(d); return d; }
  function createTooltip(btn){ const t=document.createElement("div"); t.id="ht-ai-tooltip"; t.textContent=TOOLTIP_TEXT; document.body.appendChild(t); btn.addEventListener("mouseenter",()=>{const r=btn.getBoundingClientRect(); t.style.left=`${r.left+r.width/2}px`; t.style.top=`${r.top}px`; t.classList.add("show");}); btn.addEventListener("mouseleave",()=>t.classList.remove("show")); }
  function createSidebar(){ const p=document.createElement("div"); p.id="ht-ai-panel"; p.innerHTML=`<div id="ht-ai-header"><strong>HackTricks Chat</strong><div class="ht-actions"><button id="ht-ai-reset" title="Reset">↺</button><span id="ht-ai-close" title="Close">✖</span></div></div><div id="ht-ai-chat"></div><div id="ht-ai-input"><textarea id="ht-ai-question" placeholder="Type your question…"></textarea><button id="ht-ai-send">Send</button></div>`; document.body.appendChild(p); return p; }
})();
