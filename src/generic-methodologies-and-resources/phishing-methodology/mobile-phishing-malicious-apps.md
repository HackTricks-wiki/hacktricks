# Phishing Mobile & Distribution d'Applications Malveillantes (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par les acteurs de la menace pour distribuer des **APK Android malveillants** et des **profils de configuration mobile iOS** via le phishing (SEO, ingénierie sociale, faux magasins, applications de rencontre, etc.).
> Le matériel est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d'autres recherches publiques.

## Flux d'Attaque

1. **Infrastructure SEO/Phishing**
* Enregistrer des dizaines de domaines similaires (rencontre, partage de cloud, service de voiture…).
– Utiliser des mots-clés et des emojis en langue locale dans l'élément `<title>` pour se classer sur Google.
– Héberger *à la fois* les instructions d'installation Android (`.apk`) et iOS sur la même page d'atterrissage.
2. **Téléchargement de Première Étape**
* Android : lien direct vers un APK *non signé* ou “magasin tiers”.
* iOS : `itms-services://` ou lien HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Ingénierie Sociale Post-Installation**
* Au premier lancement, l'application demande un **code d'invitation / de vérification** (illusion d'accès exclusif).
* Le code est **POSTé en HTTP** vers le Command-and-Control (C2).
* C2 répond `{"success":true}` ➜ le malware continue.
* L'analyse dynamique Sandbox / AV qui ne soumet jamais un code valide ne voit **aucun comportement malveillant** (évasion).
4. **Abus de Permissions d'Exécution** (Android)
* Les permissions dangereuses ne sont demandées **qu'après une réponse positive du C2** :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Les anciennes versions demandaient également des permissions SMS -->
```
* Les variantes récentes **suppriment `<uses-permission>` pour SMS de `AndroidManifest.xml`** mais laissent le chemin de code Java/Kotlin qui lit les SMS par réflexion ⇒ abaisse le score statique tout en restant fonctionnel sur les appareils qui accordent la permission via un abus de `AppOps` ou d'anciens cibles.
5. **Interface Facade & Collecte en Arrière-plan**
* L'application montre des vues inoffensives (visualiseur de SMS, sélecteur de galerie) implémentées localement.
* Pendant ce temps, elle exfiltre :
- IMEI / IMSI, numéro de téléphone
- Dump complet de `ContactsContract` (tableau JSON)
- JPEG/PNG de `/sdcard/DCIM` compressé avec [Luban](https://github.com/Curzibn/Luban) pour réduire la taille
- Contenu SMS optionnel (`content://sms`)
Les charges utiles sont **compressées par lots** et envoyées via `HTTP POST /upload.php`.
6. **Technique de Livraison iOS**
* Un seul **profil de configuration mobile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. pour inscrire l'appareil dans une supervision de type “MDM”.
* Instructions d'ingénierie sociale :
1. Ouvrir Réglages ➜ *Profil téléchargé*.
2. Appuyer sur *Installer* trois fois (captures d'écran sur la page de phishing).
3. Faire confiance au profil non signé ➜ l'attaquant obtient les droits *Contacts* & *Photo* sans révision de l'App Store.
7. **Couche Réseau**
* HTTP simple, souvent sur le port 80 avec un en-tête HOST comme `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Tests Défensifs / Conseils pour Équipe Rouge

* **Bypass d'Analyse Dynamique** – Lors de l'évaluation du malware, automatisez la phase de code d'invitation avec Frida/Objection pour atteindre la branche malveillante.
* **Différence Manifest vs. Runtime** – Comparez `aapt dump permissions` avec `PackageManager#getRequestedPermissions()` à l'exécution ; l'absence de permissions dangereuses est un signal d'alarme.
* **Canari Réseau** – Configurez `iptables -p tcp --dport 80 -j NFQUEUE` pour détecter des pics de POST non solides après la saisie du code.
* **Inspection de mobileconfig** – Utilisez `security cms -D -i profile.mobileconfig` sur macOS pour lister `PayloadContent` et repérer des droits excessifs.

## Idées de Détection pour Équipe Bleue

* **Transparence des Certificats / Analytique DNS** pour attraper des pics soudains de domaines riches en mots-clés.
* **User-Agent & Regex de Chemin** : `(?i)POST\s+/(check|upload)\.php` des clients Dalvik en dehors de Google Play.
* **Télémetrie de Code d'Invitation** – POST de codes numériques de 6 à 8 chiffres peu après l'installation de l'APK peut indiquer une mise en scène.
* **Signature de MobileConfig** – Bloquez les profils de configuration non signés via la politique MDM.

## Extrait Frida Utile : Bypass Automatique du Code d'Invitation
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
## Indicateurs (Généraux)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## Références

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
