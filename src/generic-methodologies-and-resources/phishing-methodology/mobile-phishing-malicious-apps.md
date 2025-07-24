# Mobiele Phishing & Kwaadwillige App Verspreiding (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **kwaadwillige Android APK's** en **iOS mobiele konfigurasieprofiele** deur phishing (SEO, sosiale ingenieurswese, vals winkels, dating-apps, ens.) te versprei.
> Die materiaal is aangepas van die SarangTrap veldtog wat deur Zimperium zLabs (2025) blootgelê is en ander openbare navorsing.

## Aanvalstroom

1. **SEO/Phishing Infrastruktuur**
* Registreer dosyne soortgelyke domeine (dating, wolkdeel, motor diens…).
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
<!-- Ouers bou ook vir SMS toestemmings gevra -->
```
* Onlangse variasies **verwyder `<uses-permission>` vir SMS uit `AndroidManifest.xml`** maar laat die Java/Kotlin kode pad wat SMS deur refleksie lees ⇒ verlaag statiese telling terwyl dit steeds funksioneel is op toestelle wat die toestemming via `AppOps` misbruik of ou teikens.
5. **Fasade UI & Agtergrond Versameling**
* App wys onskadelike uitsigte (SMS kyker, galery kieser) wat plaaslik geïmplementeer is.
* Intussen eksfiltreer dit:
- IMEI / IMSI, telefoonnommer
- Volle `ContactsContract` dump (JSON array)
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
* **Netwerk Kanarie** – Konfigureer `iptables -p tcp --dport 80 -j NFQUEUE` om onsamehangende POST uitbarstings na kode invoer te ontdek.
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
## Verwysings

- [Die Donker Kant van Romantiek: SarangTrap Afpersing Campagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android beeldkompressiebiblioteek](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
