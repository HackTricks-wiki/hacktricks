# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unashughulikia mbinu zinazotumiwa na wahusika wa vitisho kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, uhandisi wa kijamii, maduka ya uwongo, programu za uchumba, n.k.).
> Nyenzo hii imebadilishwa kutoka kwa kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Jisajili majina ya kikoa yanayofanana (uchumba, kushiriki wingu, huduma za magari…).
– Tumia maneno muhimu ya lugha ya ndani na emojis katika kipengele cha `<title>` ili kuorodheshwa kwenye Google.
– Weka *zote* Android (`.apk`) na maelekezo ya usakinishaji wa iOS kwenye ukurasa mmoja wa kutua.
2. **First Stage Download**
* Android: kiungo cha moja kwa moja kwa APK *isiyo na saini* au “duka la upande wa tatu”.
* iOS: `itms-services://` au kiungo cha HTTPS wazi kwa profaili ya **mobileconfig** hatari (angalia hapa chini).
3. **Post-install Social Engineering**
* Katika kuanza kwa kwanza, programu inahitaji **nambari ya mwaliko / uthibitisho** (dhana ya ufikiaji wa kipekee).
* Nambari hiyo inatumwa **POST kupitia HTTP** kwa Command-and-Control (C2).
* C2 inajibu `{"success":true}` ➜ malware inaendelea.
* Uchambuzi wa dynamic wa Sandbox / AV ambao hauwasilishi nambari halali unaona **hakuna tabia hatari** (kuepuka).
4. **Runtime Permission Abuse** (Android)
* Ruhusa hatari zinahitajiwa tu **baada ya majibu chanya kutoka C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Mifano ya zamani pia ilihitaji ruhusa za SMS -->
```
* Mifano ya hivi karibuni **ondoa `<uses-permission>` kwa SMS kutoka `AndroidManifest.xml`** lakini inacha njia ya msimbo wa Java/Kotlin inayosoma SMS kupitia reflection ⇒ inapunguza alama ya static wakati bado inafanya kazi kwenye vifaa vinavyotoa ruhusa kupitia unyanyasaji wa `AppOps` au malengo ya zamani.
5. **Facade UI & Background Collection**
* Programu inaonyesha maoni yasiyo na madhara (mtazamaji wa SMS, mchaguo wa picha) iliyotekelezwa kwa ndani.
* Wakati huo inatoa:
- IMEI / IMSI, nambari ya simu
- Tupa kamili ya `ContactsContract` (JSON array)
- JPEG/PNG kutoka `/sdcard/DCIM` iliyoshinikizwa na [Luban](https://github.com/Curzibn/Luban) ili kupunguza ukubwa
- Maudhui ya SMS ya hiari (`content://sms`)
Payloads ni **batch-zipped** na kutumwa kupitia `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Profaili moja ya **mobile-configuration** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. kujiandikisha kifaa katika usimamizi kama “MDM”.
* Maelekezo ya uhandisi wa kijamii:
1. Fungua Mipangilio ➜ *Profaili imeshushwa*.
2. Bonyeza *Sakinisha* mara tatu (picha za skrini kwenye ukurasa wa phishing).
3. Amini profaili isiyo na saini ➜ mshambuliaji anapata *Contacts* & *Photo* haki bila ukaguzi wa Duka la Programu.
7. **Network Layer**
* HTTP wazi, mara nyingi kwenye bandari 80 na kichwa cha HOST kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, otomatisha awamu ya nambari ya mwaliko kwa Frida/Objection ili kufikia tawi hatari.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na `PackageManager#getRequestedPermissions()` ya wakati wa kukimbia; kukosekana kwa ruhusa hatari ni bendera nyekundu.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua milipuko isiyo thabiti ya POST baada ya kuingiza nambari.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS kuorodhesha `PayloadContent` na kugundua haki nyingi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ili kukamata milipuko ya ghafla ya majina ya kikoa yenye maneno muhimu.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` kutoka kwa wateja wa Dalvik nje ya Google Play.
* **Invite-code Telemetry** – POST ya nambari za nambari za 6–8 mara tu baada ya usakinishaji wa APK inaweza kuashiria hatua ya maandalizi.
* **MobileConfig Signing** – Zuia profaili za usanidi zisizo na saini kupitia sera ya MDM.

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
## Ishara (Kawaida)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## Marejeo

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
