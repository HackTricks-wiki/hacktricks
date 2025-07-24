# मोबाइल फ़िशिंग और दुर्भावनापूर्ण ऐप वितरण (Android और iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पृष्ठ उन तकनीकों को कवर करता है जो खतरे के अभिनेताओं द्वारा **दुर्भावनापूर्ण Android APKs** और **iOS मोबाइल-कॉन्फ़िगरेशन प्रोफाइल** को फ़िशिंग (SEO, सोशल इंजीनियरिंग, फर्जी स्टोर, डेटिंग ऐप्स, आदि) के माध्यम से वितरित करने के लिए उपयोग की जाती हैं।
> सामग्री को Zimperium zLabs (2025) द्वारा उजागर किए गए SarangTrap अभियान और अन्य सार्वजनिक अनुसंधान से अनुकूलित किया गया है।

## हमले का प्रवाह

1. **SEO/फ़िशिंग अवसंरचना**
* दर्जनों समान दिखने वाले डोमेन (डेटिंग, क्लाउड शेयर, कार सेवा…) को पंजीकृत करें।
– Google में रैंक करने के लिए `<title>` तत्व में स्थानीय भाषा के कीवर्ड और इमोजी का उपयोग करें।
– *दोनों* Android (`.apk`) और iOS इंस्टॉलेशन निर्देशों को एक ही लैंडिंग पृष्ठ पर होस्ट करें।
2. **पहला चरण डाउनलोड**
* Android: *unsigned* या "तीसरे पक्ष के स्टोर" APK के लिए सीधा लिंक।
* iOS: `itms-services://` या दुर्भावनापूर्ण **mobileconfig** प्रोफाइल के लिए सामान्य HTTPS लिंक (नीचे देखें)।
3. **पोस्ट-इंस्टॉल सोशल इंजीनियरिंग**
* पहले रन पर ऐप **आमंत्रण / सत्यापन कोड** (विशेष पहुंच का भ्रम) के लिए पूछता है।
* कोड **HTTP के माध्यम से POST** किया जाता है Command-and-Control (C2) पर।
* C2 जवाब देता है `{"success":true}` ➜ मैलवेयर जारी रहता है।
* सैंडबॉक्स / AV डायनामिक विश्लेषण जो कभी भी एक मान्य कोड प्रस्तुत नहीं करता है, **कोई दुर्भावनापूर्ण व्यवहार नहीं देखता** (निष्कासन)।
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
पेलोड्स **बैच-ज़िप** किए जाते हैं और `HTTP POST /upload.php` के माध्यम से भेजे जाते हैं।
6. **iOS वितरण तकनीक**
* एकल **mobile-configuration प्रोफाइल** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध कर सकता है ताकि डिवाइस को "MDM"-जैसी पर्यवेक्षण में नामांकित किया जा सके।
* सोशल-इंजीनियरिंग निर्देश:
1. सेटिंग्स खोलें ➜ *प्रोफ़ाइल डाउनलोड किया गया*।
2. *इंस्टॉल* पर तीन बार टैप करें (फ़िशिंग पृष्ठ पर स्क्रीनशॉट)।
3. बिना हस्ताक्षर वाले प्रोफ़ाइल पर भरोसा करें ➜ हमलावर *संपर्क* और *फोटो* अधिकार प्राप्त करता है बिना ऐप स्टोर समीक्षा के।
7. **नेटवर्क परत**
* सामान्य HTTP, अक्सर पोर्ट 80 पर HOST हेडर के साथ जैसे `api.<phishingdomain>.com`।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (कोई TLS → पहचानना आसान)।

## रक्षा परीक्षण / रेड-टीम सुझाव

* **डायनामिक विश्लेषण बायपास** – मैलवेयर मूल्यांकन के दौरान, निमंत्रण कोड चरण को Frida/Objection के साथ स्वचालित करें ताकि दुर्भावनापूर्ण शाखा तक पहुंच सकें।
* **Manifest बनाम रनटाइम डिफ़** – `aapt dump permissions` की तुलना करें रनटाइम `PackageManager#getRequestedPermissions()` के साथ; खतरनाक अनुमतियों का गायब होना एक लाल झंडा है।
* **नेटवर्क कैनरी** – कोड प्रविष्टि के बाद असंगत POST बर्स्ट का पता लगाने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` कॉन्फ़िगर करें।
* **mobileconfig निरीक्षण** – `security cms -D -i profile.mobileconfig` का उपयोग करें macOS पर `PayloadContent` को सूचीबद्ध करने और अत्यधिक अधिकारों को पहचानने के लिए।

## ब्लू-टीम पहचान विचार

* **सर्टिफिकेट पारदर्शिता / DNS विश्लेषण** अचानक कीवर्ड-समृद्ध डोमेन के बर्स्ट को पकड़ने के लिए।
* **User-Agent और पथ Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik क्लाइंट से Google Play के बाहर।
* **आमंत्रण-कोड टेलीमेट्री** – APK इंस्टॉल के तुरंत बाद 6–8 अंकों के संख्यात्मक कोड का POST स्टेजिंग का संकेत दे सकता है।
* **MobileConfig साइनिंग** – बिना हस्ताक्षर वाले कॉन्फ़िगरेशन प्रोफाइल को MDM नीति के माध्यम से अवरुद्ध करें।

## उपयोगी Frida स्निपेट: ऑटो-बायपास निमंत्रण कोड
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
## संदर्भ

- [रोमांस का अंधेरा पक्ष: सरंगट्रैप जबरन वसूली अभियान](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [लुबान – एंड्रॉइड इमेज संकुचन पुस्तकालय](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
