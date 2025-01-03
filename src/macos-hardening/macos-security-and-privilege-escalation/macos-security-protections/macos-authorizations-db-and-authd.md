# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Athorizarions DB**

डेटाबेस `/var/db/auth.db` में स्थित है, जो संवेदनशील ऑपरेशनों को करने के लिए अनुमतियों को स्टोर करने के लिए उपयोग किया जाता है। ये ऑपरेशन पूरी तरह से **उपयोगकर्ता स्थान** में किए जाते हैं और आमतौर पर **XPC सेवाओं** द्वारा उपयोग किए जाते हैं जिन्हें यह जांचने की आवश्यकता होती है कि **क्या कॉलिंग क्लाइंट को विशेष क्रिया करने के लिए अधिकृत किया गया है** इस डेटाबेस की जांच करके।

शुरुआत में, यह डेटाबेस `/System/Library/Security/authorization.plist` की सामग्री से बनाया जाता है। फिर, कुछ सेवाएँ इस डेटाबेस में अन्य अनुमतियाँ जोड़ने या संशोधित करने के लिए इसे जोड़ सकती हैं।

नियम डेटाबेस के अंदर `rules` तालिका में संग्रहीत होते हैं और निम्नलिखित कॉलम होते हैं:

- **id**: प्रत्येक नियम के लिए एक अद्वितीय पहचानकर्ता, स्वचालित रूप से बढ़ता है और प्राथमिक कुंजी के रूप में कार्य करता है।
- **name**: नियम का अद्वितीय नाम जिसका उपयोग इसे पहचानने और अधिकृत प्रणाली के भीतर संदर्भित करने के लिए किया जाता है।
- **type**: नियम के प्रकार को निर्दिष्ट करता है, इसके अधिकृत तर्क को परिभाषित करने के लिए 1 या 2 के मानों तक सीमित है।
- **class**: नियम को एक विशिष्ट वर्ग में वर्गीकृत करता है, यह सुनिश्चित करते हुए कि यह एक सकारात्मक पूर्णांक है।
- "allow" अनुमति के लिए, "deny" अस्वीकृति के लिए, "user" यदि समूह संपत्ति ने एक समूह को इंगित किया है जिसकी सदस्यता पहुँच की अनुमति देती है, "rule" एक नियम को पूरा करने के लिए एक सरणी में इंगित करता है, "evaluate-mechanisms" के बाद एक `mechanisms` सरणी होती है जो या तो अंतर्निहित होती है या `/System/Library/CoreServices/SecurityAgentPlugins/` या /Library/Security//SecurityAgentPlugins के अंदर एक बंडल का नाम होता है।
- **group**: समूह-आधारित अधिकृत के लिए नियम से संबंधित उपयोगकर्ता समूह को इंगित करता है।
- **kofn**: "k-of-n" पैरामीटर का प्रतिनिधित्व करता है, यह निर्धारित करता है कि कुल संख्या में से कितने उपनियमों को संतुष्ट किया जाना चाहिए।
- **timeout**: उस अवधि को परिभाषित करता है जो नियम द्वारा दी गई अधिकृत समाप्त होने से पहले सेकंड में होती है।
- **flags**: विभिन्न ध्वजों को शामिल करता है जो नियम के व्यवहार और विशेषताओं को संशोधित करते हैं।
- **tries**: सुरक्षा बढ़ाने के लिए अनुमत अधिकृत प्रयासों की संख्या को सीमित करता है।
- **version**: संस्करण नियंत्रण और अपडेट के लिए नियम के संस्करण को ट्रैक करता है।
- **created**: ऑडिटिंग उद्देश्यों के लिए नियम के निर्माण का समय रिकॉर्ड करता है।
- **modified**: नियम में किए गए अंतिम संशोधन का समय संग्रहीत करता है।
- **hash**: नियम की अखंडता सुनिश्चित करने और छेड़छाड़ का पता लगाने के लिए नियम का हैश मान रखता है।
- **identifier**: नियम के लिए बाहरी संदर्भों के लिए एक अद्वितीय स्ट्रिंग पहचानकर्ता, जैसे UUID, प्रदान करता है।
- **requirement**: नियम की विशिष्ट अधिकृत आवश्यकताओं और तंत्रों को परिभाषित करने वाले अनुक्रमित डेटा को शामिल करता है।
- **comment**: दस्तावेज़ीकरण और स्पष्टता के लिए नियम के बारे में एक मानव-पठनीय विवरण या टिप्पणी प्रदान करता है।

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
इसके अलावा [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) पर `authenticate-admin-nonshared` का अर्थ देखना संभव है:
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

यह एक डेमन है जो संवेदनशील क्रियाओं को करने के लिए क्लाइंट्स को अधिकृत करने के लिए अनुरोध प्राप्त करेगा। यह `XPCServices/` फ़ोल्डर के अंदर परिभाषित एक XPC सेवा के रूप में काम करता है और अपने लॉग `/var/log/authd.log` में लिखता है।

इसके अलावा, सुरक्षा उपकरण का उपयोग करके कई `Security.framework` APIs का परीक्षण करना संभव है। उदाहरण के लिए, `AuthorizationExecuteWithPrivileges` चलाते समय: `security execute-with-privileges /bin/ls`

यह `/usr/libexec/security_authtrampoline /bin/ls` को रूट के रूप में फोर्क और एक्सेक करेगा, जो रूट के रूप में ls निष्पादित करने के लिए अनुमतियों के लिए एक प्रॉम्प्ट में पूछेगा:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
