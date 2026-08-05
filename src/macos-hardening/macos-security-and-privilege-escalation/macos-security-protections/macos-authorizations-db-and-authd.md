# macOS Authorizations DB और Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

`/var/db/auth.db` में स्थित database संवेदनशील operations को perform करने की permissions store करने के लिए उपयोग किया जाता है। ये operations पूरी तरह **user space** में perform किए जाते हैं और आमतौर पर **XPC services** द्वारा उपयोग किए जाते हैं, जिन्हें इस database को check करके यह निर्धारित करना होता है कि **calling client** किसी निश्चित action को perform करने के लिए **authorized** है या नहीं।

शुरुआत में यह database `/System/Library/Security/authorization.plist` की content से बनाया जाता है। इसके बाद, कुछ services इसमें अन्य permissions जोड़ने या data को modify करने के लिए इस database में बदलाव कर सकती हैं।

Rules database के अंदर `rules` table में store किए जाते हैं और इसमें निम्नलिखित columns होते हैं:

- **id**: प्रत्येक rule के लिए एक unique identifier, जो automatically increment होता है और primary key के रूप में कार्य करता है।
- **name**: rule का unique name, जिसका उपयोग authorization system के अंदर उसे identify और reference करने के लिए किया जाता है।
- **type**: rule का type specify करता है। Authorization logic को define करने के लिए यह केवल 1 या 2 values तक सीमित होता है।
- **class**: rule को एक specific class में categorize करता है और यह सुनिश्चित करता है कि वह positive integer हो।
- "allow" allow के लिए, "deny" deny के लिए, "user" तब जब group property किसी ऐसे group को indicate करे जिसकी membership access की अनुमति देती है, "rule" array में पूरी की जाने वाली rule को indicate करता है, और "evaluate-mechanisms" के बाद एक `mechanisms` array होता है, जिसमें या तो builtins होते हैं या `/System/Library/CoreServices/SecurityAgentPlugins/` अथवा `/Library/Security//SecurityAgentPlugins` के अंदर किसी bundle का name होता है।
- **group**: group-based authorization के लिए rule से associated user group को indicate करता है।
- **kofn**: "k-of-n" parameter को represent करता है और यह निर्धारित करता है कि कुल कितनी subrules में से कितनी satisfy करनी होंगी।
- **timeout**: rule द्वारा प्रदान की गई authorization के expire होने से पहले की duration को seconds में define करता है।
- **flags**: विभिन्न flags रखता है, जो rule के behavior और characteristics को modify करते हैं।
- **tries**: security बढ़ाने के लिए allowed authorization attempts की संख्या को limit करता है।
- **version**: version control और updates के लिए rule का version track करता है।
- **created**: auditing purposes के लिए rule के create होने का timestamp record करता है।
- **modified**: rule में किए गए last modification का timestamp store करता है।
- **hash**: rule की integrity सुनिश्चित करने और tampering detect करने के लिए rule की hash value रखता है।
- **identifier**: rule के external references के लिए एक unique string identifier, जैसे UUID, provide करता है।
- **requirement**: rule की specific authorization requirements और mechanisms को define करने वाला serialized data रखता है।
- **comment**: documentation और clarity के लिए rule का human-readable description या comment provide करता है।

### उदाहरण
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
इसके अलावा, [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) में `authenticate-admin-nonshared` का अर्थ देखना संभव है:<sup>[1]</sup>
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

यह एक daemon है जो clients को sensitive actions करने के लिए authorize करने के requests प्राप्त करता है। यह `XPCServices/` फ़ोल्डर के अंदर defined एक XPC service के रूप में काम करता है और अपने logs को `/var/log/authd.log` में लिखता है।

इसके अलावा, security tool का उपयोग करके कई `Security.framework` APIs को test करना संभव है। उदाहरण के लिए, `AuthorizationExecuteWithPrivileges` को चलाना: `security execute-with-privileges /bin/ls`

यह `/usr/libexec/security_authtrampoline /bin/ls` को root के रूप में fork और exec करेगा, जो root के रूप में ls को execute करने के लिए prompt में permissions मांगेगा:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right का overview](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
