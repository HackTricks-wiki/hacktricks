# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

`/var/db/auth.db` में स्थित database, sensitive operations को perform करने की permissions store करने के लिए उपयोग किया जाता है। ये operations पूरी तरह **user space** में perform किए जाते हैं और आमतौर पर **XPC services** द्वारा उपयोग किए जाते हैं, जिन्हें इस database को check करके यह निर्धारित करना होता है कि **calling client** किसी action को perform करने के लिए **authorized** है या नहीं।

शुरुआत में यह database `/System/Library/Security/authorization.plist` के content से बनाया जाता है। इसके बाद, कुछ services इसमें अन्य permissions जोड़ने के लिए इस database को modify या update कर सकती हैं।

Rules को database के अंदर `rules` table में store किया जाता है, जिसमें निम्नलिखित columns होते हैं:

- **id**: प्रत्येक rule के लिए एक unique identifier, जो automatically increment होता है और primary key के रूप में कार्य करता है।
- **name**: Rule का unique name, जिसका उपयोग authorization system के अंदर उसे identify और reference करने के लिए किया जाता है।
- **type**: Rule के type को specify करता है। यह 1 या 2 values तक सीमित होता है, जो इसकी authorization logic को define करती हैं।
- **class**: Rule को एक specific class में categorize करता है और यह सुनिश्चित करता है कि यह एक positive integer हो।
- "allow" का अर्थ allow, "deny" का अर्थ deny, "user" तब उपयोग होता है जब group property किसी ऐसे group को indicate करती है जिसकी membership access की अनुमति देती है, "rule" एक array में उस rule को indicate करता है जिसे fulfill करना आवश्यक है, और "evaluate-mechanisms" के बाद एक `mechanisms` array होता है, जिसमें या तो builtins होते हैं या `/System/Library/CoreServices/SecurityAgentPlugins/` अथवा `/Library/Security//SecurityAgentPlugins` के अंदर किसी bundle का name होता है।
- **group**: Group-based authorization के लिए rule से associated user group को indicate करता है।
- **kofn**: "k-of-n" parameter को represent करता है, जो यह निर्धारित करता है कि total संख्या में से कितने subrules satisfy होने चाहिए।
- **timeout**: Rule द्वारा दी गई authorization के expire होने से पहले की अवधि को seconds में define करता है।
- **flags**: विभिन्न flags contain करता है, जो rule के behavior और characteristics को modify करते हैं।
- **tries**: Security बढ़ाने के लिए allowed authorization attempts की संख्या को limit करता है।
- **version**: Version control और updates के लिए rule के version को track करता है।
- **created**: Auditing purposes के लिए rule के create होने का timestamp record करता है।
- **modified**: Rule में किए गए last modification का timestamp store करता है।
- **hash**: Rule की integrity सुनिश्चित करने और tampering detect करने के लिए उसका hash value रखता है।
- **identifier**: External references के लिए एक unique string identifier, जैसे UUID, provide करता है।
- **requirement**: Rule की specific authorization requirements और mechanisms को define करने वाला serialized data contain करता है।
- **comment**: Documentation और clarity के लिए rule का human-readable description या comment provide करता है।

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
इसके अलावा, [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) में `authenticate-admin-nonshared` का अर्थ देखा जा सकता है:<sup>[[1]](#references)</sup>
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

यह एक daemon है जो clients को sensitive actions करने के लिए authorize करने के requests receive करता है। यह `XPCServices/` folder के अंदर defined XPC service के रूप में काम करता है और अपने logs `/var/log/authd.log` में write करता है।

इसके अलावा, security tool का उपयोग करके कई `Security.framework` APIs को test करना संभव है। उदाहरण के लिए, `AuthorizationExecuteWithPrivileges` को इस तरह run किया जा सकता है: `security execute-with-privileges /bin/ls`

यह `/usr/libexec/security_authtrampoline /bin/ls` को root के रूप में fork और exec करेगा, जिसके बाद root के रूप में ls execute करने के लिए एक prompt में permissions मांगी जाएंगी:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [macOS Authorization Right का authenticate-admin-nonshared - Overview](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
