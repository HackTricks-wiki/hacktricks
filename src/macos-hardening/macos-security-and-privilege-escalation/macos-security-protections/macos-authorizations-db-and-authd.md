# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Security framework की Authorization Services privileged helpers और अन्य components को named authorization rights का मूल्यांकन करने देती हैं। वर्तमान macOS versions में, इनमें से कई rules `/var/db/auth.db` में persist किए जाते हैं और `authd` द्वारा evaluate किए जाते हैं; यह file और इसका SQLite schema implementation details हैं और releases के बीच बदल सकते हैं।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

System defaults ऐतिहासिक रूप से `/System/Library/Security/authorization.plist` से seed किए जाते रहे हैं, और installers या privileged services named rights जोड़ सकते हैं। Database को सीधे edit करने के बजाय supported `security authorizationdb read|write|remove` interface को प्राथमिकता दें।<sup>[[3]](#references)</sup>

Documented build पर देखी गई `rules` table में निम्नलिखित columns हैं। इसे stable public schema के बजाय forensic map मानें:

- **id**: प्रत्येक rule के लिए एक unique identifier, जो automatically increment होता है और primary key के रूप में कार्य करता है।
- **name**: rule का unique name, जिसका उपयोग authorization system के भीतर इसे identify और reference करने के लिए किया जाता है।
- **type**: rule का type निर्दिष्ट करता है, जो 1 या 2 values तक सीमित होता है और इसकी authorization logic को define करता है।
- **class**: rule को एक specific class में categorize करता है और यह सुनिश्चित करता है कि वह positive integer हो।
- सामान्य rule classes में `allow`, `deny`, `user`, `rule`, और `evaluate-mechanisms` शामिल हैं। Mechanisms built-ins या `/System/Library/CoreServices/SecurityAgentPlugins/` अथवा `/Library/Security/SecurityAgentPlugins/` के अंतर्गत मौजूद Security Agent plug-ins हो सकते हैं।<sup>[[2]](#references)</sup>
- **group**: group-based authorization के लिए rule से associated user group को दर्शाता है।
- **kofn**: "k-of-n" parameter को दर्शाता है, जो निर्धारित करता है कि total number में से कितने subrules satisfy होने चाहिए।
- **timeout**: rule द्वारा granted authorization expire होने से पहले की duration को seconds में define करता है।
- **flags**: rule के behavior और characteristics को modify करने वाले विभिन्न flags रखता है।
- **tries**: security बढ़ाने के लिए allowed authorization attempts की संख्या को सीमित करता है।
- **version**: version control और updates के लिए rule का version track करता है।
- **created**: auditing purposes के लिए rule create किए जाने का timestamp record करता है।
- **modified**: rule में किए गए अंतिम modification का timestamp store करता है।
- **hash**: rule की integrity सुनिश्चित करने और tampering detect करने के लिए उसका hash value रखता है।
- **identifier**: rule के external references के लिए एक unique string identifier, जैसे UUID, प्रदान करता है।
- **requirement**: rule की specific authorization requirements और mechanisms को define करने वाला serialized data रखता है।
- **comment**: documentation और clarity के लिए rule का human-readable description या comment प्रदान करता है।

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
निम्नलिखित decoded rule एक documented macOS version पर `authenticate-admin-nonshared` को दर्शाता है:<sup>[[1]](#references)</sup>
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

`authd` वह XPC service है जो Authorization Services requests का evaluation करती है। वर्तमान macOS builds में इसके bundle का निरीक्षण `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` पर किया जा सकता है; यह path implementation detail है और अलग-अलग releases में बदल सकता है। पुराने releases `/var/log/authd.log` में लिखते थे; वर्तमान releases मुख्य रूप से unified logging system का उपयोग करते हैं, जिसे `authd` process predicate के साथ `log show`/`log stream` द्वारा query किया जा सकता है।<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

`security` tool कई Authorization Services operations उपलब्ध कराता है। एक historical example `security execute-with-privileges /bin/ls` के साथ `AuthorizationExecuteWithPrivileges` invoke करता है। Apple ने macOS 10.7 में उस API को deprecated कर दिया; modern privileged helpers को इसके बजाय launchd-managed helper और XPC authorization का उपयोग करना चाहिए।<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

जिन releases में यह अभी भी supported है, उनमें यह `/usr/libexec/security_authtrampoline` का उपयोग करता है और command को root के रूप में चलाने से पहले authorization prompt दिखाता है:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right का overview](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: launchd jobs बनाना](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security project - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
