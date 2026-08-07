# Container Protections का अवलोकन

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening में सबसे महत्वपूर्ण विचार यह है कि "container security" नाम का कोई एकल control नहीं होता। जिसे लोग container isolation कहते हैं, वह वास्तव में कई Linux security और resource-management mechanisms के साथ मिलकर काम करने का परिणाम है। यदि documentation इनमें से केवल एक mechanism का वर्णन करती है, तो readers उसकी strength को जरूरत से अधिक आंकने लगते हैं। यदि documentation interaction समझाए बिना इन सभी के नामों की सूची देती है, तो readers को नामों की catalog तो मिल जाती है, लेकिन कोई वास्तविक model नहीं मिलता। यह section दोनों गलतियों से बचने का प्रयास करता है।

इस model के केंद्र में **namespaces** हैं, जो यह isolate करते हैं कि workload क्या देख सकता है। ये process को filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths और कुछ clocks का private या partially private view देते हैं। लेकिन namespaces अकेले यह तय नहीं करते कि process क्या करने की अनुमति रखता है। यहीं अगली layers काम आती हैं।

**cgroups** resource usage को नियंत्रित करते हैं। ये mount या PID namespaces के समान अर्थ में मुख्यतः isolation boundary नहीं हैं, लेकिन operational रूप से अत्यंत महत्वपूर्ण हैं क्योंकि ये memory, CPU, PIDs, I/O और device access को सीमित करते हैं। इनका security relevance भी है क्योंकि historical breakout techniques ने writable cgroup features का दुरुपयोग किया था, विशेष रूप से cgroup v1 environments में।

**Capabilities** पुराने all-powerful root model को छोटे privilege units में विभाजित करती हैं। Containers के लिए यह fundamental है क्योंकि कई workloads अभी भी container के अंदर UID 0 के रूप में चलते हैं। इसलिए प्रश्न केवल "क्या process root है?" नहीं है, बल्कि "कौन-सी capabilities बची हैं, किन namespaces के अंदर, और किन seccomp तथा MAC restrictions के अंतर्गत?" यही कारण है कि एक container में root process अपेक्षाकृत constrained हो सकता है, जबकि दूसरे container में root process व्यवहार में host root से लगभग अलग पहचान में नहीं आता।

**seccomp** syscalls को filter करता है और workload के सामने मौजूद kernel attack surface को कम करता है। अक्सर यही mechanism स्पष्ट रूप से खतरनाक calls जैसे `unshare`, `mount`, `keyctl` या breakout chains में उपयोग किए जाने वाले अन्य syscalls को block करता है। यदि किसी process के पास ऐसी capability भी हो जो सामान्यतः किसी operation की अनुमति देती, तब भी seccomp syscall path को block कर सकता है, इससे पहले कि kernel उसे पूरी तरह process करे।

**AppArmor** और **SELinux** सामान्य filesystem और privilege checks के ऊपर Mandatory Access Control जोड़ते हैं। ये विशेष रूप से महत्वपूर्ण हैं क्योंकि तब भी प्रभावी रहते हैं जब container के पास आवश्यकता से अधिक capabilities हों। किसी workload के पास किसी action का प्रयास करने के लिए theoretical privilege हो सकता है, लेकिन फिर भी वह उसे पूरा करने से रोका जा सकता है क्योंकि उसका label या profile संबंधित path, object या operation तक access को प्रतिबंधित करता है।

अंत में, कुछ अतिरिक्त hardening layers हैं जिन पर कम ध्यान दिया जाता है, लेकिन real attacks में उनका नियमित रूप से महत्व होता है: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems और सावधानीपूर्वक निर्धारित runtime defaults। ये mechanisms अक्सर compromise के "last mile" को रोकते हैं, विशेष रूप से तब जब attacker code execution को व्यापक privilege gain में बदलने का प्रयास करता है।

इस folder के बाकी भाग में इनमें से प्रत्येक mechanism को अधिक विस्तार से समझाया गया है, जिसमें यह भी शामिल है कि संबंधित kernel primitive वास्तव में क्या करता है, इसे locally कैसे observe करें, common runtimes इसका उपयोग कैसे करते हैं और operators अनजाने में इसे कैसे कमजोर कर देते हैं।

## आगे पढ़ें

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

कई वास्तविक escapes इस बात पर भी निर्भर करते हैं कि workload में host का कौन-सा content mount किया गया था। इसलिए core protections पढ़ने के बाद आगे पढ़ना उपयोगी है:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
