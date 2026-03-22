# कंटेनर सुरक्षा अवलोकन

{{#include ../../../../banners/hacktricks-training.md}}

कंटेनर हार्डनिंग में सबसे महत्वपूर्ण विचार यह है कि "container security" नाम का कोई एकल नियंत्रण नहीं होता। जो लोग container isolation कहते हैं, वह वास्तव में कई Linux सुरक्षा और resource-management मैकेनिज्म का एक साथ काम करने का नतीजा है। अगर दस्तावेज़ केवल उनमें से किसी एक का वर्णन करते हैं, तो पाठक उसकी ताकत को अधिक आंका कर सकते हैं। अगर दस्तावेज़ सभी का नाम सूचीबद्ध करते हैं बिना यह समझाए कि वे कैसे इंटरैक्ट करते हैं, तो पाठक केवल नामों की सूची पा लेते हैं पर कोई वास्तविक मॉडल नहीं मिलता। यह सेक्शन इन दोनों गलतियों से बचने की कोशिश करता है।

मॉडल के केंद्र में हैं **namespaces**, जो यह अलग करते हैं कि workload क्या देख सकता है। वे प्रोसेस को filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, और कुछ क्लॉक्स का निजी या आंशिक निजी दृश्य देते हैं। लेकिन केवल namespaces यह तय नहीं करते कि किसी प्रक्रिया को क्या करने की अनुमति है। इसी बिंदु पर अगली परतें प्रवेश करती हैं।

**cgroups** resource उपयोग को नियंत्रित करते हैं। वे मूलतः mount या PID namespaces जैसी अलगाव सीमा नहीं हैं, लेकिन वे ऑपरेशनल रूप से महत्वपूर्ण हैं क्योंकि वे memory, CPU, PIDs, I/O, और device access को सीमित करते हैं। इनका security संबंध भी है क्योंकि ऐतिहासिक breakout तकनीकों ने writable cgroup फीचर्स का फायदा उठाया है, खासकर cgroup v1 पर्यावरणों में।

**Capabilities** पुराने सर्वशक्तिमान root मॉडल को छोटे privilege यूनिट्स में विभाजित करते हैं। यह कंटेनरों के लिए मूलभूत है क्योंकि कई workloads अभी भी container के अंदर UID 0 के रूप में चलते हैं। इसलिए प्रश्न केवल "क्या प्रक्रिया root है?" नहीं है, बल्कि "कौन सी capabilities बची हैं, किन namespaces के अंदर, किन seccomp और MAC प्रतिबंधों के तहत?" यही कारण है कि एक container में root प्रक्रिया अपेक्षाकृत constrained हो सकती है जबकि दूसरे container में root प्रक्रिया व्यवहार में host root से लगभग अलग नहीं हो सकती।

**seccomp** syscalls को फ़िल्टर करता है और workload को दिखने वाले kernel attack surface को घटाता है। अक्सर यह वह मैकेनिज्म होता है जो स्पष्ट रूप से ख़तरनाक कॉल्स जैसे `unshare`, `mount`, `keyctl`, या breakout chaînes में प्रयुक्त अन्य syscalls को रोकता है। भले ही किसी प्रक्रिया के पास ऐसी capability हो जो सामान्यतः किसी ऑपरेशन की अनुमति देती हो, seccomp फिर भी syscall path को ब्लॉक कर सकता है इससे पहले कि kernel उसे पूरी तरह प्रोसेस करे।

**AppArmor** और **SELinux** सामान्य filesystem और privilege चेक्स के ऊपर Mandatory Access Control जोड़ते हैं। ये विशेष रूप से महत्वपूर्ण हैं क्योंकि ये तब भी मायने रखते हैं जब किसी container के पास अपेक्षित से अधिक capabilities होती हैं। किसी workload के पास सैद्धांतिक रूप से किसी क्रिया का प्रयत्न करने का privilege हो सकता है पर फिर भी उसे रोका जा सकता है क्योंकि उसका label या profile संबंधित path, object, या operation पर पहुँच को मना करता है।

अंत में, कुछ अतिरिक्त hardening परतें हैं जिन पर कम ध्यान जाता है पर वास्तविक हमलों में अक्सर महत्व होता है: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, और सावधानीपूर्वक runtime defaults। ये मैकेनिज्म अक्सर compromise के "last mile" को रोकते हैं, खासकर जब कोई attacker code execution को व्यापक privilege प्राप्ति में बदलने की कोशिश करता है।

इस फ़ोल्डर के बाकी हिस्से में इन में से प्रत्येक मैकेनिज्म का अधिक विवरण है, जिसमें kernel primitive असल में क्या करता है, इसे लोकली कैसे अवलोकित करें, सामान्य runtimes इसे कैसे उपयोग करते हैं, और ऑपरेटर इसे अनजाने में कैसे कमजोर कर सकते हैं।

## इसके बाद पढ़ें

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

कई वास्तविक escapes इस बात पर भी निर्भर करते हैं कि host का कौन सा content workload में mount किया गया था, इसलिए core protections पढ़ने के बाद यह उपयोगी होगा कि आप आगे पढ़ें:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
