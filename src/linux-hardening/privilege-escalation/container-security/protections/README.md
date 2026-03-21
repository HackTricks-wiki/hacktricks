# कंटेनर सुरक्षा का अवलोकन

{{#include ../../../../banners/hacktricks-training.md}}

कंटेनर हार्डनिंग में सबसे महत्वपूर्ण विचार यह है कि कोई एकल नियंत्रण "container security" नाम से मौजूद नहीं है। जो लोग container isolation कहते हैं, वह वास्तव में कई Linux सुरक्षा और resource-management मैकेनिज्म का एक साथ काम करने का परिणाम है। अगर दस्तावेज़ केवल उनमें से किसी एक का वर्णन करते हैं, तो पाठक उसकी ताकत को बढ़ाकर आंकते हैं। यदि दस्तावेज़ सभी के नाम मात्र सूचीबद्ध कर दे पर यह न बताए कि वे कैसे इंटरैक्ट करते हैं, तो पाठक केवल नामों की सूची पाते हैं पर कोई वास्तविक मॉडल नहीं। यह सेक्शन दोनों गलतियों से बचने की कोशिश करता है।

मॉडल के केंद्र में हैं **namespaces**, जो यह अलग करते हैं कि workload क्या देख सकता है। ये प्रोसेस को निजी या आंशिक निजी दृश्य देते हैं—filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, और कुछ clocks। लेकिन केवल namespaces ही यह तय नहीं करते कि एक प्रोसेस क्या कर सकता है। यही वह जगह है जहाँ अगले लेयर्स आते हैं।

**cgroups** resource उपयोग को नियंत्रित करते हैं। वे mount या PID namespaces जैसे अलगाव सीमा के रूप में प्राथमिक रूप से नहीं हैं, पर ऑपरेशनल रूप से महत्वपूर्ण हैं क्योंकि वे memory, CPU, PIDs, I/O, और device access को सीमित करते हैं। इनके सुरक्षा संबंधी महत्व भी हैं क्योंकि ऐतिहासिक breakout techniques ने writable cgroup सुविधाओं का दुरुपयोग किया है, खासकर cgroup v1 परिवेशों में।

**Capabilities** पुराने सर्वशक्तिमान root मॉडल को छोटे-छोटे privilege यूनिट्स में बाँटते हैं। यह containers के लिए मौलिक है क्योंकि कई workloads अभी भी UID 0 के रूप में container के अंदर चलते हैं। इसलिए सवाल सिर्फ़ "क्या प्रोसेस root है?" नहीं है, बल्कि "किस capabilities ने बचे रखा, किस namespaces के अंदर, किन seccomp और MAC प्रतिबंधों के तहत?" यही कारण है कि एक container में root प्रोसेस अपेक्षाकृत प्रतिबंधित हो सकता है जबकि दूसरे container में root प्रोसेस व्यवहार में host root से लगभग अलग न हो।

**seccomp** syscalls को फिल्टर करता है और workload को एक्सपोज़ किए जाने वाले kernel attack surface को घटाता है। यह अक्सर वह मैकेनिज्म होता है जो स्पष्ट रूप से खतरनाक कॉल्स जैसे कि `unshare`, `mount`, `keyctl`, या अन्य syscalls जिन्हें breakout chains में इस्तेमाल किया जाता है, को ब्लॉक करता है। भले ही किसी प्रोसेस के पास कोई capability हो जो किसी ऑपरेशन की अनुमति देता हो, seccomp फिर भी syscall पाथ को ब्लॉक कर सकता है इससे पहले कि kernel उसे पूरी तरह प्रोसेस करे।

**AppArmor** और **SELinux** सामान्य फाइलसिस्टम और privilege चेक्स पर Mandatory Access Control जोड़ते हैं। ये विशेष रूप से महत्वपूर्ण हैं क्योंकि ये तब भी मायने रखती हैं जब कोई container की capabilities अपेक्षित से अधिक हों। एक workload के पास सैद्धांतिक रूप से किसी कार्रवाई का privilege हो सकता है पर फिर भी उसे उस कार्रवाई को करने से रोका जा सकता है क्योंकि उसका label या profile संबंधित path, object, या operation तक पहुंचने से मना करता है।

अंत में, कुछ अतिरिक्त हार्डनिंग लेयर्स हैं जिनपर कम ध्यान दिया जाता है लेकिन वास्तविक हमलों में नियमित रूप से मायने रखती हैं: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, और सावधानीपूर्वक runtime defaults। ये मैकेनिज्म अक्सर समझौते के "last mile" को रोकते हैं, खासकर जब एक attacker कोड execution को व्यापक privilege प्राप्ति में बदलने की कोशिश करता है।

इस फ़ोल्डर का बाकी हिस्सा इन प्रत्येक मैकेनिज्म को और विस्तार से समझाता है—जिसमें यह भी शामिल है कि kernel primitive वास्तव में क्या करता है, इसे लोकली कैसे अवलोकन करें, सामान्य runtimes इसे कैसे उपयोग करते हैं, और operators कैसे गलती से इसे कमजोर कर देते हैं।

## अगला पढ़ें

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

कई वास्तविक escapes भी इस बात पर निर्भर करते हैं कि host का कौन सा कंटेंट workload में mount किया गया था, इसलिए core protections पढ़ने के बाद यह उपयोगी है कि आप आगे बढ़कर पढ़ें:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
