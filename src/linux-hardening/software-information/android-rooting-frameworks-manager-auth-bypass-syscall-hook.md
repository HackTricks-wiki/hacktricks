# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot ve Magisk gibi Rooting framework'leri Linux/Android kernel'ini sık sık patch'ler ve hook'lanmış bir syscall aracılığıyla ayrıcalıklı işlevleri ayrıcalıksız bir userspace "manager" uygulamasına sunar. Manager authentication adımı hatalıysa herhangi bir local app bu kanala ulaşabilir ve zaten root'lanmış cihazlarda ayrıcalıklarını yükseltebilir.

Bu sayfa, saldırı ve savunma ekiplerinin attack surface'leri, exploitation primitive'lerini ve sağlam mitigation yöntemlerini anlamasına yardımcı olmak amacıyla public research'te (özellikle Zimperium'un KernelSU v0.5.7 analysis'i) ortaya çıkarılan teknikleri ve pitfalls'ları özetler.

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch bir syscall'ı (genellikle prctl) hook'layarak userspace'ten gelen "command"ları alır.
- Protocol genellikle şöyledir: magic_value, command_id, arg_ptr/len ...
- Bir userspace manager app önce authentication yapar (ör. CMD_BECOME_MANAGER). Kernel caller'ı trusted manager olarak işaretledikten sonra privileged command'lar kabul edilir:
- Caller'a root verme (ör. CMD_GRANT_ROOT)
- su için allowlist/deny-list yönetme
- SELinux policy'yi ayarlama (ör. CMD_SET_SEPOLICY)
- Version/configuration sorgulama
- Her app syscall'ları invoke edebildiğinden manager authentication'ın doğruluğu kritik öneme sahiptir.

Example (KernelSU design):
- Hook'lanmış syscall: prctl
- KernelSU handler'a yönlendirmek için magic value: 0xDEADBEEF
- Command'lar arasında şunlar bulunur: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT vb.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) çağırdığında KernelSU şunları doğrular:

1) Path prefix check
- Sağlanan path, caller UID için beklenen prefix ile başlamalıdır; ör. /data/data/<pkg> veya /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- Path, caller UID tarafından sahiplenilmiş olmalıdır.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) FD table scan aracılığıyla APK signature check
- Calling process'in açık file descriptor'ları (FD'ler) taranır.
- Path'i /data/app/*/base.apk ile eşleşen ilk file seçilir.
- APK v2 signature parse edilir ve official manager certificate'a karşı verify edilir.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

Tüm check'ler geçerse kernel manager'ın UID'sini geçici olarak cache'ler ve reset edilene kadar bu UID'den gelen privileged command'ları kabul eder.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Signature check, process'in FD table'ında bulunan ilk eşleşen /data/app/*/base.apk file'ına bağlanıyorsa caller'ın kendi package'ını gerçekten verify etmiyor demektir. Saldırgan, legitimately signed bir APK'yı (gerçek manager'ın APK'sını) kendi base.apk'sından daha önce FD listesinde görünecek şekilde önceden yerleştirebilir.

Bu trust-by-indirection, ayrıcalıksız bir app'in manager'ın signing key'ine sahip olmadan manager'ı impersonate etmesini sağlar.

Exploited key properties:
- FD scan, caller'ın package identity'siyle bind edilmez; yalnızca path string'leri pattern-match eder.
- open() kullanılabilir en düşük FD'yi döndürür. Saldırgan, önce daha düşük numaralı FD'leri kapatarak sıralamayı kontrol edebilir.
- Filter yalnızca path'in /data/app/*/base.apk ile eşleşip eşleşmediğini kontrol eder; caller'ın installed package'ına karşılık gelip gelmediğini kontrol etmez.

---
## Attack preconditions

- Cihaz, vulnerable bir Rooting framework ile (ör. KernelSU v0.5.7) zaten root'lanmış olmalıdır.
- Saldırgan local olarak arbitrary unprivileged code çalıştırabilmelidir (Android app process).
- Gerçek manager henüz authenticate olmamış olmalıdır (ör. reboot'tan hemen sonra). Bazı framework'ler success sonrasında manager UID'sini cache'ler; race'i kazanmanız gerekir.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Prefix ve ownership check'lerini karşılamak için kendi app data directory'niz için geçerli bir path oluşturun.
2) Genuine KernelSU Manager base.apk'nın kendi base.apk'nızdan daha düşük numaralı bir FD'de açıldığından emin olun.
3) Check'leri geçmek için prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) invoke edin.
4) Elevation'ı kalıcı hâle getirmek için CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY gibi privileged command'ları gönderin.

Practical notes on step 2 (FD ordering):
- /proc/self/fd symlink'lerini yürüyerek process'in kendi /data/app/*/base.apk FD'sini belirleyin.
- Düşük numaralı bir FD'yi (ör. stdin, fd 0) kapatın ve legitimate manager APK'sını ilk olarak açarak fd 0'ı (veya kendi base.apk FD'nizden daha düşük herhangi bir index'i) almasını sağlayın.
- Legitimate manager APK'sını app'inizle birlikte bundle edin; böylece path'i kernel'in naive filter'ını karşılar. Örneğin, onu /data/app/*/base.apk ile eşleşen bir subpath altına yerleştirin.

Example code snippets (Android/Linux, illustrative only):

Enumerate open FDs to locate base.apk entries:
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
Daha düşük numaralı bir FD'yi meşru manager APK'sine işaret edecek şekilde zorlayın:
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
Manager kimlik doğrulaması prctl hook üzerinden:
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
Başarının ardından privileged commands (örnekler):
- CMD_GRANT_ROOT: mevcut process'i root'a yükselt
- CMD_ALLOW_SU: kalıcı su için package/UID'nizi allowlist'e ekle
- CMD_SET_SEPOLICY: framework tarafından desteklendiği şekilde SELinux policy'yi ayarla

Race/persistence ipucu:
- AndroidManifest'e (RECEIVE_BOOT_COMPLETED) bir BOOT_COMPLETED receiver kaydederek reboot sonrasında erken başlatın ve gerçek manager'dan önce authentication gerçekleştirmeyi deneyin.

---
## Detection ve mitigation rehberi

Framework geliştiricileri için:
- Authentication'ı rastgele FD'lere değil, caller'ın package/UID'sine bağlayın:
- Caller'ın package'ını UID'sinden çözümleyin ve FD'leri taramak yerine installed package'ın signature'ını (PackageManager aracılığıyla) doğrulayın.
- Kernel-only ise kararlı caller identity (task creds) kullanın ve process FD'leri yerine init/userspace helper tarafından yönetilen kararlı bir source of truth üzerinde doğrulama yapın.
- Identity olarak path-prefix kontrollerinden kaçının; caller bunları kolayca karşılayabilir.
- Channel üzerinden nonce-based challenge–response kullanın ve boot sırasında veya önemli event'lerde cache'lenmiş manager identity'yi temizleyin.
- Mümkün olduğunda generic syscall'leri aşırı yüklemek yerine binder-based authenticated IPC kullanmayı değerlendirin.

Defenders/blue team için:
- Rooting frameworks ve manager process'lerinin varlığını tespit edin; kernel telemetry'niz varsa şüpheli magic constants (ör. 0xDEADBEEF) içeren prctl çağrılarını izleyin.
- Managed fleets üzerinde, boot sonrasında kısa sürede privileged manager commands gerçekleştirmeye çalışan untrusted package'lara ait boot receiver'lar için block veya alert uygulayın.
- Cihazların patched framework sürümlerine güncellendiğinden emin olun; update sırasında cache'lenmiş manager ID'lerini geçersiz kılın.

Attack'in sınırlamaları:
- Yalnızca vulnerable framework ile zaten rooted olan cihazları etkiler.
- Genellikle legitimate manager authentication gerçekleştirmeden önce bir reboot/race window gerekir (bazı framework'ler reset edilene kadar manager UID'sini cache'ler).

---
## Framework'ler arasındaki ilgili notlar

- Password-based auth (ör. historical APatch/SKRoot builds), password'lar tahmin edilebilir/bruteforce edilebilir olduğunda veya validation'lar hatalı olduğunda zayıf olabilir.
- Package/signature-based auth (ör. KernelSU) prensipte daha güçlüdür; ancak FD scan gibi indirect artefacts yerine actual caller'a bağlanmalıdır.
- Magisk: CVE-2024-48336 (MagiskEoP), mature ecosystem'lerin bile identity spoofing'e karşı savunmasız olabileceğini ve bunun manager context içinde root ile code execution'a yol açabileceğini gösterdi.

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
