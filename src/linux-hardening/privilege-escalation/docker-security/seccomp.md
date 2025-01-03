# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**Seccomp**는 Secure Computing mode의 약자로, **시스템 호출을 필터링하기 위해 설계된 Linux 커널의 보안 기능**입니다. 이는 프로세스를 제한된 시스템 호출 집합(`exit()`, `sigreturn()`, `read()`, 및 `write()` 이미 열린 파일 설명자에 대해)으로 제한합니다. 프로세스가 다른 호출을 시도하면 커널에 의해 SIGKILL 또는 SIGSYS로 종료됩니다. 이 메커니즘은 리소스를 가상화하지 않고 프로세스를 이로부터 격리합니다.

Seccomp를 활성화하는 방법은 두 가지가 있습니다: `PR_SET_SECCOMP`와 함께 `prctl(2)` 시스템 호출을 사용하거나, Linux 커널 3.17 이상에서는 `seccomp(2)` 시스템 호출을 사용하는 것입니다. `/proc/self/seccomp`에 쓰는 오래된 방법은 `prctl()`을 선호하여 더 이상 사용되지 않습니다.

향상된 기능인 **seccomp-bpf**는 Berkeley Packet Filter (BPF) 규칙을 사용하여 사용자 정의 정책으로 시스템 호출을 필터링할 수 있는 기능을 추가합니다. 이 확장은 OpenSSH, vsftpd 및 Chrome OS와 Linux의 Chrome/Chromium 브라우저와 같은 소프트웨어에서 유연하고 효율적인 시스템 호출 필터링을 위해 활용되며, 이제 지원되지 않는 Linux의 systrace에 대한 대안을 제공합니다.

### **원본/엄격 모드**

이 모드에서 Seccomp는 **오직 syscalls** `exit()`, `sigreturn()`, `read()` 및 `write()`를 이미 열린 파일 설명자에 대해서만 허용합니다. 다른 syscalls가 발생하면 프로세스는 SIGKILL로 종료됩니다.
```c:seccomp_strict.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

이 모드는 **버클리 패킷 필터 규칙을 사용하여 구현된 구성 가능한 정책을 사용하여 시스템 호출을 필터링**할 수 있게 해줍니다.
```c:seccomp_bpf.c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Docker에서의 Seccomp

**Seccomp-bpf**는 **Docker**에서 **syscalls**를 제한하여 컨테이너의 공격 표면을 효과적으로 줄이는 것을 지원합니다. [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)에서 **기본적으로 차단된 syscalls**를 확인할 수 있으며, **기본 seccomp 프로필**은 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 확인할 수 있습니다.\
다음과 같이 **다른 seccomp** 정책으로 도커 컨테이너를 실행할 수 있습니다:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
컨테이너가 `uname`과 같은 **syscall**을 실행하는 것을 **금지**하려면 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 기본 프로필을 다운로드하고 **목록에서 `uname` 문자열을 제거**하면 됩니다.\
**어떤 바이너리가 도커 컨테이너 내에서 작동하지 않도록** 하려면 strace를 사용하여 바이너리가 사용하는 syscalls를 나열한 다음 이를 금지할 수 있습니다.\
다음 예제에서는 `uname`의 **syscalls**가 발견됩니다:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> 만약 **애플리케이션을 실행하기 위해 Docker를 사용하는 것이라면**, **`strace`**로 **프로파일링**하고 필요한 시스템 호출만 **허용**할 수 있습니다.

### 예제 Seccomp 정책

[여기에서 예제](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) 

Seccomp 기능을 설명하기 위해, 아래와 같이 "chmod" 시스템 호출을 비활성화하는 Seccomp 프로파일을 생성해 보겠습니다.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
위 프로필에서는 기본 동작을 "허용"으로 설정하고 "chmod"를 비활성화하는 블랙리스트를 생성했습니다. 더 안전하게 만들기 위해 기본 동작을 드롭으로 설정하고 시스템 호출을 선택적으로 활성화하는 화이트리스트를 생성할 수 있습니다.\
다음 출력은 seccomp 프로필에서 비활성화되어 있기 때문에 "chmod" 호출이 오류를 반환하는 것을 보여줍니다.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
다음 출력은 프로파일을 표시하는 "docker inspect"를 보여줍니다:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
