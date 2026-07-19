# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux에서 프로그램을 실행하려면 해당 프로그램이 파일로 존재해야 하며, 파일 시스템 계층을 통해 어떤 방식으로든 접근할 수 있어야 합니다(이는 `execve()`가 작동하는 방식입니다). 이 파일은 디스크나 ram(tmpfs, memfd)에 존재할 수 있지만 filepath가 필요합니다. 이 때문에 Linux 시스템에서 무엇이 실행되는지 제어하기가 매우 쉬워졌고, threats와 attacker의 tools를 쉽게 탐지하거나, 애초에 그들이 자신의 파일을 실행하지 못하도록 방지할 수 있습니다(_예:_ 권한이 없는 사용자가 어디에도 executable files를 배치하지 못하도록 허용하지 않음).

하지만 이 technique은 이 모든 것을 바꾸기 위해 존재합니다. 원하는 process를 시작할 수 없다면... **이미 존재하는 process를 hijack하면 됩니다**.

이 technique을 사용하면 **read-only, noexec, file-name whitelisting, hash whitelisting과 같은 일반적인 protection techniques를 bypass할 수 있습니다...**

## Dependencies

최종 script가 작동하려면 다음 tools에 의존하며, 공격 중인 system에서 해당 tools에 접근할 수 있어야 합니다(기본적으로 어디에서나 이들 모두를 찾을 수 있습니다):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## The technique

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 탈취할 수 있습니다. 이는 이미 존재하는 프로세스를 hijack하여 다른 프로그램으로 교체하는 데 사용할 수 있습니다. 이를 달성하는 방법은 `ptrace()` syscall을 사용하는 것(시스템에서 syscall을 실행할 수 있거나 gdb를 사용할 수 있어야 함) 또는 더 흥미롭게는 `/proc/$pid/mem`에 쓰는 것입니다.

`/proc/$pid/mem` 파일은 프로세스의 전체 address space에 대한 일대일 매핑입니다(_예:_ x86-64에서는 `0x0000000000000000`부터 `0x7ffffffffffff000`까지). 즉, 이 파일의 offset `x`에서 읽거나 쓰는 것은 virtual address `x`의 내용을 읽거나 수정하는 것과 같습니다.

이제 해결해야 할 네 가지 기본 문제가 있습니다.

- 일반적으로 root와 해당 파일의 program owner만 파일을 수정할 수 있습니다.
- ASLR.
- 프로그램의 address space에 매핑되지 않은 address를 읽거나 쓰려고 하면 I/O error가 발생합니다.

이 문제에는 완벽하지는 않지만 유효한 해결책이 있습니다.

- 대부분의 shell interpreter는 이후 child process가 상속하게 될 file descriptor를 생성할 수 있습니다. write permissions를 가진 shell의 `mem` 파일을 가리키는 fd를 생성하면, 해당 fd를 사용하는 child process가 shell의 memory를 수정할 수 있습니다.
- ASLR은 사실 문제가 되지 않습니다. shell의 `maps` 파일이나 procfs의 다른 파일을 확인하여 process의 address space에 대한 정보를 얻을 수 있습니다.
- 따라서 파일에서 `lseek()`을 수행해야 합니다. shell에서는 악명 높은 `dd`를 사용하지 않는 한 이를 수행할 수 없습니다.

### In more detail

단계는 비교적 간단하며 이를 이해하는 데 어떤 전문 지식도 필요하지 않습니다.

- 실행하려는 binary와 loader를 parse하여 필요한 mappings를 확인합니다. 그런 다음 대략적으로 말해 kernel이 `execve()`를 호출할 때마다 수행하는 것과 동일한 단계를 수행할 "shell"code를 작성합니다.
- 해당 mappings를 생성합니다.
- binary를 mappings에 읽어 넣습니다.
- permissions를 설정합니다.
- 마지막으로 program의 arguments로 stack을 초기화하고 auxiliary vector(loader에 필요)를 배치합니다.
- loader로 jump하여 나머지 작업을 수행하게 합니다(program에 필요한 libraries를 load).
- `syscall` 파일에서 현재 실행 중인 syscall 이후 process가 return할 address를 가져옵니다.
- 실행 가능한 해당 위치를 shellcode로 덮어씁니다(`mem`을 통해 write-protected pages를 수정할 수 있음).
- 실행하려는 program을 process의 stdin으로 전달합니다(해당 "shell"code가 `read()`하게 됨).
- 이 시점부터 필요한 libraries를 load하고 program으로 jump하는 것은 loader의 역할입니다.

**Check out the tool in** [**https://github.com/arget13/DDexec**](**https://github.com/arget13/DDexec**)

## EverythingExec

`dd`에는 여러 대안이 있으며, 그중 하나인 `tail`은 현재 `mem` 파일에서 `lseek()`을 수행하는 데 사용되는 기본 program입니다(`dd`를 사용한 유일한 목적이 바로 이것이었습니다). 이러한 대안은 다음과 같습니다.
```bash
tail
hexdump
cmp
xxd
```
변수 `SEEKER`를 설정하여 사용하는 seeker를 변경할 수 있습니다. _예:_
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
스크립트에 구현되지 않은 다른 유효한 seeker를 찾았다면 `SEEKER_ARGS` 변수를 설정하여 사용할 수 있습니다:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
이것을 차단하세요, EDR 여러분.

## 참고 자료

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
