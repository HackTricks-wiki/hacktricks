# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux에서 프로그램을 실행하려면 해당 프로그램이 파일로 존재해야 하며, 파일 시스템 계층을 통해 어떤 방식으로든 접근할 수 있어야 합니다(이는 단순히 `execve()`가 작동하는 방식입니다). 이 파일은 디스크나 ram(tmpfs, memfd)에 있을 수 있지만, filepath가 필요합니다. 이 때문에 Linux 시스템에서 무엇이 실행되는지 제어하기가 매우 쉬워지고, threat와 attacker의 tool을 탐지하거나, 애초에 이들이 어떤 것도 실행하지 못하도록 방지하기도 쉬워집니다(_예:_ 권한이 없는 사용자가 어디에도 executable file을 배치하지 못하도록 허용하지 않는 방식).

하지만 이 technique은 이 모든 것을 바꾸기 위해 존재합니다. 원하는 process를 시작할 수 없다면... **이미 존재하는 process를 hijack하면 됩니다**.

이 technique을 사용하면 **read-only, noexec, file-name whitelisting, hash whitelisting과 같은 일반적인 protection technique을 bypass할 수 있습니다...**<sup>[[1]](#references)</sup>

## Dependencies

최종 script는 작동하기 위해 다음 tool에 의존하며, 공격 대상 system에서 해당 tool에 접근할 수 있어야 합니다(기본적으로 어디에서나 이 모든 tool을 찾을 수 있습니다):
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
## 기법

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 장악할 수 있습니다. 이는 이미 존재하는 프로세스를 hijack하여 다른 프로그램으로 교체하는 데 사용할 수 있습니다. 이를 위해 `ptrace()` syscall을 사용할 수 있으며(이는 syscall을 실행할 수 있는 능력이나 시스템에 gdb가 설치되어 있어야 함), 더 흥미로운 방법으로는 `/proc/$pid/mem`에 쓰는 방법이 있습니다.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` 파일은 프로세스의 전체 address space에 대한 일대일 매핑입니다(_예:_ x86-64에서는 `0x0000000000000000`부터 `0x7ffffffffffff000`까지). 즉, 이 파일의 오프셋 `x`에서 읽거나 쓰는 것은 virtual address `x`의 내용을 읽거나 수정하는 것과 같습니다.

이제 해결해야 할 기본적인 문제는 네 가지입니다.

- 일반적으로 root와 해당 파일의 소유자만 파일을 수정할 수 있습니다.
- ASLR.
- 프로그램의 address space에 매핑되지 않은 address를 읽거나 쓰려고 하면 I/O error가 발생합니다.

이 문제들은 완벽하지는 않지만 다음과 같은 방법으로 해결할 수 있습니다.

- 대부분의 shell interpreter는 이후 child process가 상속할 file descriptor를 생성할 수 있도록 허용합니다. write permissions가 있는 shell의 `mem` 파일을 가리키는 fd를 생성하면, 해당 fd를 사용하는 child process가 shell의 memory를 수정할 수 있습니다.
- ASLR은 문제가 되지 않습니다. shell의 `maps` 파일이나 procfs의 다른 파일을 확인하여 프로세스의 address space에 대한 정보를 얻을 수 있습니다.
- 따라서 파일에서 `lseek()`를 수행해야 합니다. shell에서는 악명 높은 `dd`를 사용하지 않으면 이를 수행할 수 없습니다.

### 더 자세히

단계는 비교적 간단하며 이해하는 데 특별한 전문 지식이 필요하지 않습니다.<sup>[[1]](#references)</sup>

- 실행하려는 binary와 loader를 분석하여 필요한 mapping을 확인합니다. 그런 다음 대략적으로 kernel이 `execve()`를 호출할 때마다 수행하는 것과 동일한 단계를 수행하는 "shell"code를 작성합니다.
- 해당 mapping을 생성합니다.
- binary를 해당 mapping에 읽어 들입니다.
- permissions를 설정합니다.
- 마지막으로 program의 arguments로 stack을 초기화하고 auxiliary vector를 배치합니다(loader에 필요).
- loader로 jump하여 나머지 작업을 맡깁니다(program에 필요한 library를 load).
- `syscall` 파일에서 프로세스가 실행 중인 syscall 이후 반환될 address를 가져옵니다.
- 실행 가능한 해당 위치를 shellcode로 덮어씁니다(`mem`을 통해 write-protected page도 수정할 수 있음).
- 실행하려는 program을 프로세스의 stdin으로 전달합니다(해당 "shell"code가 `read()`하게 됨).
- 이제 필요한 library를 load하고 program으로 jump하는 작업은 loader에 맡겨집니다.

**다음 도구를 확인하세요:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

`dd`의 대안은 여러 가지가 있으며, 그중 하나인 `tail`은 현재 `mem` 파일에서 `lseek()`를 수행하는 데 기본적으로 사용되는 program입니다(`dd`를 사용한 유일한 목적이 바로 이것이었습니다). 이러한 대안은 다음과 같습니다.<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` 변수를 설정하면 사용되는 seeker를 변경할 수 있습니다. _예:_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
스크립트에 구현되지 않은 다른 유효한 seeker를 찾았다면 `SEEKER_ARGS` 변수를 설정하여 사용할 수 있습니다:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
이걸 차단하세요, EDR 여러분.

## References

- [1] [DDexec: A technique to run binaries filelessly and stealthily on Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
