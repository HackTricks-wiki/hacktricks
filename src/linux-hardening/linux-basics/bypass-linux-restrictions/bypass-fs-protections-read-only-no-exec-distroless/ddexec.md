# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux에서 프로그램을 실행하려면 해당 프로그램이 파일로 존재해야 하며, 파일 시스템 계층을 통해 어떤 방식으로든 접근할 수 있어야 합니다(이는 단순히 `execve()`가 작동하는 방식입니다). 이 파일은 디스크나 메모리(ram)에 존재할 수 있지만(tmpfs, memfd), 파일 경로가 필요합니다. 이로 인해 Linux 시스템에서 실행되는 항목을 매우 쉽게 제어할 수 있고, 위협 요소와 공격자의 도구를 쉽게 탐지하거나, 공격자가 자신의 항목을 실행하려는 시도 자체를 방지할 수 있습니다(_예:_ 권한이 없는 사용자가 어디에도 실행 파일을 배치하지 못하도록 허용하지 않음).

하지만 이 technique은 이 모든 것을 바꾸기 위해 존재합니다. 원하는 process를 시작할 수 없다면... **이미 존재하는 process를 hijack하면 됩니다**.

이 technique을 사용하면 **read-only, noexec, file-name whitelisting, hash whitelisting과 같은 일반적인 보호 기법을 우회할 수 있습니다**.<sup>[[1]](#references)</sup>

## Dependencies

최종 script가 작동하려면 다음 tools에 의존하며, 공격 대상 system에서 해당 tools에 접근할 수 있어야 합니다(기본적으로 어디에서나 이들 모두를 찾을 수 있습니다):
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

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 탈취할 수 있습니다. 이를 사용하면 이미 존재하는 프로세스를 가로채 다른 프로그램으로 교체할 수 있습니다. 이는 `ptrace()` syscall을 사용하거나(`syscall`을 실행할 수 있는 권한 또는 시스템에 gdb가 있어야 함), 더 흥미롭게는 `/proc/$pid/mem`에 쓰는 방식으로 수행할 수 있습니다.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` 파일은 프로세스 전체 주소 공간에 대한 일대일 매핑입니다(_예:_ x86-64에서는 `0x0000000000000000`부터 `0x7ffffffffffff000`까지). 따라서 이 파일의 오프셋 `x`에서 읽거나 쓰는 것은 가상 주소 `x`의 내용을 읽거나 수정하는 것과 같습니다.

이제 해결해야 할 기본적인 문제는 네 가지입니다.

- 일반적으로 root와 해당 파일의 프로그램 소유자만 이를 수정할 수 있습니다.
- ASLR.
- 프로그램의 주소 공간에 매핑되지 않은 주소를 읽거나 쓰려고 하면 I/O 오류가 발생합니다.

이러한 문제에는 완벽하지는 않지만 유효한 해결 방법이 있습니다.

- 대부분의 shell interpreter는 이후 자식 프로세스에 상속될 파일 디스크립터를 생성할 수 있습니다. 쓰기 권한으로 shell의 `mem` 파일을 가리키는 fd를 생성하면, 해당 fd를 사용하는 자식 프로세스가 shell의 메모리를 수정할 수 있습니다.
- ASLR은 문제가 되지 않습니다. procfs의 shell `maps` 파일이나 다른 파일을 확인하여 프로세스의 주소 공간에 대한 정보를 얻을 수 있습니다.
- 따라서 파일에서 `lseek()`을 수행해야 합니다. shell에서는 악명 높은 `dd`를 사용하지 않는 한 이를 수행할 수 없습니다.

### In more detail

단계는 비교적 간단하며 이해하는 데 특별한 전문 지식이 필요하지 않습니다.<sup>[[1]](#references)</sup>

- 실행하려는 binary와 loader를 파싱하여 필요한 매핑을 확인합니다. 그런 다음 대략적으로 말해 kernel이 `execve()`를 호출할 때마다 수행하는 것과 동일한 단계를 수행하는 "shell"code를 작성합니다.
- 해당 매핑을 생성합니다.
- binary를 매핑에 읽어 들입니다.
- 권한을 설정합니다.
- 마지막으로 프로그램의 인수로 stack을 초기화하고 auxiliary vector를 배치합니다(loader에 필요).
- loader로 점프하여 나머지 작업을 수행하게 합니다(프로그램에 필요한 library를 로드).
- `syscall` 파일에서 프로세스가 실행 중인 syscall 이후 반환될 주소를 가져옵니다.
- 실행 가능한 해당 위치를 `mem`을 통해 shellcode로 덮어씁니다(`mem`을 사용하면 쓰기 불가능한 페이지도 수정할 수 있음).
- 실행하려는 프로그램을 프로세스의 stdin으로 전달합니다(해당 "shell"code가 `read()`합니다).
- 이 시점부터 필요한 library를 로드하고 프로그램으로 점프하는 것은 loader의 역할입니다.

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

`dd`의 여러 대안이 있으며, 그중 하나인 `tail`은 현재 `mem` 파일에서 `lseek()`을 수행하는 데 사용되는 기본 프로그램입니다(`dd`를 사용한 유일한 목적이 바로 이것이었습니다). 이러한 대안은 다음과 같습니다.<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
변수 `SEEKER`를 설정하면 사용되는 seeker를 변경할 수 있습니다. _예:_
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
스크립트에 구현되지 않은 유효한 다른 seeker를 찾았다면 `SEEKER_ARGS` 변수를 설정하여 사용할 수도 있습니다:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
이것을 차단하세요, EDR들.

## References

- [1] [DDexec: Linux에서 바이너리 파일을 파일리스하고 은밀하게 실행하는 기법](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
