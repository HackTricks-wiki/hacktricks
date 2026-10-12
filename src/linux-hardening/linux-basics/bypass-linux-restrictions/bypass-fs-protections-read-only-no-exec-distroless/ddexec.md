# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## 배경

Linux는 일반적으로 디스크나 메모리에 저장된 실행 파일에서 프로그램을 실행합니다. 실행 파일은 경로명이나 파일 디스크립터로 식별할 수 있으므로, 일반적인 파일 시스템 경로명이 항상 필요한 것은 아닙니다.<sup>[[2]](#references)</sup>

DDexec / EverythingExec는 **이미 실행 중인 프로세스**의 메모리를 사용합니다. [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) 페이지에서는 익명 파일 실행과 관련 탐지 및 포렌식 수집을 다룹니다. [Memory Bypasses overview](index.html#memory-bypasses)에서도 MemExec와 Memdlopen을 찾아볼 수 있습니다.<sup>[[1]](#references)</sup>

이 기법을 사용하면 **read-only, noexec, 파일 이름 화이트리스트, 해시 화이트리스트와 같은 일반적인 보호 기법을 우회할 수 있습니다**.<sup>[[1]](#references)</sup>

## 의존성

최종 스크립트가 작동하려면 다음 도구가 필요하며, 공격 대상 시스템에서 사용할 수 있어야 합니다(기본적으로 어디서나 이 도구들을 찾을 수 있습니다):

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

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 장악할 수 있습니다. 이를 통해 이미 실행 중인 프로세스를 하이재킹하고 다른 프로그램으로 대체할 수 있습니다. `ptrace()` syscall을 사용하거나(시스템에서 syscall을 실행할 수 있거나 gdb를 사용할 수 있어야 함), 더 흥미롭게는 `/proc/$pid/mem`에 쓰는 방식으로 이를 수행할 수 있습니다.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` 파일은 프로세스의 전체 주소 공간에 대한 일대일 매핑입니다(_예:_ x86-64에서 `0x0000000000000000`부터 `0x7ffffffffffff000`까지). 즉, 이 파일에서 오프셋 `x`를 읽거나 쓰는 것은 가상 주소 `x`의 내용을 읽거나 수정하는 것과 같습니다.

이제 해결해야 할 기본적인 문제는 네 가지입니다.

- 일반적으로 root와 해당 파일의 소유 프로그램만 이 파일을 수정할 수 있습니다.
- ASLR.
- 프로그램의 주소 공간에 매핑되지 않은 주소를 읽거나 쓰려고 하면 I/O 오류가 발생합니다.

완벽하지는 않지만 다음과 같은 해결 방법이 있습니다.

- 대부분의 셸 인터프리터에서는 자식 프로세스에 상속되는 file descriptor를 만들 수 있습니다. 쓰기 권한으로 셸의 `mem` 파일을 가리키는 fd를 만들면, 해당 fd를 사용하는 자식 프로세스가 셸의 메모리를 수정할 수 있습니다.
- ASLR은 문제가 되지 않습니다. 셸의 `maps` 파일이나 procfs의 다른 파일을 확인해 프로세스의 주소 공간에 관한 정보를 얻을 수 있습니다.
- 따라서 파일에서 `lseek()`를 해야 합니다. 셸에서는 악명 높은 `dd`를 사용하지 않고는 이를 수행할 수 없습니다.

### 더 자세히 알아보기

단계는 비교적 간단하며 이해하는 데 특별한 전문 지식이 필요하지 않습니다.<sup>[[1]](#references)</sup>

- 실행하려는 바이너리와 로더를 분석해 필요한 매핑을 확인합니다. 그런 다음 커널이 `execve()` 호출마다 수행하는 것과 대체로 동일한 작업을 수행하는 "shell"code를 만듭니다.
  - 해당 매핑을 생성합니다.
  - 바이너리를 해당 매핑에 읽어들입니다.
  - 권한을 설정합니다.
  - 마지막으로 프로그램의 인수로 스택을 초기화하고 auxiliary vector(로더에 필요함)를 배치합니다.
  - 로더로 이동해 나머지를 처리하도록 합니다(프로그램에 필요한 라이브러리를 로드).
- `syscall` 파일에서 프로세스가 실행 중인 syscall 이후에 돌아갈 주소를 가져옵니다.
- 실행 권한이 있는 해당 위치를 shellcode로 덮어씁니다(`mem`을 통해 쓰기 금지 페이지를 수정할 수 있음).
- 실행하려는 프로그램을 프로세스의 stdin에 전달합니다(해당 "shell"code가 `read()`를 통해 읽음).
- 이제 로더가 프로그램에 필요한 라이브러리를 로드하고 프로그램으로 이동합니다.

**도구는** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)**에서 확인하세요.**<sup>[[1]](#references)</sup>

## EverythingExec

`dd`의 대안은 여러 가지가 있으며, 그중 현재 기본 프로그램으로 사용되는 것은 `tail`입니다. 이 프로그램은 `mem` 파일에서 `lseek()`를 수행하는 데 사용됩니다(`dd`를 사용한 유일한 목적이었습니다). 이러한 대안은 다음과 같습니다.<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

변수 `SEEKER`를 설정하면 사용할 seeker를 변경할 수 있습니다. _예:_

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

스크립트에 구현되지 않은 다른 유효한 seeker를 찾더라도 `SEEKER_ARGS` 변수를 설정해 사용할 수 있습니다:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

EDR에서 이를 차단하세요.

## References

- [1] [DDexec: Linux에서 바이너리 파일을 파일 없이 은밀하게 실행하는 기법](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux 매뉴얼 페이지](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
