# SUID 공유 라이브러리 및 링커 악용

{{#include ../../banners/hacktricks-training.md}}

SUID 바이너리는 보통 직접적인 명령 실행 취약점을 중심으로 검토하지만, 사용자 지정 SUID 프로그램은 동적 링커를 통해서도 취약해질 수 있습니다. 일반적인 원리는 간단합니다. 권한이 높은 실행 파일이 권한이 낮은 사용자가 영향을 줄 수 있는 경로나 설정에서 코드를 로드합니다.<sup>[[1]](#references)</sup>

이 페이지에서는 누락된 라이브러리, 쓰기 가능한 라이브러리 디렉터리, `RPATH`/`RUNPATH`, sudo를 통한 `LD_PRELOAD`, 링커 설정, SUID 하드링크 혼동과 같은 일반적인 기술 패턴을 다룹니다.

이 검사의 기반이 되는 ELF 프로그램 헤더, 동적 섹션, 로더 동작에 대해서는 [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)을 참조하세요.

## 빠른 열거

먼저 특이한 SUID 파일을 찾고 동적으로 링크되어 있는지 확인합니다:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

낯선 실행 파일에는 `readelf`를 사용하세요. [`ldd`는 신뢰할 수 없는 ELF 인터프리터를 실행할 수 있습니다](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf`는 직접 종속성을 보여 주므로, loader가 실제로 선택한 경로는 별도로 확인하세요.<sup>[[1]](#references)[[3]](#references)</sup>

표준이 아닌 위치, 사용자 지정 애플리케이션 경로, 패키지 관리 디렉터리 외부에 있는 root 소유 바이너리, 쓰기 가능한 디렉터리에서 로드되는 종속성에 집중하세요.<sup>[[1]](#references)</sup>

유용한 쓰기 권한 확인 방법:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

일부 custom SUID 바이너리는 존재하지 않는 shared object를 로드하려고 합니다. 누락된 경로가 공격자가 제어하는 디렉터리 아래에 있으면, 바이너리는 공격자가 제공한 코드를 유효 사용자 권한으로 로드할 수 있습니다.<sup>[[1]](#references)</sup>

호출자가 쓰기 가능한 홈 디렉터리나 설정 디렉터리 아래의 절대 `.so` 경로에 `dlopen()`을 호출하는 **sudo를 통해 실행이 허용된 custom binary**에도 같은 경계가 적용됩니다. 이렇게 늦게 라이브러리를 로드하는 경우 `ldd` 및 ELF `NEEDED` 항목에 나타나지 않을 수 있습니다. 제한적으로 `strings`를 확인하거나 **권한이 없는** 상태에서 실행을 추적하면 시도되는 경로를 확인할 수 있습니다. 애플리케이션 암호나 메뉴 선택에 따라 해당 경로 조회가 이루어질 수도 있습니다. 권한 상승으로 간주하기 전에 유효한 sudo 규칙, 정확한 경로와 상위 디렉터리 권한, 그리고 권한이 있는 실행에서 해당 경로 조회에 도달하는지 확인하세요. 단순히 열거하기 위해 sudo 대상을 실행하지 마세요.

`strace`의 syscall 필터를 사용해 실패한 라이브러리 조회를 찾으세요:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

바이너리가 쓰기 가능한 경로에서 `libexample.so`를 검색한다면, 최소한의 proof 라이브러리에 constructor를 사용할 수 있습니다. 검증 중에는 영향 입증이 무해하도록 유지하세요:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

바이너리가 로드하려는 정확한 파일 이름으로 빌드합니다:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

악용 가능한 조건은 단순히 라이브러리가 없는 것만이 아닙니다. 공격자는 권한이 높은 loader가 허용하는 경로에 호환되는 shared object를 둘 수 있어야 합니다.<sup>[[1]](#references)</sup>

## 쓰기 가능한 라이브러리 디렉터리

때로는 모든 dependency가 존재하지만, dependency를 찾는 데 사용되는 디렉터리 중 하나에 쓰기 권한이 있습니다. 이 경우 로드된 라이브러리를 바꾸거나 같은 이름의 라이브러리를 더 높은 우선순위 경로에 심을 수 있습니다.<sup>[[1]](#references)</sup>

SUID 비트가 없고 허용된 RunAs 계정이 root가 아니더라도, **sudo를 통해 허용된** 사용자 지정 ELF에도 같은 검토를 적용합니다. 해당 ELF의 `DT_NEEDED` 항목과 loader가 찾을 라이브러리 경로를 비교한 다음, 호출자가 그 파일에 쓸 수 있는지 또는 쓰기 및 탐색 권한이 있는 상위 디렉터리를 통해 파일을 바꿀 수 있는지 확인합니다. 정확한 sudo RunAs 규칙, 심볼릭 링크와 ACL, loader 정책, 그리고 대상 프로세스가 권한이 더 높은 계정으로 라이브러리를 로드하는지 확인합니다. 쓰기 가능한 `.so`나 dependency 이름만으로는 단서일 뿐입니다. sudo 명령을 실행하지 말고 메타데이터를 검사하세요.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

dependency 경로를 검토하세요:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

디렉터리에 쓰기 권한이 있다면, 실험 환경에서 원본을 안전하게 보존하는 방식으로 검증하세요. 실행 중인 호스트에서 시스템 라이브러리를 교체하면 동시에 시작되는 프로세스가 서로 다른 라이브러리 버전을 사용하는 문제가 생길 수 있습니다.<sup>[[8]](#references)</sup>

### chroot 내부의 쓰기 가능한 라이브러리

chroot만으로는 상속된 파일 디스크립터가 닫히지 않으며 모든 파일시스템 접근이 제한되는 것도 아닙니다. 샌드박스가 새 루트 외부를 가리키는 디렉터리 디스크립터를 남겨 두고, 격리된 프로세스가 해당 디스크립터를 역참조할 수 있다면(예: 접근 가능한 `/proc/<pid>/fd/` 항목을 통해) 호스트 경로에 계속 접근할 수 있습니다. 이는 파일시스템 경계 문제이며, 그 자체로 root 권한을 부여하지는 않습니다.<sup>[[11]](#references)[[12]](#references)</sup>

격리된 사용자가 jail에서 실행될 때 **호스트 root-SUID 실행 파일**이 사용할 라이브러리 디렉터리에 쓸 수 있는지 별도로 확인하세요. 로더는 프로세스의 파일시스템 뷰에서 의존성을 확인하므로, 공격자가 제어하는 라이브러리가 해당 위치에 있으면 SUID 프로그램의 유효 사용자 ID로 실행될 수 있습니다. 정확한 실행 파일, SUID 비트와 마운트 정책, 디스크립터의 대상과 접근 권한, jail의 라이브러리 검색 경로, 그리고 프로그램이 실제로 호스트 실행 파일에 접근할 수 있는지 확인하세요. 샌드박스 실행기의 파일 capability, 쓰기 가능한 jail 또는 호스트 SUID 바이너리만으로는 단서일 뿐입니다. 전체 공격 경로는 샌드박스 구현 방식에 따라 달라집니다.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH`와 `RUNPATH`는 로더에 라이브러리를 검색할 위치를 알려주는 dynamic section 항목입니다. 공격자가 쓸 수 있는 디렉터리를 가리키는 경우 SUID 프로그램에서 위험합니다.<sup>[[1]](#references)</sup>

확인 방법:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

위험한 출력 예시:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

`/opt/app/lib`에 쓰기 권한이 있고 바이너리가 `libcustom.so`를 필요로 한다면, 공격자는 악성 `libcustom.so`를 해당 경로에 배치할 수 있습니다:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH`와 `RUNPATH`는 모든 해석 세부 사항에서 동일하지는 않지만, privilege-escalation 검토에서 실질적인 질문은 같습니다. SUID 바이너리가 공격자가 쓸 수 있는 디렉터리에서 라이브러리 이름을 검색하는가?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH 및 SUID

일반 프로그램에서는 `LD_PRELOAD`와 `LD_LIBRARY_PATH`를 사용해 shared object 로딩을 강제하거나 영향을 줄 수 있습니다. SUID 프로그램의 경우 dynamic loader는 보통 secure-execution mode로 진입해 위험한 환경 변수를 무시합니다.<sup>[[1]](#references)</sup>

따라서 사용자가 `LD_PRELOAD`를 설정할 수 있다는 이유만으로 일반 SUID 바이너리가 취약한 것은 아닙니다:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

일반적인 예외는 `SETENV` 태그나 해당하는 `setenv` 옵션처럼 대상에 대한 명령줄 환경 변수 할당을 허용하는 sudo 정책입니다. 대상이 동적으로 링크되어 있고 sudo가 `LD_PRELOAD=/path/to/library`를 허용하면, 대상이 호출자가 제어하는 코드를 로드할 수 있습니다. 적용되는 규칙과 대상의 신원을 확인하세요. `env_keep`에 `LD_PRELOAD`를 추가하는 것만으로는 충분하지 않습니다. 동적 로더가 SUID `sudo` 프로세스 시작 전에 상속된 `LD_PRELOAD`를 제거하는 시스템에서는 특히 그렇습니다. 명령줄 할당은 sudo가 자체적으로 시작된 후 sudo에 의해 평가됩니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

이러한 경우를 혼동하지 마세요. 위의 로더 및 sudo 정책 규칙에서 각각 구분합니다:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 일반 SUID 바이너리에 대한 `LD_PRELOAD`: 보안 실행으로 대개 차단됩니다.
- 권한이 있는 동적 링크 대상에 대한 sudo 명령줄 할당으로 허용되는 `LD_PRELOAD`: 악용될 가능성이 있습니다.
- 쓰기 가능한 경로에 없는 `.so`: SUID 바이너리가 해당 경로를 정상적으로 로드할 때 악용할 수 있습니다.
- 쓰기 가능한 디렉터리를 가리키는 `RPATH`/`RUNPATH`: 필요한 라이브러리를 제어할 수 있을 때 악용할 수 있습니다.
- `/etc/ld.so.preload` 또는 링커 설정 파일에 대한 쓰기 권한: 시스템 전체에 영향을 미치며 위험도가 높습니다.

## 링커 설정

`ld.so`는 링커 캐시와 `/etc/ld.so.preload`를 사용합니다. `ldconfig`는 `/etc/ld.so.conf` 및 여기서 포함하는 파일(일반적으로 `/etc/ld.so.conf.d/`에 있음)을 바탕으로 캐시를 생성합니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

주요 점검 항목:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

쓰기 가능한 링커 설정은 여러 동적 링크 프로세스에 영향을 줄 수 있으므로, 취약한 SUID 바이너리 하나보다 대개 더 심각합니다. 특히 `/etc/ld.so.preload`는 권한이 높은 프로세스에 공유 객체를 강제로 로드할 수 있어 위험합니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID 하드링크 혼동

하드링크를 사용하면 동일한 SUID inode가 여러 이름으로 표시될 수 있습니다.<sup>[[9]](#references)</sup> 이를 통해 권한이 높은 헬퍼를 숨기거나, 정리 작업을 혼란스럽게 하거나, 경로만 확인하는 단순한 검토를 우회할 수 있습니다.

링크 수가 둘 이상인 SUID 파일을 찾습니다:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

동일한 inode로 이어지는 모든 경로를 확인합니다:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

남용의 핵심은 hardlink가 권한을 변경한다는 것이 아닙니다. 문제는 경로 혼동입니다. 권한이 높은 inode가 방어 담당자나 스크립트가 예상하지 못한 이름으로 접근 가능할 수 있습니다.<sup>[[9]](#references)</sup> inode와 hardlink 작업 흐름에 대한 자세한 내용은 [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)를 참조하세요.

## 방어 참고 사항

- SUID 바이너리는 최소한으로 유지하고, 감사를 거치며, 가능하면 패키지로 관리하세요.
- 쓰기 가능한 디렉터리나 애플리케이션에서 관리하는 디렉터리를 가리키는 `RPATH`/`RUNPATH` 항목은 피하세요.<sup>[[1]](#references)[[8]](#references)</sup>
- 라이브러리 디렉터리의 소유자는 root로 유지하고 일반 사용자가 쓰지 못하도록 하세요.<sup>[[8]](#references)</sup>
- sudo를 통해 `LD_PRELOAD`, `LD_LIBRARY_PATH` 또는 이와 유사한 loader 변수가 유지되지 않도록 하세요.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` 및 예상치 못한 SUID 파일을 모니터링하세요.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlink로 연결된 SUID 파일을 검토하고 표준 시스템 경로 외부의 사용자 지정 SUID 래퍼를 조사하세요.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU 바이너리 유틸리티)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [일반 속성 (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [동적 링커 강화 (GNU C 라이브러리)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [하드 링크 (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU 바이너리 유틸리티)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
