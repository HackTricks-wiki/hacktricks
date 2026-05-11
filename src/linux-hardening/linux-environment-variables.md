# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Глобальні змінні

Глобальні змінні **будуть** успадковані **дочірніми процесами**.

Ви можете створити глобальну змінну для поточної сесії, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна у ваших поточних сесіях і їх дочірніх процесах.

Ви можете **видалити** змінну, виконавши:
```bash
unset MYGLOBAL
```
## Локальні змінні

**Локальні змінні** можуть бути **доступні** лише **поточному shell/script**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Перелік поточних змінних
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Вміст `/proc/*/environ` **розділений NUL**, тож ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Якщо ви шукаєте **credentials** або **interesting service configuration** всередині успадкованих середовищ, також перевірте [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display, який використовується **X**. Зазвичай ця змінна має значення **:0.0**, що означає перший display на поточному комп'ютері.
- **EDITOR** – улюблений текстовий редактор користувача.
- **HISTFILESIZE** – максимальна кількість рядків, що містяться у файлі history.
- **HISTSIZE** – кількість рядків, які додаються до файлу history, коли користувач завершує сесію
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – hostname комп'ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштового spool користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку manual pages.
- **OSTYPE** – тип operating system.
- **PS1** – стандартний prompt у bash.
- **PATH** – зберігає path усіх каталогів, які містять binary files, що ви хочете виконувати, просто вказавши ім'я файлу, а не relative або absolute path.
- **PWD** – поточний working directory.
- **SHELL** – path до поточної command shell (наприклад, **/bin/bash**).
- **TERM** – поточний тип terminal (наприклад, **xterm**).
- **TZ** – ваш time zone.
- **USER** – ваше поточне username.

## Interesting variables for hacking

Не кожна змінна однаково корисна. З offensive perspective, пріоритет слід надавати змінним, які змінюють **search paths**, **startup files**, **dynamic linker behavior** або **audit/logging**.

### **HISTFILESIZE**

Змініть **value of this variable to 0**, щоб коли ви **end your session** файл **history** (\~/.bash_history) був **truncated to 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** і не записувалися назад у **файл історії** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Якщо **значення цієї змінної встановлено на `ignorespace` або `ignoreboth`**, будь-яка команда, перед якою додано пробіл, не буде збережена в history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Вкажіть **history file** на **`/dev/null`** або повністю unset it. Це зазвичай надійніше, ніж лише змінювати розмір history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Процеси використовуватимуть **proxy**, оголошений тут, щоб підключатися до internet через **http or https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: проксі за замовчуванням для інструментів/протоколів, які його підтримують.
- `no_proxy`: список обходу (hosts/domains/CIDRs), які мають підключатися напряму.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Як у нижньому, так і у верхньому регістрі варіанти можуть використовуватися залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, вказаним у **цих env variables**. Це корисно, щоб змусити інструменти на кшталт **`curl`**, **`git`**, Python HTTP clients або package managers довіряти CA, контрольованому attacker'ом (наприклад, щоб зробити interception proxy виглядати легітимним).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейований wrapper/script виконує команди **без absolute paths**, **перший attacker-controlled directory** у `PATH` перемагає. Це примітив, на якому базуються багато **PATH hijacks** у `sudo`, cron jobs, shell wrappers і custom SUID helpers. Шукайте `env_keep+=PATH`, слабкий `secure_path` або wrappers, які викликають `tar`, `service`, `cp`, `python` тощо за назвою.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Для повних ланцюжків privilege-escalation, що зловживають `PATH`, дивіться [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` — це не лише посилання на директорію: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **per-user configuration** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований workflow зберігає ці значення, **config injection** може бути простішою за binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, а також файли, специфічні для tool, такі як `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **dynamic linker**:

- `LD_PRELOAD`: примусово завантажує додаткові shared objects першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку library на початок.
- `LD_AUDIT`: завантажує auditor libraries, які спостерігають за завантаженням library та resolution symbol.

Вони надзвичайно цінні для **hooking**, **instrumentation** та **privilege escalation**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад setuid/setgid/capabilities), loader видаляє або обмежує багато з цих змінних. Однак помилки парсера на цій ранній стадії loader все ще мають високий вплив, оскільки вони виконуються **до** target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, allocator tunables) і дуже корисний у exploit labs. Це також важливо з точки зору безпеки, тому що **dynamic loader parses it very early**. Помилка 2023 року **Looney Tunables** була хорошим нагадуванням, що одна змінна середовища, яку парсить loader, може стати **local privilege-escalation primitive** проти SUID programs.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Якщо **Bash** запущено **неінтерактивно**, він перевіряє `BASH_ENV` і підключає цей файл перед запуском цільового скрипта. Коли Bash викликається як `sh`, або в інтерактивному режимі у стилі POSIX, також може враховуватися `ENV`. Це класичний спосіб перетворити shell wrapper на виконання коду, якщо середовище контролює attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Сам Bash вимикає ці startup files, коли **real/effective IDs differ**, якщо не використано `-p`, тому точна поведінка залежить від того, як wrapper викликає shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ці variables змінюють те, як Python запускається:

- `PYTHONPATH`: додає import search paths на початок.
- `PYTHONHOME`: змінює розташування standard library tree.
- `PYTHONSTARTUP`: виконує file перед interactive prompt.
- `PYTHONINSPECT=1`: переводить у interactive mode після завершення script.

Вони корисні проти maintenance scripts, debuggers, shells і wrappers, які викликають Python із controllable environment. `python -E` і `python -I` ігнорують усі `PYTHON*` variables.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl має не менш корисні startup variables:

- `PERL5LIB`: додає library directories на початок.
- `PERL5OPT`: inject switches так, ніби вони були в кожному `perl` command line.

Це може примусити **automatic module loading** або змінити поведінку interpreter до того, як target script зробить щось цікаве. Perl ігнорує ці variables у контекстах **taint / setuid / setgid**, але вони все ще дуже важливі для звичайних root-run wrappers, CI jobs, installers і custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Те саме стосується й інших runtimes (`RUBYOPT`, `NODE_OPTIONS` тощо): щоразу, коли interpreter запускається через privileged wrapper, шукайте env vars, які змінюють **module loading** або **startup behavior**.

З perspective post-exploitation також пам’ятайте, що успадковані environments часто містять **credentials**, **proxy settings**, **service tokens** або **cloud keys**. Перевірте [Linux Post Exploitation](linux-post-exploitation/README.md) для `/proc/<PID>/environ` і пошуку `systemd` `Environment=`.

### PS1

Змініть, як виглядає ваш prompt.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
