# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Глобальні змінні

Глобальні змінні **будуть** успадковані **дочірніми процесами**.

Ви можете створити глобальну змінну для вашої поточної сесії, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна у ваших поточних сесіях та їхніх дочірніх процесах.

Ви можете **видалити** змінну так:
```bash
unset MYGLOBAL
```
## Локальні змінні

**Локальні змінні** можуть бути **доступні** лише для **поточного shell/script**.
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
Вміст `/proc/*/environ` є **розділеним NUL**, тож ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – дисплей, який використовується **X**. Це значення зазвичай встановлюється в **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – текстовий редактор, який користувач вважає за краще використовувати.
- **HISTFILESIZE** – максимальна кількість рядків, що містяться у файлі history.
- **HISTSIZE** – кількість рядків, що додаються до файлу history, коли користувач завершує свою сесію
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – hostname комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштового spool користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку сторінок manual.
- **OSTYPE** – тип операційної системи.
- **PS1** – стандартний prompt у bash.
- **PATH** – зберігає path усіх каталогів, які містять binary files, які ви хочете запускати, просто вказавши ім’я файла, а не relative або absolute path.
- **PWD** – поточний working directory.
- **SHELL** – path до поточного command shell (наприклад, **/bin/bash**).
- **TERM** – поточний тип terminal (наприклад, **xterm**).
- **TZ** – ваш time zone.
- **USER** – ваше поточне username.

## Interesting variables for hacking

Не кожна змінна однаково корисна. З offensive perspective, пріоритезуйте змінні, які змінюють **search paths**, **startup files**, **dynamic linker behavior** або **audit/logging**.

### **HISTFILESIZE**

Змініть **значення цієї змінної на 0**, щоб коли ви **завершите свою session**, **history file** (\~/.bash_history) було **обрізано до 0 рядків**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** і не записувалися назад у **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Якщо **значення цієї змінної встановлено в `ignorespace` або `ignoreboth`**, будь-яка команда, перед якою додано ще один пробіл, не буде збережена в історії.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Вкажіть **history file** на **`/dev/null`** або повністю скасуйте його встановлення. Це зазвичай надійніше, ніж лише змінювати розмір history.
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

- `all_proxy`: типовий proxy для інструментів/протоколів, які його враховують.
- `no_proxy`: список обходу (hosts/domains/CIDRs), до яких слід підключатися напряму.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Як у нижньому, так і у верхньому регістрі можуть використовуватися варіанти залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, вказаним у **цих env variables**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, Python HTTP clients або package managers, довіряти CA, контрольованому attacker'ом (наприклад, щоб зробити interception proxy схожим на легітимний).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейований wrapper/script виконує команди **без absolute paths**, **перший attacker-controlled directory** у `PATH` перемагає. Це primitive, на якому базуються багато **PATH hijacks** у `sudo`, cron jobs, shell wrappers та custom SUID helpers. Шукайте `env_keep+=PATH`, weak `secure_path` або wrappers, які викликають `tar`, `service`, `cp`, `python`, тощо за назвою.
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
Для повних chains privilege-escalation, що зловживають `PATH`, дивіться [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` — це не лише посилання на директорію: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **per-user configuration** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований workflow зберігає ці значення, **config injection** може бути простішим, ніж binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` і tool-specific файли, такі як `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **dynamic linker**:

- `LD_PRELOAD`: примусово завантажує додаткові shared objects першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку бібліотек на початок.
- `LD_AUDIT`: завантажує auditor libraries, які відстежують завантаження бібліотек і resolution символів.

Вони надзвичайно цінні для **hooking**, **instrumentation** і **privilege escalation**, якщо привілейована команда їх зберігає. У режимі **secure-execution** (`AT_SECURE`, наприклад setuid/setgid/capabilities), loader видаляє або обмежує багато з цих змінних. Однак баги parser на цій ранній стадії loader усе ще мають високий вплив, оскільки вони виконуються **до** цільової програми.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, tunables алокатора) і дуже корисний у exploit labs. Це також важливо з точки зору безпеки, тому що **dynamic loader аналізує його дуже рано**. Помилка 2023 року **Looney Tunables** була гарним нагадуванням, що одна змінна середовища, яка аналізується в loader, може стати **local privilege-escalation primitive** проти SUID programs.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Якщо **Bash** запускається **неінтерактивно**, він перевіряє `BASH_ENV` і підключає цей файл перед виконанням цільового скрипта. Коли Bash запускається як `sh` або в інтерактивному режимі POSIX-style, може також враховуватися `ENV`. Це класичний спосіб перетворити shell wrapper на code execution, якщо середовище контролюється атакувальником.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash сам вимикає ці startup files, коли **real/effective IDs differ**, якщо не використано `-p`, тож точна поведінка залежить від того, як wrapper викликає shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ці змінні змінюють те, як запускається Python:

- `PYTHONPATH`: додає шляхи пошуку import на початок.
- `PYTHONHOME`: змінює розташування дерева standard library.
- `PYTHONSTARTUP`: виконує файл перед interactive prompt.
- `PYTHONINSPECT=1`: переходить в interactive mode після завершення script.

Вони корисні проти maintenance scripts, debuggers, shells і wrappers, які викликають Python із контрольованим environment. `python -E` і `python -I` ігнорують усі `PYTHON*` variables.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl має не менш корисні змінні запуску:

- `PERL5LIB`: додає каталоги бібліотек на початок.
- `PERL5OPT`: підставляє перемикачі так, ніби вони були в кожному рядку команди `perl`.

Це може примусити **автоматичне завантаження модулів** або змінити поведінку інтерпретатора ще до того, як цільовий скрипт зробить щось цікаве. Perl ігнорує ці змінні в контекстах **taint / setuid / setgid**, але вони все ще дуже важливі для звичайних обгорток, запущених від root, CI jobs, інсталяторів і кастомних правил sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Така сама ідея з’являється в інших runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): коли interpreter запускається привілейованою wrapper, шукай env vars, які змінюють **module loading** або **startup behavior**.

З точки зору post-exploitation, також пам’ятай, що успадковані environments часто містять **credentials**, **proxy settings**, **service tokens**, або **cloud keys**. Перевір [Linux Post Exploitation](linux-post-exploitation/README.md) для пошуку в `/proc/<PID>/environ` і `systemd` `Environment=`.

### PS1

Зміни, як виглядає твій prompt.

[**Це приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

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
