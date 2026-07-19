# Змінні середовища Linux

{{#include ../../banners/hacktricks-training.md}}

## Глобальні змінні

**Глобальні змінні будуть** успадковані **дочірніми процесами**.

Ви можете створити глобальну змінну для поточного сеансу, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна вашим поточним сеансам і їхнім дочірнім процесам.

Ви можете **видалити** змінну за допомогою:
```bash
unset MYGLOBAL
```
## Локальні змінні

**Локальні змінні** можна **отримати доступ** лише з **поточної оболонки/скрипту**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Список поточних змінних
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Вміст `/proc/*/environ` розділений **NUL-символами**, тому ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Якщо ви шукаєте **credentials** або **цікаву конфігурацію сервісів** усередині успадкованих середовищ, також перевірте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Поширені змінні

Джерело: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – дисплей, який використовується **X**. Зазвичай цій змінній встановлюється значення **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – текстовий редактор, якому надає перевагу користувач.
- **HISTFILESIZE** – максимальна кількість рядків у файлі history.
- **HISTSIZE** – кількість рядків, що додаються до файлу history після завершення користувачем сеансу.
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – hostname комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування mail spool користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку manual pages.
- **OSTYPE** – тип операційної системи.
- **PS1** – стандартний prompt у bash.
- **PATH** – зберігає шляхи до всіх каталогів, що містять binary files, які потрібно виконувати, вказуючи лише ім’я файлу, а не relative або absolute path.
- **PWD** – поточний робочий каталог.
- **SHELL** – шлях до поточної command shell (наприклад, **/bin/bash**).
- **TERM** – поточний тип terminal (наприклад, **xterm**).
- **TZ** – ваш часовий пояс.
- **USER** – ваше поточне username.

## Цікаві змінні для hacking

Не кожна змінна однаково корисна. З offensive perspective надавайте пріоритет змінним, які змінюють **пошукові шляхи**, **startup files**, **поведінку dynamic linker** або **audit/logging**.

### **HISTFILESIZE**

Змініть **значення цієї змінної на 0**, щоб після **завершення вашого сеансу** **history file** (\~/.bash_history) було **усічено до 0 рядків**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** та не записувалися назад у **файл історії** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Якщо **значення цієї змінної встановлено як `ignorespace` або `ignoreboth`**, будь-яка команда, перед якою додано пробіл, не зберігатиметься в історії.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Спрямуйте **файл історії** до **`/dev/null`** або повністю скасуйте його. Зазвичай це надійніше, ніж лише змінити розмір історії.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Процеси використовуватимуть вказаний тут **proxy**, щоб підключатися до internet через **http або https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: проксі за замовчуванням для інструментів/протоколів, які його підтримують.
- `no_proxy`: список обходу (хости/домени/CIDR), які мають підключатися напряму.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Можуть використовуватися варіанти як у нижньому, так і у верхньому регістрі залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, указаним у **цих змінних середовища**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, HTTP-клієнти Python або менеджери пакетів, довіряти CA, контрольованому attacker'ом (наприклад, щоб proxy для перехоплення трафіку виглядав легітимним).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейований wrapper/script виконує команди **без абсолютних шляхів**, перемагає перший контрольований атакувальником каталог у `PATH`. Це примітив, що лежить в основі багатьох **PATH hijacks** у `sudo`, cron jobs, shell wrappers і власних SUID helpers. Шукайте `env_keep+=PATH`, слабкий `secure_path` або wrappers, які викликають `tar`, `service`, `cp`, `python` тощо за іменем.
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
Для повних ланцюжків privilege escalation із використанням `PATH` див. [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` — це не лише посилання на директорію: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **конфігурацію користувача** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований workflow зберігає ці значення, **config injection** може бути простішим за binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, а також специфічні для інструментів файли, наприклад `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **dynamic linker**:

- `LD_PRELOAD`: примусово завантажує додаткові shared objects першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку бібліотек на початок списку.
- `LD_AUDIT`: завантажує auditor libraries, які відстежують завантаження бібліотек і розв'язання символів.

Вони надзвичайно цінні для **hooking**, **instrumentation** і **privilege escalation**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад, setuid/setgid/capabilities) loader видаляє або обмежує багато з цих змінних. Однак parser bugs на цьому ранньому етапі loader усе ще мають високий вплив, оскільки спрацьовують **до** цільової програми.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, параметри allocator) і дуже зручна в exploit labs. Вона також важлива з погляду безпеки, оскільки **dynamic loader розбирає її на дуже ранньому етапі**. Вразливість **Looney Tunables** 2023 року стала хорошим нагадуванням про те, що одна змінна середовища, яку обробляє loader, може перетворитися на **примітив локального підвищення привілеїв** проти SUID-програм.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Якщо **Bash** запускається **неінтерактивно**, він перевіряє `BASH_ENV` і підключає цей файл перед запуском цільового скрипту. Коли Bash викликається як `sh` або в інтерактивному режимі POSIX, також може перевірятися `ENV`. Це класичний спосіб перетворити shell wrapper на code execution, якщо середовище контролюється атакувальником.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash сам вимикає ці startup-файли, коли **real/effective IDs відрізняються**, якщо не використовується `-p`, тому точна поведінка залежить від того, як wrapper запускає shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP і PYTHONINSPECT**

Ці змінні змінюють спосіб запуску Python:

- `PYTHONPATH`: додає на початок шляхи пошуку імпортів.
- `PYTHONHOME`: переміщує дерево стандартної бібліотеки.
- `PYTHONSTARTUP`: виконує файл перед появою інтерактивного запрошення.
- `PYTHONINSPECT=1`: переходить в інтерактивний режим після завершення скрипта.

Вони корисні проти maintenance-скриптів, debugger-ів, shell-ів і wrapper-ів, які запускають Python із контрольованим environment. `python -E` і `python -I` ігнорують усі змінні `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl має такі ж корисні змінні запуску:

- `PERL5LIB`: додає каталоги бібліотек на початок списку.
- `PERL5OPT`: впроваджує перемикачі так, ніби вони були вказані в кожному командному рядку `perl`.

Це може примусово активувати **автоматичне завантаження модулів** або змінити поведінку інтерпретатора ще до того, як цільовий скрипт виконає щось важливе. Perl ігнорує ці змінні в контекстах **taint / setuid / setgid**, але вони все одно мають велике значення для звичайних обгорток, що запускаються від root, CI-завдань, інсталяторів і спеціальних правил sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Та сама ідея застосовується в інших runtime (`RUBYOPT`, `NODE_OPTIONS` тощо): щоразу, коли interpreter запускається privileged wrapper, шукайте env vars, які змінюють **завантаження модулів** або **поведінку під час запуску**.

З точки зору post-exploitation також пам’ятайте, що успадковані environments часто містять **credentials**, **налаштування proxy**, **service tokens** або **cloud keys**. Перегляньте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), щоб дізнатися про `/proc/<PID>/environ` і пошук `Environment=` у `systemd`.

### PS1

Змініть вигляд prompt.

[**Це приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Це приклад](<../images/image (897).png>)

Звичайний користувач:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три jobs, запущені у background](<../images/image (740).png>)

Одне, два та три jobs, запущені у background:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три jobs, запущені у background](<../images/image (145).png>)

Одне job у background, одне зупинене, а остання команда завершилася некоректно:

![PERL5OPT & PERL5LIB - PS1: Одне job у background, одне зупинене, а остання команда завершилася некоректно](<../images/image (715).png>)

## Посилання

- [Посібник GNU Bash - Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
