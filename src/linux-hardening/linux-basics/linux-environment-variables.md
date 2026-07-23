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

**Локальні змінні** можна **отримати** лише з **поточної оболонки/скрипту**.
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
Вміст `/proc/*/environ` **розділено NUL-символами**, тому ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Якщо ви шукаєте **облікові дані** або **цікаву конфігурацію сервісів** у успадкованих середовищах, також перевірте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Поширені змінні

Джерело: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – дисплей, який використовується **X**. Зазвичай цій змінній встановлюють значення **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – текстовий редактор, якому надає перевагу користувач.
- **HISTFILESIZE** – максимальна кількість рядків у файлі історії.
- **HISTSIZE** – кількість рядків, які додаються до файлу історії після завершення користувачем сеансу.
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – ім’я хоста комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштової скриньки користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку сторінок посібника.
- **OSTYPE** – тип операційної системи.
- **PS1** – стандартне запрошення в bash.
- **PATH** – містить шляхи до всіх каталогів, у яких знаходяться бінарні файли, що ви хочете виконувати, вказуючи лише ім’я файлу, а не відносний або абсолютний шлях.
- **PWD** – поточний робочий каталог.
- **SHELL** – шлях до поточної командної оболонки (наприклад, **/bin/bash**).
- **TERM** – поточний тип термінала (наприклад, **xterm**).
- **TZ** – ваш часовий пояс.
- **USER** – ваше поточне ім’я користувача.

## Цікаві змінні для hacking

Не кожна змінна однаково корисна. З offensive perspective пріоритет слід надавати змінним, які змінюють **шляхи пошуку**, **файли запуску**, **поведінку dynamic linker** або **аудит/логування**.

### **HISTFILESIZE**

Змініть **значення цієї змінної на 0**, щоб після **завершення сеансу** **файл історії** (\~/.bash_history) було **усічено до 0 рядків**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** та не записувалися назад у **файл історії** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Якщо **значення цієї змінної встановлено як `ignorespace` або `ignoreboth`**, будь-яка команда, перед якою додано пробіл, не буде збережена в історії.
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

Процеси використовуватимуть **proxy**, оголошений тут, щоб підключатися до internet через **http або https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy та no_proxy

- `all_proxy`: проксі за замовчуванням для інструментів/протоколів, які його підтримують.
- `no_proxy`: список винятків (хости/домени/CIDR), які мають підключатися напряму.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Можуть використовуватися варіанти в нижньому та верхньому регістрі залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, указаним у **цих змінних середовища**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, HTTP-клієнти Python або менеджери пакетів, довіряти CA, контрольованому attacker (наприклад, щоб проксі перехоплення виглядав легітимним).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейований wrapper/script виконує команди **без абсолютних шляхів**, перший контрольований атакувальником каталог у `PATH` отримує перевагу. Це примітив, що лежить в основі багатьох **PATH hijacks** у `sudo`, cron jobs, shell wrappers і власних SUID helpers. Шукайте `env_keep+=PATH`, слабкий `secure_path` або wrappers, які викликають `tar`, `service`, `cp`, `python` тощо за іменем.
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
Для повних ланцюжків підвищення привілеїв із використанням `PATH` див. [Підвищення привілеїв у Linux](linux-privilege-escalation/README.md).

### **HOME і XDG_CONFIG_HOME**

`HOME` — це не лише посилання на каталог: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **конфігурацію для окремого користувача** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований процес зберігає ці значення, **ін'єкція конфігурації** може бути простішою за **перехоплення бінарних файлів**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` і специфічні для інструментів файли, такі як `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **динамічний linker**:

- `LD_PRELOAD`: змушує додаткові shared objects завантажуватися першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку бібліотек на початок списку.
- `LD_AUDIT`: завантажує auditor libraries, які відстежують завантаження бібліотек і розв'язання символів.

Вони надзвичайно цінні для **hooking**, **instrumentation** і **privilege escalation**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад setuid/setgid/capabilities) loader видаляє або обмежує багато з цих змінних. Однак parser bugs на цьому ранньому етапі роботи loader усе одно мають значний вплив, оскільки виконуються **до** цільової програми.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, налаштування allocator) і дуже корисна в exploit-лабораторіях. Вона також важлива з погляду безпеки, оскільки **dynamic loader аналізує її на дуже ранньому етапі**. Вразливість **Looney Tunables** 2023 року стала хорошим нагадуванням про те, що одна змінна середовища, яку аналізує loader, може перетворитися на **примітив локального підвищення привілеїв** проти програм SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV і ENV**

Якщо **Bash** запускається **неінтерактивно**, він перевіряє `BASH_ENV` і виконує цей файл перед запуском цільового скрипту. Коли Bash викликається як `sh` або в інтерактивному режимі POSIX, також може перевірятися `ENV`. Це класичний спосіб перетворити shell wrapper на виконання коду, якщо середовище контролюється зловмисником.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Сам Bash вимикає ці startup files, коли **реальні/ефективні ідентифікатори відрізняються**, якщо не використано `-p`, тому точна поведінка залежить від того, як wrapper запускає shell. Будьте обережні з privileged wrappers, які викликають `setuid()`/`setgid()` **до** запуску Bash: щойно ідентифікатори знову збігаються, Bash може довіряти `BASH_ENV`, `ENV` та пов'язаному shell state, які в іншому випадку ігнорувалися б.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ці змінні змінюють спосіб запуску Python:

- `PYTHONPATH`: додає на початок шляхи пошуку імпортів.
- `PYTHONHOME`: переміщує дерево стандартної бібліотеки.
- `PYTHONSTARTUP`: виконує файл перед появою інтерактивного prompt.
- `PYTHONINSPECT=1`: переходить в інтерактивний режим після завершення script.

Вони корисні проти maintenance scripts, debuggers, shells і wrappers, які запускають Python із контрольованим environment. `python -E` і `python -I` ігнорують усі змінні `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Нещодавнім прикладом із реального світу стала LPE через **needrestart** у 2024 році на системах Ubuntu/Debian: сканер, що належав root, копіював `PYTHONPATH` непривілейованого процесу з `/proc/<PID>/environ`, а потім виконував Python. Опублікований exploit розміщував `importlib/__init__.so` у шляху, контрольованому attacker, завдяки чому Python виконував код attacker під час власної ініціалізації, ще до того, як взагалі мав значення жорстко заданий скрипт helper.

### **PERL5OPT & PERL5LIB**

Perl має такі ж корисні змінні запуску:

- `PERL5LIB`: додає каталоги бібліотек на початок списку.
- `PERL5OPT`: вставляє switches так, ніби вони були в кожному командному рядку `perl`.

Це може примусово увімкнути **автоматичне завантаження модулів** або змінити поведінку interpreter ще до того, як цільовий скрипт виконає щось важливе. Perl ігнорує ці змінні в контекстах **taint / setuid / setgid**, але вони все одно мають велике значення для звичайних wrapper-ів, що запускаються від root, CI jobs, installers і custom правил sudoers.
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

`NODE_OPTIONS` додає **Node.js CLI flags** перед аргументами кожного процесу `node`, який успадковує середовище. Це робить його корисним проти wrappers, CI jobs, Electron helpers і sudo rules, які зрештою запускають Node. Найцікавішими flags для атак зазвичай є:

- `--require <file>`: попередньо завантажує CommonJS file перед цільовим script.
- `--import <module>`: попередньо завантажує ES module перед цільовим script.

Node відхиляє деякі небезпечні flags у `NODE_OPTIONS`, але `--require` і `--import` явно дозволені та обробляються **до** звичайних аргументів командного рядка.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Для remote gadget chains, які опосередковано встановлюють `NODE_OPTIONS` (наприклад, через prototype-pollution to RCE), перегляньте [цю іншу сторінку](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby підтримує такий самий клас зловживань під час запуску:

- `RUBYLIB`: додає каталоги на початок шляху завантаження Ruby.
- `RUBYOPT`: інжектує параметри командного рядка, наприклад `-r`, у кожен виклик `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Вразливості **needrestart** у 2024 році показали, що це не просто лабораторний трюк: той самий helper, власником якого є root і який був вразливим до зловживання `PYTHONPATH`, також можна було змусити запускати Ruby з контрольованим зловмисником `RUBYLIB`, завантажуючи `enc/encdb.so` зі зловмисної директорії.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Деякі інструменти не просто читають шлях із environment; вони передають значення до **shell**, **editor** або **input preprocessor**. Це робить наведені нижче змінні особливо цікавими, коли privileged wrapper запускає `git`, `man`, `less` або подібні переглядачі тексту:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: обирають команду pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: обирають команду editor, часто з аргументами.
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
Git також підтримує **інʼєкцію конфігурації лише через змінні середовища** без запису на диск за допомогою `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` і `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
З perspective post-exploitation також пам’ятайте, що успадковані середовища часто містять **credentials**, **proxy settings**, **service tokens** або **cloud keys**. Перегляньте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), щоб дізнатися про `/proc/<PID>/environ` і пошук `Environment=` у `systemd`.

### PS1

Змініть вигляд prompt.

[**Це приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Це приклад](<../images/image (897).png>)

Звичайний користувач:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три backgrounded jobs](<../images/image (740).png>)

Одне, два та три backgrounded jobs:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три backgrounded jobs](<../images/image (145).png>)

Одне background job, одне зупинене, а остання команда завершилася некоректно:

![PERL5OPT & PERL5LIB - PS1: Одне background job, одне зупинене, а остання команда завершилася некоректно](<../images/image (715).png>)

## References

- [GNU Bash Manual - Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Документація Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
