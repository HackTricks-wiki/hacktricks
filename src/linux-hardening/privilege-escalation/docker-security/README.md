# Docker Security

{{#include ../../../banners/hacktricks-training.md}}

## **Основна безпека Docker Engine**

**Docker engine** використовує **Namespaces** та **Cgroups** ядра Linux для ізоляції контейнерів, пропонуючи базовий рівень безпеки. Додатковий захист забезпечується через **Capabilities dropping**, **Seccomp** та **SELinux/AppArmor**, що покращує ізоляцію контейнерів. **Auth plugin** може додатково обмежити дії користувачів.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Безпечний доступ до Docker Engine

Docker engine можна отримати доступ або локально через Unix-сокет, або віддалено за допомогою HTTP. Для віддаленого доступу важливо використовувати HTTPS та **TLS** для забезпечення конфіденційності, цілісності та автентифікації.

Docker engine за замовчуванням слухає на Unix-сокеті за адресою `unix:///var/run/docker.sock`. На системах Ubuntu параметри запуску Docker визначені в `/etc/default/docker`. Щоб увімкнути віддалений доступ до Docker API та клієнта, відкрийте демон Docker через HTTP-сокет, додавши наступні налаштування:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Однак, не рекомендується відкривати демон Docker через HTTP через проблеми безпеки. Рекомендується захищати з'єднання за допомогою HTTPS. Існує два основних підходи до забезпечення безпеки з'єднання:

1. Клієнт перевіряє особу сервера.
2. Як клієнт, так і сервер взаємно аутентифікують особу один одного.

Сертифікати використовуються для підтвердження особи сервера. Для детальних прикладів обох методів зверніться до [**цього посібника**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Безпека контейнерних образів

Контейнерні образи можуть зберігатися в приватних або публічних репозиторіях. Docker пропонує кілька варіантів зберігання для контейнерних образів:

- [**Docker Hub**](https://hub.docker.com): Публічний реєстр від Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Проект з відкритим кодом, що дозволяє користувачам хостити свій власний реєстр.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Комерційний реєстр Docker, що пропонує аутентифікацію користувачів на основі ролей та інтеграцію з службами каталогів LDAP.

### Сканування образів

Контейнери можуть мати **вразливості безпеки** як через базовий образ, так і через програмне забезпечення, встановлене поверх базового образу. Docker працює над проектом під назвою **Nautilus**, який виконує сканування безпеки контейнерів і перераховує вразливості. Nautilus працює, порівнюючи кожен шар образу контейнера з репозиторієм вразливостей для виявлення дірок у безпеці.

Для отримання більшої [**інформації прочитайте це**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Команда **`docker scan`** дозволяє сканувати існуючі образи Docker, використовуючи ім'я або ID образу. Наприклад, виконайте наступну команду, щоб просканувати образ hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Підписування образів Docker

Підписування образів Docker забезпечує безпеку та цілісність образів, що використовуються в контейнерах. Ось стисле пояснення:

- **Docker Content Trust** використовує проект Notary, заснований на The Update Framework (TUF), для управління підписуванням образів. Для отримання додаткової інформації дивіться [Notary](https://github.com/docker/notary) та [TUF](https://theupdateframework.github.io).
- Щоб активувати довіру до вмісту Docker, встановіть `export DOCKER_CONTENT_TRUST=1`. Ця функція вимкнена за замовчуванням у версії Docker 1.10 і пізніше.
- З цією активованою функцією можна завантажувати лише підписані образи. Перший пуш образу вимагає встановлення паролів для кореневого та тегового ключів, при цьому Docker також підтримує Yubikey для підвищення безпеки. Більше деталей можна знайти [тут](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Спроба витягти непідписаний образ з активованою довірою до вмісту призводить до помилки "No trust data for latest".
- Для пушів образів після першого Docker запитує пароль для ключа репозиторію, щоб підписати образ.

Щоб зробити резервну копію ваших приватних ключів, використовуйте команду:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Коли ви перемикаєтеся між Docker-хостами, необхідно перемістити ключі root і репозиторію для підтримки роботи.

## Безпека контейнерів

<details>

<summary>Підсумок функцій безпеки контейнерів</summary>

**Основні функції ізоляції процесів**

У контейнеризованих середовищах ізоляція проектів та їх процесів є надзвичайно важливою для безпеки та управління ресурсами. Ось спрощене пояснення ключових концепцій:

**Простори імен**

- **Мета**: Забезпечити ізоляцію ресурсів, таких як процеси, мережа та файлові системи. Особливо в Docker простори імен утримують процеси контейнера окремо від хоста та інших контейнерів.
- **Використання `unshare`**: Команда `unshare` (або підлягаюча системна виклик) використовується для створення нових просторів імен, забезпечуючи додатковий рівень ізоляції. Однак, хоча Kubernetes не блокує це за замовчуванням, Docker робить це.
- **Обмеження**: Створення нових просторів імен не дозволяє процесу повернутися до стандартних просторів імен хоста. Щоб проникнути в простори імен хоста, зазвичай потрібно мати доступ до каталогу `/proc` хоста, використовуючи `nsenter` для входу.

**Контрольні групи (CGroups)**

- **Функція**: Переважно використовуються для розподілу ресурсів між процесами.
- **Аспект безпеки**: CGroups самі по собі не забезпечують ізоляцію безпеки, за винятком функції `release_agent`, яка, якщо неправильно налаштована, може бути використана для несанкціонованого доступу.

**Скидання можливостей**

- **Важливість**: Це важлива функція безпеки для ізоляції процесів.
- **Функціональність**: Вона обмежує дії, які може виконувати процес з правами root, скидаючи певні можливості. Навіть якщо процес працює з привілеями root, відсутність необхідних можливостей заважає йому виконувати привілейовані дії, оскільки системні виклики зазнають невдачі через недостатні дозволи.

Це **залишкові можливості** після скидання процесом інших:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Він увімкнений за замовчуванням у Docker. Це допомагає **додатково обмежити syscalls**, які може викликати процес.\
**Профіль Seccomp за замовчуванням Docker** можна знайти за посиланням [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker має шаблон, який ви можете активувати: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Це дозволить зменшити можливості, syscalls, доступ до файлів і папок...

</details>

### Namespaces

**Namespaces** - це функція ядра Linux, яка **розділяє ресурси ядра** так, що один набір **процесів** **бачить** один набір **ресурсів**, тоді як **інший** набір **процесів** бачить **інший** набір ресурсів. Функція працює, маючи один і той же простір імен для набору ресурсів і процесів, але ці простори імен посилаються на різні ресурси. Ресурси можуть існувати в кількох просторах.

Docker використовує наступні простори імен ядра Linux для досягнення ізоляції контейнерів:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Для **додаткової інформації про простори імен** перегляньте наступну сторінку:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Функція ядра Linux **cgroups** надає можливість **обмежувати ресурси, такі як cpu, пам'ять, io, мережеву пропускну здатність серед** набору процесів. Docker дозволяє створювати контейнери, використовуючи функцію cgroup, яка дозволяє контролювати ресурси для конкретного контейнера.\
Наступний контейнер створено з обмеженням пам'яті користувацького простору до 500m, обмеженням пам'яті ядра до 50m, часткою cpu до 512, blkioweight до 400. Частка CPU - це співвідношення, яке контролює використання CPU контейнером. Воно має значення за замовчуванням 1024 і діапазон від 0 до 1024. Якщо три контейнери мають однакову частку CPU 1024, кожен контейнер може використовувати до 33% CPU у разі конкуренції за ресурси CPU. blkio-weight - це співвідношення, яке контролює IO контейнера. Воно має значення за замовчуванням 500 і діапазон від 10 до 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Щоб отримати cgroup контейнера, ви можете зробити:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Для отримання додаткової інформації перевірте:

{{#ref}}
cgroups.md
{{#endref}}

### Можливості

Можливості дозволяють **більш детальний контроль за можливостями, які можуть бути дозволені** для користувача root. Docker використовує функцію можливостей ядра Linux, щоб **обмежити операції, які можуть бути виконані всередині контейнера**, незалежно від типу користувача.

Коли запускається контейнер Docker, **процес скидає чутливі можливості, які процес міг би використовувати для втечі з ізоляції**. Це намагається забезпечити, щоб процес не міг виконувати чутливі дії та втекти:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp у Docker

Це функція безпеки, яка дозволяє Docker **обмежити системні виклики**, які можуть бути використані всередині контейнера:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor у Docker

**AppArmor** є покращенням ядра для обмеження **контейнерів** до **обмеженого** набору **ресурсів** з **профілями для кожної програми**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux у Docker

- **Система маркування**: SELinux призначає унікальну мітку кожному процесу та об'єкту файлової системи.
- **Забезпечення політики**: Він забезпечує виконання політик безпеки, які визначають, які дії може виконувати мітка процесу на інших мітках у системі.
- **Мітки процесів контейнера**: Коли контейнерні движки ініціюють процеси контейнера, їм зазвичай призначається обмежена мітка SELinux, зазвичай `container_t`.
- **Маркування файлів у контейнерах**: Файли всередині контейнера зазвичай маркуються як `container_file_t`.
- **Правила політики**: Політика SELinux в основному забезпечує, щоб процеси з міткою `container_t` могли взаємодіяти (читати, писати, виконувати) лише з файлами, маркованими як `container_file_t`.

Цей механізм забезпечує, що навіть якщо процес у контейнері буде скомпрометований, він обмежений у взаємодії лише з об'єктами, які мають відповідні мітки, значно обмежуючи потенційні збитки від таких компрометацій.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

У Docker плагін авторизації відіграє важливу роль у безпеці, вирішуючи, чи дозволити або заблокувати запити до демона Docker. Це рішення приймається шляхом аналізу двох ключових контекстів:

- **Контекст аутентифікації**: Це включає в себе всебічну інформацію про користувача, таку як хто вони і як вони аутентифікувалися.
- **Контекст команди**: Це містить усі відповідні дані, пов'язані із запитом, що робиться.

Ці контексти допомагають забезпечити, щоб лише законні запити від аутентифікованих користувачів оброблялися, підвищуючи безпеку операцій Docker.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS з контейнера

Якщо ви не обмежуєте належним чином ресурси, які може використовувати контейнер, скомпрометований контейнер може здійснити DoS на хост, на якому він працює.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- DoS з використанням пропускної здатності
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Цікаві прапорці Docker

### --privileged flag

На наступній сторінці ви можете дізнатися **що означає прапорець `--privileged`**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Якщо ви запускаєте контейнер, в якому зловмисник отримує доступ як користувач з низькими привілеями. Якщо у вас є **неправильно налаштований suid бінарний файл**, зловмисник може зловживати ним і **ескалювати привілеї всередині** контейнера. Це може дозволити йому втекти з нього.

Запуск контейнера з увімкненою опцією **`no-new-privileges`** дозволить **запобігти такій ескалації привілеїв**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Інше
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Для отримання додаткових опцій **`--security-opt`** перегляньте: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Інші аспекти безпеки

### Управління секретами: Найкращі практики

Важливо уникати вбудовування секретів безпосередньо в Docker-образи або використання змінних середовища, оскільки ці методи піддають вашу чутливу інформацію ризику для будь-кого, хто має доступ до контейнера через команди, такі як `docker inspect` або `exec`.

**Docker volumes** є більш безпечним варіантом, рекомендованим для доступу до чутливої інформації. Їх можна використовувати як тимчасову файлову систему в пам'яті, зменшуючи ризики, пов'язані з `docker inspect` та веденням журналів. Однак, користувачі з правами root та ті, хто має доступ до `exec` в контейнері, все ще можуть отримати доступ до секретів.

**Docker secrets** пропонують ще більш безпечний метод для обробки чутливої інформації. Для екземплярів, які потребують секретів під час етапу побудови образу, **BuildKit** представляє ефективне рішення з підтримкою секретів під час побудови, що підвищує швидкість побудови та надає додаткові функції.

Щоб скористатися BuildKit, його можна активувати трьома способами:

1. Через змінну середовища: `export DOCKER_BUILDKIT=1`
2. Додаючи префікс до команд: `DOCKER_BUILDKIT=1 docker build .`
3. Увімкнувши його за замовчуванням у конфігурації Docker: `{ "features": { "buildkit": true } }`, після чого потрібно перезапустити Docker.

BuildKit дозволяє використовувати секрети під час побудови з опцією `--secret`, забезпечуючи, щоб ці секрети не були включені в кеш побудови образу або в фінальний образ, використовуючи команду, таку як:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Для секретів, необхідних у запущеному контейнері, **Docker Compose та Kubernetes** пропонують надійні рішення. Docker Compose використовує ключ `secrets` у визначенні служби для вказівки секретних файлів, як показано в прикладі `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Ця конфігурація дозволяє використовувати секрети при запуску сервісів за допомогою Docker Compose.

У середовищах Kubernetes секрети підтримуються на рівні системи і можуть бути додатково керовані за допомогою інструментів, таких як [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Контроль доступу на основі ролей (RBAC) у Kubernetes підвищує безпеку управління секретами, подібно до Docker Enterprise.

### gVisor

**gVisor** - це ядро програми, написане на Go, яке реалізує значну частину системної поверхні Linux. Воно включає в себе [Open Container Initiative (OCI)](https://www.opencontainers.org) середовище виконання під назвою `runsc`, яке забезпечує **межу ізоляції між додатком і ядром хоста**. Середовище виконання `runsc` інтегрується з Docker і Kubernetes, що спрощує запуск контейнерів у пісочниці.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** - це спільнота з відкритим кодом, яка працює над створенням безпечного середовища виконання контейнерів з легкими віртуальними машинами, які відчуваються і працюють як контейнери, але забезпечують **сильнішу ізоляцію навантаження за допомогою технології апаратної віртуалізації** як другого рівня захисту.

{% embed url="https://katacontainers.io/" %}

### Поради щодо підсумків

- **Не використовуйте прапорець `--privileged` або монтуйте** [**сокет Docker всередині контейнера**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Сокет Docker дозволяє створювати контейнери, тому це простий спосіб отримати повний контроль над хостом, наприклад, запустивши інший контейнер з прапорцем `--privileged`.
- **Не запускайте як root всередині контейнера. Використовуйте** [**іншого користувача**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **і** [**простори імен користувачів**](https://docs.docker.com/engine/security/userns-remap/)**.** Root у контейнері є тим самим, що і на хості, якщо не переназначений за допомогою просторів імен користувачів. Він лише слабо обмежений, в основному, просторами імен Linux, можливостями та cgroups.
- [**Скиньте всі можливості**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) і активуйте лише ті, які потрібні** (`--cap-add=...`). Багато навантажень не потребують жодних можливостей, і їх додавання збільшує обсяг потенційної атаки.
- [**Використовуйте опцію безпеки “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) для запобігання отриманню процесами більшої кількості привілеїв, наприклад, через двійкові файли suid.
- [**Обмежте ресурси, доступні контейнеру**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Обмеження ресурсів можуть захистити машину від атак відмови в обслуговуванні.
- **Налаштуйте** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(або SELinux)** профілі для обмеження дій і системних викликів, доступних для контейнера, до мінімуму.
- **Використовуйте** [**офіційні образи Docker**](https://docs.docker.com/docker-hub/official_images/) **і вимагайте підписи** або створюйте свої власні на їх основі. Не успадковуйте або не використовуйте [задніми дверима](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) образи. Також зберігайте кореневі ключі, пароль у безпечному місці. Docker має плани керувати ключами за допомогою UCP.
- **Регулярно** **перебудовуйте** свої образи, щоб **застосовувати патчі безпеки до хоста та образів.**
- Розумно керуйте своїми **секретами**, щоб ускладнити доступ до них зловмиснику.
- Якщо ви **використовуєте демон Docker, використовуйте HTTPS** з автентифікацією клієнта та сервера.
- У вашому Dockerfile, **надавайте перевагу COPY замість ADD**. ADD автоматично розпаковує стиснуті файли і може копіювати файли з URL-адрес. COPY не має цих можливостей. Коли це можливо, уникайте використання ADD, щоб не піддаватися атакам через віддалені URL-адреси та Zip-файли.
- Майте **окремі контейнери для кожного мікросервісу**.
- **Не ставте ssh** всередині контейнера, “docker exec” можна використовувати для ssh до контейнера.
- Майте **менші** образи **контейнерів**.

## Вихід з Docker / Підвищення привілеїв

Якщо ви **всередині контейнера Docker** або маєте доступ до користувача в **групі docker**, ви можете спробувати **втекти та підвищити привілеї**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Обхід плагіна автентифікації Docker

Якщо у вас є доступ до сокета Docker або доступ до користувача в **групі docker, але ваші дії обмежуються плагіном автентифікації Docker**, перевірте, чи можете ви **обійти його:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Ускладнення Docker

- Інструмент [**docker-bench-security**](https://github.com/docker/docker-bench-security) - це скрипт, який перевіряє десятки загальних найкращих практик щодо розгортання контейнерів Docker у виробництві. Тести повністю автоматизовані і базуються на [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Вам потрібно запустити інструмент з хоста, на якому працює Docker, або з контейнера з достатніми привілеями. Дізнайтеся, **як його запустити в README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Посилання

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)


{{#include ../../../banners/hacktricks-training.md}}
