# Простір імен UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Базова інформація

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**ізоляцію двох системних ідентифікаторів**: the **hostname** and the **NIS** (Network Information Service) domain name. Ця ізоляція дозволяє кожному UTS простору імен мати **власний незалежний hostname і NIS domain name**, що особливо корисно в сценаріях контейнеризації, коли кожен контейнер має виглядати як окрема система зі своїм hostname.

### Як це працює:

1. Коли створюється новий UTS простір імен, він починається з **копії hostname і NIS domain name з його батьківського простору імен**. Це означає, що при створенні новий простір імен s**ділить ті ж ідентифікатори, що й батьківський**. Однак будь-які наступні зміни hostname або NIS domain name в межах цього простору імен не вплинуть на інші простори імен.
2. Процеси в межах UTS простору імен **можуть змінювати hostname і NIS domain name** за допомогою системних викликів `sethostname()` та `setdomainname()` відповідно. Ці зміни є локальними для простору імен і не впливають на інші простори імен або хост-систему.
3. Процеси можуть переміщуватися між просторами імен за допомогою системного виклику `setns()` або створювати нові простори імен за допомогою `unshare()` або `clone()` з прапорцем `CLONE_NEWUTS`. Коли процес переходить у новий простір імен або створює його, він починає використовувати hostname і NIS domain name, пов'язані з тим простором імен.

## Лабораторія:

### Створення різних просторів імен

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Монтування нового екземпляра файлової системи `/proc` за допомогою параметра `--mount-proc` гарантує, що новий mount namespace має **точний і ізольований вигляд інформації про процеси, специфічної для цього namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Коли `unshare` виконується без опції `-f`, виникає помилка через спосіб, яким Linux обробляє нові PID (Process ID) простори імен. Нижче наведено ключові деталі та рішення:

1. **Пояснення проблеми**:

- Ядро Linux дозволяє процесу створювати нові простори імен за допомогою системного виклику `unshare`. Однак процес, який ініціює створення нового PID-простору імен (званий процес "unshare"), не переходить у новий простір імен; у нього переходять тільки дочірні процеси.
- Запуск %unshare -p /bin/bash% запускає `/bin/bash` в тому ж процесі, що й `unshare`. Внаслідок цього `/bin/bash` та його дочірні процеси залишаються в оригінальному PID-просторі імен.
- Перший дочірній процес `/bin/bash` у новому просторі імен стає PID 1. Коли цей процес завершує роботу, це запускає очищення простору імен, якщо немає інших процесів, оскільки PID 1 має особливу роль приймання orphan processes. Ядро Linux тоді вимкне виділення PID у цьому просторі імен.

2. **Наслідок**:

- Вихід PID 1 у новому просторі імен призводить до очищення прапорця `PIDNS_HASH_ADDING`. Це спричиняє збій функції `alloc_pid` при виділенні нового PID під час створення процесу, що породжує помилку "Cannot allocate memory".

3. **Рішення**:
- Проблему можна вирішити, використавши опцію `-f` з `unshare`. Ця опція змушує `unshare` зробити fork нового процесу після створення нового PID-простору імен.
- Виконання %unshare -fp /bin/bash% гарантує, що сам `unshare` стане PID 1 у новому просторі імен. `/bin/bash` та його дочірні процеси тоді безпечно перебувають у цьому новому просторі імен, що запобігає передчасному виходу PID 1 і дозволяє нормальне виділення PID.

Забезпечивши запуск `unshare` з прапорцем `-f`, новий PID-простір імен правильно підтримується, що дозволяє `/bin/bash` та його підпроцесам працювати без виникнення помилки виділення пам'яті.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Перевірте, у якому namespace знаходиться ваш процес
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Знайти всі простори імен UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Увійти в UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Зловживання спільним UTS хоста

Якщо контейнер запущено з `--uts=host`, він приєднується до UTS namespace хоста замість отримання ізольованого. Маючи можливості, такі як `--cap-add SYS_ADMIN`, код у контейнері може змінити hostname/NIS name хоста через `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Зміна імені хоста може спотворити логи/оповіщення, заплутати виявлення кластера або зламати TLS/SSH конфігурації, які прив'язують перевірку до імені хоста.

### Виявлення контейнерів, які ділять UTS з хостом
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
