# Користувацький простір імен

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Посилання

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Основна інформація

Користувацький простір імен — це функція ядра Linux, яка **надає ізоляцію відображень user та group ID**, дозволяючи кожному користувацькому простору імен мати **власний набір user і group ID**. Ця ізоляція дозволяє процесам, що виконуються в різних користувацьких просторах імен, **мати різні привілеї та власність**, навіть якщо числово вони мають однакові user і group ID.

Користувацькі простори імен особливо корисні в контейнеризації, де кожен контейнер повинен мати свій незалежний набір user і group ID, що забезпечує кращу безпеку та ізоляцію між контейнерами та хост-системою.

### Як це працює:

1. Коли створюється новий користувацький простір імен, він **починається з порожнього набору відображень user і group ID**. Це означає, що будь-який процес, що виконується в новому просторі імен, **спочатку не матиме привілеїв поза межами простору імен**.
2. Можна встановити відображення ID між user і group ID у новому просторі імен і тими, що в батьківському (або хостовому) просторі імен. Це **дозволяє процесам у новому просторі мати привілеї та власність, що відповідають user і group ID у батьківському просторі**. Однак відображення ID можуть бути обмежені певними діапазонами та підмножинами ID, що дозволяє точно контролювати привілеї, надані процесам у новому просторі імен.
3. Всередині користувацького простору імен **процеси можуть мати повні привілеї root (UID 0) для операцій всередині простору імен**, одночасно маючи обмежені привілеї поза простором імен. Це дозволяє **контейнерам працювати з привілеями, схожими на root, всередині їхнього власного простору імен, без надання повних root-привілеїв на хості**.
4. Процеси можуть переміщуватися між просторами імен за допомогою виклику системи `setns()` або створювати нові простори імен за допомогою `unshare()` або `clone()` з прапором `CLONE_NEWUSER`. Коли процес переходить у новий простір імен або створює його, він починає використовувати відображення user і group ID, пов'язані з цим простором імен.

## Лабораторія:

### Створення різних просторів імен

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Помилка: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Пояснення проблеми**:

- Ядро Linux дозволяє процесу створювати нові namespaces за допомогою системного виклику `unshare`. Однак процес, який ініціює створення нового PID (Process ID) namespace (званий процесом "unshare"), не входить у новий namespace; тільки його дочірні процеси входять.
- Запуск `%unshare -p /bin/bash%` запускає `/bin/bash` у тому ж процесі, що й `unshare`. Внаслідок цього `/bin/bash` та його дочірні процеси перебувають в оригінальному PID namespace.
- Перший дочірній процес `/bin/bash` у новому namespace отримує PID 1. Коли цей процес завершується, якщо в просторі імен немає інших процесів, це запускає очистку namespace, оскільки PID 1 має спеціальну роль приймати сиріт (orphan processes). Ядро Linux тоді відключить виділення PID у цьому просторі імен.

2. **Наслідок**:

- Вихід PID 1 у новому namespace призводить до очищення прапорця `PIDNS_HASH_ADDING`. Це призводить до того, що функція `alloc_pid` не може виділити новий PID при створенні нового процесу, внаслідок чого з’являється помилка "Cannot allocate memory".

3. **Рішення**:
- Проблему можна вирішити, використавши опцію `-f` з `unshare`. Ця опція змушує `unshare` зробити fork нового процесу після створення нового PID namespace.
- Виконання `%unshare -fp /bin/bash%` гарантує, що сам `unshare` стане PID 1 у новому namespace. `/bin/bash` та його дочірні процеси тоді безпечно міститимуться в цьому просторі імен, що запобігає передчасному завершенню PID 1 і дозволяє нормальне виділення PID.

Переконавшись, що `unshare` запускається з прапорцем `-f`, новий PID namespace правильно підтримується, що дозволяє `/bin/bash` та його підпроцесам працювати без виникнення помилки виділення пам'яті.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Щоб використовувати простір імен користувача, демон Docker має бути запущений з **`--userns-remap=default`**(У ubuntu 14.04 це можна зробити, відредагувавши `/etc/default/docker` і потім виконавши `sudo service docker restart`)

### Перевірте, у якому просторі імен знаходиться ваш процес
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Можна перевірити user map з контейнера docker за допомогою:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Або з хоста за допомогою:
```bash
cat /proc/<pid>/uid_map
```
### Знайти всі User namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Увійти в User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Також ви можете тільки **увійти в простір імен іншого процесу, якщо ви root**. І ви **не можете** **увійти** в інший простір імен **без дескриптора**, що вказує на нього (наприклад `/proc/self/ns/user`).

### Створити новий простір імен користувача (з відображеннями)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Правила відображення UID/GID для неповнопривілейованих процесів

Коли процес, що записує в `uid_map`/`gid_map`, **не має CAP_SETUID/CAP_SETGID у батьківському користувацькому просторі імен**, ядро застосовує суворіші правила: дозволяється лише **одне відображення** для ефективного UID/GID викликача, а для `gid_map` ви **повинні спочатку відключити `setgroups(2)`**, записавши `deny` у `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **приєднують відображення user namespace до mount**, тож власність файлів перемаповується при доступі через цей mount. Це зазвичай використовується контейнерними рантаймами (особливо rootless) для **спільного використання хост-путів без рекурсивного `chown`**, одночасно застосовуючи трансляцію UID/GID user namespace.

### Відновлення можливостей

У випадку user namespaces, **коли створюється новий user namespace, процес, що входить у нього, отримує повний набір capabilities в межах цього namespace**. Ці capabilities дозволяють процесу виконувати привілейовані операції, такі як **монтування** **файлових систем**, створення пристроїв або зміну власності файлів, але **тільки в контексті свого user namespace**.

Наприклад, коли у вас є `CAP_SYS_ADMIN` всередині user namespace, ви можете виконувати операції, які зазвичай вимагають цієї capability, як-от монтування файлових систем, але лише в контексті вашого user namespace. Жодні операції з цією capability не вплинуть на хост-систему або інші namespaces.

> [!WARNING]
> Тому, навіть якщо запуск нового процесу в новому User namespace **поверне вам усі capabilities** (CapEff: 000001ffffffffff), насправді ви зможете **використовувати лише ті, що стосуються namespace** (mount, наприклад), а не всі. Отже, цього самого по собі недостатньо, щоб вийти з Docker контейнера.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Посилання

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
