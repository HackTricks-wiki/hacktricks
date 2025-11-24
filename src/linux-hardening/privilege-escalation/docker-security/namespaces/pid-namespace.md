# Простір імен PID

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

Простір імен PID (Process IDentifier) — це функція ядра Linux, яка забезпечує ізоляцію процесів, дозволяючи групі процесів мати власний набір унікальних PID, відокремлений від PID в інших просторах імен. Це особливо корисно в контейнеризації, де ізоляція процесів є суттєвою для безпеки та управління ресурсами.

Коли створюється новий простір імен PID, першому процесу в цьому просторі присвоюється PID 1. Цей процес стає процесом "init" нового простору імен і відповідає за керування іншими процесами в ньому. Кожний наступний процес, створений у просторі імен, матиме унікальний PID у цьому просторі, і ці PID будуть незалежними від PID в інших просторах імен.

З перспективи процесу всередині простору імен PID він може бачити лише інші процеси в тому самому просторі імен. Він не знає про процеси в інших просторах імен і не може взаємодіяти з ними за допомогою традиційних інструментів управління процесами (наприклад, `kill`, `wait` тощо). Це забезпечує рівень ізоляції, який допомагає запобігти взаємному втручанню процесів.

### Як це працює:

1. When a new process is created (e.g., by using the `clone()` system call), the process can be assigned to a new or existing PID namespace. **Якщо створюється новий простір імен, процес стає процесом "init" цього простору імен**.
2. The **ядро** підтримує **відображення між PID у новому просторі імен та відповідними PID** у батьківському просторі імен (тобто просторі, з якого був створений новий простір імен). Це відображення **дозволяє ядру транслювати PID за потреби**, наприклад при надсиланні сигналів між процесами в різних просторах імен.
3. **Процеси всередині простору імен PID можуть бачити та взаємодіяти лише з іншими процесами в тому самому просторі імен**. Вони не знають про процеси в інших просторах імен, а їхні PID є унікальними в межах їхнього простору імен.
4. Коли **простір імен PID знищується** (наприклад, коли процес "init" цього простору імен завершується), **всі процеси в межах цього простору імен припиняються**. Це гарантує, що всі ресурси, пов'язані з простором імен, будуть належним чином очищені.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Коли `unshare` виконується без опції `-f`, виникає помилка через те, як Linux обробляє нові простори імен PID (Process ID). Нижче наведено основні деталі та рішення:

1. **Пояснення проблеми**:

- Ядро Linux дозволяє процесу створювати нові простори імен за допомогою системного виклику `unshare`. Однак процес, який ініціює створення нового PID namespace (званий процесом "unshare"), не входить у новий простір імен; туди входять лише його дочірні процеси.
- Виконання `%unshare -p /bin/bash%` запускає `/bin/bash` в тому ж процесі, що й `unshare`. Внаслідок цього `/bin/bash` та його дочірні процеси залишаються у початковому просторі імен PID.
- Перший дочірній процес `/bin/bash` у новому просторі імен отримує PID 1. Коли цей процес завершується, це ініціює очищення простору імен, якщо немає інших процесів, оскільки PID 1 має особливу роль усиновлювача сиріт. Ядро Linux тоді вимкне виділення PID у цьому просторі імен.

2. **Наслідок**:

- Вихід PID 1 у новому просторі імен призводить до очищення прапора `PIDNS_HASH_ADDING`. Внаслідок цього функція `alloc_pid` не може виділити новий PID під час створення процесу, що спричиняє помилку "Cannot allocate memory".

3. **Рішення**:
- Проблему можна вирішити, використавши опцію `-f` з `unshare`. Ця опція змушує `unshare` виконати fork нового процесу після створення нового простору імен PID.
- Виконання `%unshare -fp /bin/bash%` гарантує, що сам `unshare` стане PID 1 у новому просторі імен. `/bin/bash` та його дочірні процеси будуть безпечно розміщені в цьому просторі імен, що запобігає передчасному виходу PID 1 і дозволяє нормальне виділення PID.

Забезпечивши запуск `unshare` з прапором `-f`, новий простір імен PID правильно підтримується, що дозволяє `/bin/bash` та його підпроцесам працювати без виникнення помилки виділення пам'яті.

</details>

Монтуючи новий екземпляр файлової системи `/proc` за допомогою параметра `--mount-proc`, ви гарантуєте, що новий mount namespace має **точний та ізольований вигляд інформації про процеси, специфічний для цього простору імен**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Перевірте, у якому namespace знаходиться ваш процес
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Знайти всі PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Зауважте, що користувач root з початкового (default) PID namespace може бачити всі процеси, навіть ті, що перебувають у нових PID namespaces, саме тому ми можемо бачити всі PID namespaces.

### Увійти в PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **увійти в PID namespace іншого процесу лише якщо ви root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Останні нотатки щодо експлуатації

### CVE-2025-31133: зловживання `maskedPaths` для доступу до host PIDs

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Практичний робочий процес:

1. Збудуйте OCI bundle, чий rootfs замінює `/dev/null` на посилання на потрібний host path (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Запустіть контейнер до виправлення, щоб runc bind-mount-ив ціль host procfs поверх цього посилання.
3. Всередині container namespace запишіть у тепер відкритий procfs файл (наприклад, вкажіть `core_pattern` на helper для reverse shell) і аварійно завершите будь-який процес, щоб змусити kernel хоста виконати ваш helper в контексті PID 1.

Ви можете швидко перевірити, чи bundle маскує потрібні файли перед його запуском:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Якщо runtime не має очікуваного запису маскування (або пропускає його через те, що `/dev/null` зник), вважайте container таким, що може мати потенційну host PID visibility.

### Namespace injection with `insject`

NCC Group’s `insject` завантажується як LD_PRELOAD payload, який хукає пізню стадію в цільовій програмі (за замовчуванням `main`) і виконує послідовність викликів `setns()` після `execve()`. Це дозволяє приєднатися з host (або іншого container) у PID namespace жертви *після* ініціалізації її runtime, зберігаючи його `/proc/<pid>` view без необхідності копіювати бінарники у filesystem контейнера. Оскільки `insject` може відкладати приєднання до PID namespace до fork, ви можете тримати один thread у host namespace (з CAP_SYS_PTRACE), тоді як інший thread виконується у цільовому PID namespace, створюючи потужні можливості для debugging або offensive primitives.

Приклад використання:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ключові висновки при зловживанні або захисті від namespace injection:

- Використовуйте `-S/--strict`, щоб примусити `insject` перервати роботу, якщо потоки вже існують або namespace joins fail, інакше ви можете залишити частково переміщені потоки, що перетинають простори PID хоста і контейнера.
- Ніколи не підключайте інструменти, які все ще мають записувані файлові дескриптори хоста, якщо ви також не приєднаєтесь до mount namespace — інакше будь-який процес всередині PID namespace може ptrace ваш helper і повторно використати ці дескриптори для маніпуляцій з ресурсами хоста.

## Посилання

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
