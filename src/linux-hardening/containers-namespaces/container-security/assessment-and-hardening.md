# Tathmini Na Kuimarisha Usalama

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Tathmini nzuri ya container inapaswa kujibu maswali mawili kwa wakati mmoja. Kwanza, attacker anaweza kufanya nini kutoka kwenye workload ya sasa? Pili, ni chaguo zipi za operator zilizowezesha hilo? Zana za enumeration husaidia kujibu swali la kwanza, na mwongozo wa hardening husaidia kujibu la pili. Kuyaweka yote kwenye ukurasa mmoja hufanya sehemu hii iwe muhimu zaidi kama marejeo ya uwanjani badala ya kuwa katalogi tu ya mbinu za escape.

Sasisho moja la muhimu kwa mazingira ya kisasa ni kwamba maandishi mengi ya zamani kuhusu containers hudhani kwa siri matumizi ya **rootful runtime**, **hakuna user namespace isolation**, na mara nyingi **cgroup v1**. Mawazo hayo si salama tena. Kabla ya kutumia muda kwenye escape primitives za zamani, thibitisha kwanza ikiwa workload ni rootless au userns-remapped, ikiwa host inatumia cgroup v2, na ikiwa Kubernetes au runtime sasa inatumia seccomp na AppArmor profiles za msingi. Maelezo haya mara nyingi huamua ikiwa breakout maarufu bado inatumika.

## Zana za Enumeration

Zana kadhaa bado zinafaa kwa kutambua kwa haraka sifa za container environment:

- `linpeas` inaweza kutambua viashiria vingi vya container, sockets zilizomountiwa, capability sets, filesystems hatari, na dalili za breakout.
- `CDK` inalenga hasa container environments na inajumuisha enumeration pamoja na baadhi ya ukaguzi wa escape unaoendeshwa kiotomatiki.
- `amicontained` ni nyepesi na inafaa kwa kutambua vizuizi vya container, capabilities, namespace exposure, na aina zinazowezekana za breakout.
- `deepce` ni enumerator nyingine inayolenga containers yenye ukaguzi unaohusiana na breakout.
- `grype` inafaa wakati tathmini inajumuisha ukaguzi wa vulnerabilities za packages kwenye image badala ya uchanganuzi wa runtime escape pekee.
- `Tracee` inafaa unapohitaji **ushahidi wa runtime** badala ya static posture pekee, hasa kwa process execution zinazotiliwa shaka, file access, na ukusanyaji wa events unaotambua containers.
- `Inspektor Gadget` inafaa katika uchunguzi wa Kubernetes na Linux-host unapohitaji visibility inayotumia eBPF na inayohusishwa na pods, containers, namespaces, na concepts nyingine za kiwango cha juu.

Thamani ya zana hizi iko kwenye kasi na coverage, si uhakika. Zinasaidia kufichua posture ya jumla kwa haraka, lakini findings muhimu bado zinahitaji tafsiri ya manual kulingana na runtime, namespace, capability, na mount model halisi.

## Vipaumbele vya Hardening

Kanuni muhimu zaidi za hardening ni rahisi kimawazo ingawa utekelezaji wake hutofautiana kulingana na platform. Epuka privileged containers. Epuka runtime sockets zilizomountiwa. Usizipe containers host paths zenye writable access isipokuwa kuna sababu mahususi sana. Tumia user namespaces au rootless execution inapowezekana. Ondoa capabilities zote na urudishe tu zile ambazo workload inahitaji kweli. Weka seccomp, AppArmor, na SELinux zikiwa zimewezeshwa badala ya kuzizima ili kutatua matatizo ya application compatibility. Weka mipaka ya resources ili container iliyo-compromise isiweze kwa urahisi kusababisha denial of service kwa host.

Usafi wa image na build ni muhimu sawa na runtime posture. Tumia images ndogo, zijenge upya mara kwa mara, zifanyie scan, hitaji provenance inapowezekana, na usihifadhi secrets kwenye layers. Container inayoendesha kama non-root yenye image ndogo na syscall na capability surface finyu ni rahisi zaidi kuilinda kuliko convenience image kubwa inayoendesha kama host-equivalent root ikiwa na debugging tools zilizosakinishwa mapema.

Kwa Kubernetes, misingi ya sasa ya hardening ina masharti makali zaidi kuliko operators wengi bado wanavyodhani. **Pod Security Standards** zilizojengwa ndani zinachukulia `restricted` kuwa profile ya "best practice ya sasa": `allowPrivilegeEscalation` inapaswa kuwa `false`, workloads zinapaswa kuendeshwa kama non-root, seccomp inapaswa kuwekwa wazi kuwa `RuntimeDefault` au `Localhost`, na capability sets zinapaswa kuondolewa kwa kiwango kikubwa. Wakati wa assessment, jambo hili ni muhimu kwa sababu cluster inayotumia labels za `warn` au `audit` pekee inaweza kuonekana kuwa ime-hardening kwenye nyaraka huku bado ikiruhusu pods hatari kwa vitendo.<sup>[[1]](#references)</sup>

## Maswali ya Kisasa ya Triage

Kabla ya kuingia kwenye kurasa zinazohusu escape mahususi, jibu maswali haya ya haraka:

1. Je, workload ni **rootful**, **rootless**, au **userns-remapped**?
2. Je, node inatumia **cgroup v1** au **cgroup v2**?
3. Je, **seccomp** na **AppArmor/SELinux** zimewekwa wazi, au zinarithiwa tu zinapopatikana?
4. Katika Kubernetes, je, namespace kweli ina-**enforce** `baseline` au `restricted`, au ina-warning/audit pekee?

Ukaguzi muhimu:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Kinachovutia hapa:

- Ikiwa `/proc/self/uid_map` inaonyesha container root ikiwa imepangwa kwenye **high host UID range**, writeup nyingi za zamani kuhusu host-root huwa na umuhimu mdogo kwa sababu root ndani ya container si sawa tena na host-root.
- Ikiwa `/sys/fs/cgroup` ni `cgroup2fs`, writeup za zamani zinazohusiana mahususi na **cgroup v1**, kama matumizi mabaya ya `release_agent`, hazipaswi kuwa dhana yako ya kwanza tena.
- Ikiwa seccomp na AppArmor zinarithiwa tu bila kuwekwa wazi, portability inaweza kuwa dhaifu kuliko defenders wanavyotarajia. Katika Kubernetes, kuweka wazi `RuntimeDefault` mara nyingi huwa salama zaidi kuliko kutegemea kimya kimya defaults za node.
- Ikiwa `supplementalGroupsPolicy` imewekwa kuwa `Strict`, pod inapaswa kuepuka kurithi kimya kimya memberships za ziada za groups kutoka `/etc/group` ndani ya image, jambo linalofanya tabia ya ufikiaji wa volumes na files kwa kutumia groups iwe rahisi kutabirika.
- Labels za namespace kama `pod-security.kubernetes.io/enforce=restricted` zinafaa kuangaliwa moja kwa moja. `warn` na `audit` zinafaa, lakini hazizuii pod hatari kuundwa.

## Triage ya Msingi wa Runtime

Msingi wa runtime ni ukaguzi wa haraka unaokuonyesha ikiwa container inaonekana kama workload ya kawaida iliyotengwa au kama foothold ya control plane inayoweza kuathiri host. Inapaswa kukusanya facts za kutosha ili kupanga kipaumbele cha ukurasa unaofuata wa kusoma: matumizi mabaya ya runtime socket, host mounts, namespaces, cgroups, capabilities, au ukaguzi wa image-secrets.

Ukaguzi muhimu kutoka ndani ya workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Tafsiri:

- `memory.max` / `pids.max` zilizokosekana au zisizo na kikomo zinaonyesha udhibiti dhaifu wa blast radius hata bila escape safi.
- Root shell yenye `NoNewPrivs: 0`, capabilities pana, na seccomp yenye ruhusa nyingi inavutia zaidi kuliko workload finyu isiyo ya root.
- Runtime sockets na host mounts zinazoweza kuandikwa kwa kawaida huwa muhimu zaidi kuliko kernel exploits kwa sababu tayari zinaonyesha njia ya udhibiti wa management au filesystem.
- Shared PID, network, IPC, au cgroup namespaces si full escapes kila mara zikiwa peke yake, lakini hurahisisha kupata hatua inayofuata.

## Mifano ya Resource-Exhaustion

Resource controls si za kuvutia, lakini ni sehemu ya container security kwa sababu hupunguza blast radius ya compromise. Bila memory, CPU, au PID limits, shell rahisi inaweza kutosha kudhoofisha host au workloads zilizo jirani.

Mifano ya majaribio yanayoathiri host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Mifano hii ni muhimu kwa sababu inaonyesha kwamba si kila matokeo hatari ya container huwa "escape" iliyo wazi. Vikomo dhaifu vya cgroup bado vinaweza kubadilisha code execution kuwa athari halisi za kiutendaji.

Katika mazingira yanayotegemea Kubernetes, pia kagua kama resource controls zipo kabisa kabla ya kuchukulia DoS kuwa ya kinadharia:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Zana za Hardening

Kwa mazingira yanayolenga Docker, `docker-bench-security` bado ni msingi muhimu wa audit upande wa host kwa sababu hukagua matatizo ya kawaida ya usanidi dhidi ya mwongozo wa benchmark unaotambulika kwa upana:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Zana hii si mbadala wa threat modeling, lakini bado ni muhimu kwa kugundua mipangilio ya msingi ya daemon, mount, network, na runtime ambayo hujilimbikiza bila uangalifu baada ya muda.

Kwa mazingira ya Kubernetes na yenye utegemezi mkubwa wa runtime, unganisha ukaguzi tuli na uonekano wa runtime:

- `Tracee` ni muhimu kwa utambuzi wa runtime unaotambua containers na kwa forensics za haraka unapohitaji kuthibitisha kile ambacho workload iliyoathirika ilifikia.
- `Inspektor Gadget` ni muhimu wakati assessment inahitaji telemetry ya kiwango cha kernel iliyohusishwa na pods, containers, shughuli za DNS, utekelezaji wa faili, au tabia ya network.

## Ukaguzi

Tumia hizi kama commands za haraka za awamu ya kwanza wakati wa assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Kinachovutia hapa:

- Mchakato wa root wenye capabilities pana na `Seccomp: 0` unastahili kuangaliwa mara moja.
- Mchakato wa root ambao pia una **1:1 UID map** unavutia zaidi kuliko "root" ndani ya user namespace iliyotengwa ipasavyo.
- `cgroup2fs` kwa kawaida humaanisha kuwa **cgroup v1** escape chains nyingi za zamani si sehemu bora ya kuanzia, huku kukosekana kwa `memory.max` au `pids.max` bado kukionyesha udhibiti dhaifu wa blast radius.
- Mounts zenye kutiliwa shaka na runtime sockets mara nyingi hutoa njia ya haraka zaidi ya kupata impact kuliko kernel exploit yoyote.
- Mchanganyiko wa runtime posture dhaifu na resource limits dhaifu kwa kawaida huonyesha container environment yenye ruhusa kwa ujumla, badala ya kosa moja lililotengwa.

## Marejeo

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
