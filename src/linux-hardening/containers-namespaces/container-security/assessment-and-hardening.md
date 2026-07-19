# Tathmini Na Kuimarisha Usalama

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Tathmini nzuri ya container inapaswa kujibu maswali mawili yanayofanyika sambamba. Kwanza, attacker anaweza kufanya nini kutoka kwenye workload ya sasa? Pili, ni chaguo zipi za operator zilizowezesha hilo? Zana za enumeration husaidia kujibu swali la kwanza, na mwongozo wa hardening husaidia kujibu la pili. Kuziweka zote kwenye ukurasa mmoja hufanya sehemu hii iwe na manufaa zaidi kama marejeo ya field badala ya kuwa katalogi tu ya mbinu za escape.

Mabadiliko moja ya muhimu kwa mazingira ya kisasa ni kwamba maandishi mengi ya zamani kuhusu containers huchukulia bila kutaja kuwa kuna **rootful runtime**, **hakuna user namespace isolation**, na mara nyingi **cgroup v1**. Mawazo hayo si salama tena. Kabla ya kutumia muda kwenye escape primitives za zamani, thibitisha kwanza ikiwa workload ni rootless au userns-remapped, ikiwa host inatumia cgroup v2, na ikiwa Kubernetes au runtime sasa inatumia default seccomp na AppArmor profiles. Maelezo haya mara nyingi huamua ikiwa breakout maarufu bado inatumika.

## Zana za Enumeration

Zana kadhaa bado zinafaa kwa kubainisha kwa haraka mazingira ya container:

- `linpeas` inaweza kutambua viashiria vingi vya container, sockets zilizomountiwa, capability sets, filesystems hatari, na vidokezo vya breakout.
- `CDK` inalenga hasa mazingira ya container na inajumuisha enumeration pamoja na ukaguzi fulani wa escape unaofanywa kiotomatiki.
- `amicontained` ni nyepesi na inafaa kwa kutambua vikwazo vya container, capabilities, namespace exposure, na aina zinazowezekana za breakout.
- `deepce` ni enumerator nyingine inayolenga containers yenye ukaguzi unaohusiana na breakout.
- `grype` inafaa wakati assessment inajumuisha ukaguzi wa vulnerabilities za image packages badala ya uchambuzi wa runtime escape pekee.
- `Tracee` inafaa unapohitaji **runtime evidence** badala ya static posture pekee, hasa kwa process execution yenye shaka, file access, na ukusanyaji wa events unaotambua containers.
- `Inspektor Gadget` inafaa katika uchunguzi wa Kubernetes na Linux-host unapohitaji mwonekano unaotegemea eBPF unaohusishwa na pods, containers, namespaces, na dhana nyingine za kiwango cha juu.

Thamani ya zana hizi ni kasi na coverage, si uhakika. Husaidia kufichua posture ya jumla kwa haraka, lakini findings zenye umuhimu bado zinahitaji kutafsiriwa manually kulingana na runtime, namespace, capability, na mount model halisi.

## Vipaumbele vya Hardening

Kanuni muhimu zaidi za hardening ni rahisi kimawazo, ingawa utekelezaji wake hutofautiana kulingana na platform. Epuka privileged containers. Epuka runtime sockets zilizomountiwa. Usipe containers host paths zinazoweza kuandikwa isipokuwa kuna sababu maalum sana. Tumia user namespaces au rootless execution inapowezekana. Ondoa capabilities zote na ongeza tu zile ambazo workload inahitaji kwa kweli. Weka seccomp, AppArmor, na SELinux ikiwa enabled badala ya kuzizima ili kutatua matatizo ya application compatibility. Punguza resources ili container iliyo compromised isiweze kwa urahisi kusababisha denial of service kwa host.

Usafi wa image na build ni muhimu sawa na runtime posture. Tumia images ndogo, zijenge upya mara kwa mara, zichanganue, hitaji provenance inapowezekana, na usiweke secrets kwenye layers. Container inayoendesha kama non-root yenye image ndogo na syscall na capability surface finyu ni rahisi zaidi kuilinda kuliko convenience image kubwa inayoendesha kama root yenye privileges sawa na host na debugging tools zilizowekwa mapema.

Kwa Kubernetes, misingi ya sasa ya hardening ina masharti zaidi kuliko operators wengi wanavyodhani bado. **Pod Security Standards** zilizojengwa ndani huchukulia `restricted` kuwa profile ya "current best practice": `allowPrivilegeEscalation` inapaswa kuwa `false`, workloads zinapaswa kuendesha kama non-root, seccomp inapaswa kuwekwa wazi kuwa `RuntimeDefault` au `Localhost`, na capability sets zinapaswa kuondolewa kwa kiwango kikubwa. Wakati wa assessment, jambo hili ni muhimu kwa sababu cluster inayotumia labels za `warn` au `audit` pekee inaweza kuonekana kuwa hardened kwenye karatasi huku ikiendelea kuruhusu risky pods kwa vitendo.

## Maswali ya Kisasa ya Triage

Kabla ya kuingia kwenye kurasa zinazohusu escape pekee, jibu maswali haya ya haraka:

1. Je, workload ni **rootful**, **rootless**, au **userns-remapped**?
2. Je, node inatumia **cgroup v1** au **cgroup v2**?
3. Je, **seccomp** na **AppArmor/SELinux** zimesanidiwa wazi, au zimerithiwa tu zinapopatikana?
4. Katika Kubernetes, je, namespace inatekeleza kweli `baseline` au `restricted`, au inaonya/kukagua tu?

Ukaguzi unaofaa:
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

- Ikiwa `/proc/self/uid_map` inaonyesha kuwa container root imepangwa kwenye **high host UID range**, maelezo mengi ya zamani kuhusu uandishi wa host-root yanakuwa na umuhimu mdogo, kwa sababu root ndani ya container si sawa tena na host-root.
- Ikiwa `/sys/fs/cgroup` ni `cgroup2fs`, maelezo ya zamani yanayohusu **cgroup v1**, kama vile matumizi mabaya ya `release_agent`, hayapaswi kuwa dhana yako ya kwanza tena.
- Ikiwa seccomp na AppArmor zinarithiwa kwa njia isiyo wazi pekee, portability inaweza kuwa dhaifu kuliko defenders wanavyotarajia. Katika Kubernetes, kuweka `RuntimeDefault` wazi mara nyingi huwa na nguvu zaidi kuliko kutegemea kimya kimya defaults za node.
- Ikiwa `supplementalGroupsPolicy` imewekwa kuwa `Strict`, pod inapaswa kuepuka kurithi kimya kimya memberships za ziada za groups kutoka `/etc/group` ndani ya image, jambo linalofanya tabia ya access ya volumes na files kulingana na groups itabirike zaidi.
- Labels za namespace kama `pod-security.kubernetes.io/enforce=restricted` zinafaa kuchunguzwa moja kwa moja. `warn` na `audit` zinafaa, lakini hazizuii pod hatari kuundwa.

## Upimaji wa Haraka wa Msingi wa Runtime

Msingi wa runtime ni ukaguzi wa haraka unaokuambia ikiwa container inaonekana kama workload ya kawaida iliyotengwa au kama foothold ya control plane inayoweza kuathiri host. Unapaswa kukusanya facts za kutosha ili kupanga kipaumbele cha ukurasa unaofuata wa kusoma: matumizi mabaya ya runtime socket, mounts za host, namespaces, cgroups, capabilities, au ukaguzi wa image secrets.

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
Ufafanuzi:

- `memory.max` / `pids.max` zinazokosekana au zisizo na kikomo zinaonyesha udhibiti dhaifu wa blast radius hata bila escape salama.
- root shell yenye `NoNewPrivs: 0`, capabilities pana, na seccomp yenye ruhusa nyingi inavutia zaidi kuliko workload finyu isiyo ya root.
- Runtime sockets na mounts za host zinazoweza kuandikwa kwa kawaida huwa muhimu zaidi kuliko kernel exploits kwa sababu tayari zinaonyesha njia ya udhibiti wa usimamizi au filesystem.
- Shared PID, network, IPC, au cgroup namespaces si lazima ziwe full escapes zenyewe, lakini hurahisisha kupata hatua inayofuata.

## Mifano ya Resource-Exhaustion

Vidhibiti vya rasilimali si vya kuvutia sana, lakini ni sehemu ya container security kwa sababu hupunguza blast radius ya compromise. Bila mipaka ya memory, CPU, au PID, shell rahisi inaweza kutosha kudhoofisha host au workloads zilizo jirani.

Majaribio ya kuathiri host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Mifano hii ni muhimu kwa sababu inaonyesha kwamba si kila matokeo hatari ya container huwa ni "escape" safi. Vikomo dhaifu vya cgroup bado vinaweza kubadilisha code execution kuwa athari halisi ya kiutendaji.

Katika mazingira yanayotumia Kubernetes, pia hakikisha kama resource controls zipo kabisa kabla ya kuchukulia DoS kuwa ya kinadharia:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Zana za Hardening

Kwa mazingira yanayolenga Docker, `docker-bench-security` bado ni msingi muhimu wa ukaguzi wa upande wa host kwa sababu hukagua masuala ya kawaida ya usanidi dhidi ya mwongozo wa benchmark unaotambuliwa kwa upana:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Zana hii si mbadala wa threat modeling, lakini bado ni muhimu kwa kugundua daemon, mount, network, na runtime defaults zisizozingatia usalama ambazo hujikusanya baada ya muda.

Kwa Kubernetes na mazingira yanayotegemea runtime sana, changanya ukaguzi tuli na mwonekano wa runtime:

- `Tracee` ni muhimu kwa runtime detection inayotambua container na forensics ya haraka unapohitaji kuthibitisha kile ambacho workload iliyoathiriwa iligusa.
- `Inspektor Gadget` ni muhimu wakati assessment inahitaji kernel-level telemetry inayohusishwa na pods, containers, shughuli za DNS, utekelezaji wa faili, au tabia ya network.

## Ukaguzi

Tumia hizi kama amri za awamu ya kwanza wakati wa assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Ni nini kinachovutia hapa:

- Mchakato wa `root` wenye capabilities pana na `Seccomp: 0` unastahili kupewa kipaumbele mara moja.
- Mchakato wa `root` ambao pia una **1:1 UID map** unavutia zaidi kuliko "root" ndani ya user namespace iliyotengwa ipasavyo.
- `cgroup2fs` kwa kawaida humaanisha kwamba chain nyingi za zamani za kutoroka kwenye **cgroup v1** si sehemu bora ya kuanzia, huku kutokuwepo kwa `memory.max` au `pids.max` bado kukionyesha udhibiti dhaifu wa blast radius.
- Mounts zinazotiliwa shaka na runtime sockets mara nyingi hutoa njia ya haraka zaidi ya kupata impact kuliko kernel exploit yoyote.
- Mchanganyiko wa runtime posture dhaifu na resource limits dhaifu kwa kawaida huashiria container environment inayoruhusu mambo kwa ujumla, badala ya kosa moja lililotengwa.

## Marejeo

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
