# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Tathmini nzuri ya container inapaswa kujibu maswali mawili sambamba. Kwanza, mshambuliaji anaweza kufanya nini kutoka kwenye workload ya sasa? Pili, ni chaguo gani za operator zilizoifanya iwezekane? Zana za enumeration husaidia kwa swali la kwanza, na mwongozo wa hardening husaidia kwa la pili. Kuviweka vyote kwenye ukurasa mmoja kunafanya sehemu hii iwe muhimu zaidi kama rejea ya uwanjani badala ya kuwa tu katalogi ya mbinu za escape.

Sasisho moja la vitendo kwa mazingira ya kisasa ni kwamba writeups nyingi za zamani za container kwa utulivu zinachukulia **rootful runtime**, **hakuna user namespace isolation**, na mara nyingi **cgroup v1**. Dhana hizo si salama tena. Kabla ya kutumia muda kwenye primitives za zamani za escape, kwanza thibitisha kama workload ni rootless au userns-remapped, kama host inatumia cgroup v2, na kama Kubernetes au runtime sasa inatumia default seccomp na AppArmor profiles. Maelezo haya mara nyingi huamua kama breakout maarufu bado inatumika.

## Enumeration Tools

Zana kadhaa bado ni muhimu kwa kuchambua haraka mazingira ya container:

- `linpeas` inaweza kutambua viashiria vingi vya container, sockets zilizomountiwa, capability sets, dangerous filesystems, na vihinta vya breakout.
- `CDK` inalenga hasa mazingira ya container na inajumuisha enumeration pamoja na baadhi ya automated escape checks.
- `amicontained` ni nyepesi na ni muhimu kwa kutambua vizuizi vya container, capabilities, ufichuzi wa namespace, na aina zinazowezekana za breakout.
- `deepce` ni enumerator nyingine inayolenga container yenye checks za breakout.
- `grype` ni muhimu wakati tathmini inajumuisha ukaguzi wa udhaifu wa image-package badala ya uchambuzi wa runtime escape pekee.
- `Tracee` ni muhimu unapohitaji **runtime evidence** badala ya posture ya tuli pekee, hasa kwa suspicious process execution, file access, na ukusanyaji wa event unaofahamu container.
- `Inspektor Gadget` ni muhimu katika Kubernetes na uchunguzi wa host wa Linux unapohitaji mwonekano unaoungwa mkono na eBPF unaorudishwa kwenye pods, containers, namespaces, na dhana nyingine za kiwango cha juu.

Thamani ya zana hizi ni kasi na ufunikaji, si uhakika. Husaidia kuibua posture ya jumla haraka, lakini matokeo ya kuvutia bado yanahitaji tafsiri ya mikono dhidi ya runtime halisi, namespace, capability, na mount model.

## Hardening Priorities

Kanuni muhimu zaidi za hardening ni rahisi ki dhana ingawa utekelezaji wake hutofautiana kwa platform. Epuka privileged containers. Epuka mounted runtime sockets. Usipe containers host paths zinazoweza kuandikwa isipokuwa kuwe na sababu maalum sana. Tumia user namespaces au rootless execution inapowezekana. Ondoa capabilities zote na urudishe tu zile workload inazohitaji kweli. Weka seccomp, AppArmor, na SELinux zimewashwa badala ya kuzima ili kutatua matatizo ya compatibility ya application. Weka resource limits ili container iliyoharibika isiweze kwa urahisi kuzuia huduma kwa host.

Usafi wa image na build ni muhimu kama posture ya runtime. Tumia images ndogo, zijenge upya mara kwa mara, ziskane, hitaji provenance inapowezekana, na weka secrets nje ya layers. Container inayoendeshwa kama non-root yenye image ndogo na syscall na capability surface nyembamba ni rahisi zaidi kuitetea kuliko image kubwa ya urahisi inayoendeshwa kama host-equivalent root ikiwa na debugging tools tayari zimesakinishwa.

Kwa Kubernetes, msingi wa sasa wa hardening ni wa maoni zaidi kuliko ambavyo waendeshaji wengi bado wanadhani. **Pod Security Standards** zilizojengwa ndani zinachukulia `restricted` kama profile ya "best practice" ya sasa: `allowPrivilegeEscalation` inapaswa kuwa `false`, workloads zinapaswa kuendeshwa kama non-root, seccomp inapaswa kuwekwa wazi kuwa `RuntimeDefault` au `Localhost`, na capability sets zinapaswa kupunguzwa kwa ukali. Wakati wa tathmini, hili ni muhimu kwa sababu cluster inayotumia tu labels za `warn` au `audit` inaweza kuonekana imara kwenye karatasi ilhali bado inaruhusu pods hatari kwa vitendo.

## Modern Triage Questions

Kabla ya kuingia kwenye kurasa mahususi za escape, jibu maswali haya ya haraka:

1. Je, workload ni **rootful**, **rootless**, au **userns-remapped**?
2. Je, node inatumia **cgroup v1** au **cgroup v2**?
3. Je, **seccomp** na **AppArmor/SELinux** zimesanidiwa wazi, au zimerithiwa tu zinapopatikana?
4. Katika Kubernetes, je, namespace kweli inatekeleza `baseline` au `restricted`, au inatoa warning/auditing tu?

Useful checks:
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
Kinachovutia hapa ni:

- Ikiwa `/proc/self/uid_map` inaonyesha container root imepangwa kwenye **high host UID range**, many older host-root writeups huwa hazifai sana tena kwa sababu root ndani ya container si tena sawa na host-root.
- Ikiwa `/sys/fs/cgroup` ni `cgroup2fs`, old **cgroup v1**-specific writeups kama `release_agent` abuse hazipaswi tena kuwa dhana yako ya kwanza.
- Ikiwa seccomp na AppArmor zinarithiwa tu implicitly, portability inaweza kuwa dhaifu kuliko ambavyo defenders wanavyotarajia. Katika Kubernetes, kuweka `RuntimeDefault` explicitly mara nyingi ni stronger kuliko kutegemea kimya kimya node defaults.
- Ikiwa `supplementalGroupsPolicy` imewekwa kuwa `Strict`, pod inapaswa kuepuka kurithi kwa kimya kimya extra group memberships kutoka `/etc/group` ndani ya image, jambo linalofanya group-based volume na file access behavior iwe predictable zaidi.
- Namespace labels kama `pod-security.kubernetes.io/enforce=restricted` zinafaa kukaguliwa moja kwa moja. `warn` na `audit` ni useful, lakini hazizuii risky pod kuundwa.

## Resource-Exhaustion Examples

Resource controls si glamorous, lakini ni sehemu ya container security kwa sababu zinapunguza blast radius ya compromise. Bila memory, CPU, au PID limits, shell rahisi inaweza kutosha kudhoofisha host au neighboring workloads.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hii mifano ni muhimu kwa sababu inaonyesha kwamba si kila matokeo hatari ya container ni "escape" safi. Mipaka dhaifu ya cgroup bado inaweza kubadilisha code execution kuwa athari halisi ya kiutendaji.

Katika mazingira yanayoendeshwa na Kubernetes, pia angalia kama resource controls zipo kabisa kabla ya kuchukulia DoS kuwa ya kinadharia:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Kwa mazingira yanayozingatia Docker, `docker-bench-security` bado ni msingi muhimu wa ukaguzi upande wa host kwa sababu hukagua matatizo ya kawaida ya usanidi dhidi ya guidance inayotambulika sana ya benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
The tool is not a substitute for threat modeling, but it is still valuable for finding careless daemon, mount, network, and runtime defaults that accumulate over time.

Kwa Kubernetes na mazingira yenye runtime nzito, changanya static checks na runtime visibility:

- `Tracee` ni muhimu kwa container-aware runtime detection na quick forensics unapohitaji kuthibitisha workload iliyoharibiwa iligusa nini hasa.
- `Inspektor Gadget` ni muhimu wakati assessment inahitaji kernel-level telemetry iliyopangwa tena kwa pods, containers, DNS activity, file execution, au network behavior.

## Checks

Tumia hizi kama quick first-pass commands wakati wa assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Nini cha kuvutia hapa:

- Mchakato wa root wenye capabilities pana na `Seccomp: 0` unastahili umakini wa haraka.
- Mchakato wa root ambao pia una **1:1 UID map** ni wa kuvutia zaidi kuliko "root" ndani ya user namespace iliyotengwa ipasavyo.
- `cgroup2fs` kwa kawaida humaanisha kwamba njia nyingi za zamani za kutoroka za **cgroup v1** si mahali bora pa kuanzia, ilhali kukosekana kwa `memory.max` au `pids.max` bado kunaashiria udhibiti dhaifu wa blast-radius.
- Mounts za kushukiwa na runtime sockets mara nyingi hutoa njia ya haraka zaidi ya kuleta athari kuliko exploit yoyote ya kernel.
- Mchanganyiko wa weak runtime posture na weak resource limits kwa kawaida unaashiria mazingira ya container yaliyoruhusu kwa ujumla badala ya kosa moja lililotengwa.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
