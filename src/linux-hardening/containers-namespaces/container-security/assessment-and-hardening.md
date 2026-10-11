# Tathmini na Uimarishaji

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Tathmini nzuri ya container inapaswa kujibu maswali mawili yanayohusiana. Kwanza, mshambulizi anaweza kufanya nini kutoka kwenye workload ya sasa? Pili, ni maamuzi gani ya operator yaliyowezesha hilo? Zana za enumeration husaidia kujibu swali la kwanza, na mwongozo wa uimarishaji husaidia kujibu la pili. Kuweka yote mawili kwenye ukurasa mmoja hufanya sehemu hii iwe rejeleo la vitendo zaidi, badala ya kuwa katalogi tu ya mbinu za escape.

Jambo moja la vitendo la kuzingatia katika mazingira ya kisasa ni kwamba maandishi mengi ya zamani kuhusu containers huchukulia kimyakimya kuwa kuna **rootful runtime**, **hakuna user namespace isolation**, na mara nyingi **cgroup v1**. Mawazo hayo si salama tena. Kabla ya kutumia muda kuchunguza mbinu za zamani za escape, kwanza thibitisha kama workload ni rootless au imetumia userns-remapped, kama host inatumia cgroup v2, na kama Kubernetes au runtime sasa inatumia profaili za kawaida za seccomp na AppArmor. Mara nyingi maelezo haya huamua kama breakout maarufu bado inatumika.

## Zana za Enumeration

Zana kadhaa bado zinafaa kwa kutathmini haraka mazingira ya container:

- `linpeas` inaweza kutambua viashiria vingi vya container, sockets zilizomountiwa, seti za capabilities, mifumo hatari ya faili, na vidokezo vya breakout.
- `CDK` inalenga mazingira ya container pekee na inajumuisha enumeration pamoja na ukaguzi fulani wa kiotomatiki wa escape.
- `amicontained` ni nyepesi na inafaa kwa kutambua vizuizi vya container, capabilities, ufikiaji wa namespace, na makundi yanayowezekana ya breakout.
- `deepce` ni zana nyingine ya enumeration inayolenga containers, yenye ukaguzi unaohusiana na breakout.
- `grype` inafaa pale tathmini inapojumuisha ukaguzi wa udhaifu wa vifurushi vya image, badala ya uchanganuzi wa escape ya runtime pekee.
- `Tracee` inafaa unapohitaji **ushahidi wa runtime** badala ya hali ya usanidi tuli pekee, hasa kwa utekelezaji wa michakato yenye kutia shaka, ufikiaji wa faili, na ukusanyaji wa matukio unaotambua containers.
- `Inspektor Gadget` inafaa katika uchunguzi wa Kubernetes na Linux host unapohitaji mwonekano unaotegemea eBPF na unaohusishwa na pods, containers, namespaces, na dhana nyingine za kiwango cha juu.

Faida ya zana hizi ni kasi na wigo wa ukaguzi, si uhakika. Zinasaidia kufichua haraka hali ya jumla ya usalama, lakini matokeo muhimu bado yanahitaji kufasiriwa kwa mikono kulingana na runtime halisi, namespace, capability, na modeli ya mount.

## Vipaumbele vya Uimarishaji

Kanuni muhimu zaidi za uimarishaji ni rahisi kidhana, ingawa utekelezaji wake hutofautiana kulingana na jukwaa. Epuka containers zenye privileged. Epuka sockets za runtime zilizomountiwa. Usipe containers host paths zinazoweza kuandikwa isipokuwa kuwe na sababu mahususi kabisa. Tumia user namespaces au rootless execution inapowezekana. Ondoa capabilities zote na urudishe tu zile ambazo workload inahitaji kweli. Acha seccomp, AppArmor, na SELinux zikiwa zimewashwa badala ya kuzizima ili kutatua matatizo ya ulinganifu wa programu. Weka mipaka ya rasilimali ili container iliyodukuliwa isiweze kwa urahisi kusababisha kunyimwa huduma kwa host.

Usafi wa image na build ni muhimu sawa na hali ya runtime. Tumia images ndogo, zijenge upya mara kwa mara, zichanganue, hitaji provenance inapowezekana, na usiweke secrets ndani ya layers. Container inayoendeshwa kama non-root, yenye image ndogo na eneo finyu la syscalls na capabilities, ni rahisi zaidi kutetea kuliko image kubwa ya matumizi ya jumla inayoendeshwa kama root yenye mamlaka sawa na host na zana za utatuzi zilizowekwa mapema.

Kwa Kubernetes, viwango vya sasa vya uimarishaji vina masharti makali zaidi kuliko ambavyo operators wengi bado hudhani. **Pod Security Standards** zilizojengewa ndani huchukulia `restricted` kuwa profaili ya "mbinu bora ya sasa": `allowPrivilegeEscalation` inapaswa kuwa `false`, workloads zinapaswa kuendeshwa kama non-root, seccomp inapaswa kuwekwa wazi kuwa `RuntimeDefault` au `Localhost`, na seti za capabilities zinapaswa kuondolewa kwa ukali. Wakati wa tathmini, hili ni muhimu kwa sababu cluster inayotumia lebo za `warn` au `audit` pekee inaweza kuonekana kuwa imeimarishwa kwenye karatasi, ilhali kwa vitendo bado inaruhusu pods hatari.<sup>[[1]](#references)</sup>

Pod ikiwa na token ya service-account iliyomountiwa, tathmini ruhusa zake **kwa kila target namespace**. Kanuni inayoorodhesha Pods katika namespace moja haithibitishi ruhusa katika nyingine; token iliyomountiwa kwenye Pod tofauti inaweza kuwa na ruhusa tofauti. Tumia `kubectl auth can-i list pods -n <target-namespace>` na `kubectl auth can-i list secrets -n <target-namespace>` kwa utambulisho unaochunguzwa. Ukaguzi unaoruhusu kuorodhesha Secrets ni kidokezo muhimu cha hatari kwa sababu jibu la list linaweza kujumuisha maudhui ya Secrets, lakini halithibitishi kuwa kuna token yenye privileged. Ufikiaji wa host pia unahitaji ruhusa inayoweza kutumika ya kuunda workload, kuruhusiwa kwa mount ya `hostPath` iliyopendekezwa, na security context ya node/pod inayoruhusu operesheni ya faili iliyokusudiwa. Tazama [ukaguzi wa authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) na [mwongozo wa RBAC kuhusu kupandisha privilege](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) wa Kubernetes.

## Maswali ya Triage ya Kisasa

Kabla ya kwenda kwenye kurasa zinazohusu escape maalum, jibu maswali haya ya haraka:

1. Je, workload ni **rootful**, **rootless**, au **userns-remapped**?
2. Je, node inatumia **cgroup v1** au **cgroup v2**?
3. Je, **seccomp** na **AppArmor/SELinux** zimesanidiwa waziwazi, au zimerithiwa tu zinapopatikana?
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

- Ikiwa `/proc/self/uid_map` inaonyesha kuwa root ya container imepangwa kwenye **masafa ya juu ya UID ya host**, maandishi mengi ya zamani kuhusu kuandika kwa host-root hayahusiki sana tena, kwa sababu root ndani ya container si sawa tena na host-root.
- Ikiwa `/sys/fs/cgroup` ni `cgroup2fs`, maandishi ya zamani yanayohusu **cgroup v1** pekee, kama vile matumizi mabaya ya `release_agent`, hayapaswi kuwa jambo la kwanza unaloshuku tena.
- Ikiwa seccomp na AppArmor hurithiwa tu bila kuwekwa wazi, uwezo wa kuhamisha usanidi unaweza kuwa dhaifu kuliko walinzi wanavyotarajia. Kwenye Kubernetes, kuweka `RuntimeDefault` wazi mara nyingi ni imara zaidi kuliko kutegemea chaguomsingi za node bila kutangaza.
- Ikiwa `supplementalGroupsPolicy` imewekwa kuwa `Strict`, pod inapaswa kuepuka kurithi kimyakimya uanachama wa ziada wa makundi kutoka `/etc/group` ndani ya image, jambo linalofanya tabia ya ufikiaji wa volume na faili inayotegemea makundi iwe rahisi zaidi kutabirika.
- Inafaa kukagua moja kwa moja lebo za namespace kama `pod-security.kubernetes.io/enforce=restricted`. `warn` na `audit` zina manufaa, lakini hazizuii pod hatarishi kuundwa.

## Tathmini ya Haraka ya Msingi wa Runtime

Msingi wa runtime ni ukaguzi wa haraka unaokuambia ikiwa container inaonekana kama workload ya kawaida iliyotengwa au kama njia ya kuingia kwenye control plane inayoathiri host. Unapaswa kukusanya ukweli wa kutosha ili kupanga kipaumbele cha ukurasa unaofuata wa kusoma: matumizi mabaya ya runtime socket, host mounts, namespaces, cgroups, capabilities, au ukaguzi wa image-secret.

Ukaguzi unaofaa kutoka ndani ya workload:

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

- `memory.max` / `pids.max` zisizowekwa au zisizo na kikomo zinaashiria udhibiti dhaifu wa ukubwa wa athari, hata kama hakuna njia rahisi ya kutoroka.
- Root shell yenye `NoNewPrivs: 0`, capabilities nyingi na seccomp inayoruhusu mengi inavutia zaidi kuliko workload finyu isiyo ya root.
- Runtime sockets na host mounts zinazoweza kuandikwa kwa kawaida ni muhimu zaidi kuliko kernel exploits, kwa sababu tayari zinaweka wazi njia ya kudhibiti mifumo au mfumo wa faili.
- Namespaces za PID, network, IPC au cgroup zinazoshirikiwa si lazima ziwe njia kamili za kutoroka zenyewe, lakini hurahisisha kupata hatua inayofuata.

## Mifano ya Kumaliza Rasilimali

Vidhibiti vya rasilimali havivutii sana, lakini ni sehemu ya usalama wa container kwa sababu hupunguza ukubwa wa athari ya uvamizi. Bila vikomo vya memory, CPU au PID, shell rahisi inaweza kutosha kudhoofisha host au workloads jirani.

Mifano ya majaribio yanayoathiri host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Mifano hii ni muhimu kwa sababu inaonyesha kuwa si kila matokeo hatari ya container ni "escape" kamili. Vikomo dhaifu vya cgroup bado vinaweza kugeuza code execution kuwa athari halisi za kiutendaji.

Katika mazingira yanayotumia Kubernetes, pia hakikisha kama vidhibiti vya rasilimali vipo kabla ya kuchukulia DoS kuwa ya kinadharia:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Zana za Kuimarisha Usalama

Kwa mazingira yanayotumia Docker, `docker-bench-security` bado ni msingi muhimu wa ukaguzi kwenye host, kwa kuwa hukagua matatizo ya kawaida ya usanidi kwa kutumia mwongozo wa benchmark unaotambulika sana. Ushauri kuhusu runtime unapaswa kukaguliwa kivyake, kwa kuwa benchmark ya usanidi haiwezi kubaini kama runtime iliyosakinishwa imeathiriwa na udhaifu mpya uliotangazwa. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Chombo hiki si mbadala wa threat modeling, lakini bado kinafaa kutafuta mipangilio chaguomsingi isiyozingatia usalama ya daemon, mount, network na runtime ambayo hujikusanya kadiri muda unavyopita.

Kwa mazingira ya Kubernetes na yale yanayotegemea sana runtime, unganisha ukaguzi tuli na ufuatiliaji wa runtime:

- `Tracee` ni muhimu kwa utambuzi wa runtime unaozingatia containers na uchunguzi wa haraka unapohitaji kuthibitisha ni vitu gani workload iliyoathiriwa iligusa hasa.
- `Inspektor Gadget` ni muhimu pale tathmini inapohitaji telemetry ya kiwango cha kernel inayohusishwa na pods, containers, shughuli za DNS, utekelezaji wa faili au tabia ya network.

## Ukaguzi

Tumia hizi kama amri za haraka za ukaguzi wa awali:

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

- Mchakato wa root wenye capabilities nyingi na `Seccomp: 0` unahitaji kuangaliwa mara moja.
- Mchakato wa root ambao pia una **1:1 UID map** unavutia zaidi sana kuliko "root" ndani ya user namespace iliyotengwa ipasavyo.
- `cgroup2fs` kwa kawaida humaanisha kuwa minyororo mingi ya zamani ya **cgroup v1** ya kutoroka si mahali pazuri pa kuanzia, ilhali kukosekana kwa `memory.max` au `pids.max` bado kunaashiria udhibiti dhaifu wa ukubwa wa athari.
- Mounts zinazotiliwa shaka na runtime sockets mara nyingi hutoa njia ya haraka zaidi ya kufikia athari kuliko exploit yoyote ya kernel.
- Mchanganyiko wa mkao dhaifu wa runtime na vikomo dhaifu vya rasilimali kwa kawaida huashiria mazingira ya container yaliyoruhusu mambo mengi kwa ujumla, badala ya kosa moja lililotengwa.

## References

- [1] [Viwango vya Usalama wa Pod za Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Taarifa ya Usalama ya Docker: Udhaifu Mwingi katika runc, BuildKit na Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
