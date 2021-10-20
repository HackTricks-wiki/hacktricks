# Namespaces

To get the namespace of a container you can do:

```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```

To illustrate the five following namespaces, let’s create two Ubuntu containers:

```
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
docker run -ti --name ubuntu2 -v /usr:/ubuntu2 ubuntu bash
```

### **PID namespace**

Let’s look at processes running in Container ubuntu1:

```
root@3a1bf12161c9:/# ps
  PID TTY          TIME CMD
    1 ?        00:00:00 bash
   15 ?        00:00:00 ps
```

Let’s look at processes running in Container ubuntu2:

```
root@8beb85abe6a5:/# ps
  PID TTY          TIME CMD
    1 ?        00:00:00 bash
   14 ?        00:00:00 ps
```

Let’s look at the 2 “bash” process in host machine:

```
$ ps -eaf|grep root | grep bash
root      5413  1697  0 05:54 pts/28   00:00:00 bash
root      5516  1697  0 05:54 pts/31   00:00:00 bash
```

bash process in Container1 and Container2 have the same PID 1 since they have their own process namespace. The same bash process shows up in host machine as a different pid.

### **Mount namespace**

Let’s look at the root directory content in Container ubuntu1:

```
root@3a1bf12161c9:/# ls /
bin   dev  home  lib64  mnt  proc  run   srv  tmp      usr
boot  etc  lib   media  opt  root  sbin  sys  ubuntu1  var
```

Let’s look at the root directory content in Container ubuntu2:

```
root@8beb85abe6a5:/# ls /
bin   dev  home  lib64  mnt  proc  run   srv  tmp      usr
boot  etc  lib   media  opt  root  sbin  sys  ubuntu2  var
```

As we can see above, each Container has its own filesystem and we can see “/usr” from host machine mounted as “/ubuntu1” in Container1 and as “/ubuntu2” in Container2.

### **Network namespace**

Let’s look at ifconfig output in Container ubuntu1:

```
root@3a1bf12161c9:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:15:00:02  
          inet addr:172.21.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe15:2/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:36 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:4940 (4.9 KB)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

Let’s look at ifconfig output in Container ubuntu2:

```
root@8beb85abe6a5:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:15:00:03  
          inet addr:172.21.0.3  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe15:3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:28 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:4292 (4.2 KB)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

As we can see above, each Container has their own IP address.

### **IPC Namespace**

Let’s create shared memory in Container ubuntu1:

```
root@3a1bf12161c9:/# ipcmk -M 100
Shared memory id: 0
root@3a1bf12161c9:/# ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status      
0x2fba9021 0          root       644        100        0     
```

Let’s create shared memory in Container ubuntu2:

```
root@8beb85abe6a5:/# ipcmk -M 100
Shared memory id: 0
root@8beb85abe6a5:/# ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status      
0x1f91e62c 0          root       644        100        0                  
```

As we can see above, each Container has its own IPC namespace and shared memory created in Container 1 is not visible in Container 2.

### **UTS namespace**

Let’s look at hostname of Container ubuntu1:

```
root@3a1bf12161c9:/# hostname
3a1bf12161c9
```

Let’s look at hostname of Container ubuntu2:

```
root@8beb85abe6a5:/# hostname
8beb85abe6a5
```

As we can see above, each Container has its own hostname and domainname.

### User namespace

User namespaces are available from Linux kernel versions > 3.8. With User namespace, **userid and groupid in a namespace is different from host machine’s userid and groupid** for the same user and group. When Docker Containers use User namespace, each **container gets their own userid and groupid**. For example, **root** user **inside** **Container** is **not** root **inside** **host** **machine**. This provides greater security. In case the Container gets compromised and the hacker gets root access inside Container, the hacker still cannot break inside the host machine since the root user inside the Container is not root inside the host machine. Docker introduced support for user namespace in version 1.10.\
To use user namespace, Docker daemon needs to be started with `–userns-remap=default`(In ubuntu 14.04, this can be done by modifying `/etc/default/docker` and then executing `sudo service docker restart`)\
Following output shows Docker daemon running with user namespace turned on:

```
root      8207     1  0 20:03 ?        00:00:09 /usr/bin/docker daemon --userns-remap=default
```

Let’s start a ubuntu Container and look at its UID and GID:

```
root@3a1bf12161c9:/# id
uid=0(root) gid=0(root) groups=0(root)
```

To find the UID associated with the root UID inside Container, we need to first find the PID in host machine for the Container process and get the associated UID.\
Following output shows the “bash” PID in host machine for the Container:

```
231072    8955  8207  0 21:23 pts/14   00:00:00 bash
```

Let’s look at the associated UID for PID 8955:

```
smakam14@jungle1:/usr$ cat /proc/8955/uid_map
         0     231072      65536
```

As we can see above, userid 0(root) in container 1 is mapped to userid 231072 in host machine.\
In the current Docker user namespace implementation, UID and GID mapping happens at Docker daemon level. There is work ongoing to allow the mappings to be done at Container level so that multi-tenant support is possible.

## References

* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
