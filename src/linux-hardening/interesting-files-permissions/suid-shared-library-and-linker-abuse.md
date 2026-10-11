# Matumizi Mabaya ya Shared Library na Linker ya SUID

{{#include ../../banners/hacktricks-training.md}}

Kwa kawaida, binaries za SUID hukaguliwa ili kubaini utekelezaji wa amri moja kwa moja, lakini programu maalum za SUID pia zinaweza kuwa na udhaifu kupitia dynamic linker. Wazo la jumla ni rahisi: executable yenye privileges hupakia code kutoka kwenye path au usanidi ambao mtumiaji mwenye privileges za chini anaweza kuathiri.<sup>[[1]](#references)</sup>

Ukurasa huu unaangazia mifumo ya jumla ya mbinu: libraries zilizokosekana, saraka za library zinazoweza kuandikwa, `RPATH`/`RUNPATH`, `LD_PRELOAD` kupitia sudo, usanidi wa linker, na mkanganyiko wa SUID hardlink.

Kwa maelezo kuhusu ELF program headers, dynamic section, na tabia ya loader inayohusika na ukaguzi huu, tazama [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Ukusanyaji wa Taarifa kwa Haraka

Anza kwa kutafuta faili zisizo za kawaida za SUID na kuangalia kama zimeunganishwa dynamically:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Tumia `readelf` kuchunguza executable usiyoifahamu: [`ldd` inaweza kutekeleza ELF interpreter isiyoaminika](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` huonyesha dependencies za moja kwa moja, kwa hivyo thibitisha kando njia ambayo loader imechagua.<sup>[[1]](#references)[[3]](#references)</sup>

Zingatia maeneo yasiyo ya kawaida, njia maalum za programu, binaries zinazomilikiwa na root lakini ziko nje ya saraka zinazosimamiwa na package, na dependencies zinazopakiwa kutoka kwenye saraka zenye ruhusa ya kuandikika.<sup>[[1]](#references)</sup>

Ukaguzi muhimu wa ruhusa za kuandikika:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Baadhi ya binaries maalum za SUID hujaribu kupakia shared object ambayo haipo. Ikiwa path inayokosekana iko ndani ya directory inayodhibitiwa na mshambuliaji, binary inaweza kupakia code iliyotolewa na mshambuliaji ikiwa na effective user.<sup>[[1]](#references)</sup>

Kanuni hiyo hiyo inatumika kwa **binary maalum inayoruhusiwa kupitia sudo** inapopiga `dlopen()` kwenye path kamili ya `.so` iliyo chini ya home au directory ya usanidi inayoweza kuandikwa na mtumiaji anayeiendesha. Upakiaji huu wa library unaotokea baadaye huenda usionekane kwenye `ldd` na ELF `NEEDED` entries. Ukaguzi wa `strings` wenye mipaka au ufuatiliaji wa uendeshaji **usio na privileges** unaweza kufichua path inayojaribiwa; nenosiri la programu au chaguo la menyu linaweza kuzuia lookup hiyo. Thibitisha sheria halisi ya sudo, path kamili na ruhusa za parent directory, na kwamba uendeshaji wenye privileges unafikia lookup hiyo kabla ya kuichukulia kama njia ya kupata privileges zaidi. Usiendeshe target ya sudo kwa lengo la kuiorodhesha tu.

Tafuta library lookups zilizoshindwa kwa kutumia syscall filter ya `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Ikiwa binary itatafuta `libexample.so` kwenye njia inayoweza kuandikwa, proof library ndogo inaweza kutumia constructor. Hakikisha proof-of-impact haina madhara wakati wa uthibitishaji:<sup>[[6]](#references)</sup>

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

Hali inayoweza kutumiwa vibaya si kukosekana kwa library pekee. Mshambulizi lazima aweze kuweka shared object inayolingana kwenye njia ambayo loader mwenye upendeleo atakubali.<sup>[[1]](#references)</sup>

## Directory ya Library Inayoweza Kuandikwa

Wakati mwingine dependencies zote zipo, lakini mojawapo ya directories zinazotumika kuzitatua inaweza kuandikwa. Hii inaweza kuruhusu kubadilisha library iliyopakiwa au kuweka library yenye jina lilelile na kipaumbele cha juu zaidi.<sup>[[1]](#references)</sup>

Ukaguzi huohuo unatumika kwa ELF maalum **inayoruhusiwa kupitia sudo**, hata kama ELF haina SUID bit na akaunti ya RunAs iliyoruhusiwa si root. Linganisha maingizo yake ya `DT_NEEDED` na pathname ya library ambayo loader itatatua; kisha angalia kama mtumiaji anayeita amri anaweza kuandika faili hiyo au kuibadilisha kupitia parent directory inayoweza kuandikwa na kutafutwa. Thibitisha kanuni halisi ya sudo RunAs, symlinks na ACLs, sera ya loader, na kwamba mchakato lengwa unapakia library hiyo ukiwa na akaunti yenye upendeleo wa juu zaidi. `.so` inayoweza kuandikwa au jina la dependency pekee ni kidokezo tu; kagua metadata bila kuendesha amri ya sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Kagua njia za dependencies:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Ikiwa directory inaweza kuandikwa, thibitisha kwa kutumia mbinu salama inayotumia nakala kwenye lab. Kubadilisha maktaba za mfumo kwenye host inayotumika kunaweza kusababisha michakato inayoanza kwa wakati mmoja kutumia matoleo yasiyolingana ya maktaba.<sup>[[8]](#references)</sup>

### Maktaba zinazoweza kuandikwa ndani ya chroot

chroot pekee haifungi file descriptors zilizorithiwa wala kuzuia ufikiaji wote wa filesystem. Ikiwa sandbox itaacha descriptor ya directory inayoelekeza nje ya root yake mpya, na mchakato uliofungiwa unaweza kutumia descriptor hiyo (kwa mfano, kupitia entry ya `/proc/<pid>/fd/` inayoweza kufikiwa), paths za host zinaweza kubaki zinafikika. Hili ni tatizo la mpaka wa filesystem; lenyewe halitoi ruhusa za root.<sup>[[11]](#references)[[12]](#references)</sup>

Kagua kando ikiwa mtumiaji aliyefungiwa anaweza kuandika kwenye directory ya maktaba ambayo **executable ya host yenye root-SUID** itatumia ikizinduliwa kutoka kwenye jail. Loader hutatua dependencies kulingana na mtazamo wa filesystem wa mchakato, kwa hiyo maktaba inayodhibitiwa na mshambuliaji hapo inaweza kutekelezwa kwa utambulisho wa effective wa programu ya SUID. Thibitisha executable husika, SUID bit yake na mount policy, target na ruhusa za ufikiaji za descriptor, library search path ya jail, na kwamba programu inaweza kufikia executable ya host. File capability kwenye sandbox launcher, jail inayoweza kuandikwa, au binary ya host ya SUID pekee ni dalili tu; mnyororo mzima hutegemea jinsi sandbox ilivyotekelezwa.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` na `RUNPATH` ni entries za dynamic section zinazoiambia loader mahali pa kutafuta maktaba. Ni hatari katika programu za SUID zinapoelekeza kwenye directories zinazoweza kuandikwa na mshambuliaji.<sup>[[1]](#references)</sup>

Zigundue:<sup>[[3]](#references)[[10]](#references)</sup>

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

`RPATH` na `RUNPATH` hazifanani katika maelezo yote ya utatuzi, lakini kwa ukaguzi wa privilege-escalation swali la msingi ni lilelile: je, binary ya SUID hutafuta jina la library katika directory inayoweza kuandikwa na mshambuliaji?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH na SUID

Kwa programu za kawaida, `LD_PRELOAD` na `LD_LIBRARY_PATH` zinaweza kulazimisha au kuathiri upakiaji wa shared object. Kwa programu za SUID, dynamic loader kwa kawaida huingia katika hali ya secure-execution na kupuuza environment variables hatari.<sup>[[1]](#references)</sup>

Hii inamaanisha kuwa binary ya kawaida ya SUID kwa kawaida si hatarishi kwa sababu tu mtumiaji anaweza kuweka `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Isipokuwa cha kawaida ni sera ya sudo inayoruhusu kuweka thamani ya mazingira kwenye mstari wa amri kwa target, kama vile tag ya `SETENV` au chaguo la `setenv` linalotumika. Ikiwa target imeunganishwa kwa njia ya dynamic na sudo inakubali `LD_PRELOAD=/path/to/library`, target inaweza kupakia code inayodhibitiwa na mpigaji. Kagua kanuni inayotumika na utambulisho wa target. Kuongeza tu `LD_PRELOAD` kwenye `env_keep` hakutoshi kwenye mifumo ambako dynamic loader huondoa `LD_PRELOAD` iliyorithiwa kabla ya mchakato wa SUID `sudo` kuanza; sudo hutathmini thamani iliyowekwa kwenye mstari wa amri baada ya kuanza yenyewe.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Usichanganye hali hizi; sheria za loader na sera ya sudo zilizo hapo juu huzitofautisha:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` dhidi ya binary ya kawaida ya SUID: kwa kawaida huzuiwa na secure execution.
- `LD_PRELOAD` ikikubaliwa kama assignment ya mstari wa amri ya sudo kwa target yenye privileged na iliyounganishwa dynamically: inaweza kutumiwa vibaya.
- `.so` haipo kwenye path inayoweza kuandikwa: inaweza kutumiwa vibaya ikiwa binary ya SUID hupakia path hiyo kwa kawaida.
- `RPATH`/`RUNPATH` inayoelekeza kwenye directory inayoweza kuandikwa: inaweza kutumiwa vibaya ikiwa library inayohitajika inaweza kudhibitiwa.
- Ruhusa za kuandika kwenye `/etc/ld.so.preload` au usanidi wa linker: huathiri mfumo mzima na zina athari kubwa.

## Usanidi wa Linker

`ld.so` hutumia linker cache na `/etc/ld.so.preload`; `ldconfig` huunda cache hiyo kutoka `/etc/ld.so.conf` na faili zinazojumuishwa humo, mara nyingi kutoka `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Ukaguzi muhimu:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Mipangilio ya linker inayoweza kuandikwa kwa kawaida ni tatizo kubwa zaidi kuliko binary moja ya SUID iliyo hatarini, kwa sababu inaweza kuathiri michakato mingi inayotumia dynamic linking. `/etc/ld.so.preload` ni hatari hasa kwa sababu inaweza kulazimisha shared object kupakiwa katika michakato yenye mapendeleo.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Mkanganyiko wa Hardlink za SUID

Hardlink zinaweza kufanya inode ileile ya SUID ionekane kwa majina mengi.<sup>[[9]](#references)</sup> Hii ni muhimu kwa kuficha helper yenye mapendeleo, kuchanganya usafishaji au kukwepa ukaguzi wa kijuujuu unaotegemea path.

Tafuta faili za SUID zilizo na link zaidi ya moja:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Kagua njia zote zinazoelekeza kwenye inode ileile:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Matumizi mabaya hayahusiani na hardlink kubadilisha permissions. Ni mkanganyiko wa path: inode yenye privileges inaweza kufikiwa kupitia jina ambalo defenders au scripts hawatarajii.<sup>[[9]](#references)</sup> Kwa maelezo zaidi kuhusu inode na workflow ya hardlink, angalia [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Weka SUID binaries chache, zilizokaguliwa na zinazosimamiwa na package inapowezekana.
- Epuka entries za `RPATH`/`RUNPATH` zinazoelekeza kwenye directories zinazoweza kuandikwa au zinazosimamiwa na application.<sup>[[1]](#references)[[8]](#references)</sup>
- Hakikisha directories za library zinamilikiwa na root na haziwezi kuandikwa na users wa kawaida.<sup>[[8]](#references)</sup>
- Usihifadhi `LD_PRELOAD`, `LD_LIBRARY_PATH`, au variables zinazofanana za loader kupitia sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Fuatilia `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na SUID files zisizotarajiwa.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Kagua SUID files zilizounganishwa kwa hardlink na chunguza SUID wrappers maalum zilizo nje ya system paths za kawaida.<sup>[[9]](#references)</sup>

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
- [11] [chroot(2) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
